import { execFile } from "node:child_process";
import { mkdir, symlink, unlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

import type { BrowserWindow } from "electron";
import { afterEach, describe, expect, it } from "vitest";

import type {
  ApprovalAuthoritySnapshot,
  DirectorStatus,
  ErrorEnvelope,
  ExecutionApprovalReview,
  Method,
} from "../../src/generated/studio-protocol-v6";
import {
  MAX_DIRECTOR_REVIEW_BYTES,
  StudioDirectorAuthority,
  StudioDirectorDomainError,
  directorReviewOpenFlags,
  readDirectorReviewFile,
  type StudioDirectorModalClient,
  type StudioDirectorServiceClient,
} from "../../src/main/director-authority";
import {
  StudioRequestTimeoutError,
  StudioTransportError,
} from "../../src/main/ndjson-supervisor";
import { directorReview } from "../fixtures/director-review";

const roots: string[] = [];
const parent = {} as BrowserWindow;
const execFileAsync = promisify(execFile);

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map(async (root) => {
      await import("node:fs/promises").then(({ rm }) =>
        rm(root, { force: true, recursive: true }),
      );
    }),
  );
});

async function temporaryRoot(): Promise<string> {
  const root = await import("node:fs/promises").then(({ mkdtemp }) =>
    mkdtemp(path.join(os.tmpdir(), "studio-director-test-")),
  );
  roots.push(root);
  return root;
}

class FakeDirectorService implements StudioDirectorServiceClient {
  public readonly calls: Array<{
    method: Method;
    params: Record<string, unknown>;
    protocolVersion: 6;
  }> = [];
  public maxConcurrent = 0;
  public delayMs = 0;
  public rejectMethod: Method | null = null;
  public rejectAfterMutationMethod: Method | null = null;
  public timeoutAfterMutationMethod: Method | null = null;
  public errorReply: {
    method: Method;
    code: ErrorEnvelope["error"]["code"];
    message: string;
  } | null = null;
  public status: DirectorStatus = {
    credential_id: "director_local",
    state: "not_enrolled",
  };
  public snapshot: ApprovalAuthoritySnapshot | null = null;
  readonly #listeners = new Set<(event: unknown) => void>();
  #concurrent = 0;

  public subscribe(listener: (event: never) => void): () => void {
    this.#listeners.add(listener as (event: unknown) => void);
    return () => this.#listeners.delete(listener as (event: unknown) => void);
  }

  public emitStatus(state: "stopped" | "starting" | "ready" | "crashed" | "unavailable"): void {
    for (const listener of this.#listeners) {
      listener({
        type: "service-status",
        status: { state, message: state, pid: null },
      });
    }
  }

  public async request(
    requestId: string,
    method: Method,
    params: Record<string, unknown>,
    timeoutMs: number,
    protocolVersion: 6,
  ): Promise<unknown> {
    void timeoutMs;
    this.calls.push({ method, params, protocolVersion });
    this.#concurrent += 1;
    this.maxConcurrent = Math.max(this.maxConcurrent, this.#concurrent);
    if (this.delayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, this.delayMs));
    }
    this.#concurrent -= 1;
    if (method === this.rejectMethod) {
      throw new StudioTransportError(`simulated ${method} transport failure`);
    }
    if (this.errorReply?.method === method) {
      return {
        protocol: "rpg-world-forge.studio_protocol",
        protocol_version: 6,
        kind: "error",
        request_id: requestId,
        error: {
          code: this.errorReply.code,
          message: this.errorReply.message,
          details: {},
        },
      };
    }

    if (method === "director.enroll" || method === "director.unlock") {
      this.status = { credential_id: "director_local", state: "unlocked" };
    } else if (method === "director.lock") {
      this.status = { credential_id: "director_local", state: "locked" };
    }
    if (method === "director.review.inspect") {
      const review = params.review as ExecutionApprovalReview;
      this.snapshot = {
        prepared_review: null,
        current_decision: null,
        generation: 0,
        review_hash: review.content_hash,
        decision_hash: null,
        state: "missing",
      };
    } else if (method === "director.review.prepare") {
      const review = params.review as ExecutionApprovalReview;
      this.snapshot = {
        prepared_review: review,
        current_decision: null,
        generation: 0,
        review_hash: review.content_hash,
        decision_hash: null,
        state: "prepared",
      };
    } else if (method === "director.review.approve") {
      const review = params.review as ExecutionApprovalReview;
      this.snapshot = {
        prepared_review: review,
        current_decision: {
          format: "world-forge.private.execution_approval_decision",
          format_version: 1,
          approval_id: review.approval_id,
          execution_id: review.execution_id,
          review_hash: review.content_hash,
          generation: 1,
          reviewer_id: "director_local",
          outcome: "approved",
          approved_tool_ids: params.approved_tool_ids as string[],
          expires_at_ms: params.expires_at_ms as number,
          content_hash: "2".repeat(64),
        },
        generation: 1,
        review_hash: review.content_hash,
        decision_hash: "2".repeat(64),
        state: "approved",
      };
    } else if (method === "director.review.deny") {
      const review = params.review as ExecutionApprovalReview;
      this.snapshot = {
        prepared_review: review,
        current_decision: {
          format: "world-forge.private.execution_approval_decision",
          format_version: 1,
          approval_id: review.approval_id,
          execution_id: review.execution_id,
          review_hash: review.content_hash,
          generation: 1,
          reviewer_id: "director_local",
          outcome: "denied",
          approved_tool_ids: [],
          expires_at_ms: null,
          content_hash: "3".repeat(64),
        },
        generation: 1,
        review_hash: review.content_hash,
        decision_hash: "3".repeat(64),
        state: "denied",
      };
    } else if (method === "director.review.revoke") {
      if (!this.snapshot?.current_decision) throw new Error("missing decision");
      this.snapshot = { ...this.snapshot, generation: 2, state: "revoked" };
    }

    if (method === this.rejectAfterMutationMethod) {
      throw new StudioTransportError(`simulated ${method} post-mutation transport failure`);
    }
    if (method === this.timeoutAfterMutationMethod) {
      throw new StudioRequestTimeoutError(requestId);
    }

    const result =
      method.startsWith("director.review.")
        ? { snapshot: this.snapshot }
        : { status: this.status };
    return {
      protocol: "rpg-world-forge.studio_protocol",
      protocol_version: 6,
      kind: "response",
      request_id: requestId,
      method,
      result,
    };
  }
}

function modal(
  decision: "approve" | "deny" = "approve",
): StudioDirectorModalClient {
  return {
    requestCredential() {
      return Promise.resolve({
        action: "submit" as const,
        passphrase: "correct horse battery staple",
      });
    },
    requestDecision() {
      return Promise.resolve(decision === "deny"
        ? { action: "deny" }
        : {
            action: "approve",
            approvedToolIds: ["source.read"],
            expiresAtMs: 20_000,
          });
    },
  };
}

describe("Director review file import", () => {
  it("opens POSIX reviews nonblocking while preserving Windows flags", () => {
    expect(directorReviewOpenFlags("linux", 0x20_000, 0x800)).toBe(0x20_800);
    expect(directorReviewOpenFlags("darwin", 0x20_000, 0x800)).toBe(0x20_800);
    expect(directorReviewOpenFlags("win32", 0x20_000, 0x800)).toBe(0);
  });

  it("accepts only one bounded, no-follow, stable regular JSON file", async () => {
    const root = await temporaryRoot();
    const reviewPath = path.join(root, "review.json");
    await writeFile(reviewPath, JSON.stringify(directorReview), { flag: "wx" });
    await expect(readDirectorReviewFile(reviewPath)).resolves.toEqual(directorReview);

    const duplicatePath = path.join(root, "duplicate.json");
    await writeFile(duplicatePath, '{"format":1,"format":2}', { flag: "wx" });
    await expect(readDirectorReviewFile(duplicatePath)).rejects.toThrow("invalid");

    const oversizedPath = path.join(root, "oversized.json");
    await writeFile(oversizedPath, Buffer.alloc(MAX_DIRECTOR_REVIEW_BYTES + 1, 0x20), {
      flag: "wx",
    });
    await expect(readDirectorReviewFile(oversizedPath)).rejects.toThrow("invalid");

    if (process.platform !== "win32") {
      const linkPath = path.join(root, "link.json");
      await symlink(reviewPath, linkPath);
      await expect(readDirectorReviewFile(linkPath)).rejects.toThrow("invalid");
    }
  });

  it("rejects a named-file replacement across the open boundary", async () => {
    const root = await temporaryRoot();
    const reviewPath = path.join(root, "review.json");
    const replacement = path.join(root, "replacement.json");
    await Promise.all([
      writeFile(reviewPath, JSON.stringify(directorReview), { flag: "wx" }),
      writeFile(replacement, JSON.stringify(directorReview), { flag: "wx" }),
    ]);

    await expect(
      readDirectorReviewFile(reviewPath, {
        beforeOpen: async () => {
          const { rename } = await import("node:fs/promises");
          await rename(replacement, reviewPath);
        },
      }),
    ).rejects.toThrow("invalid");
  });

  it.skipIf(process.platform === "win32")(
    "rejects a regular-file to FIFO swap without blocking",
    async () => {
      const root = await temporaryRoot();
      const reviewPath = path.join(root, "review.json");
      await writeFile(reviewPath, JSON.stringify(directorReview), { flag: "wx" });

      await expect(
        readDirectorReviewFile(reviewPath, {
          beforeOpen: async () => {
            await unlink(reviewPath);
            await execFileAsync("/usr/bin/mkfifo", [reviewPath]);
          },
        }),
      ).rejects.toThrow("invalid");
    },
  );
});

describe("StudioDirectorAuthority", () => {
  it("owns credentials, selected review, CAS fields, and decision construction in main", async () => {
    const root = await temporaryRoot();
    const reviewPath = path.join(root, "review.json");
    await writeFile(reviewPath, JSON.stringify(directorReview), { flag: "wx" });
    const service = new FakeDirectorService();
    const authority = new StudioDirectorAuthority({
      service,
      dialogs: {
        showOpenDialog() {
          return Promise.resolve({ canceled: false, filePaths: [reviewPath] });
        },
      },
      modal: modal(),
      nowMs: () => 10_000,
      requestId: (() => {
        let next = 0;
        return () => `director_${String((next += 1)).padStart(2, "0")}`;
      })(),
    });

    expect((await authority.getStatus()).status.state).toBe("not_enrolled");
    expect((await authority.enroll(parent)).status.state).toBe("unlocked");
    expect((await authority.selectReview(parent)).snapshot?.state).toBe("missing");
    expect((await authority.prepareSelectedReview()).snapshot?.state).toBe("prepared");
    expect((await authority.requestSelectedDecision(parent)).snapshot?.state).toBe(
      "approved",
    );
    expect((await authority.revokeSelectedDecision()).snapshot?.state).toBe("revoked");

    const enroll = service.calls.find((call) => call.method === "director.enroll");
    expect(enroll?.params).toEqual({ passphrase: "correct horse battery staple" });
    const approve = service.calls.find(
      (call) => call.method === "director.review.approve",
    );
    expect(approve?.params).toEqual({
      review: directorReview,
      expected_generation: 0,
      expected_review_hash: directorReview.content_hash,
      approved_tool_ids: ["source.read"],
      expires_at_ms: 20_000,
    });
    expect(approve?.params).not.toHaveProperty("path");
    expect(approve?.params).not.toHaveProperty("reviewer_id");
    expect(approve?.params).not.toHaveProperty("outcome");

    const locked = await authority.lock();
    expect(locked.status.state).toBe("locked");
    expect(locked.selectedReview).toBeNull();
    expect(locked.snapshot).toBeNull();
  });

  it("fails closed before a lock request and recovers only through status refresh", async () => {
    const root = await temporaryRoot();
    const reviewPath = path.join(root, "review.json");
    await writeFile(reviewPath, JSON.stringify(directorReview), { flag: "wx" });
    const service = new FakeDirectorService();
    const authority = new StudioDirectorAuthority({
      service,
      dialogs: {
        showOpenDialog() {
          return Promise.resolve({ canceled: false, filePaths: [reviewPath] });
        },
      },
      modal: modal(),
    });

    await authority.enroll(parent);
    await authority.selectReview(parent);
    expect(authority.currentState().selectedReview).toEqual(directorReview);
    service.rejectMethod = "director.lock";

    await expect(authority.lock()).rejects.toMatchObject({
      name: "StudioDirectorDomainError",
      code: "service_unavailable",
      message: "Director service request did not complete.",
    });
    expect(authority.currentState()).toEqual({
      status: { credentialId: "director_local", state: "locked" },
      selectedReview: null,
      snapshot: null,
    });

    service.rejectMethod = null;
    service.status = { credential_id: "director_local", state: "locked" };
    await expect(authority.getStatus()).resolves.toEqual({
      status: { credentialId: "director_local", state: "locked" },
      selectedReview: null,
      snapshot: null,
    });
  });

  it.each([
    ["enroll", "director.enroll", "not_enrolled"],
    ["unlock", "director.unlock", "locked"],
  ] as const)(
    "projects unknown after an ambiguous %s response and recovers only through status",
    async (operation, method, initialState) => {
      const service = new FakeDirectorService();
      service.status = {
        credential_id: "director_local",
        state: initialState,
      };
      service.rejectAfterMutationMethod = method;
      const authority = new StudioDirectorAuthority({
        service,
        dialogs: {
          showOpenDialog() {
            return Promise.resolve({ canceled: true, filePaths: [] });
          },
        },
        modal: modal(),
      });

      await expect(authority[operation](parent)).rejects.toMatchObject({
        name: "StudioDirectorDomainError",
        code: "service_unavailable",
        message: "Director service request did not complete.",
      });
      expect(service.status.state).toBe("unlocked");
      expect(authority.currentState()).toEqual({
        status: { credentialId: "director_local", state: "unknown" },
        selectedReview: null,
        snapshot: null,
      });

      service.rejectAfterMutationMethod = null;
      await expect(authority.getStatus()).resolves.toEqual({
        status: { credentialId: "director_local", state: "unlocked" },
        selectedReview: null,
        snapshot: null,
      });
    },
  );

  it.each([
    ["unlock", "director.unlock", "locked", "invalid_state", "Director credential was not accepted."],
    ["enroll", "director.enroll", "not_enrolled", "invalid_request", "Director credential request was rejected."],
  ] as const)(
    "preserves a known credential projection for sanitized %s rejection",
    async (operation, method, initialState, code, message) => {
      const service = new FakeDirectorService();
      service.status = {
        credential_id: "director_local",
        state: initialState,
      };
      service.errorReply = {
        method,
        code,
        message: "private /tmp/review.json secret-passphrase service detail",
      };
      const authority = new StudioDirectorAuthority({
        service,
        dialogs: {
          showOpenDialog() {
            return Promise.resolve({ canceled: true, filePaths: [] });
          },
        },
        modal: modal(),
      });
      await authority.getStatus();

      const result = authority[operation](parent);
      await expect(result).rejects.toBeInstanceOf(StudioDirectorDomainError);
      await expect(result).rejects.toMatchObject({
        name: "StudioDirectorDomainError",
        code,
        message,
      });
      expect(authority.currentState()).toEqual({
        status: { credentialId: "director_local", state: initialState },
        selectedReview: null,
        snapshot: null,
      });
    },
  );

  it("keeps credential projection unknown for sanitized internal and timeout ambiguity", async () => {
    for (const failure of ["internal_error", "timeout"] as const) {
      const service = new FakeDirectorService();
      service.status = { credential_id: "director_local", state: "locked" };
      if (failure === "timeout") {
        service.timeoutAfterMutationMethod = "director.unlock";
      } else {
        service.errorReply = {
          method: "director.unlock",
          code: "internal_error",
          message: "private /tmp/review.json secret-passphrase service detail",
        };
      }
      const authority = new StudioDirectorAuthority({
        service,
        dialogs: {
          showOpenDialog() {
            return Promise.resolve({ canceled: true, filePaths: [] });
          },
        },
        modal: modal(),
      });

      const result = authority.unlock(parent);
      await expect(result).rejects.toBeInstanceOf(StudioDirectorDomainError);
      await expect(result).rejects.toMatchObject({
        name: "StudioDirectorDomainError",
        code: failure,
      });
      expect(authority.currentState()).toEqual({
        status: { credentialId: "director_local", state: "unknown" },
        selectedReview: null,
        snapshot: null,
      });
    }
  });

  it("preserves a sanitized conflict code while discarding stale review evidence", async () => {
    const root = await temporaryRoot();
    const reviewPath = path.join(root, "conflict.json");
    await writeFile(reviewPath, JSON.stringify(directorReview), { flag: "wx" });
    const service = new FakeDirectorService();
    service.status = { credential_id: "director_local", state: "locked" };
    const authority = new StudioDirectorAuthority({
      service,
      dialogs: {
        showOpenDialog() {
          return Promise.resolve({ canceled: false, filePaths: [reviewPath] });
        },
      },
      modal: modal(),
    });
    await authority.unlock(parent);
    await authority.selectReview(parent);
    service.errorReply = {
      method: "director.review.prepare",
      code: "conflict",
      message: "private /tmp/review.json secret-passphrase service detail",
    };

    const result = authority.prepareSelectedReview();
    await expect(result).rejects.toBeInstanceOf(StudioDirectorDomainError);
    await expect(result).rejects.toMatchObject({
      name: "StudioDirectorDomainError",
      code: "conflict",
      message: "Exact Director review state changed.",
    });
    expect(authority.currentState()).toMatchObject({
      status: { state: "unlocked" },
      selectedReview: null,
      snapshot: null,
    });
  });

  it("retains prior evidence only when modal cancellation precedes every mutation request", async () => {
    const root = await temporaryRoot();
    const reviewPath = path.join(root, "cancel.json");
    await writeFile(reviewPath, JSON.stringify(directorReview), { flag: "wx" });
    const service = new FakeDirectorService();
    service.status = { credential_id: "director_local", state: "locked" };
    const authority = new StudioDirectorAuthority({
      service,
      dialogs: {
        showOpenDialog() {
          return Promise.resolve({ canceled: false, filePaths: [reviewPath] });
        },
      },
      modal: {
        requestCredential() {
          return Promise.resolve({ action: "cancel" });
        },
        requestDecision() {
          return Promise.resolve({ action: "cancel" });
        },
      },
    });

    expect(await authority.unlock(parent)).toMatchObject({
      status: { state: "locked" },
    });
    expect(service.calls.some((call) => call.method === "director.unlock")).toBe(false);

    const preparedAuthority = new StudioDirectorAuthority({
      service,
      dialogs: {
        showOpenDialog() {
          return Promise.resolve({ canceled: false, filePaths: [reviewPath] });
        },
      },
      modal: {
        requestCredential() {
          return Promise.resolve({
            action: "submit",
            passphrase: "correct horse battery staple",
          });
        },
        requestDecision() {
          return Promise.resolve({ action: "cancel" });
        },
      },
    });
    await preparedAuthority.unlock(parent);
    await preparedAuthority.selectReview(parent);
    await preparedAuthority.prepareSelectedReview();
    const before = preparedAuthority.currentState();
    const mutationCalls = service.calls.filter((call) =>
      ["director.review.approve", "director.review.deny"].includes(call.method),
    ).length;

    expect(await preparedAuthority.requestSelectedDecision(parent)).toEqual(before);
    expect(service.calls.filter((call) =>
      ["director.review.approve", "director.review.deny"].includes(call.method),
    )).toHaveLength(mutationCalls);
  });

  it("rejects unpaired credential surrogates before service dispatch", async () => {
    for (const passphrase of [
      "\ud800".repeat(6),
      "\udfff".repeat(6),
      "a".repeat(16) + "\ud800",
    ]) {
      const service = new FakeDirectorService();
      const authority = new StudioDirectorAuthority({
        service,
        dialogs: {
          showOpenDialog() {
            return Promise.resolve({ canceled: true, filePaths: [] });
          },
        },
        modal: {
          requestCredential() {
            return Promise.resolve({ action: "submit", passphrase });
          },
          requestDecision() {
            return Promise.resolve({ action: "cancel" });
          },
        },
      });

      await expect(authority.enroll(parent)).rejects.toThrow(
        "Director credential reply fields are invalid",
      );
      expect(service.calls).toEqual([]);
    }

    const service = new FakeDirectorService();
    const authority = new StudioDirectorAuthority({
      service,
      dialogs: {
        showOpenDialog() {
          return Promise.resolve({ canceled: true, filePaths: [] });
        },
      },
      modal: {
        requestCredential() {
          return Promise.resolve({ action: "submit", passphrase: "😀".repeat(4) });
        },
        requestDecision() {
          return Promise.resolve({ action: "cancel" });
        },
      },
    });
    await expect(authority.enroll(parent)).resolves.toMatchObject({
      status: { state: "unlocked" },
    });
  });

  it("serializes operations and clears selected authority on a service crash", async () => {
    const root = await temporaryRoot();
    const reviewPath = path.join(root, "review.json");
    await mkdir(root, { recursive: true });
    await writeFile(reviewPath, JSON.stringify(directorReview), { flag: "wx" });
    const service = new FakeDirectorService();
    service.status = { credential_id: "director_local", state: "locked" };
    const authority = new StudioDirectorAuthority({
      service,
      dialogs: {
        showOpenDialog() {
          return Promise.resolve({ canceled: false, filePaths: [reviewPath] });
        },
      },
      modal: modal(),
      nowMs: () => 10_000,
      requestId: () => `request_${String(service.calls.length + 1).padStart(2, "0")}`,
    });
    await authority.unlock(parent);
    await authority.selectReview(parent);
    service.delayMs = 10;

    const preparing = authority.prepareSelectedReview();
    const deciding = authority.requestSelectedDecision(parent);
    await Promise.all([preparing, deciding]);
    expect(service.maxConcurrent).toBe(1);

    service.emitStatus("crashed");
    const state = authority.currentState();
    expect(state.status.state).toBe("locked");
    expect(state.selectedReview).toBeNull();
    expect(state.snapshot).toBeNull();
  });

  it.each([
    ["prepare", "director.review.prepare", "prepared", "approve"],
    ["approve", "director.review.approve", "approved", "approve"],
    ["deny", "director.review.deny", "denied", "deny"],
    ["revoke", "director.review.revoke", "revoked", "approve"],
  ] as const)(
    "clears exact review authority after ambiguous %s completion",
    async (operation, method, committedState, decision) => {
      for (const failure of ["post-commit rejection", "timeout"] as const) {
        const root = await temporaryRoot();
        const reviewPath = path.join(root, `${operation}-${failure}.json`);
        await writeFile(reviewPath, JSON.stringify(directorReview), { flag: "wx" });
        const service = new FakeDirectorService();
        service.status = { credential_id: "director_local", state: "locked" };
        const authority = new StudioDirectorAuthority({
          service,
          dialogs: {
            showOpenDialog() {
              return Promise.resolve({ canceled: false, filePaths: [reviewPath] });
            },
          },
          modal: modal(decision),
          nowMs: () => 10_000,
        });
        await authority.unlock(parent);
        await authority.selectReview(parent);
        if (method !== "director.review.prepare") {
          await authority.prepareSelectedReview();
        }
        if (method === "director.review.revoke") {
          await authority.requestSelectedDecision(parent);
        }
        if (failure === "timeout") {
          service.timeoutAfterMutationMethod = method;
        } else {
          service.rejectAfterMutationMethod = method;
        }

        const result =
          method === "director.review.prepare"
            ? authority.prepareSelectedReview()
            : method === "director.review.revoke"
              ? authority.revokeSelectedDecision()
              : authority.requestSelectedDecision(parent);
        await expect(result).rejects.toThrow();
        expect(service.snapshot?.state).toBe(committedState);
        expect(authority.currentState()).toEqual({
          status: { credentialId: "director_local", state: "unlocked" },
          selectedReview: null,
          snapshot: null,
        });
        const sentCalls = service.calls.length;
        await expect(authority.prepareSelectedReview()).rejects.toThrow(
          "No exact Director review is selected",
        );
        expect(service.calls).toHaveLength(sentCalls);
      }
    },
  );

  it("invalidates an open file-selection ceremony when the service lifecycle changes", async () => {
    const root = await temporaryRoot();
    const reviewPath = path.join(root, "review.json");
    await writeFile(reviewPath, JSON.stringify(directorReview), { flag: "wx" });
    let resolveDialog!: (value: {
      canceled: false;
      filePaths: string[];
    }) => void;
    const dialogResult = new Promise<{
      canceled: false;
      filePaths: string[];
    }>((resolve) => {
      resolveDialog = resolve;
    });
    const service = new FakeDirectorService();
    service.status = { credential_id: "director_local", state: "locked" };
    const authority = new StudioDirectorAuthority({
      service,
      dialogs: {
        showOpenDialog() {
          return dialogResult;
        },
      },
      modal: modal(),
      nowMs: () => 10_000,
      requestId: () => `request_${String(service.calls.length + 1).padStart(2, "0")}`,
    });
    await authority.unlock(parent);

    const selecting = authority.selectReview(parent);
    await Promise.resolve();
    service.emitStatus("crashed");
    resolveDialog({ canceled: false, filePaths: [reviewPath] });

    await expect(selecting).rejects.toThrow(
      "Director ceremony state changed during operation",
    );
    expect(
      service.calls.some((call) => call.method === "director.review.inspect"),
    ).toBe(false);
    expect(authority.currentState()).toMatchObject({
      status: { state: "locked" },
      selectedReview: null,
      snapshot: null,
    });
  });

  it("does not send a passphrase returned by a modal invalidated by service loss", async () => {
    let resolveCredential!: (value: {
      action: "submit";
      passphrase: string;
    }) => void;
    const credentialResult = new Promise<{
      action: "submit";
      passphrase: string;
    }>((resolve) => {
      resolveCredential = resolve;
    });
    const service = new FakeDirectorService();
    const authority = new StudioDirectorAuthority({
      service,
      dialogs: {
        showOpenDialog() {
          return Promise.resolve({ canceled: true, filePaths: [] });
        },
      },
      modal: {
        requestCredential() {
          return credentialResult;
        },
        requestDecision() {
          return Promise.resolve({ action: "cancel" });
        },
      },
    });

    const enrolling = authority.enroll(parent);
    await Promise.resolve();
    service.emitStatus("crashed");
    resolveCredential({
      action: "submit",
      passphrase: "correct horse battery staple",
    });

    await expect(enrolling).rejects.toThrow(
      "Director ceremony state changed during operation",
    );
    expect(
      service.calls.some((call) => call.method === "director.enroll"),
    ).toBe(false);
  });
});
