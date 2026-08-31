import { describe, expect, it, vi } from "vitest";

import { registerStudioIpc } from "../../src/main/ipc";
import { StudioDirectorDomainError } from "../../src/main/director-authority";
import { createStudioApi, type PreloadTransport } from "../../src/preload/api";
import {
  IPC_CHANNELS,
  type StudioDirectorCeremonyState,
} from "../../src/shared/studio-api";

const state: StudioDirectorCeremonyState = {
  status: { credentialId: "director_local", state: "locked" },
  selectedReview: null,
  snapshot: null,
};

const directorOperations = [
  ["getStatus", "getDirectorStatus"],
  ["enroll", "enrollDirector"],
  ["unlock", "unlockDirector"],
  ["lock", "lockDirector"],
  ["selectReview", "selectDirectorReview"],
  ["prepareSelectedReview", "prepareSelectedDirectorReview"],
  ["requestSelectedDecision", "requestSelectedDirectorDecision"],
  ["revokeSelectedDecision", "revokeSelectedDirectorDecision"],
] as const;

describe("Studio Director named IPC", () => {
  it("accepts only trusted argument-free calls and disposes every handler", async () => {
    const handlers = new Map<string, (event: unknown, ...args: unknown[]) => unknown>();
    const ipcMain = {
      handle: vi.fn(
        (channel: string, handler: (event: unknown, ...args: unknown[]) => unknown) => {
          handlers.set(channel, handler);
        },
      ),
      removeHandler: vi.fn((channel: string) => handlers.delete(channel)),
    };
    const mainFrame = { url: "rwf-studio://app/index.html" };
    const webContents = { mainFrame, isDestroyed: () => false, send: vi.fn() };
    const window = { webContents, isDestroyed: () => false };
    const authority = Object.fromEntries(
      directorOperations.map(([method]) => [method, vi.fn().mockResolvedValue(state)]),
    );
    const service = {
      status: { state: "ready", message: "ready", pid: 1 },
      subscribe: () => () => undefined,
    };
    const codex = { subscribe: () => () => undefined };
    const dispose = registerStudioIpc(
      ipcMain as never,
      window as never,
      service as never,
      codex as never,
      { showOpenDialog: vi.fn(), showSaveDialog: vi.fn() },
      undefined,
      { directorAuthority: authority as never },
    );
    const trusted = { sender: webContents, senderFrame: mainFrame };
    const untrusted = { sender: {}, senderFrame: mainFrame };

    for (const [method, channelKey] of directorOperations) {
      const channel = IPC_CHANNELS[channelKey];
      const handler = handlers.get(channel);
      expect(handler, channel).toBeDefined();
      await expect(handler!(trusted)).resolves.toEqual({ ok: true, value: state });
      await expect(handler!(trusted, { forbidden: true })).resolves.toMatchObject({
        ok: false,
        error: { code: "invalid_request" },
      });
      await expect(handler!(untrusted)).resolves.toMatchObject({
        ok: false,
        error: { code: "invalid_request" },
      });
      expect(authority[method]).toHaveBeenCalledTimes(1);
    }

    dispose();
    for (const [, channelKey] of directorOperations) {
      expect(handlers.has(IPC_CHANNELS[channelKey])).toBe(false);
    }
  });

  it.each([
    [
      "Error",
      new Error("secret-error /tmp/private-review.json file:///home/director/review.json"),
    ],
    [
      "string",
      "secret-string /tmp/private-review.json file:///home/director/review.json",
    ],
    [
      "object",
      {
        message: "secret-object",
        path: "/tmp/private-review.json",
        url: "file:///home/director/review.json",
      },
    ],
    [
      "non-domain TypeError",
      new TypeError("secret-type /tmp/private-review.json file:///home/director/review.json"),
    ],
  ] as const)(
    "sanitizes an unexpected %s through every Director handler and preload method",
    async (_kind, thrown) => {
      const handlers = new Map<
        string,
        (event: unknown, ...args: unknown[]) => unknown
      >();
      const ipcMain = {
        handle(
          channel: string,
          handler: (event: unknown, ...args: unknown[]) => unknown,
        ) {
          handlers.set(channel, handler);
        },
        removeHandler: vi.fn(),
      };
      const mainFrame = { url: "rwf-studio://app/index.html" };
      const webContents = {
        mainFrame,
        isDestroyed: () => false,
        send: vi.fn(),
      };
      const window = { webContents, isDestroyed: () => false };
      const authority = Object.fromEntries(
        directorOperations.map(([operation]) => [
          operation,
          vi.fn().mockRejectedValue(thrown),
        ]),
      );
      registerStudioIpc(
        ipcMain as never,
        window as never,
        {
          status: { state: "ready", message: "ready", pid: 1 },
          subscribe: () => () => undefined,
        } as never,
        { subscribe: () => () => undefined } as never,
        { showOpenDialog: vi.fn(), showSaveDialog: vi.fn() },
        undefined,
        { directorAuthority: authority as never },
      );
      const trusted = { sender: webContents, senderFrame: mainFrame };
      const invoke = vi.fn((channel: string): Promise<unknown> =>
        Promise.resolve(handlers.get(channel)!(trusted)),
      );
      const api = createStudioApi({
        invoke,
        on: vi.fn(),
        removeListener: vi.fn(),
      });

      for (const [, method] of directorOperations) {
        const result = await api[method]();
        expect(result).toEqual({
          ok: false,
          error: {
            code: "internal_error",
            message: "Director operation did not complete.",
          },
        });
        expect(JSON.stringify(result)).not.toMatch(
          /secret|private-review|file:\/\/|\/tmp|\/home/iu,
        );
      }
      expect(invoke).toHaveBeenCalledTimes(directorOperations.length);
    },
  );

  it("preserves a typed sanitized domain error through its handler and preload method", async () => {
    const handlers = new Map<
      string,
      (event: unknown, ...args: unknown[]) => unknown
    >();
    const ipcMain = {
      handle(
        channel: string,
        handler: (event: unknown, ...args: unknown[]) => unknown,
      ) {
        handlers.set(channel, handler);
      },
      removeHandler: vi.fn(),
    };
    const mainFrame = { url: "rwf-studio://app/index.html" };
    const webContents = { mainFrame, isDestroyed: () => false, send: vi.fn() };
    const window = { webContents, isDestroyed: () => false };
    const authority = Object.fromEntries(
      directorOperations.map(([operation]) => [
        operation,
        vi.fn().mockResolvedValue(state),
      ]),
    );
    authority.prepareSelectedReview = vi.fn().mockRejectedValue(
      new StudioDirectorDomainError("conflict", "director.review.prepare"),
    );
    registerStudioIpc(
      ipcMain as never,
      window as never,
      {
        status: { state: "ready", message: "ready", pid: 1 },
        subscribe: () => () => undefined,
      } as never,
      { subscribe: () => () => undefined } as never,
      { showOpenDialog: vi.fn(), showSaveDialog: vi.fn() },
      undefined,
      { directorAuthority: authority as never },
    );
    const trusted = { sender: webContents, senderFrame: mainFrame };
    const api = createStudioApi({
      invoke: (channel: string): Promise<unknown> =>
        Promise.resolve(handlers.get(channel)!(trusted)),
      on: vi.fn(),
      removeListener: vi.fn(),
    });

    await expect(api.prepareSelectedDirectorReview()).resolves.toEqual({
      ok: false,
      error: {
        code: "conflict",
        message: "Exact Director review state changed.",
      },
    });
  });

  it.each([
    ["invalid_state", "director.unlock"],
    ["invalid_request", "director.enroll"],
    ["not_found", "director.review.inspect"],
    ["conflict", "director.review.prepare"],
    ["internal_error", "director.review.approve"],
    ["timeout", "director.review.deny"],
    ["cancelled", "director.review.revoke"],
    ["service_unavailable", "director.status"],
    ["recovery_ambiguous", "director.review.approve"],
    ["recovery_failed", "director.review.revoke"],
  ] as const)("preserves the sanitized Director %s domain code", async (code, method) => {
    const handlers = new Map<string, (event: unknown, ...args: unknown[]) => unknown>();
    const ipcMain = {
      handle(channel: string, handler: (event: unknown, ...args: unknown[]) => unknown) {
        handlers.set(channel, handler);
      },
      removeHandler: vi.fn(),
    };
    const mainFrame = { url: "rwf-studio://app/index.html" };
    const webContents = { mainFrame, isDestroyed: () => false, send: vi.fn() };
    const window = { webContents, isDestroyed: () => false };
    const authority = Object.fromEntries(
      directorOperations.map(([operation]) => [operation, vi.fn().mockResolvedValue(state)]),
    );
    authority.unlock = vi.fn().mockRejectedValue(
      new StudioDirectorDomainError(
        code,
        method,
      ),
    );
    registerStudioIpc(
      ipcMain as never,
      window as never,
      { status: { state: "ready", message: "ready", pid: 1 }, subscribe: () => () => undefined } as never,
      { subscribe: () => () => undefined } as never,
      { showOpenDialog: vi.fn(), showSaveDialog: vi.fn() },
      undefined,
      { directorAuthority: authority as never },
    );

    await expect(
      handlers.get(IPC_CHANNELS.unlockDirector)!({
        sender: webContents,
        senderFrame: mainFrame,
      }),
    ).resolves.toEqual({
      ok: false,
      error: {
        code,
        message: new StudioDirectorDomainError(
          code,
          method,
        ).message,
      },
    });
  });
});

describe("Studio Director preload surface", () => {
  it("exposes only eight named argument-free invocations", async () => {
    const invoke = vi.fn().mockResolvedValue({ ok: true, value: state });
    const transport: PreloadTransport = {
      invoke,
      on: vi.fn(),
      removeListener: vi.fn(),
    };
    const api = createStudioApi(transport);

    for (const [, method] of directorOperations) {
      const operation = api[method].bind(api);
      expect(operation).toBeTypeOf("function");
      await operation();
    }
    expect(invoke.mock.calls.slice(-directorOperations.length)).toEqual(
      directorOperations.map(([, channelKey]) => [IPC_CHANNELS[channelKey]]),
    );
    expect(api).not.toHaveProperty("directorRequest");
    expect(api).not.toHaveProperty("directorPassphrase");
    expect(api).not.toHaveProperty("directorReviewPath");
  });

  it("preserves only closed Director error results", async () => {
    const invoke = vi
      .fn()
      .mockResolvedValueOnce({
        ok: false,
        error: {
          code: "conflict",
          message: "Exact Director review state changed.",
        },
      })
      .mockResolvedValueOnce({
        ok: false,
        error: {
          code: "private_raw_code",
          message: "secret-passphrase /tmp/private-review.json",
        },
      });
    const api = createStudioApi({
      invoke,
      on: vi.fn(),
      removeListener: vi.fn(),
    });

    await expect(api.prepareSelectedDirectorReview()).resolves.toEqual({
      ok: false,
      error: {
        code: "conflict",
        message: "Exact Director review state changed.",
      },
    });
    await expect(api.prepareSelectedDirectorReview()).resolves.toEqual({
      ok: false,
      error: {
        code: "internal_error",
        message: "Main process returned an invalid Director result",
      },
    });
  });
});
