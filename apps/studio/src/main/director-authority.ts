import { randomUUID } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import path from "node:path";

import type {
    BrowserWindow,
    OpenDialogOptions,
    OpenDialogReturnValue,
} from "electron";

import { decodeStrictJsonObject } from "../../scripts/strict-json.mjs";
import type {
    ApprovalAuthoritySnapshot,
    DirectorReviewResult,
    DirectorStatus,
    DirectorStatusResult,
    ErrorEnvelope as StudioV6ErrorEnvelope,
    ExecutionApprovalReview,
    Method as StudioV6Method,
    Response as StudioV6ResponseEnvelope,
} from "../generated/studio-protocol-v6";
import type {
    StudioActivityEvent,
    StudioDirectorCeremonyState,
} from "../shared/studio-api";
import { hasOnlyUnicodeScalarValues } from "../shared/unicode";
import { noFollowOpenFlagForPlatform } from "./no-follow-open-flag";
import {
    StudioRequestCancelledError,
    StudioRequestTimeoutError,
    StudioTransportError,
} from "./ndjson-supervisor";
import {
    describeProtocolErrors,
    validateStudioEnvelope,
} from "./protocol-validator";

export const MAX_DIRECTOR_REVIEW_BYTES = 256 * 1024;
const DIRECTOR_REQUEST_TIMEOUT_MS = 10_000;
const DIRECTOR_CREDENTIAL_ID = "director_local" as const;

type StudioDirectorWireErrorCode = StudioV6ErrorEnvelope["error"]["code"];
export type StudioDirectorDomainErrorCode =
    | StudioDirectorWireErrorCode
    | "service_unavailable"
    | "timeout"
    | "cancelled";

export class StudioDirectorDomainError extends Error {
    public readonly code: StudioDirectorDomainErrorCode;

    public constructor(
        code: StudioDirectorDomainErrorCode,
        method: StudioV6Method,
    ) {
        super(directorDomainErrorMessage(code, method));
        this.name = "StudioDirectorDomainError";
        this.code = code;
    }
}

export interface StudioDirectorServiceClient {
    subscribe(listener: (event: StudioActivityEvent) => void): () => void;
    request(
        requestId: string,
        method: StudioV6Method,
        params: Record<string, unknown>,
        timeoutMs: number,
        protocolVersion: 6,
    ): Promise<unknown>;
}

export interface StudioDirectorDialogClient {
    showOpenDialog(
        window: BrowserWindow,
        options: OpenDialogOptions,
    ): Promise<OpenDialogReturnValue>;
}

export type StudioDirectorCredentialReply =
    | { action: "cancel" }
    | { action: "submit"; passphrase: string };

export type StudioDirectorDecisionReply =
    | { action: "cancel" }
    | { action: "deny" }
    | {
          action: "approve";
          approvedToolIds: string[];
          expiresAtMs: number;
      };

export interface StudioDirectorModalClient {
    requestCredential(
        window: BrowserWindow,
        payload: {
            credentialId: "director_local";
            mode: "enroll" | "unlock";
        },
    ): Promise<StudioDirectorCredentialReply>;
    requestDecision(
        window: BrowserWindow,
        payload: {
            credentialId: "director_local";
            review: ExecutionApprovalReview;
            snapshot: ApprovalAuthoritySnapshot;
        },
    ): Promise<StudioDirectorDecisionReply>;
}

export interface DirectorReviewReadOptions {
    beforeOpen?: () => Promise<void> | void;
    platform?: NodeJS.Platform;
}

interface FileState {
    ctimeNs: bigint;
    dev: bigint;
    ino: bigint;
    mode: bigint;
    mtimeNs: bigint;
    nlink: bigint;
    size: bigint;
}

interface StudioDirectorAuthorityOptions {
    service: StudioDirectorServiceClient;
    dialogs: StudioDirectorDialogClient;
    modal: StudioDirectorModalClient;
    requestId?: () => string;
    nowMs?: () => number;
}

export async function readDirectorReviewFile(
    filename: string,
    options: DirectorReviewReadOptions = {},
): Promise<ExecutionApprovalReview> {
    const absolute = path.resolve(filename);
    try {
        if (filename !== absolute) {
            throw new Error("path is not absolute");
        }
        const before = await lstat(absolute, { bigint: true });
        if (
            !before.isFile() ||
            before.isSymbolicLink() ||
            before.nlink !== 1n ||
            before.size < 1n ||
            before.size > BigInt(MAX_DIRECTOR_REVIEW_BYTES) ||
            (await realpath(absolute)) !== absolute
        ) {
            throw new Error("file is not a stable regular file");
        }
        const initial = fileState(before);
        await options.beforeOpen?.();
        const handle = await open(
            absolute,
            directorReviewOpenFlags(options.platform),
        );
        try {
            const opened = await handle.stat({ bigint: true });
            if (
                !opened.isFile() ||
                opened.nlink !== 1n ||
                opened.size < 1n ||
                opened.size > BigInt(MAX_DIRECTOR_REVIEW_BYTES) ||
                !sameFileState(initial, fileState(opened))
            ) {
                throw new Error("opened file identity changed");
            }
            const bytes = await handle.readFile();
            const after = await handle.stat({ bigint: true });
            if (
                BigInt(bytes.byteLength) !== opened.size ||
                !sameFileState(fileState(opened), fileState(after))
            ) {
                throw new Error("opened file changed while reading");
            }
            const final = await lstat(absolute, { bigint: true });
            if (
                final.isSymbolicLink() ||
                !sameFileState(initial, fileState(final)) ||
                (await realpath(absolute)) !== absolute
            ) {
                throw new Error("named file identity changed");
            }
            const review = decodeStrictJsonObject(bytes, {
                context: "Selected Director review",
                maxBytes: MAX_DIRECTOR_REVIEW_BYTES,
            }) as unknown;
            const validationEnvelope = {
                protocol: "rpg-world-forge.studio_protocol",
                protocol_version: 6,
                kind: "request",
                request_id: "director_review_import",
                method: "director.review.inspect",
                params: { review },
            };
            if (!validateStudioEnvelope(validationEnvelope)) {
                throw new Error(describeProtocolErrors());
            }
            return review as ExecutionApprovalReview;
        } finally {
            await handle.close();
        }
    } catch {
        throw new Error("Selected Director review file is invalid");
    }
}

export function directorReviewOpenFlags(
    platform: NodeJS.Platform = process.platform,
    noFollowFlag: number | undefined = fsConstants.O_NOFOLLOW,
    nonBlockFlag: number | undefined = fsConstants.O_NONBLOCK,
): number {
    return (
        fsConstants.O_RDONLY |
        noFollowOpenFlagForPlatform(platform, noFollowFlag) |
        (platform === "win32" ? 0 : (nonBlockFlag ?? 0))
    );
}

export class StudioDirectorAuthority {
    readonly #service: StudioDirectorServiceClient;
    readonly #dialogs: StudioDirectorDialogClient;
    readonly #modal: StudioDirectorModalClient;
    readonly #requestId: () => string;
    readonly #nowMs: () => number;
    readonly #unsubscribe: () => void;
    #status: DirectorStatus | null = {
        credential_id: DIRECTOR_CREDENTIAL_ID,
        state: "locked",
    };
    #selectedReview: ExecutionApprovalReview | null = null;
    #snapshot: ApprovalAuthoritySnapshot | null = null;
    #tail: Promise<void> = Promise.resolve();
    #epoch = 0;
    #closed = false;

    public constructor({
        service,
        dialogs,
        modal,
        requestId = randomUUID,
        nowMs = Date.now,
    }: StudioDirectorAuthorityOptions) {
        this.#service = service;
        this.#dialogs = dialogs;
        this.#modal = modal;
        this.#requestId = requestId;
        this.#nowMs = nowMs;
        this.#unsubscribe = service.subscribe((event) => {
            if (
                event.type === "service-status" &&
                event.status.state !== "ready"
            ) {
                this.#epoch += 1;
                this.#clearSelection();
                if (
                    this.#status !== null &&
                    this.#status.state !== "not_enrolled"
                ) {
                    this.#status = {
                        credential_id: DIRECTOR_CREDENTIAL_ID,
                        state: "locked",
                    };
                }
            }
        });
    }

    public currentState(): StudioDirectorCeremonyState {
        return {
            status: {
                credentialId: DIRECTOR_CREDENTIAL_ID,
                state: this.#status?.state ?? "unknown",
            },
            selectedReview: cloneWire(this.#selectedReview),
            snapshot: cloneWire(this.#snapshot),
        };
    }

    public getStatus(): Promise<StudioDirectorCeremonyState> {
        return this.#serialize(async () => {
            const result = await this.#statusRequest("director.status", {});
            this.#applyStatus(result.status);
            return this.currentState();
        });
    }

    public enroll(parent: BrowserWindow): Promise<StudioDirectorCeremonyState> {
        return this.#credentialOperation(parent, "enroll", "director.enroll");
    }

    public unlock(parent: BrowserWindow): Promise<StudioDirectorCeremonyState> {
        return this.#credentialOperation(parent, "unlock", "director.unlock");
    }

    public lock(): Promise<StudioDirectorCeremonyState> {
        return this.#serialize(async () => {
            this.#status = {
                credential_id: DIRECTOR_CREDENTIAL_ID,
                state: "locked",
            };
            this.#clearSelection();
            const result = await this.#statusRequest("director.lock", {});
            this.#applyStatus(result.status);
            return this.currentState();
        });
    }

    public selectReview(
        parent: BrowserWindow,
    ): Promise<StudioDirectorCeremonyState> {
        return this.#serialize(async () => {
            this.#requireUnlocked();
            const epoch = this.#epoch;
            const selected = await this.#dialogs.showOpenDialog(parent, {
                title: "Select exact Harness approval review",
                properties: ["openFile"],
                filters: [{ name: "JSON review", extensions: ["json"] }],
            });
            this.#requireEpoch(epoch);
            if (selected.canceled) {
                return this.currentState();
            }
            if (selected.filePaths.length !== 1) {
                throw new Error("Director review selection is invalid");
            }
            const review = await readDirectorReviewFile(selected.filePaths[0]);
            this.#requireEpoch(epoch);
            const result = await this.#reviewRequest(
                "director.review.inspect",
                { review },
            );
            this.#selectedReview = freezeWire(review);
            this.#snapshot = freezeWire(result.snapshot);
            return this.currentState();
        });
    }

    public prepareSelectedReview(): Promise<StudioDirectorCeremonyState> {
        return this.#serialize(async () => {
            const review = this.#requireSelectedReview();
            if (this.#snapshot?.state !== "missing") {
                throw new Error("Selected Director review is not missing");
            }
            const result = await this.#mutatingReviewRequest(
                "director.review.prepare",
                { review, expected_generation: 0 },
            );
            this.#snapshot = freezeWire(result.snapshot);
            return this.currentState();
        });
    }

    public requestSelectedDecision(
        parent: BrowserWindow,
    ): Promise<StudioDirectorCeremonyState> {
        return this.#serialize(async () => {
            const review = this.#requireSelectedReview();
            const snapshot = this.#snapshot;
            if (snapshot?.state !== "prepared") {
                throw new Error("Selected Director review is not prepared");
            }
            const epoch = this.#epoch;
            const reply = validateDecisionReply(
                await this.#modal.requestDecision(parent, {
                    credentialId: DIRECTOR_CREDENTIAL_ID,
                    review: cloneWire(review),
                    snapshot: cloneWire(snapshot),
                }),
                review,
                this.#nowMs(),
            );
            this.#requireEpoch(epoch);
            if (reply.action === "cancel") {
                return this.currentState();
            }
            const params =
                reply.action === "deny"
                    ? {
                          review,
                          expected_generation: 0,
                          expected_review_hash: snapshot.review_hash,
                      }
                    : {
                          review,
                          expected_generation: 0,
                          expected_review_hash: snapshot.review_hash,
                          approved_tool_ids: [...reply.approvedToolIds],
                          expires_at_ms: reply.expiresAtMs,
                      };
            const result = await this.#mutatingReviewRequest(
                reply.action === "deny"
                    ? "director.review.deny"
                    : "director.review.approve",
                params,
            );
            this.#snapshot = freezeWire(result.snapshot);
            return this.currentState();
        });
    }

    public revokeSelectedDecision(): Promise<StudioDirectorCeremonyState> {
        return this.#serialize(async () => {
            const review = this.#requireSelectedReview();
            const snapshot = this.#snapshot;
            if (
                (snapshot?.state !== "approved" &&
                    snapshot?.state !== "denied") ||
                snapshot.generation !== 1 ||
                snapshot.decision_hash === null
            ) {
                throw new Error("Selected Director decision is not revocable");
            }
            const result = await this.#mutatingReviewRequest(
                "director.review.revoke",
                {
                    review,
                    expected_generation: 1,
                    expected_decision_hash: snapshot.decision_hash,
                },
            );
            this.#snapshot = freezeWire(result.snapshot);
            return this.currentState();
        });
    }

    public close(): void {
        if (this.#closed) return;
        this.#closed = true;
        this.#epoch += 1;
        this.#clearSelection();
        this.#unsubscribe();
    }

    #credentialOperation(
        parent: BrowserWindow,
        mode: "enroll" | "unlock",
        method: "director.enroll" | "director.unlock",
    ): Promise<StudioDirectorCeremonyState> {
        return this.#serialize(async () => {
            const epoch = this.#epoch;
            const reply = validateCredentialReply(
                await this.#modal.requestCredential(parent, {
                    credentialId: DIRECTOR_CREDENTIAL_ID,
                    mode,
                }),
            );
            this.#requireEpoch(epoch);
            if (reply.action === "cancel") {
                return this.currentState();
            }
            const previousStatus = this.#status;
            const previousReview = this.#selectedReview;
            const previousSnapshot = this.#snapshot;
            this.#status = null;
            this.#clearSelection();
            let result: DirectorStatusResult;
            try {
                result = await this.#statusRequest(method, {
                    passphrase: reply.passphrase,
                });
            } catch (error) {
                if (isDefiniteDirectorRejection(error)) {
                    this.#status = previousStatus;
                    this.#selectedReview = previousReview;
                    this.#snapshot = previousSnapshot;
                }
                throw error;
            }
            this.#applyStatus(result.status);
            return this.currentState();
        });
    }

    #applyStatus(status: DirectorStatus): void {
        if (
            status.credential_id !== DIRECTOR_CREDENTIAL_ID ||
            !["not_enrolled", "locked", "unlocked"].includes(status.state)
        ) {
            throw new Error("Forge Studio Director status is invalid");
        }
        this.#status = { ...status };
        if (status.state !== "unlocked") {
            this.#clearSelection();
        }
    }

    #requireUnlocked(): void {
        if (this.#status?.state !== "unlocked") {
            throw new Error("Director credential is locked");
        }
    }

    #requireSelectedReview(): ExecutionApprovalReview {
        this.#requireUnlocked();
        if (this.#selectedReview === null || this.#snapshot === null) {
            throw new Error("No exact Director review is selected");
        }
        return this.#selectedReview;
    }

    #clearSelection(): void {
        this.#selectedReview = null;
        this.#snapshot = null;
    }

    async #statusRequest(
        method:
            | "director.status"
            | "director.enroll"
            | "director.unlock"
            | "director.lock",
        params: Record<string, unknown>,
    ): Promise<DirectorStatusResult> {
        const reply = await this.#request(method, params);
        return reply.result as DirectorStatusResult;
    }

    async #reviewRequest(
        method:
            | "director.review.inspect"
            | "director.review.prepare"
            | "director.review.approve"
            | "director.review.deny"
            | "director.review.revoke",
        params: Record<string, unknown>,
    ): Promise<DirectorReviewResult> {
        const reply = await this.#request(method, params);
        return reply.result as DirectorReviewResult;
    }

    async #mutatingReviewRequest(
        method:
            | "director.review.prepare"
            | "director.review.approve"
            | "director.review.deny"
            | "director.review.revoke",
        params: Record<string, unknown>,
    ): Promise<DirectorReviewResult> {
        try {
            return await this.#reviewRequest(method, params);
        } catch (error) {
            this.#epoch += 1;
            this.#clearSelection();
            throw error;
        }
    }

    async #request(
        method: StudioV6Method,
        params: Record<string, unknown>,
    ): Promise<StudioV6ResponseEnvelope> {
        const epoch = this.#epoch;
        let value: unknown;
        try {
            value = await this.#service.request(
                this.#requestId(),
                method,
                params,
                DIRECTOR_REQUEST_TIMEOUT_MS,
                6,
            );
        } catch (error) {
            throw directorDomainError(error, method);
        }
        this.#requireEpoch(epoch);
        if (
            !validateStudioEnvelope(value) ||
            value.protocol_version !== 6 ||
            (value.kind !== "response" && value.kind !== "error")
        ) {
            throw new StudioDirectorDomainError("internal_error", method);
        }
        const reply = value;
        if (reply.kind === "error") {
            throw new StudioDirectorDomainError(reply.error.code, method);
        }
        if (reply.method !== method) {
            throw new StudioDirectorDomainError("internal_error", method);
        }
        return reply;
    }

    #requireEpoch(epoch: number): void {
        if (this.#closed || epoch !== this.#epoch) {
            throw new Error("Director ceremony state changed during operation");
        }
    }

    #serialize<T>(operation: () => Promise<T>): Promise<T> {
        const result = this.#tail.then(async () => {
            if (this.#closed) {
                throw new Error("Director authority is closed");
            }
            return await operation();
        });
        this.#tail = result.then(
            () => undefined,
            () => undefined,
        );
        return result;
    }
}

function directorDomainError(
    error: unknown,
    method: StudioV6Method,
): StudioDirectorDomainError {
    if (error instanceof StudioDirectorDomainError) return error;
    if (error instanceof StudioRequestTimeoutError) {
        return new StudioDirectorDomainError("timeout", method);
    }
    if (error instanceof StudioRequestCancelledError) {
        return new StudioDirectorDomainError("cancelled", method);
    }
    if (error instanceof StudioTransportError) {
        return new StudioDirectorDomainError("service_unavailable", method);
    }
    return new StudioDirectorDomainError("internal_error", method);
}

function isDefiniteDirectorRejection(error: unknown): boolean {
    return (
        error instanceof StudioDirectorDomainError &&
        ["invalid_request", "not_found", "conflict", "invalid_state"].includes(
            error.code,
        )
    );
}

function directorDomainErrorMessage(
    code: StudioDirectorDomainErrorCode,
    method: StudioV6Method,
): string {
    const credential = method === "director.enroll" || method === "director.unlock";
    const review = method.startsWith("director.review.");
    if (credential && code === "invalid_state") {
        return "Director credential was not accepted.";
    }
    if (credential && code === "invalid_request") {
        return "Director credential request was rejected.";
    }
    if (review && code === "conflict") {
        return "Exact Director review state changed.";
    }
    if (review && code === "invalid_request") {
        return "Exact Director review request was rejected.";
    }
    switch (code) {
        case "invalid_request":
            return "Director request was rejected as invalid.";
        case "not_found":
            return "Director state was not found.";
        case "conflict":
            return "Director state changed before the request completed.";
        case "invalid_state":
            return "Director request is not valid for the current state.";
        case "timeout":
            return "Director request confirmation timed out.";
        case "cancelled":
            return "Director request confirmation was cancelled.";
        case "service_unavailable":
            return "Director service request did not complete.";
        case "internal_error":
        case "recovery_ambiguous":
        case "recovery_failed":
            return "Director service could not confirm the request.";
    }
}

function validateCredentialReply(
    value: unknown,
): StudioDirectorCredentialReply {
    if (!isRecord(value) || (value.action !== "cancel" && value.action !== "submit")) {
        throw new TypeError("Director credential reply is invalid");
    }
    const keys = Object.keys(value).sort();
    if (value.action === "cancel") {
        if (keys.length !== 1 || keys[0] !== "action") {
            throw new TypeError("Director credential reply fields are invalid");
        }
        return { action: "cancel" };
    }
    if (
        keys.length !== 2 ||
        keys[0] !== "action" ||
        keys[1] !== "passphrase" ||
        typeof value.passphrase !== "string" ||
        !hasOnlyUnicodeScalarValues(value.passphrase) ||
        Buffer.byteLength(value.passphrase, "utf8") < 16 ||
        Buffer.byteLength(value.passphrase, "utf8") > 1024
    ) {
        throw new TypeError("Director credential reply fields are invalid");
    }
    return { action: "submit", passphrase: value.passphrase };
}

function validateDecisionReply(
    value: unknown,
    review: ExecutionApprovalReview,
    nowMs: number,
): StudioDirectorDecisionReply {
    if (!isRecord(value)) {
        throw new TypeError("Director decision reply is invalid");
    }
    if (value.action === "cancel" || value.action === "deny") {
        if (Object.keys(value).length !== 1) {
            throw new TypeError("Director decision reply fields are invalid");
        }
        return { action: value.action };
    }
    if (
        value.action !== "approve" ||
        !hasExactKeys(value, ["action", "approvedToolIds", "expiresAtMs"]) ||
        !Array.isArray(value.approvedToolIds) ||
        !Number.isSafeInteger(value.expiresAtMs) ||
        (value.expiresAtMs as number) <= nowMs
    ) {
        throw new TypeError("Director approval reply is invalid");
    }
    const approved = value.approvedToolIds;
    const candidates = review.tool_candidates.map((candidate) => candidate.tool_id);
    if (
        approved.some((toolId) => typeof toolId !== "string") ||
        approved.length !== new Set(approved).size ||
        approved.some((toolId) => !candidates.includes(toolId as string)) ||
        approved.some(
            (toolId, index) =>
                candidates.filter((candidate) => approved.includes(candidate))[index] !==
                toolId,
        )
    ) {
        throw new TypeError("Director approved tool selection is invalid");
    }
    return {
        action: "approve",
        approvedToolIds: approved as string[],
        expiresAtMs: value.expiresAtMs as number,
    };
}

function fileState(value: {
    ctimeNs: bigint;
    dev: bigint;
    ino: bigint;
    mode: bigint;
    mtimeNs: bigint;
    nlink: bigint;
    size: bigint;
}): FileState {
    return {
        ctimeNs: value.ctimeNs,
        dev: value.dev,
        ino: value.ino,
        mode: value.mode,
        mtimeNs: value.mtimeNs,
        nlink: value.nlink,
        size: value.size,
    };
}

function sameFileState(left: FileState, right: FileState): boolean {
    return (
        left.ctimeNs === right.ctimeNs &&
        left.dev === right.dev &&
        left.ino === right.ino &&
        left.mode === right.mode &&
        left.mtimeNs === right.mtimeNs &&
        left.nlink === right.nlink &&
        left.size === right.size
    );
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(
    value: Record<string, unknown>,
    expected: readonly string[],
): boolean {
    const actual = Object.keys(value).sort();
    const sorted = [...expected].sort();
    return (
        actual.length === sorted.length &&
        actual.every((key, index) => key === sorted[index])
    );
}

function freezeWire<T>(value: T): T {
    if (value === null || typeof value !== "object" || Object.isFrozen(value)) {
        return value;
    }
    for (const child of Object.values(value as Record<string, unknown>)) {
        freezeWire(child);
    }
    return Object.freeze(value);
}

function cloneWire<T>(value: T): T {
    return value === null ? value : structuredClone(value);
}
