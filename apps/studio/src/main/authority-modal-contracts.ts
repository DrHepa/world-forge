import type { ExecutionApprovalReview } from "../generated/studio-protocol-v6";
import { hasOnlyUnicodeScalarValues } from "../shared/unicode";
import type {
    StudioDirectorCredentialReply,
    StudioDirectorDecisionReply,
} from "./director-authority";

export function validateDirectorCredentialModalReply(
    value: unknown,
    expectedNonce: string,
): StudioDirectorCredentialReply {
    const reply = requireRecord(value, "Director credential modal reply");
    if (reply.nonce !== expectedNonce) {
        throw new TypeError("Director credential modal nonce is invalid");
    }
    if (reply.action === "cancel") {
        requireExactKeys(reply, ["action", "nonce"]);
        return { action: "cancel" };
    }
    if (reply.action !== "submit") {
        throw new TypeError("Director credential modal action is invalid");
    }
    requireExactKeys(reply, ["action", "nonce", "passphrase"]);
    if (
        typeof reply.passphrase !== "string" ||
        !hasOnlyUnicodeScalarValues(reply.passphrase) ||
        Buffer.byteLength(reply.passphrase, "utf8") < 16 ||
        Buffer.byteLength(reply.passphrase, "utf8") > 1024
    ) {
        throw new TypeError("Director credential modal passphrase is invalid");
    }
    return { action: "submit", passphrase: reply.passphrase };
}

export function validateDirectorDecisionModalReply(
    value: unknown,
    expectation: {
        expectedNonce: string;
        review: ExecutionApprovalReview;
        nowMs: number;
    },
): StudioDirectorDecisionReply {
    const reply = requireRecord(value, "Director decision modal reply");
    if (reply.nonce !== expectation.expectedNonce) {
        throw new TypeError("Director decision modal nonce is invalid");
    }
    if (reply.action === "cancel" || reply.action === "deny") {
        requireExactKeys(reply, ["action", "nonce"]);
        return { action: reply.action };
    }
    if (reply.action !== "approve") {
        throw new TypeError("Director decision modal action is invalid");
    }
    requireExactKeys(reply, [
        "action",
        "approvedToolIds",
        "expiresAtMs",
        "nonce",
    ]);
    if (
        !Array.isArray(reply.approvedToolIds) ||
        !Number.isSafeInteger(reply.expiresAtMs) ||
        (reply.expiresAtMs as number) <= expectation.nowMs
    ) {
        throw new TypeError("Director approval modal reply is invalid");
    }
    const approved = reply.approvedToolIds;
    const candidates = expectation.review.tool_candidates.map(
        (candidate) => candidate.tool_id,
    );
    if (
        approved.some((toolId) => typeof toolId !== "string") ||
        approved.length !== new Set(approved).size ||
        approved.some((toolId) => !candidates.includes(toolId as string)) ||
        approved.some(
            (toolId, index) =>
                candidates.filter((candidate) => approved.includes(candidate))[
                    index
                ] !== toolId,
        )
    ) {
        throw new TypeError("Director approved tool selection is invalid");
    }
    return {
        action: "approve",
        approvedToolIds: approved as string[],
        expiresAtMs: reply.expiresAtMs as number,
    };
}

function requireRecord(
    value: unknown,
    context: string,
): Record<string, unknown> {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw new TypeError(`${context} is invalid`);
    }
    return value as Record<string, unknown>;
}

function requireExactKeys(
    value: Record<string, unknown>,
    expected: readonly string[],
): void {
    const actual = Object.keys(value).sort();
    const sorted = [...expected].sort();
    if (
        actual.length !== sorted.length ||
        actual.some((key, index) => key !== sorted[index])
    ) {
        throw new TypeError("Director authority modal reply fields are invalid");
    }
}
