import { describe, expect, it } from "vitest";

import { validateStudioEnvelope } from "../../src/main/protocol-validator";
import type {
  ApprovalAuthoritySnapshot,
  Request,
  Response,
} from "../../src/generated/studio-protocol-v6";
import { directorReview } from "../fixtures/director-review";

const preparedSnapshot: ApprovalAuthoritySnapshot = {
  prepared_review: directorReview,
  current_decision: null,
  generation: 0,
  review_hash: directorReview.content_hash,
  decision_hash: null,
  state: "prepared",
};

describe("Studio protocol v6 Director ceremony", () => {
  it("accepts the closed independent v6 lane", () => {
    const requests: Request[] = [
      {
        protocol: "rpg-world-forge.studio_protocol",
        protocol_version: 6,
        kind: "request",
        request_id: "status_01",
        method: "director.status",
        params: {},
      },
      {
        protocol: "rpg-world-forge.studio_protocol",
        protocol_version: 6,
        kind: "request",
        request_id: "prepare_01",
        method: "director.review.prepare",
        params: { review: directorReview, expected_generation: 0 },
      },
    ];
    const response: Response = {
      protocol: "rpg-world-forge.studio_protocol",
      protocol_version: 6,
      kind: "response",
      request_id: "prepare_01",
      method: "director.review.prepare",
      result: { snapshot: preparedSnapshot },
    };

    expect(requests.every(validateStudioEnvelope)).toBe(true);
    expect(validateStudioEnvelope(response)).toBe(true);
  });

  it("enforces Director passphrase bounds in UTF-8 bytes", () => {
    for (const method of ["director.enroll", "director.unlock"] as const) {
      for (const [passphrase, accepted] of [
      ["four", false],
      ["a".repeat(16), true],
      ["\ud800".repeat(6), false],
      ["\udfff".repeat(6), false],
      ["a".repeat(16) + "\ud800", false],
      ["😀".repeat(4), true],
      ["é".repeat(513), false],
      ["é".repeat(512), true],
      ] as const) {
        expect(
          validateStudioEnvelope({
            protocol: "rpg-world-forge.studio_protocol",
            protocol_version: 6,
            kind: "request",
            request_id: "passphrase_01",
            method,
            params: { passphrase },
          }),
        ).toBe(accepted);
      }
    }
  });

  it("rejects cross-lane methods and renderer-owned authority fields", () => {
    const base = {
      protocol: "rpg-world-forge.studio_protocol",
      protocol_version: 6,
      kind: "request",
      request_id: "approve_01",
      method: "director.review.approve",
      params: {
        review: directorReview,
        expected_generation: 0,
        expected_review_hash: directorReview.content_hash,
        approved_tool_ids: ["source.read"],
        expires_at_ms: 20_000,
      },
    } as const;

    expect(validateStudioEnvelope(base)).toBe(true);
    expect(
      validateStudioEnvelope({
        ...base,
        method: "creation_job.create",
      }),
    ).toBe(false);
    for (const [field, value] of [
      ["reviewer_id", "director_local"],
      ["outcome", "approved"],
      ["path", "/tmp/review.json"],
    ] as const) {
      expect(
        validateStudioEnvelope({
          ...base,
          params: { ...base.params, [field]: value },
        }),
      ).toBe(false);
    }
  });

  it("rejects incoherent snapshots and v6 event envelopes", () => {
    const base = {
      protocol: "rpg-world-forge.studio_protocol",
      protocol_version: 6,
      kind: "response",
      request_id: "inspect_01",
      method: "director.review.inspect",
      result: { snapshot: preparedSnapshot },
    } as const;
    expect(validateStudioEnvelope(base)).toBe(true);
    expect(
      validateStudioEnvelope({
        ...base,
        result: {
          snapshot: { ...preparedSnapshot, state: "missing" },
        },
      }),
    ).toBe(false);
    expect(
      validateStudioEnvelope({
        protocol: "rpg-world-forge.studio_protocol",
        protocol_version: 6,
        kind: "event",
        request_id: null,
        event: { type: "fixture.ready" },
      }),
    ).toBe(false);
  });

  it("rejects response decisions that exceed outcome or candidate authority", () => {
    const response = (snapshot: unknown) => ({
      protocol: "rpg-world-forge.studio_protocol",
      protocol_version: 6,
      kind: "response",
      request_id: "decision_response_01",
      method: "director.review.approve",
      result: { snapshot },
    });
    const decision = (
      outcome: "approved" | "denied",
      approvedToolIds: string[],
      expiresAtMs: number | null,
    ) => ({
      format: "world-forge.private.execution_approval_decision" as const,
      format_version: 1 as const,
      approval_id: directorReview.approval_id,
      execution_id: directorReview.execution_id,
      review_hash: directorReview.content_hash,
      generation: 1 as const,
      reviewer_id: "director_local" as const,
      outcome,
      approved_tool_ids: approvedToolIds,
      expires_at_ms: expiresAtMs,
      content_hash: "2".repeat(64),
    });
    const decided = (
      outcome: "approved" | "denied",
      approvedToolIds: string[],
      expiresAtMs: number | null,
    ) => ({
      prepared_review: directorReview,
      current_decision: decision(outcome, approvedToolIds, expiresAtMs),
      generation: 1,
      review_hash: directorReview.content_hash,
      decision_hash: "2".repeat(64),
      state: outcome,
    });

    expect(validateStudioEnvelope(response(decided("denied", [], null)))).toBe(true);
    expect(
      validateStudioEnvelope(response(decided("approved", ["source.read"], 20_000))),
    ).toBe(true);
    expect(
      validateStudioEnvelope(response(decided("denied", ["source.read"], 20_000))),
    ).toBe(false);
    expect(
      validateStudioEnvelope(response(decided("denied", ["source.read"], null))),
    ).toBe(false);
    expect(validateStudioEnvelope(response(decided("denied", [], 20_000)))).toBe(false);
    expect(
      validateStudioEnvelope(response(decided("approved", ["outside.invoke"], 20_000))),
    ).toBe(false);
    expect(
      validateStudioEnvelope(
        response(decided("approved", ["world.validate", "source.read"], 20_000)),
      ),
    ).toBe(false);
  });

  it("rejects duplicate review candidate IDs in request and response semantics", () => {
    const exactDuplicateReview = {
      ...directorReview,
      tool_candidates: [
        ...directorReview.tool_candidates,
        { ...directorReview.tool_candidates[0] },
      ],
    };
    const conflictingDuplicateReview = {
      ...directorReview,
      tool_candidates: [
        ...directorReview.tool_candidates,
        {
          tool_id: directorReview.tool_candidates[0].tool_id,
          descriptor_hash: "9".repeat(64),
        },
      ],
    };

    expect.soft(
      validateStudioEnvelope({
        protocol: "rpg-world-forge.studio_protocol",
        protocol_version: 6,
        kind: "request",
        request_id: "duplicate_candidates_request_01",
        method: "director.review.inspect",
        params: { review: exactDuplicateReview },
      }),
    ).toBe(false);
    expect.soft(
      validateStudioEnvelope({
        protocol: "rpg-world-forge.studio_protocol",
        protocol_version: 6,
        kind: "response",
        request_id: "duplicate_candidates_response_01",
        method: "director.review.prepare",
        result: {
          snapshot: {
            ...preparedSnapshot,
            prepared_review: conflictingDuplicateReview,
          },
        },
      }),
    ).toBe(false);
  });
});
