/* AUTO-GENERATED from schemas/studio-protocol-v6.schema.json. Do not edit by hand. */
/* eslint-disable @typescript-eslint/no-empty-object-type */

export type WorldForgeStudioDirectorProtocolV6 = Request | Response | ErrorEnvelope;
export type Request = {
  protocol: "rpg-world-forge.studio_protocol";
  protocol_version: 6;
  kind: "request";
  request_id: EntityId;
  method: Method;
  params: unknown;
} & Request1;
export type EntityId = string;
export type Method =
  | "service.initialize"
  | "director.status"
  | "director.enroll"
  | "director.unlock"
  | "director.lock"
  | "director.review.inspect"
  | "director.review.prepare"
  | "director.review.approve"
  | "director.review.deny"
  | "director.review.revoke";
export type Request1 =
  | {
      method: "service.initialize";
      params: EmptyParams;
    }
  | {
      method: "director.status" | "director.lock";
      params: EmptyParams;
    }
  | {
      method: "director.enroll" | "director.unlock";
      params: PassphraseParams;
    }
  | {
      method: "director.review.inspect";
      params: ReviewParams;
    }
  | {
      method: "director.review.prepare";
      params: PrepareParams;
    }
  | {
      method: "director.review.approve";
      params: ApproveParams;
    }
  | {
      method: "director.review.deny";
      params: DenyParams;
    }
  | {
      method: "director.review.revoke";
      params: RevokeParams;
    };
export type ExecutionApprovalReview = {
  format: "world-forge.private.execution_approval_review";
  format_version: 1;
  approval_id: HarnessId;
  execution_id: HarnessId;
  activation_hash: Sha256;
  grant_hash: Sha256;
  private_input_hash: Sha256;
  runtime_id: HarnessId;
  runtime_revision: number;
  runtime_content_hash: Sha256;
  max_turns: number;
  max_tool_calls: number;
  max_total_tokens: SafeInteger;
  max_cost_minor_units: NullableSafeInteger;
  currency: string | null;
  max_duration_ms: SafeInteger;
  deadline_ms: NullableSafeInteger;
  /**
   * @maxItems 128
   */
  tool_candidates: ToolCandidate[];
  generation: 0;
  content_hash: Sha256;
} & ExecutionApprovalReview1;
export type HarnessId = string;
export type Sha256 = string;
export type SafeInteger = number;
export type NullableSafeInteger = SafeInteger | null;
export type ToolId = string;
export type ExecutionApprovalReview1 =
  | {
      max_cost_minor_units?: SafeInteger;
      currency?: string;
    }
  | {
      max_cost_minor_units?: null;
      currency?: null;
    };
export type Response = {
  protocol: "rpg-world-forge.studio_protocol";
  protocol_version: 6;
  kind: "response";
  request_id: EntityId;
  method: Method;
  result: unknown;
} & Response1;
export type Response1 =
  | {
      method: "service.initialize";
      result: InitializeResult;
    }
  | {
      method: "director.status" | "director.enroll" | "director.unlock" | "director.lock";
      result: DirectorStatusResult;
    }
  | {
      method:
        | "director.review.inspect"
        | "director.review.prepare"
        | "director.review.approve"
        | "director.review.deny"
        | "director.review.revoke";
      result: DirectorReviewResult;
    };
export type ExecutionApprovalDecision = {
  format: "world-forge.private.execution_approval_decision";
  format_version: 1;
  approval_id: HarnessId;
  execution_id: HarnessId;
  review_hash: Sha256;
  generation: 1;
  reviewer_id: "director_local";
  outcome: "approved" | "denied";
  /**
   * @maxItems 128
   */
  approved_tool_ids: ToolId[];
  expires_at_ms: NullableSafeInteger;
  content_hash: Sha256;
} & ExecutionApprovalDecision1;
export type ExecutionApprovalDecision1 =
  | {
      outcome?: "approved";
      expires_at_ms?: SafeInteger;
    }
  | {
      outcome?: "denied";
      /**
       * @maxItems 0
       */
      approved_tool_ids?: [];
      expires_at_ms?: null;
    };
export type NullableSha256 = Sha256 | null;

export type EmptyParams = Record<string, never>;
export interface PassphraseParams {
  passphrase: string;
}
export interface ReviewParams {
  review: ExecutionApprovalReview;
}
export interface ToolCandidate {
  tool_id: ToolId;
  descriptor_hash: Sha256;
}
export interface PrepareParams {
  review: ExecutionApprovalReview;
  expected_generation: 0;
}
export interface ApproveParams {
  review: ExecutionApprovalReview;
  expected_generation: 0;
  expected_review_hash: Sha256;
  /**
   * @maxItems 128
   */
  approved_tool_ids: ToolId[];
  expires_at_ms: SafeInteger;
}
export interface DenyParams {
  review: ExecutionApprovalReview;
  expected_generation: 0;
  expected_review_hash: Sha256;
}
export interface RevokeParams {
  review: ExecutionApprovalReview;
  expected_generation: 1;
  expected_decision_hash: Sha256;
}
export interface InitializeResult {
  service: "world-forge.studio";
  service_version: 6;
  protocol: "rpg-world-forge.studio_protocol";
  protocol_version: 6;
  /**
   * @minItems 10
   * @maxItems 10
   */
  methods: [Method, Method, Method, Method, Method, Method, Method, Method, Method, Method];
  capabilities: {
    authenticated_director_decisions: true;
    harness_hydration: false;
    civil_identity: false;
    secure_zeroization: false;
  };
}
export interface DirectorStatusResult {
  status: DirectorStatus;
}
export interface DirectorStatus {
  credential_id: "director_local";
  state: "not_enrolled" | "locked" | "unlocked";
}
export interface DirectorReviewResult {
  snapshot: ApprovalAuthoritySnapshot;
}
export interface ApprovalAuthoritySnapshot {
  prepared_review: ExecutionApprovalReview | null;
  current_decision: ExecutionApprovalDecision | null;
  generation: number;
  review_hash: Sha256;
  decision_hash: NullableSha256;
  state: "missing" | "prepared" | "approved" | "denied" | "revoked" | "stale";
}
export interface ErrorEnvelope {
  protocol: "rpg-world-forge.studio_protocol";
  protocol_version: 6;
  kind: "error";
  request_id: EntityId | null;
  error: {
    code:
      | "invalid_request"
      | "not_found"
      | "conflict"
      | "invalid_state"
      | "internal_error"
      | "recovery_ambiguous"
      | "recovery_failed";
    message: string;
    details: {};
  };
}
