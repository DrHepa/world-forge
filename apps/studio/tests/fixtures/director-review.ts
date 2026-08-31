import type { ExecutionApprovalReview } from "../../src/generated/studio-protocol-v6";

export const directorReview: ExecutionApprovalReview = {
  format: "world-forge.private.execution_approval_review",
  format_version: 1,
  approval_id: "approval_execution_01",
  execution_id: "execution_01",
  activation_hash: "a".repeat(64),
  grant_hash: "b".repeat(64),
  private_input_hash: "c".repeat(64),
  runtime_id: "worldforge_conformance_provider",
  runtime_revision: 1,
  runtime_content_hash: "d".repeat(64),
  max_turns: 4,
  max_tool_calls: 8,
  max_total_tokens: 100,
  max_cost_minor_units: 25,
  currency: "USD",
  max_duration_ms: 5_000,
  deadline_ms: 10_000,
  tool_candidates: [
    { tool_id: "source.read", descriptor_hash: "e".repeat(64) },
    { tool_id: "world.validate", descriptor_hash: "f".repeat(64) },
  ],
  generation: 0,
  content_hash: "1".repeat(64),
};
