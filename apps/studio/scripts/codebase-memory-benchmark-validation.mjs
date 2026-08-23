import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MAX_DOCUMENT_BYTES = 1024 * 1024;
const MAX_JSON_DEPTH = 64;
const ARMS = Object.freeze([
  "A_direct_reads",
  "B_existing_memory",
  "C_memory_candidate_index",
]);
const GATE_IDS = Object.freeze([
  "full_net_token_reduction",
  "maximum_critical_omissions",
  "maximum_incremental_p95",
  "maximum_quality_loss",
  "structural_net_token_reduction",
  "tree_unchanged",
  "zero_unauthorized_egress",
]);
const SOURCE_MODES = Object.freeze({
  A_direct_reads: "direct_reads",
  B_existing_memory: "existing_memory",
  C_memory_candidate_index: "memory_candidate_index",
});
const FIXED_GATES = Object.freeze({
  full_net_token_reduction_basis_points: 3000,
  structural_net_token_reduction_basis_points: 5000,
  maximum_quality_loss_basis_points: 200,
  maximum_critical_omissions: 0,
  maximum_incremental_p95_ms: 5000,
  require_tree_unchanged: true,
  require_zero_unauthorized_egress: true,
});
const FORBIDDEN_FIELDS = new Set([
  "prompt",
  "prompts",
  "answer",
  "answers",
  "source_excerpt",
  "source_excerpts",
  "transcript",
  "transcripts",
  "path",
  "paths",
  "host",
  "hosts",
  "url",
  "urls",
  "endpoint",
  "endpoints",
  "command",
  "commands",
  "argv",
  "env",
  "environment",
  "secret",
  "secrets",
  "credential",
  "credentials",
  "api_key",
  "token",
  "tokens",
  "api_token",
  "access_token",
  "refresh_token",
  "network_log",
  "network_logs",
  "error",
  "error_text",
  "stderr",
  "stdout",
]);

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function canonicalJson(value, { omitContentHash = false } = {}) {
  const active = new Set();
  function encode(current, depth, topLevel) {
    if (current === null || typeof current === "boolean") {
      return JSON.stringify(current);
    }
    if (typeof current === "string") {
      if (Buffer.from(current, "utf8").toString("utf8") !== current) {
        throw new Error("codebase-memory benchmark strings must be valid UTF-8");
      }
      return JSON.stringify(current);
    }
    if (typeof current === "number") {
      if (!Number.isSafeInteger(current)) {
        throw new Error("codebase-memory benchmark values require safe integers");
      }
      return JSON.stringify(current);
    }
    if (Array.isArray(current)) {
      if (depth > MAX_JSON_DEPTH) {
        throw new Error("codebase-memory benchmark JSON exceeds depth 64");
      }
      if (active.has(current)) {
        throw new Error("codebase-memory benchmark JSON cycles are unsupported");
      }
      active.add(current);
      try {
        return `[${current.map((item) => encode(item, depth + 1, false)).join(",")}]`;
      } finally {
        active.delete(current);
      }
    }
    if (isRecord(current)) {
      if (depth > MAX_JSON_DEPTH) {
        throw new Error("codebase-memory benchmark JSON exceeds depth 64");
      }
      if (active.has(current)) {
        throw new Error("codebase-memory benchmark JSON cycles are unsupported");
      }
      active.add(current);
      try {
        return `{${Object.entries(current)
          .filter(([key]) => !(topLevel && omitContentHash && key === "content_hash"))
          .map(([key, item]) => {
            if (Buffer.from(key, "utf8").toString("utf8") !== key) {
              throw new Error("codebase-memory benchmark keys must be valid UTF-8");
            }
            return [key, item];
          })
          .sort(([left], [right]) => compareUtf8(left, right))
          .map(([key, item]) => `${JSON.stringify(key)}:${encode(item, depth + 1, false)}`)
          .join(",")}}`;
      } finally {
        active.delete(current);
      }
    }
    throw new Error("codebase-memory benchmark values must contain JSON only");
  }
  return encode(value, 1, true);
}

export function canonicalCodebaseMemoryBenchmarkDocumentBytes(value) {
  return Buffer.byteLength(canonicalJson(value), "utf8");
}

export function canonicalCodebaseMemoryBenchmarkHash(value) {
  return createHash("sha256")
    .update(canonicalJson(value, { omitContentHash: true }), "utf8")
    .digest("hex");
}

function sortedUnique(values, minimum = 0, maximum = 64) {
  return (
    Array.isArray(values) &&
    values.length >= minimum &&
    values.length <= maximum &&
    values.every((item) => typeof item === "string") &&
    values.every((item, index) => index === 0 || compareUtf8(values[index - 1], item) < 0)
  );
}

function equalArrays(left, right) {
  return (
    Array.isArray(left) &&
    left.length === right.length &&
    left.every((item, index) => item === right[index])
  );
}

function fixedGatePolicy(value) {
  return (
    isRecord(value) &&
    Object.keys(value).length === Object.keys(FIXED_GATES).length &&
    Object.entries(FIXED_GATES).every(([key, expected]) => value[key] === expected)
  );
}

function hasForbiddenField(value) {
  if (Array.isArray(value)) {
    return value.some((item) => hasForbiddenField(item));
  }
  if (!isRecord(value)) {
    return false;
  }
  return Object.entries(value).some(
    ([key, item]) => FORBIDDEN_FIELDS.has(key) || hasForbiddenField(item),
  );
}

function reasonCodesAreCoherent(value, required) {
  return sortedUnique(value) && (required ? value.length > 0 : value.length === 0);
}

function hasCoherentPlan(value) {
  return (
    value.format === "world-forge.codebase_memory_benchmark_plan" &&
    value.format_version === 1 &&
    equalArrays(value.arms, ARMS) &&
    fixedGatePolicy(value.gates) &&
    value.latency_percentile_method === "nearest_rank" &&
    Array.isArray(value.task_set) &&
    value.task_set.length >= 1 &&
    value.task_set.length <= 64 &&
    sortedUnique(value.task_set.map((task) => task?.task_id), 1) &&
    value.task_set.every(
      (task) =>
        isRecord(task) &&
        Number.isSafeInteger(task.repetitions) &&
        task.repetitions >= 1 &&
        task.repetitions <= 64,
    )
  );
}

function hasCoherentObservation(value) {
  const measurements = value.measurements;
  if (
    !ARMS.includes(value.arm) ||
    value.source_mode !== SOURCE_MODES[value.arm] ||
    !["completed", "failed", "incomplete", "invalid"].includes(value.state) ||
    !isRecord(measurements) ||
    ![
      measurements.input_tokens,
      measurements.output_tokens,
      measurements.cached_input_tokens,
      measurements.task_wall_ms,
      measurements.quality_basis_points,
      measurements.critical_omission_count,
    ].every((item) => Number.isSafeInteger(item) && item >= 0) ||
    measurements.quality_basis_points > 10000 ||
    measurements.cached_input_tokens > measurements.input_tokens
  ) {
    return false;
  }
  const completed = value.state === "completed";
  if (
    !reasonCodesAreCoherent(value.reason_codes, !completed) ||
    (completed &&
      [
        measurements.final_direct_verification,
        measurements.tree_guard,
        measurements.egress_guard,
      ].some((guard) => guard !== "pass"))
  ) {
    return false;
  }
  const candidateArm = value.arm === "C_memory_candidate_index";
  if (!candidateArm) {
    return (
      value.candidate_state === null &&
      value.candidate_index_identity_hash === null &&
      value.candidate_index_content_hash === null &&
      measurements.incremental_refresh_ms === null
    );
  }
  if (!["available", "absent", "untrusted", "incomplete"].includes(value.candidate_state)) {
    return false;
  }
  const absent = value.candidate_state === "absent";
  const candidateIdentityCoherent = absent
    ? value.candidate_index_identity_hash === null &&
      value.candidate_index_content_hash === null
    : typeof value.candidate_index_identity_hash === "string" &&
      typeof value.candidate_index_content_hash === "string";
  if (!candidateIdentityCoherent) {
    return false;
  }
  if (
    ["absent", "incomplete"].includes(value.candidate_state) &&
    value.state !== "incomplete"
  ) {
    return false;
  }
  if (value.candidate_state === "untrusted" && value.state !== "invalid") {
    return false;
  }
  const needsRefresh = value.candidate_state === "available" && completed;
  return needsRefresh
    ? Number.isSafeInteger(measurements.incremental_refresh_ms) &&
        measurements.incremental_refresh_ms >= 0
    : measurements.incremental_refresh_ms === null;
}

function hasCoherentReport(value) {
  if (
    !Array.isArray(value.observation_refs) ||
    !sortedUnique(value.observation_refs.map((item) => item?.id), 1, 12288) ||
    !Array.isArray(value.arm_summaries) ||
    !equalArrays(
      value.arm_summaries.map((summary) => summary?.arm),
      ARMS,
    ) ||
    !Array.isArray(value.gates) ||
    !equalArrays(
      value.gates.map((gate) => gate?.gate_id),
      GATE_IDS,
    )
  ) {
    return false;
  }
  if (
    value.arm_summaries.some(
      (summary) =>
        !isRecord(summary) ||
        (summary.arm !== "C_memory_candidate_index" &&
          summary.incremental_refresh_p95_ms !== null),
    ) ||
    value.gates.some(
      (gate) =>
        !isRecord(gate) ||
        typeof gate.passed !== "boolean" ||
        !reasonCodesAreCoherent(gate.reason_codes, !gate.passed),
    )
  ) {
    return false;
  }
  const allPassed = value.gates.every((gate) => gate.passed);
  const reportReasons = sortedUnique(value.reason_codes);
  if (!reportReasons || !["adopt", "reject", "not_evaluable"].includes(value.decision)) {
    return false;
  }
  return value.decision === "adopt"
    ? allPassed && value.reason_codes.length === 0
    : value.decision === "reject"
      ? !allPassed
      : value.reason_codes.length > 0;
}

export function hasCoherentCodebaseMemoryBenchmarkContract(value) {
  try {
    if (
      !isRecord(value) ||
      hasForbiddenField(value) ||
      canonicalCodebaseMemoryBenchmarkDocumentBytes(value) > MAX_DOCUMENT_BYTES ||
      typeof value.content_hash !== "string" ||
      canonicalCodebaseMemoryBenchmarkHash(value) !== value.content_hash
    ) {
      return false;
    }
    if (value.format === "world-forge.codebase_memory_benchmark_plan") {
      return hasCoherentPlan(value);
    }
    if (value.format === "world-forge.codebase_memory_benchmark_observation") {
      return hasCoherentObservation(value);
    }
    if (value.format === "world-forge.codebase_memory_benchmark_report") {
      return hasCoherentReport(value);
    }
  } catch {
    return false;
  }
  return false;
}

async function selfTest() {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const fixtureRoot = path.resolve(
    here,
    "../../../examples/multigenre-contracts/codebase-memory-benchmark-minimal",
  );
  for (const name of ["plan.json", "observation-navigation-01-a-01.json", "report.json"]) {
    const document = JSON.parse(await readFile(path.join(fixtureRoot, name), "utf8"));
    if (!hasCoherentCodebaseMemoryBenchmarkContract(document)) {
      throw new Error(`semantic helper rejected fixture ${name}`);
    }
    const tampered = structuredClone(document);
    tampered.content_hash = "0".repeat(64);
    if (hasCoherentCodebaseMemoryBenchmarkContract(tampered)) {
      throw new Error(`semantic helper accepted tampered fixture ${name}`);
    }
  }
  const report = JSON.parse(await readFile(path.join(fixtureRoot, "report.json"), "utf8"));
  const oversized = structuredClone(report);
  oversized.reason_codes = [`a${"b".repeat(MAX_DOCUMENT_BYTES)}`];
  oversized.content_hash = canonicalCodebaseMemoryBenchmarkHash(oversized);
  if (
    canonicalCodebaseMemoryBenchmarkDocumentBytes(oversized) <= MAX_DOCUMENT_BYTES ||
    hasCoherentCodebaseMemoryBenchmarkContract(oversized)
  ) {
    throw new Error("semantic helper accepted an oversized document");
  }
  const forbidden = structuredClone(report);
  forbidden.metadata = { token: "secret-value" };
  forbidden.content_hash = canonicalCodebaseMemoryBenchmarkHash(forbidden);
  if (hasCoherentCodebaseMemoryBenchmarkContract(forbidden)) {
    throw new Error("semantic helper accepted a forbidden raw surface");
  }
}

if (process.argv.includes("--self-test")) {
  await selfTest();
}
