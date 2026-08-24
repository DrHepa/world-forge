import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MAX_DOCUMENT_BYTES = 1024 * 1024;
const MAX_JSON_DEPTH = 64;
const MAX_BENCHMARK_TRIALS_PER_ARM = 256;
const MAX_TOKEN_COUNTER = 10_000_000;
const MAX_CRITICAL_OMISSIONS_PER_OBSERVATION = 1_000_000;
const MAX_NET_TOKENS_PER_ARM = 5_120_000_000;
const MAX_CRITICAL_OMISSIONS_PER_ARM = 256_000_000;
const MIN_REDUCTION_BASIS_POINTS = -51_199_999_990_000;
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
    ) &&
    value.task_set.reduce((total, task) => total + task.repetitions, 0) <=
      MAX_BENCHMARK_TRIALS_PER_ARM
  );
}

function hasCoherentObservation(value) {
  const measurements = value.measurements;
  if (
    !ARMS.includes(value.arm) ||
    value.source_mode !== SOURCE_MODES[value.arm] ||
    !["completed", "failed", "incomplete", "invalid"].includes(value.state) ||
    !isRecord(measurements) ||
    ![measurements.input_tokens, measurements.output_tokens, measurements.cached_input_tokens].every(
      (item) => Number.isSafeInteger(item) && item >= 0 && item <= MAX_TOKEN_COUNTER,
    ) ||
    ![
      measurements.task_wall_ms,
      measurements.quality_basis_points,
    ].every((item) => Number.isSafeInteger(item) && item >= 0) ||
    !Number.isSafeInteger(measurements.critical_omission_count) ||
    measurements.critical_omission_count < 0 ||
    measurements.critical_omission_count > MAX_CRITICAL_OMISSIONS_PER_OBSERVATION ||
    measurements.quality_basis_points > 10000 ||
    measurements.cached_input_tokens > measurements.input_tokens
  ) {
    return false;
  }
  const completed = value.state === "completed";
  if (
    !reasonCodesAreCoherent(value.reason_codes, !completed) ||
    [
      measurements.final_direct_verification,
      measurements.tree_guard,
      measurements.egress_guard,
    ].some((guard) => !["pass", "fail", "unobserved"].includes(guard))
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
    !sortedUnique(value.observation_refs.map((item) => item?.id), 1, 768) ||
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
        !Number.isSafeInteger(summary.observation_count) ||
        summary.observation_count < 1 ||
        summary.observation_count > MAX_BENCHMARK_TRIALS_PER_ARM ||
        !Number.isSafeInteger(summary.total_net_tokens) ||
        summary.total_net_tokens < 0 ||
        summary.total_net_tokens > MAX_NET_TOKENS_PER_ARM ||
        !Number.isSafeInteger(summary.critical_omission_count) ||
        summary.critical_omission_count < 0 ||
        summary.critical_omission_count > MAX_CRITICAL_OMISSIONS_PER_ARM ||
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
  if (value.decision === "not_evaluable") {
    return (
      value.reason_codes.length > 0 &&
      value.gates.every(
        (gate) =>
          gate.measured_value === null &&
          gate.passed === false &&
          equalArrays(gate.reason_codes, ["not_measured"]),
      )
    );
  }
  const measuredDomainsValid = value.gates.every((gate, index) => {
    const measured = gate.measured_value;
    if (index === 0 || index === 4) {
      return (
        Number.isSafeInteger(measured) &&
        measured >= MIN_REDUCTION_BASIS_POINTS &&
        measured <= 10000
      );
    }
    if (index === 1 || index === 2) {
      return Number.isSafeInteger(measured) && measured >= 0;
    }
    if (index === 3) {
      return Number.isSafeInteger(measured) && measured >= -10000 && measured <= 10000;
    }
    return typeof measured === "boolean";
  });
  if (!measuredDomainsValid) {
    return false;
  }
  const expectedPasses = value.gates.map((gate, index) => {
    const measured = gate.measured_value;
    if (index >= 5) return measured;
    if (index === 0) return measured >= 3000;
    if (index === 1) return measured <= 0;
    if (index === 2) return measured <= 5000;
    if (index === 3) return measured <= 200;
    return measured >= 5000;
  });
  if (
    value.gates.some((gate, index) => gate.passed !== expectedPasses[index])
  ) {
    return false;
  }
  return value.decision === "adopt"
    ? allPassed && value.reason_codes.length === 0
    : !allPassed;
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
  const overTrialPlan = JSON.parse(
    await readFile(path.join(fixtureRoot, "plan.json"), "utf8"),
  );
  const taskTemplate = overTrialPlan.task_set[0];
  const maximumTrialTasks = [64, 64, 64, 64].map((repetitions, index) => ({
    ...taskTemplate,
    task_id: `task_${String(index).padStart(2, "0")}`,
    repetitions,
  }));
  overTrialPlan.task_set = maximumTrialTasks;
  overTrialPlan.content_hash = canonicalCodebaseMemoryBenchmarkHash(overTrialPlan);
  if (!hasCoherentCodebaseMemoryBenchmarkContract(overTrialPlan)) {
    throw new Error("semantic helper rejected exactly 256 trials per arm");
  }
  overTrialPlan.task_set = [
    ...maximumTrialTasks,
    { ...taskTemplate, task_id: "task_04", repetitions: 1 },
  ];
  overTrialPlan.content_hash = canonicalCodebaseMemoryBenchmarkHash(overTrialPlan);
  if (hasCoherentCodebaseMemoryBenchmarkContract(overTrialPlan)) {
    throw new Error("semantic helper accepted more than 256 trials per arm");
  }
  const report = JSON.parse(await readFile(path.join(fixtureRoot, "report.json"), "utf8"));
  const maximumSummaryReport = structuredClone(report);
  for (const summary of maximumSummaryReport.arm_summaries) {
    summary.observation_count = 256;
    summary.total_net_tokens = 5_120_000_000;
    summary.critical_omission_count = 256_000_000;
  }
  maximumSummaryReport.content_hash =
    canonicalCodebaseMemoryBenchmarkHash(maximumSummaryReport);
  if (!hasCoherentCodebaseMemoryBenchmarkContract(maximumSummaryReport)) {
    throw new Error("semantic helper rejected exact arm-summary maxima");
  }
  for (const [field, value] of [
    ["observation_count", 257],
    ["total_net_tokens", 5_120_000_001],
    ["critical_omission_count", 256_000_001],
  ]) {
    const oversizedSummary = structuredClone(maximumSummaryReport);
    oversizedSummary.arm_summaries[0][field] = value;
    oversizedSummary.content_hash = canonicalCodebaseMemoryBenchmarkHash(oversizedSummary);
    if (hasCoherentCodebaseMemoryBenchmarkContract(oversizedSummary)) {
      throw new Error(`semantic helper accepted oversized arm-summary ${field}`);
    }
  }
  const overReferenceReport = structuredClone(report);
  const referenceTemplate = report.observation_refs[0];
  const maximumReferences = Array.from({ length: 768 }, (_, index) => ({
    ...referenceTemplate,
    id: `observation_${String(index).padStart(4, "0")}`,
  }));
  overReferenceReport.observation_refs = maximumReferences;
  overReferenceReport.content_hash = canonicalCodebaseMemoryBenchmarkHash(overReferenceReport);
  if (!hasCoherentCodebaseMemoryBenchmarkContract(overReferenceReport)) {
    throw new Error("semantic helper rejected exactly 768 observation references");
  }
  overReferenceReport.observation_refs = [
    ...maximumReferences,
    { ...referenceTemplate, id: "observation_0768" },
  ];
  overReferenceReport.content_hash = canonicalCodebaseMemoryBenchmarkHash(overReferenceReport);
  if (hasCoherentCodebaseMemoryBenchmarkContract(overReferenceReport)) {
    throw new Error("semantic helper accepted more than 768 observation references");
  }
  const measuredNotEvaluable = structuredClone(report);
  measuredNotEvaluable.gates[0].measured_value = 0;
  measuredNotEvaluable.content_hash = canonicalCodebaseMemoryBenchmarkHash(measuredNotEvaluable);
  if (hasCoherentCodebaseMemoryBenchmarkContract(measuredNotEvaluable)) {
    throw new Error("semantic helper accepted a measured not_evaluable gate");
  }
  const adopt = structuredClone(report);
  adopt.decision = "adopt";
  adopt.reason_codes = [];
  const measuredValues = [3000, 0, 5000, 200, 5000, true, true];
  adopt.gates.forEach((gate, index) => {
    gate.measured_value = measuredValues[index];
    gate.passed = true;
    gate.reason_codes = [];
  });
  adopt.content_hash = canonicalCodebaseMemoryBenchmarkHash(adopt);
  if (!hasCoherentCodebaseMemoryBenchmarkContract(adopt)) {
    throw new Error("semantic helper rejected exact-threshold adoption");
  }
  adopt.gates[0].measured_value = 2999;
  adopt.content_hash = canonicalCodebaseMemoryBenchmarkHash(adopt);
  if (hasCoherentCodebaseMemoryBenchmarkContract(adopt)) {
    throw new Error("semantic helper accepted a gate result that contradicted its threshold");
  }
  adopt.gates[0].measured_value = 3000;
  adopt.content_hash = canonicalCodebaseMemoryBenchmarkHash(adopt);
  const negativeOmissions = structuredClone(report);
  negativeOmissions.decision = "reject";
  negativeOmissions.reason_codes = ["critical_omissions_exceeded"];
  negativeOmissions.gates.forEach((gate, index) => {
    gate.measured_value = measuredValues[index];
    gate.passed = true;
    gate.reason_codes = [];
  });
  negativeOmissions.gates[1].measured_value = -1;
  negativeOmissions.gates[1].passed = false;
  negativeOmissions.gates[1].reason_codes = ["critical_omissions_exceeded"];
  negativeOmissions.content_hash = canonicalCodebaseMemoryBenchmarkHash(negativeOmissions);
  if (hasCoherentCodebaseMemoryBenchmarkContract(negativeOmissions)) {
    throw new Error("semantic helper accepted negative critical omissions");
  }
  const invalidGateValues = new Map([
    [0, [MIN_REDUCTION_BASIS_POINTS - 1, 10001]],
    [1, [-1]],
    [2, [-1]],
    [3, [-10001, 10001]],
    [4, [MIN_REDUCTION_BASIS_POINTS - 1, 10001]],
    [5, [1]],
    [6, [0]],
  ]);
  for (const [gateIndex, invalidValues] of invalidGateValues) {
    for (const invalidValue of invalidValues) {
      const invalidGate = structuredClone(adopt);
      invalidGate.gates[gateIndex].measured_value = invalidValue;
      invalidGate.content_hash = canonicalCodebaseMemoryBenchmarkHash(invalidGate);
      if (hasCoherentCodebaseMemoryBenchmarkContract(invalidGate)) {
        throw new Error(`semantic helper accepted invalid gate ${gateIndex} measurement`);
      }
    }
  }
  const completedObservation = JSON.parse(
    await readFile(path.join(fixtureRoot, "observation-navigation-01-a-01.json"), "utf8"),
  );
  completedObservation.measurements.tree_guard = "fail";
  completedObservation.content_hash = canonicalCodebaseMemoryBenchmarkHash(completedObservation);
  if (!hasCoherentCodebaseMemoryBenchmarkContract(completedObservation)) {
    throw new Error("semantic helper rejected explicit completed tree failure evidence");
  }
  completedObservation.measurements.input_tokens = MAX_TOKEN_COUNTER + 1;
  completedObservation.content_hash = canonicalCodebaseMemoryBenchmarkHash(completedObservation);
  if (hasCoherentCodebaseMemoryBenchmarkContract(completedObservation)) {
    throw new Error("semantic helper accepted an oversized token counter");
  }
  completedObservation.measurements.input_tokens = MAX_TOKEN_COUNTER;
  completedObservation.measurements.critical_omission_count =
    MAX_CRITICAL_OMISSIONS_PER_OBSERVATION;
  completedObservation.content_hash = canonicalCodebaseMemoryBenchmarkHash(completedObservation);
  if (!hasCoherentCodebaseMemoryBenchmarkContract(completedObservation)) {
    throw new Error("semantic helper rejected maximum critical omission count");
  }
  completedObservation.measurements.critical_omission_count =
    MAX_CRITICAL_OMISSIONS_PER_OBSERVATION + 1;
  completedObservation.content_hash = canonicalCodebaseMemoryBenchmarkHash(completedObservation);
  if (hasCoherentCodebaseMemoryBenchmarkContract(completedObservation)) {
    throw new Error("semantic helper accepted an oversized critical omission count");
  }
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
