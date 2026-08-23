import { createHash } from "node:crypto";

const maxDocumentBytes = 1024 * 1024;

const capabilityIds = new Set([
  "project.read",
  "artifact.read",
  "artifact.propose",
  "tool.invoke",
  "memory.read",
  "memory.propose",
]);

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function canonicalJson(value, omitContentHash = false) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new Error("Agent Harness values must use JavaScript-safe integers");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  if (isRecord(value)) {
    return `{${Object.entries(value)
      .filter(([key]) => !omitContentHash || key !== "content_hash")
      .sort(([left], [right]) => Buffer.compare(Buffer.from(left), Buffer.from(right)))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
      .join(",")}}`;
  }
  throw new Error("Agent Harness values must contain JSON only");
}

export function canonicalAgentHarnessDocumentBytes(value) {
  return Buffer.byteLength(canonicalJson(value), "utf8");
}

function hash(value) {
  return createHash("sha256")
    .update(canonicalJson(value, true), "utf8")
    .digest("hex");
}

function sortedUnique(values, allowed = undefined) {
  if (!Array.isArray(values) || values.length > 64 || values.some((item) => typeof item !== "string")) {
    return false;
  }
  if (values.join("\u0000") !== [...new Set(values)].sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right))).join("\u0000")) {
    return false;
  }
  return allowed === undefined || values.every((item) => allowed.has(item));
}

function exactIntersection(first, second, third) {
  return [...new Set(first.filter((item) => second.includes(item) && third.includes(item)))].sort(
    (left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)),
  );
}

function equalArrays(left, right) {
  return Array.isArray(left) && Array.isArray(right) && left.length === right.length && left.every((item, index) => item === right[index]);
}

export function hasCoherentAgentHarnessContract(value, kind) {
  try {
    if (
      !isRecord(value) ||
      canonicalAgentHarnessDocumentBytes(value) > maxDocumentBytes ||
      typeof value.content_hash !== "string" ||
      hash(value) !== value.content_hash
    ) {
      return false;
    }
    if (kind === "activation") {
      return (
        value.format === "world-forge.agent_worker_activation" &&
        value.format_version === 1 &&
        !Array.isArray(value.work_order) &&
        isRecord(value.work_order) &&
        sortedUnique(value.work_order.capability_ids, capabilityIds) &&
        sortedUnique(value.work_order.tool_ids) &&
        sortedUnique(value.requested_capability_ids, capabilityIds) &&
        sortedUnique(value.requested_tool_ids) &&
        equalArrays(value.requested_capability_ids, value.work_order.capability_ids) &&
        equalArrays(value.requested_tool_ids, value.work_order.tool_ids)
      );
    }
    if (kind === "event") {
      const subjectFormats = {
        "worker.activated": "world-forge.agent_worker_activation",
        "grant.issued": "world-forge.agent_capability_grant",
        "execution.started": "world-forge.agent_worker_activation",
        "execution.cancel_requested": "world-forge.agent_worker_activation",
        "execution.receipt_recorded": "world-forge.agent_execution_receipt",
        "memory.projected": "world-forge.agent_memory_projection",
      };
      return (
        value.format === "world-forge.agent_event" &&
        value.format_version === 1 &&
        Number.isSafeInteger(value.sequence) &&
        value.sequence >= 0 &&
        (value.sequence === 0
          ? value.previous_event_hash === null
          : typeof value.previous_event_hash === "string") &&
        isRecord(value.subject) &&
        value.subject.format === subjectFormats[value.event_type]
      );
    }
    if (kind === "receipt") {
      const reasonCodes = (codes, required) =>
        sortedUnique(codes) &&
        codes.every((code) => /^[a-z][a-z0-9_]{1,63}$/u.test(code)) &&
        (!required || codes.length > 0);
      const identityArray = (items, maximum = 64) =>
        Array.isArray(items) &&
        items.length <= maximum &&
        sortedUnique(items.map((item) => item?.id)) &&
        items.every(
          (item) =>
            isRecord(item) &&
            typeof item.id === "string" &&
            typeof item.content_hash === "string",
        );
      const usage = value.usage;
      if (
        !isRecord(usage) ||
        ![
          "input_tokens",
          "output_tokens",
          "cached_input_tokens",
          "duration_ms",
          "cost_minor_units",
          "currency",
        ].every((key) => Object.hasOwn(usage, key)) ||
        ![
          usage.input_tokens,
          usage.output_tokens,
          usage.cached_input_tokens,
          usage.duration_ms,
        ].every((number) => Number.isSafeInteger(number) && number >= 0) ||
        usage.cached_input_tokens > usage.input_tokens ||
        (usage.cost_minor_units === null) !== (usage.currency === null) ||
        (usage.cost_minor_units !== null &&
          (!Number.isSafeInteger(usage.cost_minor_units) || usage.cost_minor_units < 0)) ||
        (usage.currency !== null && !/^[A-Z]{3}$/u.test(usage.currency))
      ) {
        return false;
      }
      if (
        !(
          value.format === "world-forge.agent_execution_receipt" &&
          value.format_version === 1 &&
          value.replay_support === "not_claimed" &&
          identityArray(value.prompt_identities) &&
          identityArray(value.result_artifacts) &&
          Array.isArray(value.tool_invocations) &&
          value.tool_invocations.length <= 128 &&
          ["succeeded", "failed", "cancelled"].includes(value.outcome) &&
          reasonCodes(value.failure_codes, value.outcome !== "succeeded") &&
          !(value.outcome === "succeeded" && value.failure_codes.length)
        )
      ) {
        return false;
      }
      const invocationIds = new Set();
      return value.tool_invocations.every((item, index) => {
        if (!isRecord(item) || invocationIds.has(item.invocation_id)) {
          return false;
        }
        invocationIds.add(item.invocation_id);
        return (
          item.sequence === index &&
          typeof item.tool_id === "string" &&
          item.tool_id.length <= 1024 &&
          /^[a-z][a-z0-9_]{1,63}(?:\.[a-z][a-z0-9_]{1,63})+$/u.test(item.tool_id) &&
          ["succeeded", "failed", "cancelled"].includes(item.outcome) &&
          identityArray(item.result_artifacts) &&
          reasonCodes(item.failure_codes, item.outcome !== "succeeded") &&
          !(item.outcome === "succeeded" && item.failure_codes.length)
        );
      });
    }
    if (kind === "grant") {
      return (
        value.format === "world-forge.agent_capability_grant" &&
        value.format_version === 1 &&
        isRecord(value.policy) &&
        isRecord(value.work_order) &&
        sortedUnique(value.policy.capability_ids, capabilityIds) &&
        sortedUnique(value.policy.tool_ids) &&
        sortedUnique(value.role_capability_ids, capabilityIds) &&
        sortedUnique(value.role_tool_ids) &&
        sortedUnique(value.work_order.capability_ids, capabilityIds) &&
        sortedUnique(value.work_order.tool_ids) &&
        sortedUnique(value.effective_capability_ids, capabilityIds) &&
        sortedUnique(value.effective_tool_ids) &&
        equalArrays(value.effective_capability_ids, exactIntersection(value.policy.capability_ids, value.role_capability_ids, value.work_order.capability_ids)) &&
        equalArrays(value.effective_tool_ids, exactIntersection(value.policy.tool_ids, value.role_tool_ids, value.work_order.tool_ids))
      );
    }
  } catch {
    return false;
  }
  return false;
}
