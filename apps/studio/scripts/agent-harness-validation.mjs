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
