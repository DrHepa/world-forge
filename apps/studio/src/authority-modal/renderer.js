const state = {
  kind: null,
  nonce: null,
  criteria: [],
  objectUrl: null,
  used: false,
};

const byId = (id) => document.getElementById(id);

window.worldForgeAuthorityModal.onPayload((payload) => {
  if (state.used || payload === null || typeof payload !== "object") return;
  state.used = true;
  state.kind = payload.kind;
  state.nonce = typeof payload.nonce === "string" ? payload.nonce : null;
  if (state.nonce === null) {
    report("Authority payload is invalid.", true);
    return;
  }
  if (payload.kind === "creation-review") {
    renderCreationReview(payload);
    return;
  }
  if (payload.kind === "director-credential") {
    renderDirectorCredential(payload);
    return;
  }
  if (payload.kind === "director-decision") {
    renderDirectorDecision(payload);
    return;
  }
  state.nonce = null;
  report("Authority payload kind is unsupported.", true);
});

function renderCreationReview(payload) {
  state.criteria = Array.isArray(payload.criteria) ? payload.criteria : [];
  byId("title").textContent = payload.title;
  byId("sha256").textContent = payload.preview.sha256;
  byId("bytes").textContent = String(payload.preview.byteLength);
  byId("media-type").textContent = payload.preview.mediaType;
  byId("artifact").textContent = `${payload.preview.artifactId} / ${payload.preview.subject.format}@${payload.preview.subject.formatVersion} / ${payload.preview.subject.id}`;
  renderPreview(payload.preview);
  byId("criteria").replaceChildren(
    ...state.criteria.map((criterion) => {
      const item = document.createElement("li");
      item.textContent = criterion;
      return item;
    }),
  );
  byId("creation-review").hidden = false;
  byId("approve").focus();
}

function renderDirectorCredential(payload) {
  byId("title").textContent =
    payload.mode === "enroll"
      ? "Enroll local Director credential"
      : "Unlock local Director credential";
  byId("credential-submit").textContent =
    payload.mode === "enroll" ? "Enroll and unlock" : "Unlock";
  byId("director-credential").hidden = false;
  byId("director-limitations").hidden = false;
  byId("director-passphrase").focus();
}

function renderDirectorDecision(payload) {
  const review = payload.review;
  byId("title").textContent = "Decide exact Harness approval review";
  byId("director-approval-id").textContent = review.approval_id;
  byId("director-execution-id").textContent = review.execution_id;
  byId("director-review-hash").textContent = review.content_hash;
  byId("director-runtime").textContent = `${review.runtime_id}@${review.runtime_revision} / ${review.runtime_content_hash}`;
  byId("director-activation-hash").textContent = review.activation_hash;
  byId("director-grant-hash").textContent = review.grant_hash;
  byId("director-private-input-hash").textContent = review.private_input_hash;
  byId("director-ceilings").textContent = `${review.max_turns} / ${review.max_tool_calls} / ${review.max_total_tokens}`;
  byId("director-cost").textContent =
    review.max_cost_minor_units === null
      ? "none"
      : `${review.max_cost_minor_units} minor units (${review.currency})`;
  byId("director-time").textContent = `${review.max_duration_ms} / ${review.deadline_ms === null ? "none" : review.deadline_ms}`;
  byId("director-tools").replaceChildren(
    ...review.tool_candidates.map((candidate, index) => {
      const row = document.createElement("label");
      row.className = "tool-candidate";
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.value = candidate.tool_id;
      checkbox.dataset.index = String(index);
      const exact = document.createElement("span");
      exact.textContent = `${candidate.tool_id} — ${candidate.descriptor_hash}`;
      row.append(checkbox, exact);
      return row;
    }),
  );
  const expiry = Date.now() + 15 * 60 * 1000;
  byId("director-expiry").value = String(expiry);
  byId("director-expiry").min = String(Date.now() + 1);
  byId("director-decision").hidden = false;
  byId("director-limitations").hidden = false;
  const firstTool = byId("director-tools").querySelector("input");
  (firstTool ?? byId("deny-director")).focus();
}

function renderPreview(preview) {
  const container = byId("preview");
  container.replaceChildren();
  const bytes = new Uint8Array(preview.data);
  if (bytes.byteLength !== preview.byteLength) {
    container.textContent = "Preview byte length mismatch.";
    state.nonce = null;
    return;
  }
  if (preview.mediaType === "image/png") {
    const blob = new Blob([bytes], { type: "image/png" });
    state.objectUrl = URL.createObjectURL(blob);
    const image = document.createElement("img");
    image.alt = "Verified authority preview";
    image.src = state.objectUrl;
    container.append(image);
    return;
  }
  if (preview.mediaType === "audio/wav") {
    const blob = new Blob([bytes], { type: "audio/wav" });
    state.objectUrl = URL.createObjectURL(blob);
    const audio = document.createElement("audio");
    audio.controls = true;
    audio.src = state.objectUrl;
    container.append(audio);
    return;
  }
  if (preview.mediaType === "text/plain") {
    const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    const pre = document.createElement("pre");
    pre.textContent = text;
    container.append(pre);
    return;
  }
  container.textContent = "Unsupported binary preview cannot be approved.";
  state.nonce = null;
}

function cleanup() {
  if (state.objectUrl !== null) {
    URL.revokeObjectURL(state.objectUrl);
    state.objectUrl = null;
  }
  const passphrase = byId("director-passphrase");
  if (passphrase) passphrase.value = "";
}

function send(payload) {
  if (state.nonce === null) return;
  window.worldForgeAuthorityModal.reply({ nonce: state.nonce, ...payload });
  cleanup();
  state.nonce = null;
}

function replyCreation(action) {
  const decision = action === "reject" ? "rejected" : "approved";
  send({
    action,
    criterionDecisions: state.criteria.map(() => decision),
  });
}

function report(message, error = false) {
  const status = byId("modal-status");
  status.textContent = message;
  status.classList.toggle("error", error);
  if (error) status.setAttribute("role", "alert");
}

function hasOnlyUnicodeScalarValues(value) {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      if (index + 1 >= value.length) return false;
      const trailing = value.charCodeAt(index + 1);
      if (trailing < 0xdc00 || trailing > 0xdfff) return false;
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

byId("credential-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const input = byId("director-passphrase");
  if (!input.reportValidity()) return;
  const passphrase = input.value;
  if (!hasOnlyUnicodeScalarValues(passphrase)) {
    input.setAttribute("aria-invalid", "true");
    report("Passphrase must be 16–1024 UTF-8 bytes.", true);
    input.focus();
    return;
  }
  const byteLength = new TextEncoder().encode(passphrase).byteLength;
  if (byteLength < 16 || byteLength > 1024) {
    input.setAttribute("aria-invalid", "true");
    report("Passphrase must be 16–1024 UTF-8 bytes.", true);
    input.focus();
    return;
  }
  input.removeAttribute("aria-invalid");
  input.value = "";
  send({ action: "submit", passphrase });
});

byId("approve-director").addEventListener("click", () => {
  const expiresAtMs = Number(byId("director-expiry").value);
  if (!Number.isSafeInteger(expiresAtMs) || expiresAtMs <= Date.now()) {
    report("Approval expiry must be a future safe integer.", true);
    byId("director-expiry").focus();
    return;
  }
  const approvedToolIds = [...byId("director-tools").querySelectorAll("input:checked")]
    .map((input) => input.value);
  send({ action: "approve", approvedToolIds, expiresAtMs });
});

byId("approve").addEventListener("click", () => replyCreation("approve"));
byId("reject").addEventListener("click", () => replyCreation("reject"));
byId("cancel-creation").addEventListener("click", () => replyCreation("cancel"));
byId("cancel-credential").addEventListener("click", () => send({ action: "cancel" }));
byId("deny-director").addEventListener("click", () => send({ action: "deny" }));
byId("cancel-director").addEventListener("click", () => send({ action: "cancel" }));

window.addEventListener(
  "keydown",
  (event) => {
    if (event.key === "Escape") {
      event.preventDefault();
      if (state.kind === "creation-review") replyCreation("cancel");
      else send({ action: "cancel" });
    }
  },
  { capture: true },
);
window.addEventListener("pagehide", cleanup, { once: true });
