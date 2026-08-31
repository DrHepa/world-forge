import { useEffect, useRef, useState } from "react";

import type {
  ForgeStudioApi,
  StudioClientError,
  StudioClientResult,
  StudioDirectorCeremonyState,
  StudioDirectorReview,
  StudioDirectorSnapshot,
} from "../shared/studio-api";

type DirectorApi = Pick<
  ForgeStudioApi,
  | "getDirectorStatus"
  | "enrollDirector"
  | "unlockDirector"
  | "lockDirector"
  | "selectDirectorReview"
  | "prepareSelectedDirectorReview"
  | "requestSelectedDirectorDecision"
  | "revokeSelectedDirectorDecision"
>;

type DirectorOperation =
  | "enroll"
  | "unlock"
  | "lock"
  | "select"
  | "prepare"
  | "decide"
  | "revoke";

type DirectorFocusTarget = "status" | "operation-result" | "error";

interface DirectorControlProps {
  api: DirectorApi;
  serviceReady: boolean;
}

export function DirectorControl({ api, serviceReady }: DirectorControlProps) {
  const [state, setState] = useState<StudioDirectorCeremonyState | null>(null);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState<DirectorOperation | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [operationResult, setOperationResult] = useState<string | null>(null);
  const [statusRefresh, setStatusRefresh] = useState(0);
  const [focusRequest, setFocusRequest] = useState<{
    generation: number;
    target: DirectorFocusTarget;
  } | null>(null);
  const requestGeneration = useRef(0);
  const statusRef = useRef<HTMLParagraphElement>(null);
  const operationResultRef = useRef<HTMLParagraphElement>(null);
  const errorRef = useRef<HTMLParagraphElement>(null);

  useEffect(() => {
    const generation = ++requestGeneration.current;
    const refresh = async (): Promise<void> => {
      await Promise.resolve();
      if (generation !== requestGeneration.current) return;
      setError(null);
      setOperationResult(null);
      setBusy(null);
      if (!serviceReady) {
        setLoading(false);
        setState(null);
        return;
      }

      setLoading(true);
      try {
        const result = await api.getDirectorStatus();
        if (generation !== requestGeneration.current) return;
        if (result.ok) {
          setState(result.value);
        } else {
          setState(null);
          setError(boundedDirectorMessage(result.error.message));
          setFocusRequest({ generation, target: "error" });
        }
      } catch {
        if (generation !== requestGeneration.current) return;
        setState(null);
        setError("Director status request did not complete.");
        setFocusRequest({ generation, target: "error" });
      } finally {
        if (generation === requestGeneration.current) setLoading(false);
      }
    };
    void refresh();
    return () => {
      if (generation === requestGeneration.current) requestGeneration.current += 1;
    };
  }, [api, serviceReady, statusRefresh]);

  useEffect(() => {
    if (
      !serviceReady ||
      focusRequest === null ||
      focusRequest.generation !== requestGeneration.current
    ) {
      return;
    }
    const target =
      focusRequest.target === "status"
        ? statusRef.current
        : focusRequest.target === "operation-result"
          ? operationResultRef.current
          : errorRef.current;
    target?.focus();
  }, [focusRequest, serviceReady]);

  async function run(
    operation: DirectorOperation,
    invoke: () => Promise<StudioClientResult<StudioDirectorCeremonyState>>,
  ): Promise<void> {
    if (busy !== null || !serviceReady) return;
    const generation = requestGeneration.current;
    const previousState = state;
    const credentialMutation = operation === "enroll" || operation === "unlock";
    const reviewMutation =
      operation === "prepare" || operation === "decide" || operation === "revoke";
    if (operation === "lock" || credentialMutation) setState(null);
    setBusy(operation);
    setError(null);
    setOperationResult(null);
    try {
      const result = await invoke();
      if (generation !== requestGeneration.current) return;
      if (!result.ok) {
        if (credentialMutation && isDefiniteCredentialRejection(result.error)) {
          setState(previousState);
        } else if (reviewMutation) {
          setState(withoutSelectedReview(previousState));
        }
        setError(directorOperationFailure(operation, result.error));
        setFocusRequest({ generation, target: "error" });
        return;
      }
      setState(result.value);
      const resultMessage = directorOperationResult(operation, previousState, result.value);
      if (resultMessage === null) {
        setFocusRequest({ generation, target: "status" });
      } else {
        setOperationResult(resultMessage);
        setFocusRequest({ generation, target: "operation-result" });
      }
    } catch {
      if (generation !== requestGeneration.current) return;
      if (reviewMutation) setState(withoutSelectedReview(previousState));
      setError(directorOperationFailure(operation));
      setFocusRequest({ generation, target: "error" });
    } finally {
      if (generation === requestGeneration.current) setBusy(null);
    }
  }

  const visibleState = serviceReady ? state : null;
  const unlocked = visibleState?.status.state === "unlocked";
  const snapshotState = visibleState?.snapshot?.state;

  return (
    <section
      className="director-control"
      aria-labelledby="director-control-heading"
      aria-busy={loading || busy !== null}
    >
      <div className="director-control-heading">
        <div>
          <p className="eyebrow">Authenticated local ceremony</p>
          <h2 id="director-control-heading">Director approval</h2>
        </div>
        <p
          className={`director-status director-status-${visibleState?.status.state ?? "unavailable"}`}
          role="status"
          aria-live="polite"
          tabIndex={-1}
          ref={statusRef}
        >
          {directorStatusText(serviceReady, loading, visibleState)}
        </p>
      </div>

      <div className="director-actions" aria-label="Director credential and review actions">
        {serviceReady &&
        !loading &&
        (visibleState === null || visibleState.status.state === "unknown") ? (
          <button
            type="button"
            disabled={busy !== null}
            onClick={() => setStatusRefresh((current) => current + 1)}
          >
            Refresh Director status
          </button>
        ) : null}
        {visibleState?.status.state === "not_enrolled" ? (
          <button
            type="button"
            disabled={busy !== null}
            onClick={() => void run("enroll", api.enrollDirector)}
          >
            {busy === "enroll" ? "Enrolling…" : "Enroll local Director"}
          </button>
        ) : null}
        {visibleState?.status.state === "locked" ? (
          <button
            type="button"
            disabled={busy !== null}
            onClick={() => void run("unlock", api.unlockDirector)}
          >
            {busy === "unlock" ? "Unlocking…" : "Unlock local Director"}
          </button>
        ) : null}
        {unlocked ? (
          <>
            <button
              type="button"
              className="secondary"
              disabled={busy !== null}
              onClick={() => void run("lock", api.lockDirector)}
            >
              {busy === "lock" ? "Locking…" : "Lock Director"}
            </button>
            <button
              type="button"
              disabled={busy !== null}
              onClick={() => void run("select", api.selectDirectorReview)}
            >
              {busy === "select" ? "Selecting…" : "Select exact review"}
            </button>
          </>
        ) : null}
        {unlocked && snapshotState === "missing" ? (
          <button
            type="button"
            disabled={busy !== null}
            onClick={() => void run("prepare", api.prepareSelectedDirectorReview)}
          >
            {busy === "prepare" ? "Preparing…" : "Prepare exact review"}
          </button>
        ) : null}
        {unlocked && snapshotState === "prepared" ? (
          <button
            type="button"
            disabled={busy !== null}
            onClick={() => void run("decide", api.requestSelectedDirectorDecision)}
          >
            {busy === "decide" ? "Reviewing…" : "Review exact decision"}
          </button>
        ) : null}
        {unlocked && (snapshotState === "approved" || snapshotState === "denied") ? (
          <button
            type="button"
            className="danger"
            disabled={busy !== null}
            onClick={() => void run("revoke", api.revokeSelectedDirectorDecision)}
          >
            {busy === "revoke" ? "Revoking…" : "Revoke decision"}
          </button>
        ) : null}
      </div>

      {error ? (
        <p className="director-error" role="alert" tabIndex={-1} ref={errorRef}>
          {error}
        </p>
      ) : null}

      {operationResult ? (
        <p
          className="director-operation-result"
          role="status"
          aria-label="Director operation result"
          aria-live="polite"
          tabIndex={-1}
          ref={operationResultRef}
        >
          {operationResult}
        </p>
      ) : null}

      {visibleState?.selectedReview && visibleState.snapshot ? (
        <DirectorReviewEvidence
          review={visibleState.selectedReview}
          snapshot={visibleState.snapshot}
        />
      ) : (
        <p className="director-empty">
          {unlocked
            ? "No exact review is selected. Studio does not expose the selected file path to the renderer."
            : "Unlock the local credential before selecting an exact Harness review."}
        </p>
      )}

      <aside className="director-limitations" aria-label="Director identity and authority limitations">
        <strong>Local authority limitations</strong>
        <ul>
          <li>
            <code>director_local</code> is a fixed local credential; it does not establish civil or
            legal identity.
          </li>
          <li>
            Studio does not persist the passphrase, but JavaScript strings cannot be securely
            zeroized.
          </li>
          <li>
            This ceremony records a durable Director decision only. It does not hydrate or
            authorize the Agent Harness.
          </li>
        </ul>
      </aside>
    </section>
  );
}

function DirectorReviewEvidence({
  review,
  snapshot,
}: {
  review: StudioDirectorReview;
  snapshot: StudioDirectorSnapshot;
}) {
  const decision = snapshot.current_decision;
  return (
    <div className="director-evidence">
      <section aria-labelledby="director-review-heading">
        <div className="director-evidence-heading">
          <h3 id="director-review-heading">Selected exact review</h3>
          <span>
            State: <strong>{snapshot.state}</strong>
          </span>
        </div>
        <dl className="director-evidence-grid">
          <Evidence label="Approval ID" value={review.approval_id} />
          <Evidence label="Execution ID" value={review.execution_id} />
          <Evidence label="Review content SHA-256" value={review.content_hash} />
          <Evidence label="Authority review SHA-256" value={snapshot.review_hash} />
          <Evidence label="Activation SHA-256" value={review.activation_hash} />
          <Evidence label="Grant SHA-256" value={review.grant_hash} />
          <Evidence label="Private input SHA-256" value={review.private_input_hash} />
          <Evidence label="Runtime ID" value={review.runtime_id} />
          <Evidence label="Runtime revision" value={String(review.runtime_revision)} />
          <Evidence label="Runtime content SHA-256" value={review.runtime_content_hash} />
          <Evidence label="Authority generation" value={String(snapshot.generation)} />
          <Evidence label="Max turns" value={String(review.max_turns)} />
          <Evidence label="Max tool calls" value={String(review.max_tool_calls)} />
          <Evidence label="Max total tokens" value={String(review.max_total_tokens)} />
          <Evidence
            label="Max cost (minor units)"
            value={
              review.max_cost_minor_units === null
                ? "none"
                : `${String(review.max_cost_minor_units)} minor units (${review.currency})`
            }
          />
          <Evidence label="Max duration ms" value={String(review.max_duration_ms)} />
          <Evidence label="Deadline ms" value={nullableInteger(review.deadline_ms)} />
          <Evidence label="Decision SHA-256" value={snapshot.decision_hash ?? "none"} />
        </dl>
        <h4>Candidate tool identifiers and descriptor hashes</h4>
        {review.tool_candidates.length === 0 ? (
          <p>None</p>
        ) : (
          <ul className="director-tool-list">
            {review.tool_candidates.map((candidate) => (
              <li key={`${candidate.tool_id}:${candidate.descriptor_hash}`}>
                <code>{candidate.tool_id}</code>
                <code>{candidate.descriptor_hash}</code>
              </li>
            ))}
          </ul>
        )}
      </section>

      {decision ? (
        <section aria-labelledby="director-decision-heading">
          <h3 id="director-decision-heading">Retained durable decision evidence</h3>
          <dl className="director-evidence-grid">
            <Evidence label="Reviewer ID" value={decision.reviewer_id} />
            <Evidence label="Outcome" value={decision.outcome} />
            <Evidence label="Generation" value={String(decision.generation)} />
            <Evidence label="Expires at ms" value={nullableInteger(decision.expires_at_ms)} />
            <Evidence label="Decision content SHA-256" value={decision.content_hash} />
          </dl>
          <h4>Approved tool identifiers</h4>
          {decision.approved_tool_ids.length === 0 ? (
            <p>None</p>
          ) : (
            <ul className="director-approved-tools">
              {decision.approved_tool_ids.map((toolId) => (
                <li key={toolId}><code>{toolId}</code></li>
              ))}
            </ul>
          )}
        </section>
      ) : null}
    </div>
  );
}

function Evidence({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd><code>{value}</code></dd>
    </div>
  );
}

function directorStatusText(
  serviceReady: boolean,
  loading: boolean,
  state: StudioDirectorCeremonyState | null,
): string {
  if (!serviceReady) {
    return "Director controls are unavailable while the Forge service is not ready.";
  }
  if (loading) return "Reading local Director credential status…";
  if (state?.status.state === "not_enrolled") {
    return "No local Director credential is enrolled.";
  }
  if (state?.status.state === "locked") {
    return "Local Director credential is locked.";
  }
  if (state?.status.state === "unlocked") {
    return "Local Director credential is unlocked.";
  }
  return "Local Director credential status is unavailable.";
}

function boundedDirectorMessage(message: string): string {
  const normalized = message.replace(/[\r\n\t]+/gu, " ").trim();
  return normalized.length === 0
    ? "The Director operation did not complete."
    : normalized.slice(0, 512);
}

function directorOperationFailure(
  operation: DirectorOperation,
  error?: StudioClientError,
): string {
  switch (operation) {
    case "select":
      return "Exact review selection did not complete.";
    case "prepare":
      return "Exact review preparation is not confirmed. Select the exact review again to inspect current authority state.";
    case "decide":
      return "Director decision is not confirmed. Select the exact review again to inspect current authority state.";
    case "revoke":
      return "Director decision revocation is not confirmed. Select the exact review again to inspect current authority state.";
    case "lock":
      return "Director authority is unavailable because lock confirmation did not complete. Refresh status before continuing.";
    case "enroll":
      return error && isDefiniteCredentialRejection(error)
        ? boundedDirectorMessage(error.message)
        : "Director credential status is unknown because enrollment confirmation did not complete. Refresh status before continuing.";
    case "unlock":
      return error && isDefiniteCredentialRejection(error)
        ? boundedDirectorMessage(error.message)
        : "Director credential status is unknown because unlock confirmation did not complete. Refresh status before continuing.";
    default:
      return boundedDirectorMessage(error?.message ?? "");
  }
}

function isDefiniteCredentialRejection(error: StudioClientError): boolean {
  return ["invalid_request", "not_found", "conflict", "invalid_state"].includes(
    error.code,
  );
}

function withoutSelectedReview(
  state: StudioDirectorCeremonyState | null,
): StudioDirectorCeremonyState | null {
  return state === null
    ? null
    : { ...state, selectedReview: null, snapshot: null };
}

function directorOperationResult(
  operation: DirectorOperation,
  previous: StudioDirectorCeremonyState | null,
  next: StudioDirectorCeremonyState,
): string | null {
  const state = next.snapshot?.state;
  switch (operation) {
    case "select":
      if (next.selectedReview === null || next.snapshot === null) {
        return "Review selection was canceled. No exact review is selected.";
      }
      if (sameDirectorSnapshot(previous, next)) {
        return `Review selection closed without changing the snapshot. Snapshot state remains ${state}.`;
      }
      return `Exact review selected. Snapshot state: ${state}.`;
    case "prepare":
      return `Exact review prepared. Snapshot state: ${state ?? "unavailable"}.`;
    case "decide":
      if (state === "prepared" && sameDirectorSnapshot(previous, next)) {
        return "Decision ceremony was canceled. Snapshot state remains prepared.";
      }
      return `Decision recorded. Snapshot state: ${state ?? "unavailable"}.`;
    case "revoke":
      return `Decision revoked. Snapshot state: ${state ?? "unavailable"}.`;
    default:
      return null;
  }
}

function sameDirectorSnapshot(
  previous: StudioDirectorCeremonyState | null,
  next: StudioDirectorCeremonyState,
): boolean {
  const before = previous?.snapshot;
  const after = next.snapshot;
  return (
    before !== null &&
    before !== undefined &&
    after !== null &&
    before.state === after.state &&
    before.generation === after.generation &&
    before.review_hash === after.review_hash &&
    before.decision_hash === after.decision_hash
  );
}

function nullableInteger(value: number | null): string {
  return value === null ? "none" : String(value);
}
