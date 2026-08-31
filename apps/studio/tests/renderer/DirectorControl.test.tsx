// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi, type Mock } from "vitest";

import type {
  ForgeStudioApi,
  StudioDirectorCeremonyState,
} from "../../src/shared/studio-api";
import { DirectorControl } from "../../src/renderer/DirectorControl";

const REVIEW_HASH = "a".repeat(64);
const DECISION_HASH = "b".repeat(64);

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("DirectorControl", () => {
  it("exposes local enrollment without renderer-supplied ceremony arguments", async () => {
    const api = directorApi(notEnrolledState());
    api.enrollDirector.mockResolvedValue(ok(unlockedState()));

    render(<DirectorControl api={api} serviceReady />);

    expect(
      await screen.findByRole("heading", { name: "Director approval" }),
    ).toBeInTheDocument();
    expect(screen.getByText(/does not establish civil or legal identity/iu)).toBeInTheDocument();
    expect(screen.getByText(/cannot be securely zeroized/iu)).toBeInTheDocument();
    expect(screen.getByText(/does not hydrate or authorize the Agent Harness/iu)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Enroll local Director" }));

    await screen.findByText("Local Director credential is unlocked.");
    expect(api.enrollDirector).toHaveBeenCalledTimes(1);
    expect(api.enrollDirector).toHaveBeenCalledWith();
    expect(screen.getByRole("button", { name: "Select exact review" })).toBeEnabled();
  });

  it("renders exact review evidence and performs prepare, decision, and revoke with no arguments", async () => {
    const api = directorApi(unlockedState());
    api.selectDirectorReview.mockResolvedValue(ok(missingState()));
    api.prepareSelectedDirectorReview.mockResolvedValue(ok(preparedState()));
    api.requestSelectedDirectorDecision.mockResolvedValue(ok(approvedState()));
    api.revokeSelectedDirectorDecision.mockResolvedValue(ok(revokedState()));

    render(<DirectorControl api={api} serviceReady />);
    await screen.findByText("Local Director credential is unlocked.");

    fireEvent.click(screen.getByRole("button", { name: "Select exact review" }));
    expect(await screen.findByText("approval_ui_01")).toBeInTheDocument();
    expect(screen.getByText("execution_ui_01")).toBeInTheDocument();
    expect(screen.getByText("tool.inspect")).toBeInTheDocument();
    expect(screen.getByText("c".repeat(64))).toBeInTheDocument();
    expect(screen.getByText("missing", { selector: "strong" })).toBeInTheDocument();
    expect(screen.getByText("Max cost (minor units)")).toBeInTheDocument();
    expect(screen.getByText("250 minor units (USD)")).toBeInTheDocument();
    expect(screen.queryByText("250 USD")).not.toBeInTheDocument();
    expect(screen.queryByText(/friendly|description/iu)).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Prepare exact review" }));
    expect(await screen.findByText("prepared", { selector: "strong" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Review exact decision" }));
    expect(await screen.findByText("approved", { selector: "strong" })).toBeInTheDocument();
    expect(screen.getAllByText("director_local")).toHaveLength(2);
    fireEvent.click(screen.getByRole("button", { name: "Revoke decision" }));
    expect(await screen.findByText("revoked", { selector: "strong" })).toBeInTheDocument();

    expect(api.selectDirectorReview).toHaveBeenCalledWith();
    expect(api.prepareSelectedDirectorReview).toHaveBeenCalledWith();
    expect(api.requestSelectedDirectorDecision).toHaveBeenCalledWith();
    expect(api.revokeSelectedDirectorDecision).toHaveBeenCalledWith();
  });

  it("announces and focuses each exact snapshot transition", async () => {
    const api = directorApi(unlockedState());
    api.selectDirectorReview.mockResolvedValue(ok(missingState()));
    api.prepareSelectedDirectorReview.mockResolvedValue(ok(preparedState()));
    api.requestSelectedDirectorDecision.mockResolvedValue(ok(approvedState()));
    api.revokeSelectedDirectorDecision.mockResolvedValue(ok(revokedState()));

    render(<DirectorControl api={api} serviceReady />);
    const credentialStatus = await screen.findByText(
      "Local Director credential is unlocked.",
    );

    fireEvent.click(screen.getByRole("button", { name: "Select exact review" }));
    const operationResult = await screen.findByRole("status", {
      name: "Director operation result",
    });
    expect(operationResult).toHaveTextContent(
      "Exact review selected. Snapshot state: missing.",
    );
    await waitFor(() => expect(operationResult).toHaveFocus());
    expect(credentialStatus).not.toHaveFocus();

    fireEvent.click(screen.getByRole("button", { name: "Prepare exact review" }));
    await waitFor(() =>
      expect(
        screen.getByRole("status", { name: "Director operation result" }),
      ).toHaveTextContent("Exact review prepared. Snapshot state: prepared."),
    );
    await waitFor(() =>
      expect(
        screen.getByRole("status", { name: "Director operation result" }),
      ).toHaveFocus(),
    );

    fireEvent.click(screen.getByRole("button", { name: "Review exact decision" }));
    await waitFor(() =>
      expect(
        screen.getByRole("status", { name: "Director operation result" }),
      ).toHaveTextContent("Decision recorded. Snapshot state: approved."),
    );
    await waitFor(() =>
      expect(
        screen.getByRole("status", { name: "Director operation result" }),
      ).toHaveFocus(),
    );

    fireEvent.click(screen.getByRole("button", { name: "Revoke decision" }));
    await waitFor(() =>
      expect(
        screen.getByRole("status", { name: "Director operation result" }),
      ).toHaveTextContent("Decision revoked. Snapshot state: revoked."),
    );
    await waitFor(() =>
      expect(
        screen.getByRole("status", { name: "Director operation result" }),
      ).toHaveFocus(),
    );
  });

  it("announces selection cancellation and hides review error details", async () => {
    const api = directorApi(unlockedState());
    api.selectDirectorReview
      .mockResolvedValueOnce(ok(unlockedState()))
      .mockResolvedValueOnce({
        ok: false,
        error: {
          code: "invalid_request",
          message: "Cannot read /tmp/private-review.json secret-passphrase",
        },
      });

    render(<DirectorControl api={api} serviceReady />);
    await screen.findByText("Local Director credential is unlocked.");

    fireEvent.click(screen.getByRole("button", { name: "Select exact review" }));
    const cancellation = await screen.findByRole("status", {
      name: "Director operation result",
    });
    expect(cancellation).toHaveTextContent(
      "Review selection was canceled. No exact review is selected.",
    );
    await waitFor(() => expect(cancellation).toHaveFocus());

    fireEvent.click(screen.getByRole("button", { name: "Select exact review" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Exact review selection did not complete.",
    );
    expect(screen.queryByText(/private-review|secret-passphrase/iu)).not.toBeInTheDocument();
    expect(
      screen.queryByRole("status", { name: "Director operation result" }),
    ).not.toBeInTheDocument();
  });

  it("focuses an error only after its conditional alert commits", async () => {
    const api = directorApi(unlockedState());
    api.selectDirectorReview.mockResolvedValue({
      ok: false,
      error: {
        code: "invalid_request",
        message: "The review could not be selected",
      },
    });
    vi.spyOn(window, "requestAnimationFrame").mockImplementation((callback) => {
      callback(0);
      return 1;
    });

    render(<DirectorControl api={api} serviceReady />);
    await screen.findByText("Local Director credential is unlocked.");

    fireEvent.click(screen.getByRole("button", { name: "Select exact review" }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Exact review selection did not complete.");
    expect(alert).toHaveFocus();
  });

  it("announces a canceled decision without changing the prepared snapshot", async () => {
    const api = directorApi(preparedState());
    api.requestSelectedDirectorDecision.mockResolvedValue(ok(preparedState()));

    render(<DirectorControl api={api} serviceReady />);
    await screen.findByText("prepared", { selector: "strong" });

    fireEvent.click(screen.getByRole("button", { name: "Review exact decision" }));
    const cancellation = await screen.findByRole("status", {
      name: "Director operation result",
    });
    expect(cancellation).toHaveTextContent(
      "Decision ceremony was canceled. Snapshot state remains prepared.",
    );
    await waitFor(() => expect(cancellation).toHaveFocus());
    expect(screen.getByText("prepared", { selector: "strong" })).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("serializes controls, announces failures, and focuses the completed operation status", async () => {
    let resolveLock: ((value: ReturnType<typeof ok>) => void) | undefined;
    const api = directorApi(unlockedState());
    api.lockDirector.mockImplementation(
      () => new Promise((resolve) => { resolveLock = resolve; }),
    );

    render(<DirectorControl api={api} serviceReady />);
    await screen.findByText("Local Director credential is unlocked.");
    fireEvent.click(screen.getByRole("button", { name: "Lock Director" }));

    expect(screen.queryByRole("button", { name: "Locking…" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Select exact review" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Refresh Director status" })).toBeDisabled();
    resolveLock?.(ok(lockedState()));
    const status = await screen.findByText("Local Director credential is locked.");
    await waitFor(() => expect(status).toHaveFocus());

    api.unlockDirector.mockResolvedValue({
      ok: false,
      error: { code: "invalid_request", message: "Credential was not accepted" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Unlock local Director" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Credential was not accepted");
  });

  it.each([
    {
      button: "Prepare exact review",
      initial: missingState(),
      method: "prepareSelectedDirectorReview" as const,
      code: "timeout" as const,
      message: "Exact review preparation is not confirmed. Select the exact review again to inspect current authority state.",
    },
    {
      button: "Review exact decision",
      initial: preparedState(),
      method: "requestSelectedDirectorDecision" as const,
      code: "conflict" as const,
      message: "Director decision is not confirmed. Select the exact review again to inspect current authority state.",
    },
    {
      button: "Revoke decision",
      initial: approvedState(),
      method: "revokeSelectedDirectorDecision" as const,
      code: "internal_error" as const,
      message: "Director decision revocation is not confirmed. Select the exact review again to inspect current authority state.",
    },
  ])(
    "discards stale evidence after ambiguous $method completion",
    async ({ button, initial, method, code, message }) => {
      const api = directorApi(initial);
      api[method].mockResolvedValue({
        ok: false,
        error: {
          code,
          message: "secret-passphrase /tmp/private-review.json",
        },
      });
      render(<DirectorControl api={api} serviceReady />);
      expect(await screen.findByText("approval_ui_01")).toBeInTheDocument();

      fireEvent.click(screen.getByRole("button", { name: button }));

      const alert = await screen.findByRole("alert");
      expect(alert).toHaveTextContent(message);
      expect(alert).not.toHaveTextContent(/secret-passphrase|private-review/iu);
      expect(screen.queryByText("approval_ui_01")).not.toBeInTheDocument();
      expect(screen.queryByRole("button", { name: button })).not.toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Select exact review" })).toBeEnabled();
      expect(screen.getByText("Local Director credential is unlocked.")).toBeInTheDocument();
      await waitFor(() => expect(alert).toHaveFocus());
    },
  );

  it.each([
    ["invalid_state", "Director credential was not accepted."],
    ["invalid_request", "Director credential request was rejected."],
  ] as const)(
    "restores the known locked projection after definite %s credential rejection",
    async (code, message) => {
      const api = directorApi(lockedState());
      api.unlockDirector.mockResolvedValue({
        ok: false,
        error: { code, message },
      });
      render(<DirectorControl api={api} serviceReady />);
      await screen.findByRole("button", { name: "Unlock local Director" });

      fireEvent.click(screen.getByRole("button", { name: "Unlock local Director" }));

      expect(await screen.findByRole("alert")).toHaveTextContent(message);
      expect(screen.getByText("Local Director credential is locked.")).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Unlock local Director" })).toBeEnabled();
      expect(screen.queryByRole("button", { name: "Refresh Director status" })).not.toBeInTheDocument();
    },
  );

  it("removes stale authority immediately when lock confirmation rejects and refreshes explicitly", async () => {
    const api = directorApi(approvedState());
    api.lockDirector.mockRejectedValue(new Error("private transport detail"));

    render(<DirectorControl api={api} serviceReady />);
    expect(await screen.findByText("approval_ui_01")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Lock Director" }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(
      "Director authority is unavailable because lock confirmation did not complete. Refresh status before continuing.",
    );
    await waitFor(() => expect(alert).toHaveFocus());
    expect(screen.queryByText("approval_ui_01")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Lock Director" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Select exact review" })).not.toBeInTheDocument();
    expect(screen.getByText("Local Director credential status is unavailable.")).toBeInTheDocument();

    api.getDirectorStatus.mockResolvedValueOnce(ok(lockedState()));
    fireEvent.click(screen.getByRole("button", { name: "Refresh Director status" }));
    expect(await screen.findByText("Local Director credential is locked.")).toBeInTheDocument();
    expect(api.getDirectorStatus).toHaveBeenCalledTimes(2);
  });

  it.each([
    {
      button: "Enroll local Director",
      initial: notEnrolledState(),
      method: "enrollDirector" as const,
      operation: "enrollment",
      code: "timeout" as const,
    },
    {
      button: "Unlock local Director",
      initial: lockedState(),
      method: "unlockDirector" as const,
      operation: "unlock",
      code: "timeout" as const,
    },
    {
      button: "Unlock local Director",
      initial: lockedState(),
      method: "unlockDirector" as const,
      operation: "unlock",
      code: "internal_error" as const,
    },
    {
      button: "Enroll local Director",
      initial: notEnrolledState(),
      method: "enrollDirector" as const,
      operation: "enrollment",
      code: "service_unavailable" as const,
    },
  ])(
    "projects unknown after ambiguous $operation $code confirmation and recovers by refresh",
    async ({ button, initial, method, operation, code }) => {
      const api = directorApi(initial);
      api[method].mockResolvedValue({
        ok: false,
        error: {
          code,
          message: "secret post-commit transport detail",
        },
      });

      render(<DirectorControl api={api} serviceReady />);
      await screen.findByRole("button", { name: button });
      fireEvent.click(screen.getByRole("button", { name: button }));

      const alert = await screen.findByRole("alert");
      expect(alert).toHaveTextContent(
        `Director credential status is unknown because ${operation} confirmation did not complete. Refresh status before continuing.`,
      );
      expect(alert).not.toHaveTextContent(/secret|post-commit/iu);
      expect(screen.getByText("Local Director credential status is unavailable.")).toBeInTheDocument();
      expect(screen.queryByRole("button", { name: button })).not.toBeInTheDocument();
      expect(screen.queryByRole("button", { name: "Select exact review" })).not.toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Refresh Director status" })).toBeEnabled();

      api.getDirectorStatus.mockResolvedValueOnce(ok(unlockedState()));
      fireEvent.click(screen.getByRole("button", { name: "Refresh Director status" }));
      expect(await screen.findByText("Local Director credential is unlocked.")).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Select exact review" })).toBeEnabled();
      expect(api.getDirectorStatus).toHaveBeenCalledTimes(2);
    },
  );

  it("bounds an initial status rejection and ignores a stale lifecycle rejection", async () => {
    const api = directorApi(lockedState());
    api.getDirectorStatus.mockRejectedValueOnce(
      new Error("secret status failure /tmp/director-private"),
    );
    const view = render(<DirectorControl api={api} serviceReady />);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Director status request did not complete.");
    expect(alert).not.toHaveTextContent(/secret|director-private/iu);
    await waitFor(() => expect(alert).toHaveFocus());
    expect(screen.getByText("Local Director credential status is unavailable.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Refresh Director status" })).toBeEnabled();

    let rejectStatus!: (reason: Error) => void;
    api.getDirectorStatus.mockImplementationOnce(
      () => new Promise((_, reject) => { rejectStatus = reject; }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Refresh Director status" }));
    await waitFor(() => expect(api.getDirectorStatus).toHaveBeenCalledTimes(2));
    view.rerender(<DirectorControl api={api} serviceReady={false} />);
    rejectStatus(new Error("stale private status failure"));

    expect(
      await screen.findByText(
        "Director controls are unavailable while the Forge service is not ready.",
      ),
    ).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Refresh Director status" })).not.toBeInTheDocument();
  });

  it("does not let a stale operation completion steal focus after lifecycle cancellation", async () => {
    let resolveSelection!: (value: ReturnType<typeof ok>) => void;
    const selection = new Promise<ReturnType<typeof ok>>((resolve) => {
      resolveSelection = resolve;
    });
    const api = directorApi(unlockedState());
    api.selectDirectorReview.mockReturnValue(selection);
    const view = render(
      <>
        <button type="button">Outside Director control</button>
        <DirectorControl api={api} serviceReady />
      </>,
    );
    await screen.findByText("Local Director credential is unlocked.");
    fireEvent.click(screen.getByRole("button", { name: "Select exact review" }));
    await waitFor(() => expect(api.selectDirectorReview).toHaveBeenCalledTimes(1));

    view.rerender(
      <>
        <button type="button">Outside Director control</button>
        <DirectorControl api={api} serviceReady={false} />
      </>,
    );
    await screen.findByText(
      "Director controls are unavailable while the Forge service is not ready.",
    );
    const outside = screen.getByRole("button", { name: "Outside Director control" });
    outside.focus();

    await act(async () => {
      resolveSelection(ok(missingState()));
      await selection;
    });

    expect(outside).toHaveFocus();
    expect(
      screen.queryByRole("status", { name: "Director operation result" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText("approval_ui_01")).not.toBeInTheDocument();
  });

  it("removes stale review evidence while the service is unavailable and reloads after restart", async () => {
    const api = directorApi(approvedState());
    const view = render(<DirectorControl api={api} serviceReady />);
    expect(await screen.findByText("approval_ui_01")).toBeInTheDocument();

    view.rerender(<DirectorControl api={api} serviceReady={false} />);
    expect(screen.getByText("Director controls are unavailable while the Forge service is not ready.")).toBeInTheDocument();
    expect(screen.queryByText("approval_ui_01")).not.toBeInTheDocument();

    api.getDirectorStatus.mockResolvedValue(ok(lockedState()));
    view.rerender(<DirectorControl api={api} serviceReady />);
    expect(await screen.findByText("Local Director credential is locked.")).toBeInTheDocument();
    expect(api.getDirectorStatus).toHaveBeenCalledTimes(2);
  });
});

type DirectorMethods = Pick<
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

type DirectorApi = {
  [Key in keyof DirectorMethods]: Mock<DirectorMethods[Key]>;
};

function directorApi(initial: StudioDirectorCeremonyState): DirectorApi {
  return {
    getDirectorStatus: vi.fn().mockResolvedValue(ok(initial)),
    enrollDirector: vi.fn(),
    unlockDirector: vi.fn(),
    lockDirector: vi.fn(),
    selectDirectorReview: vi.fn(),
    prepareSelectedDirectorReview: vi.fn(),
    requestSelectedDirectorDecision: vi.fn(),
    revokeSelectedDirectorDecision: vi.fn(),
  };
}

function ok(value: StudioDirectorCeremonyState) {
  return { ok: true as const, value };
}

function notEnrolledState(): StudioDirectorCeremonyState {
  return state("not_enrolled");
}

function lockedState(): StudioDirectorCeremonyState {
  return state("locked");
}

function unlockedState(): StudioDirectorCeremonyState {
  return state("unlocked");
}

function missingState(): StudioDirectorCeremonyState {
  return state("unlocked", {
    prepared_review: null,
    current_decision: null,
    generation: 0,
    review_hash: REVIEW_HASH,
    decision_hash: null,
    state: "missing",
  });
}

function preparedState(): StudioDirectorCeremonyState {
  return state("unlocked", {
    prepared_review: review(),
    current_decision: null,
    generation: 0,
    review_hash: REVIEW_HASH,
    decision_hash: null,
    state: "prepared",
  });
}

function approvedState(): StudioDirectorCeremonyState {
  return state("unlocked", {
    prepared_review: review(),
    current_decision: approvedDecision(),
    generation: 1,
    review_hash: REVIEW_HASH,
    decision_hash: DECISION_HASH,
    state: "approved",
  });
}

function revokedState(): StudioDirectorCeremonyState {
  return state("unlocked", {
    prepared_review: review(),
    current_decision: approvedDecision(),
    generation: 2,
    review_hash: REVIEW_HASH,
    decision_hash: DECISION_HASH,
    state: "revoked",
  });
}

function approvedDecision(): NonNullable<
  NonNullable<StudioDirectorCeremonyState["snapshot"]>["current_decision"]
> {
  return {
    format: "world-forge.private.execution_approval_decision",
    format_version: 1,
    approval_id: "approval_ui_01",
    execution_id: "execution_ui_01",
    review_hash: REVIEW_HASH,
    generation: 1,
    reviewer_id: "director_local",
    outcome: "approved",
    approved_tool_ids: ["tool.inspect"],
    expires_at_ms: 2_000_000_000_000,
    content_hash: DECISION_HASH,
  };
}

function state(
  credentialState: StudioDirectorCeremonyState["status"]["state"],
  snapshot: StudioDirectorCeremonyState["snapshot"] = null,
): StudioDirectorCeremonyState {
  return {
    status: { credentialId: "director_local", state: credentialState },
    selectedReview: snapshot === null ? null : review(),
    snapshot,
  };
}

function review(): NonNullable<StudioDirectorCeremonyState["selectedReview"]> {
  return {
    format: "world-forge.private.execution_approval_review",
    format_version: 1,
    approval_id: "approval_ui_01",
    execution_id: "execution_ui_01",
    activation_hash: "d".repeat(64),
    grant_hash: "e".repeat(64),
    private_input_hash: "f".repeat(64),
    runtime_id: "runtime_ui_01",
    runtime_revision: 7,
    runtime_content_hash: "9".repeat(64),
    max_turns: 12,
    max_tool_calls: 8,
    max_total_tokens: 50_000,
    max_cost_minor_units: 250,
    currency: "USD",
    max_duration_ms: 300_000,
    deadline_ms: 2_000_000_000_000,
    tool_candidates: [
      { tool_id: "tool.inspect", descriptor_hash: "c".repeat(64) },
    ],
    generation: 0,
    content_hash: REVIEW_HASH,
  };
}
