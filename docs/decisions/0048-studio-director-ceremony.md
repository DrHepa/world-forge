# ADR-0048: Main-owned Studio Director ceremony

- Status: accepted
- Date: 2026-08-31

## Context

ADR-0047 established the private durable `director_local` possession authority,
but deliberately exposed no service method, Electron ceremony, or renderer
workflow. A human therefore had no supported way to enroll or unlock that
credential, import an exact `ExecutionApprovalReview`, or prepare, decide, and
revoke its durable evidence.

Exposing the existing Studio request transport directly would put passphrases,
filesystem paths, review bodies, reviewer/outcome values, tool selections,
expiry, and compare-and-swap fields under the general renderer's authority.
That is not an acceptable security boundary. A UI that only displayed a future
workflow would not make the backend usable either.

## Decision

### Add one independent closed protocol lane

Studio protocol v6 is an additive, Director-only lane. It has request,
response, and error envelopes but no events, and exactly these ten methods:

- `service.initialize`
- `director.status`
- `director.enroll`
- `director.unlock`
- `director.lock`
- `director.review.inspect`
- `director.review.prepare`
- `director.review.approve`
- `director.review.deny`
- `director.review.revoke`

Its initialization result reports only
`authenticated_director_decisions: true`, `harness_hydration: false`,
`civil_identity: false`, and `secure_zeroization: false`. Electron requires the
exact v6 handshake after the existing v4 and v5 handshakes before declaring the
service ready. Protocol v6 neither adds methods to older versions nor changes
their schemas or generated declarations.

The protocol reuses the existing private Harness review, decision, identifier,
SHA-256, safe-integer, generation, and state shapes. It does not define a
second approval model. Requests are closed per method. The service fixes the
reviewer to `director_local`; callers cannot provide a reviewer ID or arbitrary
outcome. A stale authority transition maps to `conflict`, a missing or
unactionable state maps to `invalid_state`, malformed review/decision data maps
to `invalid_request`, and an unexpected backend failure is the generic
`internal_error`. No Python exception detail crosses this boundary.

### Keep cryptographic and storage authority in Python

Each `StudioService` owns one `StudioDirectorControl`, which in turn owns at
most one live `StudioAuthenticatedHumanDecisionAuthority`. A new service
process always starts without that live reference. Status is therefore
`not_enrolled` when the fixed credential is absent, `locked` when it exists but
there is no live authority, and `unlocked` only while the current service owns
an authenticated authority.

Enrollment and unlock accept only Unicode scalar values whose strict UTF-8
encoding is 16 through 1024 bytes, then pass the supplied string directly to
the ADR-0047 authority. The control does not persist it. Once enrollment or
unlock returns a live authority, the control returns its exact unlocked result
without a second fallible credential-status read. Lock first drops the live
authority reference and rejects subsequent review actions until another
unlock; when a live authority was present, its locked response likewise does
not depend on a second credential-store status read. Service close also drops
the live reference. This is process-local reference release, not secure
erasure of Python, JavaScript, operating-system, swap, or core-dump memory.

Review inspection, prepare, approve, deny, and revoke all execute through the
existing durable authority. The service constructs approved or denied
`ExecutionApprovalDecision` objects with the fixed reviewer and returns the
exact resulting snapshot. Generation and hash compare-and-swap fields stay
mandatory.

### Make Electron main the ceremony coordinator

`StudioDirectorAuthority` in Electron main owns the selected exact review and
current snapshot. All operations pass through one serialized queue. Lock
projects a non-authoritative locked state and clears selection and evidence
before sending its service request, so a failed confirmation cannot restore
stale unlocked actions. Enrollment and unlock instead project an explicit
unknown non-authoritative state before sending the mutation; a missing,
invalid, or timed-out reply cannot claim whether the credential mutation
committed, and recovery requires the argument-free status read. Close or any
Forge service status other than `ready` also clears the selection. A modal or
service reply that completes after such a lifecycle change cannot republish
stale UI state. These fail-closed projections do not claim that
credential-store persistence succeeded.

The native open dialog selects exactly one JSON file. Main accepts only an
absolute, non-empty, single-link regular file no larger than 256 KiB. It opens
read-only with the platform's no-follow requirement and, on POSIX, nonblocking
before the opened-handle regular-file check. It compares device,
inode, mode, link count, size, ctime, mtime, and real path before open, on the
opened handle, after reading, and after close-boundary lookup. Strict JSON and
the closed protocol-v6 review validator then validate the captured bytes. The
path is neither retained in ceremony state nor returned to the renderer.

Main derives every service request from its selected review and current
snapshot. Prepare fixes generation zero. Approve and deny use the prepared
review hash and generation zero. Revoke uses the current generation-one
decision hash. The dedicated decision modal may return only cancel, deny, or a
canonical ordered subset of the displayed candidate tool IDs plus a future
expiry. Main validates that closed reply before constructing the protocol
request.

Credential and decision collection use a dedicated modal BrowserWindow, not
the general Studio renderer. Each modal has a fresh nonce, accepts replies only
from its own `webContents`, denies navigation and new web capabilities through
the existing modal security profile, and fails closed on close, destruction,
or render-process loss. The passphrase is bounded to 16 through 1024 UTF-8
bytes and is released after the operation. The field is cleared best-effort,
but JavaScript strings cannot be securely zeroized.

### Keep the preload surface narrow and argument-free

The general renderer receives exactly eight named methods:

- `getDirectorStatus()`
- `enrollDirector()`
- `unlockDirector()`
- `lockDirector()`
- `selectDirectorReview()`
- `prepareSelectedDirectorReview()`
- `requestSelectedDirectorDecision()`
- `revokeSelectedDirectorDecision()`

The matching IPC handlers require the trusted top frame and reject every
argument. Consequently the general renderer cannot provide a passphrase,
review or filesystem path, reviewer or outcome, tool ID or descriptor hash,
expiry, generation, or expected hash. There is no generic Director RPC.

### Render the real state machine and its limits

The global React control reads status only while the Forge service is ready and
clears its projection immediately when the service is not ready. An initial
status failure or ambiguous enrollment, unlock, or lock confirmation produces
a bounded, focusable error and an unknown non-authoritative projection with no
review actions or evidence; the argument-free status method provides the
explicit refresh path. Lifecycle generation fencing prevents a stale
completion from replacing that projection.
The control exposes the real `not_enrolled`, `locked`, and `unlocked` actions;
exact selection, preparation, decision, and revocation actions appear only for
actionable snapshot states. Controls are disabled while one operation is
pending.

The selected review view shows the exact IDs, hashes, runtime revision,
budgets, deadlines, candidate tool IDs, and descriptor hashes without inventing
friendly tool descriptions. Cost ceilings are labeled and rendered as their
raw integer minor units with the exact currency code; Studio performs no
conversion or locale inference. The current decision shows its exact reviewer,
outcome, approved tool IDs, expiry, generation, and hash. Credential status,
failure, and bounded snapshot-operation result regions are announced and
programmatically focused after operations without exposing a selected path or
secret; native buttons retain keyboard semantics. The UI permanently states that the
credential is local rather than civil/legal identity, that secure zeroization
is not claimed, and that a durable decision does not hydrate or authorize the
Agent Harness.

## Compatibility

The v6 schema, generated declaration, service lane, IPC methods, and UI are
additive. Tests pin the bytes of all public Studio v1-v5 schemas and generated
declarations. Harness, public worker, EventLog, creation protocols, output
grants, and `isoworld` contracts are unchanged.

## Limitations

This increment makes the ADR-0047 authority usable from Studio; it does not
connect that authority to `AgentExecutionKernel`. It does not establish civil,
legal, operating-system, or hardware-backed identity, eliminate offline
passphrase guessing, provide secure memory zeroization, protect a compromised
main process, or add external anti-rollback evidence. Native Electron and
hosted platform evidence remain untested. This is one independent prerequisite
inside Slice 4, not completion of Slice 4.
