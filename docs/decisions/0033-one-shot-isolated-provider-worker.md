# ADR-0033: Add a one-shot isolated provider-worker supervisor

- Status: accepted
- Date: 2026-08-25

> Supersession note: ADR-0038 preserves this conformance runtime and containment
> contract byte-for-byte while adding one second code-owned offline probe behind
> the same enum-only supervisor boundary.

## Context

ADR-0031 proves only cooperative, in-process provider turns. ADR-0032 can retain
an interrupted durable prefix, but it cannot stop provider code or prove that a
process tree is gone before accepting a result. Real provider adapters must not
be added until the parent can terminate one bounded worker domain and distinguish
a proven provider failure from uncertain containment.

## Decision

World Forge adds a private one-shot supervisor under
`src/worldforge/agent_harness/` for supported Linux hosts. Every
`ProviderTurnRequest` gets a fresh child
running one fixed, code-owned conformance runtime and may return at most one
`ProviderTurnResult`. The child receives no broker, tool, proposal, event-log,
Studio, project, asset, or release handle. Tools, proposals, budgets, the
capability broker, and durable evidence remain in the parent kernel. An exact
terminal duplicate is resolved by `AgentExecutionCoordinator` before the
provider boundary and spawns no child.

This slice has no runtime, command, module, path, environment, or shell selector.
The worker command is the absolute current Python executable followed by the
fixed arguments `-I -B -S -u -X utf8 -c` and a code-owned bootstrap. `-B` is
the authoritative bytecode-write prohibition because isolated mode ignores
`PYTHONDONTWRITEBYTECODE`; the environment value remains defense in depth for
non-isolated interpreter behavior. The runtime
content hash is the SHA-256 of the exact bootstrap template bytes before its
own hash token is substituted; it is not a descriptive-label hash. It uses
`shell=False`, `close_fds=True`, a fresh empty parent-owned scratch directory, and an
environment built from an empty mapping. The worker inherits no host environment.
Fixed telemetry opt-outs and Python process controls are added; `PATH`, `PYTHONPATH`, proxies,
cloud/GitHub variables, credentials, tokens, and provider variables are not
copied.

The Linux broker blocks on an authenticated parent-start acknowledgement and
cannot create the worker until the parent has recorded the broker PID/start-time
identity and cleanup authority. The worker then blocks at its first stdin read.
The parent/broker establishes the containment identity before an authenticated
release decision. A cancellation,
deadline, or duration signal observed by the final poll immediately before
release closes the domain without running the conformance action. Parent polling
order is cancellation, absolute deadline, total duration, then the supervisor's
private per-turn timeout. That private timeout starts before process setup and
also bounds waiting for the Linux broker's ready message.

### Private protocol

The transport is a private version-1 length-prefixed canonical JSON protocol.
The request is capped at 256 KiB, the response at 32 MiB, and stderr at 64 KiB;
any stderr byte fails the turn. Decoders reject duplicate keys, non-canonical
JSON, excessive depth, unknown/missing fields, wrong exact types, more than 256
history items, out-of-bound collections/scalars, truncation, trailing bytes, and
a second frame. The worker independently validates every authenticated envelope
and request field before selecting or executing an action. Every
spawn receives a fresh 32-byte key and nonce. HMAC-SHA256 binds request/result
correlation, the fixed private runtime triple, and SHA-256 request/result
hashes. The authenticated broker-control decoder also owns exact per-kind
payloads and built-in integer sequences; a terminal control report is accepted
only after broker exit, socket EOF, and proof that no second frame or trailing
bytes exist. Keys, raw frames, stdout/stderr, scratch paths, and private input/output
are not written to the event log or public records.

The HMAC proves only possession of the per-spawn protocol key and correlation.
It does not prove provider honesty, model identity, billing, isolation from the
same UID, or absence of vendor telemetry.

### Linux containment

The parent starts one fresh code-owned broker with Python's safe `spawn` method;
there is no persistent fork server or provider RPC process. If the standard
library starts its `multiprocessing.resource_tracker`, that process is trusted
parent-side interpreter infrastructure, not part of the provider authority or
the containment proof, and it never runs the provider bootstrap. The broker sets
`PR_SET_CHILD_SUBREAPER`, starts the fixed worker only after the parent-start
acknowledgement, and reports
an authenticated ready identity containing PID plus `/proc` start time. Before
returning a response it repeatedly submits `SIGSTOP`, observes every exact live
identity reach Linux state `T`/`t`, rescans for late descendants, then kills and
reaps the private descendant domain to a stable empty fixed point. Signal
submission uses retained `pidfd` handles tied to the verified PID/start-time
identity and `pidfd_send_signal`; there is no PID-based `kill(2)` fallback when
opening or signaling a `pidfd` is unavailable or fails. The implementation
validates `/proc` identity/state around each bound signal, closes every owned
`pidfd`, treats close uncertainty conservatively, and rescans again after
kill/reap. Signal submission alone is never freeze evidence. `/proc` identity
includes process state as well as parent PID and start time: zombie/dead roots
are not live fences, and an orphan that may have escaped such a root prevents a
proven-empty result. This covers ordinary
children, `setsid`, double-fork adoption, ignored cooperative signals, and
inherited output pipes without targeting unrelated siblings. Broker loss,
PID/start-time reuse, malformed broker control, or fixed-point exhaustion is
containment uncertainty. After broker loss the parent still freezes and kills
descendants that remain attributable to authenticated PID/start-time worker
roots, but this is best-effort cleanup only and never upgrades the result to a
proven-empty domain. The parent removes its scratch tree on success, broker
death, setup failure, and finalizer failure. Without an already latched parent
outcome, cleanup uncertainty remains containment-indeterminate. After cleanup
proves the domain empty, the first latched parent `BaseException`, ordinary
callback failure, stop, or timeout outcome cannot be replaced by a later
control-transport failure. If cleanup cannot prove emptiness, an ordinary
callback failure, stop, or timeout becomes containment-indeterminate; a parent
`BaseException` is preserved with an uncertainty note. Emergency cleanup is
total over `BaseException`.

### Platform boundary

Version 1 is Linux-only and additionally requires the Linux `pidfd` APIs used by
the containment proof. On Windows and every other unsupported host,
`OneShotProviderSupervisor` construction raises
`worker_containment_unavailable` before `AgentEventLog` durable begin, broker
activation, process creation, or conformance action dispatch. No terminal
receipt is created. The worker bootstrap accepts no process arguments, and this
slice contains no Windows `Popen`, Job Object, inherited-handle, or start-gate
backend.

Windows support is deferred and `UNTESTED`. It requires a separate reviewed
slice with a custom `CreateProcess` launcher that acquires containment ownership
at creation, before provider code can execute, plus native Windows lifecycle and
failure evidence. A Python `Popen` followed by later Job assignment is not an
acceptable ownership boundary.

### Kernel and recovery semantics

The kernel supplies a code-owned polling callback to the supervisor. A
proven-empty cancellation, deadline, or total-duration stop maps to the existing
cancelled receipt codes. A proven-empty crash, stderr/protocol violation,
response overflow, or private turn timeout maps to `provider_failed`. Provider
usage and cost enter the parent ledger only after an authenticated, proven-empty
result is returned.

`ProviderBoundaryIndeterminate` deliberately escapes the kernel's ordinary
provider-exception mapping. The kernel writes no terminal receipt or later
journal record on that path. Its already durable prefix remains open and only
an exclusive offline `AgentEventLog.recovery(...)` session may mark it
`recovery_required`; it is never resumed.

## Compatibility

The five public Agent Harness v1 schemas, catalog entries, generated Studio
types, and canonical fixtures remain byte-identical. `src/isoworld` and all
published legacy formats are unchanged. The `ProviderAdapter` port gains one
private parent-control argument; this is not a published provider wire contract.

## Proven boundary

Local Linux process tests prove a distinct worker PID, result release only after
the PID is gone, exact-terminal duplicate zero-spawn behavior, bounded protocol
failures, parent budget enforcement, cancellation/deadline/duration/turn-timeout
termination, double-fork/`setsid`/ignored-signal/inherited-pipe cleanup,
unrelated-sibling survival, timeout/stop cleanup before broker ready,
best-effort known-descendant cleanup after broker loss, abrupt-parent cleanup,
minimal environment/scratch/descriptor behavior, parent-default-deny
tool/proposal routing, authenticated parent-start gating, exact worker and
broker-control decoding, control EOF, parent-owned scratch recovery, a real
zombie-broker/adopted-orphan false-proof regression, and `/proc/self/fd`
inspection beyond descriptor 63. Broker-loss tests continue to require an indeterminate
outcome and open durable prefix; they do not claim recovery or proven
containment. Pure seams cover PID reuse, fixed-point exhaustion, cleanup
exception preservation, and fail-closed unsupported-host preflight before any
journal or process authority is acquired.

## Not proven

The conformance runtime is non-production and makes no vendor/model/provider or
billing claim. This slice does not provide a real provider adapter, same-UID
filesystem or network sandbox, vendor telemetry enforcement, secrets service,
MCP integration, durable Studio job/scheduler, Studio UI/Team Mode, memory
approval/projection, asset promotion, deterministic provider replay, Windows
worker support or evidence, or hosted/native/release evidence.
