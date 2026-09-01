# ADR-0049: Durable Studio approval binding for Agent Harness execution

- Status: accepted
- Date: 2026-09-01

## Context

ADR-0047 created the authenticated durable `director_local` decision authority,
and ADR-0048 added its main-owned Studio ceremony. Neither authority could be
supplied to `AgentExecutionKernel`: the kernel accepted only the exact
in-memory authority class.

## Decision

The private Harness approval module defines one narrow nominal
`ExecutionApprovalAuthority` port containing only the execution-facing
operations `prepare`, `snapshot`, and `check_snapshot`. Decision, revocation,
credential enrollment, unlock, SQLite ownership, passphrase processing, and
HMAC custody remain Studio-owned. The in-memory authority and
`StudioAuthenticatedHumanDecisionAuthority` explicitly implement this port.
Only fully initialized exact instances created by those two code-owned paths
enter a weak identity capsule. Its synchronized registry is closure-owned; no
module attribute exposes the mutable mapping. The only registration closures
independently require the exact canonical class, constructor/completion caller,
and method/function/code identity, so importing or calling them does not admit
arbitrary objects. A copied, subclassed, uninitialized, lookalike, injected, or
owner-swapped object has no authority. Closure custody also retains exact
construction-state identity anchors for each weakly held authority and rejects
later Store, credential, event-key, connection, lock, or in-memory state-owner
replacement before use. Those anchors do not retain the authority itself.
Constructor code, canonical authority functions, function derivation, Studio
provenance consumption, registry validation, and binding construction are
captured inside the custody closure. The closure also captures the exact frame
accessor, weak-reference factory, identity/type/object operations, collection
predicates, namespace lookup, and function/method/binding constructors used by
those paths. Same-named imported-module globals are diagnostics or private
integration entrypoints, not live trust inputs.

Kernel construction is itself closed over the exact capsule binder before any
later module-alias replacement. The returned frozen binding owns an exact
validation closure bound to that binding identity and its registered owner;
the kernel has no separately assignable live validation hook. It retains the
binding's captured execution methods, so later module or binding-class
replacement cannot disable live custody checks.

The Studio class's ordinary constructor is closed. Enrollment and unlock first
build one exact unregistered provisional instance through a caller-checked
module-private path. Only after the complete credential/chain/projection audit,
successful transaction completion, and anchor publication does a synchronized
closure issue and immediately consume a one-time capability bound to that exact
instance, Store, credential-evidence object, and event-key object. Registration
follows that consumption. Equal substitute credential or key objects do not
satisfy the identity binding, and registration failure retires the pending
capability. The capability is not stored on the authority, exported, logged,
serialized, copied, or reusable. Direct construction with a persisted
credential and caller-selected event key therefore cannot seed an authenticated
chain.

Studio's public construction descriptors retain the exact provisional,
completion, and registration closures created during module initialization.
Their construction capsule retains the exact frame accessor and the identity,
type, length, object-allocation, token, and exception primitives used for
admission and completion. Each descriptor stores the exact bound-entrypoint
factory it received at module initialization. Replacing same-named module
globals therefore cannot substitute a provisional instance, forge the caller,
skip capability consumption, or make enroll/unlock return an unregistered
authority. A registration failure after capability consumption retires that
token, returns no authority, and requires a fresh Store open/unlock attempt.

Kernel construction captures exact owner-bound methods and their function/code
identity. It revalidates custody before every use, rejecting instance or class
method replacement rather than dynamically dispatching through it. Registry
entries do not retain authorities strongly.

Every review, snapshot, and authorization check returned through the port is
revalidated as the existing exact immutable Harness value and semantically
bound to the kernel-minted review before use. Prepare must return that exact
review. A snapshot must bind its exact review hash and, when present, the exact
review and decision. An authorization check must bind the frozen review hash,
decision hash, approved ordered tool subset, approved state, and unexpired
decision at the exact checked time. Structurally valid cross-approval evidence
is corruption, not authority. The
kernel captures one authority snapshot before calculating private request
fingerprint v3. That fingerprint continues to bind the exact review and
decision hashes without adding either document, a reviewer label, credential
material, Store identity, passphrase, or HMAC key to worker messages, public
schemas, activation/grant documents, receipts, or EventLog projections.

For a tool-bearing execution, `check_snapshot` now runs immediately before
`journal.begin_execution`. The kernel retains the same immutable snapshot and
checks it again after a successful begin and at every existing provider/tool
effect boundary. A decision arriving after the snapshot is not adopted, while
a revocation committed between the pre-begin and post-begin checks is observed
before provider or tool effects. Exact terminal duplicates still use the
existing durable-begin/coordinator replay path; a later revocation cannot erase
or re-execute immutable terminal EventLog evidence.

Studio main may construct or unlock the durable authority and pass that live
object directly into a same-process kernel constructor. Workers receive only
their existing closed protocol frames. A restart must reopen `StudioStore`,
explicitly unlock the Director credential, and construct a new kernel. Each
durable `check_snapshot` audits a current SQLite transaction, so commits made
through another connection or process are observed at the next boundary
without sending Store or cryptographic state to workers.

## Compatibility

This is a private backend binding. Agent worker, EventLog, activation, grant,
receipt, Studio public protocol, generated declaration, and `src/isoworld`
bytes are unchanged. Private request fingerprint format v3 is unchanged.

## Limitations

This increment does not add a general Studio execution service, automatic
per-execution hydration, a new receipt proof, separate-process kernel
isolation, socket transport, provider execution, native Electron evidence, or
hosted evidence. A receipt alone cannot reconstruct Director review/decision
evidence; explanation requires the private EventLog fingerprint together with
the authenticated Studio authority store and the exact request/tool catalog.
The Studio main process and trusted module code remain inside the authority
boundary. Capturing ordinary imported-module aliases is not interpreter
isolation: Python reflection that can rewrite closure cells, invoke arbitrary
`object.__setattr__`, or otherwise control a fully compromised same-process
interpreter is not claimed to be prevented.
