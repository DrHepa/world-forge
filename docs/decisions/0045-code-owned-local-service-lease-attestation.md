# ADR-0045: Attest one code-owned local-service lease

- Status: accepted
- Date: 2026-08-29

## Context

ADR-0040 and ADR-0043 prove that the main parent can execute one fixed ordered
loopback plan against an already selected exact numeric origin. They do not own
the server behind that origin, prove which process holds its listener, or prove
that the process domain and listener are gone before the provider turn returns.
Accepting a caller URL, command, environment, callback, service specification,
or health payload as execution authority would recreate those gaps.

The next bounded step is therefore one neutral synthetic conformance service.
It must exercise the existing parent gateway without adding a real provider,
model, SDK, credential, vendor protocol, or production endpoint. Because the
Agent Harness package is public and portable, merely importing it must not
dereference Linux-only CPython, pidfd, signal-mask, or libc symbols.

## Decision

### Portable preflight and immutable Linux authority

`OneShotProviderSupervisor.for_local_service` is the sole root factory. It
accepts only the exact governed deterministic-probe selection and a bounded
timeout. An exact platform/runtime/type preflight rejects unsupported hosts and
subclasses before policy, catalog, journal, scratch, listener, process, or
provider action. Caller origins, ports, commands, environments, factories,
callbacks, modules, service documents, and URLs cannot mint this authority.

Portable module definitions use numeric Linux constants where needed and do not
load `_posixsubprocess`, pidfd, pthread signal-mask, or `libc.prctl` authority.
After the closed preflight, a lock-guarded loader admits only Linux CPython 3.12,
resolves the required native symbols once, verifies their exact types, names,
constants, function-pointer address and ABI, and freezes one per-process
authority object. Concurrent callers receive that exact object. A missing,
replaced, or mutated dependency fails closed; it cannot synthesize a degraded
policy.

The immutable launch policy hashes the fixed service revision, bootstrap and
runtime bytes, isolated `-I -B -S -u -X utf8 -c` argv, exact four-key
environment, descriptor/filter contracts, and the executable launch authority.
That authority includes the parent-death installer and factory code, complete
typed default/keyword-default/closure/transitive-dependency fingerprints, the
single-thread checker, the audit and low-level `_fork_exec` contract, relevant
CPython `Popen` class/dependency state, the native `prctl` pointer/ABI, the
private pidfd process-handle class, and the signal-mask policy. Fingerprints use
explicit type tags, canonical bytes, deterministic unordered-container order,
and recursion/cycle handling so value-shape substitutions cannot collide.

The deterministic-probe catalog entry binds that stable policy hash while
retaining its existing runtime ID, revision, and bootstrap content hash. The
closed factory also issues one identity-registered concrete recipe. Its
immutable snapshot binds the exact policy identity, executable path/realpath,
device/inode/mode/size/mtime/content hash, absence of file capabilities, exact
bootstrap, argv, environment, launch/custody hashes, descriptor census, network
filter, and self-test. Setuid, setgid, and `security.capability` executables are
rejected because a privilege-changing exec could clear `PDEATHSIG`.

Policy, recipe, lease, capability, and attestation registries require exact
issued object identities and canonical full-field snapshots. Copies,
subclasses, `object.__new__` forgeries, owner swaps, mutation, and replay fail
closed. Per-turn PID, start time, port, inode, nonce, key, and readiness evidence
remain private and never enter a public schema, EventLog record, or durable
request fingerprint.

### One-use lease and low-level launch

For each genuinely new provider turn, the parent binds and listens on one fresh
`127.0.0.1:0` socket and retains that handle until cleanup is proven. There is
no hostname, DNS, wildcard, fixed port, alternate address, attach, reuse,
fallback, restart, retry, or recovery path. Exact terminal duplicates return
existing durable evidence before provider dispatch and therefore perform no
bind, spawn, connect, or cleanup.

The existing spawn-context subreaper broker launches the fixed service lazily,
after the socketless worker asks for its gateway operation. Before checking its
thread census, the broker blocks every catchable signal and captures the exact
prior mask. It then proves the expected PID, one `/proc/self/task` entry, and no
active Python trace or profile callback. The broker precomputes the exact argv,
environment, cwd, stdin/stdout/stderr pipes, inherited descriptors, and exec
error pipe.

The launcher emits the standard `subprocess.Popen` audit event before creating
the pre-exec closure or private process handle. When every synchronous audit
callback has returned, it repeats the PID/thread/trace/profile fence and
revalidates the exact captured low-level, pidfd, signal-mask, native `prctl`,
custody-factory, and process-handle dependencies. Only those validated local
references and precomputed immutable values remain live. It then constructs the
fixed closure and invokes the captured CPython 3.12
`subprocess._fork_exec` directly; Python `Popen.__init__` and
`Popen._execute_child` are not executable launch authority.

In the forked child, before exec, the closure makes exactly
`prctl(PR_SET_PDEATHSIG, SIGKILL)`, immediately compares `getppid()` with the
captured broker PID, exits with the fixed failure code if the parent already
changed, and restores the exact pre-launch signal mask through the validated
signal-mask authority. The broker restores its own exact prior mask in a
guaranteed `finally`. The captured `_fork_exec` error pipe proves the pre-exec
and exec handshake. Immediately after the returned PID, the broker opens a
pidfd before accepting the spawn.

The minimal private process handle owns that pidfd and the output streams. It
polls and waits with `waitid(P_PIDFD, ...)`, signals only with
`pidfd_send_signal`, retries EINTR, interprets only the closed Linux wait
statuses, and makes descriptor closure/reaping idempotent across exec failure,
timeout, kill, normal completion, external reap, and destructor cleanup. It
never falls back to raw-PID signaling or global child reaping.

### Pre-secret proof and authenticated handoff

The child inherits exactly stdin `/dev/null`, stdout/stderr pipes, the listener,
one initially empty configuration pipe, and one readiness pipe. Before any
configuration or HMAC key can cross the empty pipe, the broker proves through
`/proc` the exact live PID/PPID/start identity, executable metadata and bytes,
NUL-delimited cmdline, root, scratch-directory cwd device/inode, complete six-FD
set, targets, and access modes.

The fixed bootstrap first requires its exact four-key `os.environ` and descriptor
census. It then performs `prctl(PR_GET_PDEATHSIG)`, reads its current
PID/PPID/start and `/proc/self/status` `SigBlk`, and sends one exact bounded
pre-configuration frame over the already-attested readiness pipe. The broker
accepts only the expected `SIGKILL`, PID/PPID/start, and restored prior signal
mask. Because the fixed bootstrap checks environment and FD state before
writing that frame, accepting it also proves those checks ran before secret
release.

After this proof, the broker retains the exact PID/start identity and sends one
authenticated handoff to the main parent. The main parent re-reads the live
broker relationship, retains its own pidfd for that exact identity, records the
identity in the fixed-point cleanup domain, and returns an authenticated
PID/start acknowledgement. Only then may the broker write the nonce-bound
configuration and HMAC key. Kernel parent-death custody therefore covers every
post-spawn window, including a stopped child before proof, and main-parent pidfd
custody covers the post-handoff window. Broker death before this fence remains
`ProviderBoundaryIndeterminate` even if `PDEATHSIG` removes the service.

After configuration, the child rechecks its signal mask, cwd, root, listener,
and recipe-bound values, installs `no_new_privs` plus the architecture-pinned
seccomp-BPF policy, and performs its denial self-tests. The canonical HMAC
readiness record binds the fresh nonce, policy and recipe hashes, bootstrap,
runtime, exact environment through the recipe, network filter, descriptor
census, self-test, service revision, signal mask, PID/PPID/start, root/cwd, and
listener FD/inode/IPv4 tuple. The main parent pins every parsed field to the
exact lease/recipe/policy identities and revalidates the live pidfd, process,
root/cwd, listener descriptor, and `/proc/net/tcp` ownership before gateway use.

### Gateway and cleanup boundary

The service recognizes only the existing bodyless GET followed by canonical
JSON POST on `/worldforge/v1/ordered-loopback-probe`, using strict ordinary
HTTP/1.1 framing and fixed neutral responses. The socketless worker receives no
origin, lease, listener, key, nonce, PID, or service authority. Only the main
parent derives the ephemeral numeric origin and connects through the existing
governed gateway plan. Service liveness and listener ownership are composed
with every gateway boundary poll.

The service remains in the existing subreaper cleanup domain. Only identities
retained from an exact process-table PID/start observation with their own pidfd
may enter its signal set. Cleanup repeatedly freezes, rescans, signals through
retained pidfds, reaps, and proves a fixed point across escaped sessions and
descendants; it never downgrades to process-group-only or raw-PID cleanup.

Listener-inode discovery is observation-only absence evidence. It scans every
plausible live same-UID process regardless of whether it started before the
broker, but possession of the inode never grants tracking or signal authority.
An inaccessible process, changing PID/start observation, or observed holder
makes the absence proof false/indeterminate. The parent closes its retained
listener only after exact domain-empty and listener-absent proof.

A proven-clean crash, cancellation, timeout, or closed pre-send failure may
remain an ordinary stopped or provider-failed result. Broker loss before
fencing, any possible request send, accepted-response ambiguity, ownership
drift, pidfd uncertainty, inaccessible listener candidate, or incomplete close,
reap, fixed-point, or absence proof is indeterminate and leaves the durable
EventLog prefix open for offline recovery. Cleanup never replaces an already
latched cancellation, timeout, or boundary classification with a weaker result.

## Compatibility

The five public Agent Harness v1 schemas, public ports, Harness v1 validators,
EventLog schema v3, provider-turn protocol v3, loopback side-band v2, worker
bootstrap/protocol, Studio, generated types, and `src/isoworld` remain
byte-identical. The conformance runtime remains revision 4 and the deterministic
probe remains revision 6; there are still exactly two runtime IDs. Only private
local-service policy, recipe, lease, launch, attestation, handoff, and cleanup
authority is added.

## Proven boundary

Native local-service execution evidence is Linux `aarch64`, CPython `3.12.3`,
`/usr/bin/python3` only. Focused evidence includes 48/48 local-service tests,
227/227 combined provider-path tests, 124/124 kernel/contract/architecture
tests, and 17/17 worker-egress tests. It covers authority mutation before and
after the audit callback; exact `prctl` success/failure/PPID-race behavior;
parent-death and signal-mask proof; executable, cwd, environment, FD and
readiness attestation; immediate pidfd lifecycle and EINTR; stopped child and
broker-death windows; unrelated, inaccessible, older and PID-reused listener
holders; latched cleanup branches; bounded private Pipe cleanup; terminal
duplicates; privacy; and protected public bytes.

Clean subprocess tests simulate `sys.platform == "win32"` and `"darwin"` while
removing Linux-only attributes before import. They prove portable imports and
pre-side-effect unsupported rejection only; they are not native Windows or
macOS execution evidence.

## Not proven

Python 3.11, native x86_64, actual Windows or macOS execution, hosted CI, full
test discovery, real providers/models/inference, SDKs, credentials, vendor
APIs, telemetry-zero guarantees, Internet routes, hostname policy, general
filesystem or same-UID isolation, Studio/CLI/UI exposure, restart, retry,
attach, reuse, recovery, or production readiness is implemented or claimed.
Every such item remains `UNTESTED` or `PENDING`, never skipped or passed.
