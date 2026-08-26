# ADR-0039: Deny all direct network operations in provider workers

- Status: accepted
- Date: 2026-08-26

## Context

ADR-0038 closes provider dispatch over exactly two code-owned offline workers,
but source inspection alone is not network enforcement. Before a later
parent-owned loopback gateway can be reviewed, every provider worker needs a
negative invariant: the worker and its descendants cannot directly create or
operate IPv4, IPv6, or Unix-domain sockets or enter another namespace.

The invariant must remain private. It cannot widen the public Agent Harness
records, worker protocol, fixed runtime identities, or the byte-pinned
conformance bootstrap.

## Decision

World Forge adds one private frozen `ProviderEgressEnforcementProfile` with mode
`deny_all_direct_network`. Its exact content hash binds the code-owned launcher
plan and one exact seccomp-BPF program for each reviewed native Linux identity:
`aarch64`/`AUDIT_ARCH_AARCH64` and `x86_64`/`AUDIT_ARCH_X86_64`. Every closed
runtime entry and `ProviderRuntimeSpec.egress_enforcement_hash` binds that same
profile. `network_scope` remains `none`; networked runtime specifications remain
non-executable.

Supervisor construction validates the canonical profile, catalog specification,
architecture identity, launcher and filter hashes before capturing launch
authority. A request cannot supply or replace a profile, syscall program,
endpoint, path, environment, command, or source. Ordinary later mutation of a
detached profile, selection, registry value, or specification cannot retarget
the captured authority.

The single-threaded Linux broker starts the fixed worker with `close_fds=True`,
an empty `pass_fds`, and fixed anonymous stdin/stdout/stderr pipes. The outer
exec and descriptor close start a code-owned single-threaded launcher rather
than the worker bootstrap. That launcher enumerates `/proc/self/fd`, `fstat`s
every descriptor, and fails closed if any is a socket or the census is
uncertain. Only after that proof does it install `PR_SET_NO_NEW_PRIVS` followed
by the exact seccomp-BPF filter, then exec the fixed bootstrap. No bootstrap
parsing or request-derived action can precede the census and filter.

The x86_64 filter rejects every syscall number carrying `__X32_SYSCALL_BIT`
before native syscall matching. Both architecture programs return `EPERM` for
socket creation and socket-specific operations, SCM_RIGHTS receive routes,
`pidfd_open`/`pidfd_getfd`, `io_uring_setup`, BPF, `setns`, `unshare`, `clone3`,
and `clone` calls carrying namespace flags. It permits ordinary `fork`/`clone`
and generic `read`/`write` so existing containment probes and anonymous-pipe IPC
remain valid. The direct-network invariant is therefore composite: clean launch
proves there is no socket to read or write, acquisition routes remain denied,
and seccomp plus `no_new_privs` are inherited across fork and exec. The seccomp
filter alone is not claimed to neutralize generic I/O on an existing socket.

Unsupported OS or architecture fails with the existing
`worker_containment_unavailable` boundary before provider-worker authority is
created. Child setup failure exits through the existing private generic provider
failure path before worker source executes. Raw BPF instructions, OS errors,
stderr, paths, or profile internals do not enter receipts, `AgentEventLog`, or
files.

## Compatibility

The two fixed offline runtime IDs, their revision numbers and bootstrap-template
bytes remain unchanged. The private runtime-spec and catalog hashes change
because they now bind the egress profile. Public Agent Harness schemas,
canonical fixtures, EventLog schema, worker on-wire version 1, Studio types,
the reference runtime, and the published Agent Harness byte baseline remain unchanged.

## Proven boundary

Local native Linux tests validate the immutable profile and hashes, exact-type
rejection, architecture preflight, setup-failure behavior, launch binding, and
real `EPERM` results for IPv4, IPv6, and Unix socket creation. Valid connected
IPv4, IPv6, and Unix descriptors deliberately passed to a test child are
rejected by the launcher before its action; census errors are generic and fail
before `prctl`. Pure exact-instruction simulation covers all x32 aliases on
x86_64. Native tests also prove `pidfd_open`/`pidfd_getfd` denial, filter inheritance
across fork/exec, preserved pipe IPC, and denial of namespace-changing syscalls.
Existing worker containment, runtime dispatch, governance, kernel, and EventLog
contracts remain separate gates.

## Not proven

This is not a complete OS network sandbox. In particular, it does not claim
host firewall policy, namespace isolation, same-UID filesystem isolation,
protection against hostile same-process reflection or memory corruption, vendor
telemetry behavior, a loopback gateway, or control of sockets deliberately
opened and operated by a future trusted parent outside this worker boundary. No
real provider, SDK, endpoint, credential, cloud call, Windows worker,
hosted/native release result, or production-readiness claim is added.
