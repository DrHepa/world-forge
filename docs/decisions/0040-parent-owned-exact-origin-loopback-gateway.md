# ADR-0040: Relay one exact-origin loopback exchange through the main parent

- Status: accepted
- Date: 2026-08-26

> Supersession note: ADR-0041 advances the deterministic probe to revision 4
> and provider-turn protocol to version 2. This ADR's loopback side-band
> protocol and gateway policy remain version 1.

## Context

ADR-0039 denies direct socket creation and descriptor acquisition in every
provider worker. A local provider cannot be exercised safely by weakening that
filter or passing a connected socket into the worker. The next prerequisite is
a provider-neutral proof that one governed worker can request one bounded
loopback exchange while the trusted main parent remains the only socket owner.

## Decision

World Forge adds a frozen parent-owned gateway authority for exactly one
canonical origin: `http://127.0.0.1:<port>` or
`http://[::1]:<port>`, with port 1 through 65535. Parsing finishes before the
authority exists. The policy fixes `POST /worldforge/v1/loopback-probe`,
canonical JSON, an 8 KiB request body, 8 KiB response headers, a 64 KiB response
body, and one shared monotonic deadline no greater than two seconds. The main
parent derives a separate absolute private-turn deadline from the execution
start and `turn_timeout_ms`; every connect, write, read, and clean-EOF wait uses
the earlier of those two deadlines. Requests use only canonical `Host`,
`Content-Type`, `Accept`, `Content-Length`, and `Connection: close` headers.

The main parent creates one nonblocking `AF_INET` or `AF_INET6` socket directly
from the parsed literal and verifies the connected peer family, address, and
port. It performs no name resolution, proxy lookup, bind, listen, redirect,
retry, reconnect, pool, persistent connection, thread, caller-selected method,
path, header, URL, socket, or socket option. A valid response is exactly one
HTTP/1.1 200 response with one decimal `Content-Length`, JSON content type, a
canonical JSON body, no transfer encoding, compression, upgrade, interim or
redirect response, obs-fold, bare LF, conflicting framing, truncation,
surplus, trailer, or missing clean EOF. The gateway socket closes before any
response can be accepted by the worker boundary.

The existing broker remains the only process between worker and main parent.
The networkless worker receives only stdin/stdout/stderr pipes. A distinct
canonical side-band protocol authenticates one context, one semantic request,
and one response with the existing per-spawn key. Its HMAC binds the exact
format/version, runtime triple, spawn nonce, original provider request hash,
gateway-policy hash, sequence zero, and body hash and length. Broker control
frames bind equivalent correlation and transcript hashes. The main parent adds
a fresh unpredictable challenge to the authenticated response and derives its
exchange hash from the complete response transcript. A gateway worker final is
valid only when its authenticated envelope binds that exact exchange hash; the
broker strips the private proof only after validation and passes the ordinary
provider result onward. Thus a final emitted before the response cannot predict
the required proof. Replays, a second exchange, early final results,
prior-spawn frames, wrong runtime/policy/request bindings, overflow, and
trailing bytes fail closed.

The deterministic probe keeps runtime ID
`worldforge_deterministic_probe_provider`, advances to revision 3, and derives
its new content hash from the exact bootstrap template. The conformance worker
revision, template bytes, and content hash remain unchanged. The closed
registry still has exactly two runtime IDs. A loopback catalog is derived only
from an exact frozen gateway policy: its probe specification binds the origin,
gateway policy hash as `endpoint_policy_hash`, ADR-0039 enforcement hash as
`egress_enforcement_hash`, and a truthful code-owned no-telemetry-branch proof
as `telemetry_attestation_hash`. This is not a vendor telemetry attestation.
The selection, provider destination facet, and private execution fingerprint
therefore bind the resulting spec and catalog. The kernel accepts a loopback
catalog only through a module-private construction capability owned by an exact
`OneShotProviderSupervisor`. Before durable effects it class-validates the
capability owner and open state together with the captured policy, catalog,
selection, runtime entry, launch authority, process supervisor, and dispatch.
Issuance also installs an immutable owner-bound closure that captures the
original authority and capability object identities. Validation requires the
provider's current private slots to be those issued objects; identical
dataclass or slot copies cannot acquire provenance by preserving field values
or references. Copying the closure with a shallow provider copy does not move
its captured owner.
Protocol-compatible objects, subclasses, uninitialized instances, copied or
rebound authority records, closed or consumed capabilities, and alternate
catalogs have no network authority. Offline `ProviderPort` fakes remain valid
only with the exact code-owned catalog whose specifications all use
`network_scope=none`.

Cancellation, deadline, provider revocation, and tool revocation are polled
before connect, throughout connect/write/read, after HTTP validation, and
before relay and result acceptance. A proven-clean failure before the first
request byte may use the existing stopped or `provider_failed` handling. Once
any byte may have been sent, an incomplete or unacceptable response or cleanup
uncertainty raises `ProviderBoundaryIndeterminate`; there is no retry and no
terminal receipt, and the durable prefix remains open for offline recovery.
The exchange latches its primary result or control outcome, attempts exactly
one socket close, and resolves cleanup precedence only afterward. An uncertain
close converts an ordinary failure, stop, timeout, or success into
`ProviderBoundaryIndeterminate`; the first parent `BaseException` remains
authoritative with a bounded cleanup-uncertainty note.
One supervisor permits one active turn, and exact terminal duplicates are
resolved by durable evidence before worker or gateway effects.

Raw HTTP bytes, request and response bodies, headers, keys, nonces, paths, and
OS errors never enter receipts, the EventLog, exceptions, stderr, or tracked
files. Private transient hashes do not create a public evidence claim.

## Compatibility

The five public Agent Harness v1 schemas, contract catalog, canonical fixtures,
EventLog schema, public ports, Studio contracts, and `src/isoworld` remain
unchanged. The provider-turn protocol stays version 1; the loopback side-band
has its own private format. No workflow or dependency is added.

## Proven boundary

Bounded tests cover exact origins and built-in types, immutable policy and
catalog binding, authenticated correlation, replay and second-exchange fences,
strict HTTP framing, size limits, pre-connect zero effects, post-send
indeterminacy and privacy, timeout plus uncertain-close precedence, issuance
copy rejection, direct numeric socket use without DNS helpers, exact
governance, one native deterministic loopback exchange, immediate and delayed
pre-response worker finals, a private-turn timeout shorter than gateway policy,
an indeterminate post-send prefix that requires offline recovery,
process-domain-empty release, and terminal duplicate zero-spawn/zero-connect
behavior. ADR-0039's native worker socket-denial evidence remains a separate
gate.

## Not proven

Numeric loopback restricts the destination; it does not authenticate the
server process, prove that the server is not externally exposed, or establish
provider/model identity, billing, token accounting, vendor telemetry behavior,
credential safety, deterministic provider replay, Windows support, hosted
release evidence, or production readiness. No vendor provider, SDK, secret,
credential lease, arbitrary endpoint, Internet route, or production catalog is
added. Deliberate in-process memory corruption through
`object.__setattr__` against both the issued anchor and current slots, or direct
mutation of closure cells through implementation-specific memory techniques,
is outside this Python object-capability boundary; ordinary assignment,
deletion, copying, rebinding, subclassing, and uninitialized construction are
rejected.
