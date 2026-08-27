# ADR-0043: Execute one fixed ordered loopback operation plan

- Status: accepted
- Date: 2026-08-27

## Context

ADR-0040 proved one parent-owned synthetic loopback POST while every provider
worker remained socketless under ADR-0039. A real local-provider protocol needs
ordered operations, but accepting caller- or worker-selected methods, paths,
headers, URLs, parsers, retries, or socket behavior would create a generic HTTP
tunnel. The next safe slice is therefore a single neutral plan whose complete
shape is owned by reviewed code.

## Decision

The gateway policy advances to version 2 and binds one immutable two-step plan.
Step 0 is `GET /worldforge/v1/ordered-loopback-probe` with no request body,
`Content-Type`, or `Content-Length`. Step 1 is `POST` to the same path with the
worker's bounded canonical semantic JSON and exact JSON content type and length.
Both requests use only the code-owned numeric-loopback origin, `Host`, `Accept`,
and `Connection: close`. There is no caller- or worker-selected operation data,
DNS, query, redirect, retry, reconnect, pooling, socket option, or alternate
parser.

The plan hash binds one closed canonical authority document: exact order and
step policies; aggregate bounds; the shared two-second absolute-deadline rule;
fresh sequential parent-owned nonblocking sockets and close-before-next/relay
lifecycle; zero retry/reconnect/pool/redirect/DNS/proxy/bind/listen; exact
request line, ordered headers and value-generation rules; accepted response
version, status, content type, single length and clean EOF; every forbidden
framing/encoding/upgrade/interim/redirect form; ordinary-JSON decoding and
canonicalization rules; and the plan-global first-send latch. The embedded
worker contains the exact same closed document. Existing runtime specification,
catalog, selection, governance, fingerprint, issuance, and supervisor
authorities bind the resulting plan and gateway-policy hashes.

The main parent opens two fresh nonblocking sockets sequentially. It closes and
proves cleanup of step 0 before creating step 1, closes step 1 before relay, and
never retries. A plan-global `effect_possible` latch is set immediately before
the first send syscall attempt and is never reset. Before that transition,
proven-clean failure retains the existing stopped or provider-failed semantics.
After it, every later stop, timeout, revocation, connection failure, malformed
response, or cleanup uncertainty is indeterminate and leaves the durable prefix
open for offline recovery. All waits share the earlier of the fixed plan
deadline and the private turn deadline. The monotonic plan anchor is captured
by process-supervisor `execute` after exact authority validation and acquisition
of the nonblocking turn lock, but before scratch creation or any process setup;
setup therefore consumes the same budget and gateway entry never resets it. A
first non-ordinary `BaseException`
remains authoritative and receives only a bounded cleanup/indeterminacy note.

Each response must be exactly one close-delimited HTTP/1.1 200 response with one
decimal `Content-Length`, JSON content type, no transfer/content encoding,
upgrade, interim or redirect response, obs-fold, bare LF, trailer, surplus,
truncation, or missing EOF. Ordinary UTF-8 JSON is decoded before internal
canonicalization. Duplicate keys at any depth, non-finite or overflow numbers,
unsafe integers, depth above 64, and per-step or aggregate overflow fail closed.
JSON `null` is an ordinary valid response at either step; a private unique
sentinel, never `None`, distinguishes missing response state.
The parser consumes only the first `CRLF CRLF` as the HTTP header terminator.
Later identical byte sequences belong exclusively to the exact-length body and
may be ordinary JSON whitespace; they never reopen header parsing. Bare LF and
obs-fold remain forbidden in the header section, while surplus bytes,
trailer-like text, or header-like body text must still pass exact length and
ordinary-JSON decoding or fail closed.

The loopback side-band advances from version 1 to version 2. Context and request
bind the exact policy, plan hash, and count two. The parent returns exactly two
ordered step records. Every record binds its index, step-policy hash, request
body presence/hash/length, canonical response body/hash/length, a fresh
post-close parent challenge, prior chain value, transcript hash, step HMAC, and
cumulative HMAC. The terminal chain HMAC binds the plan, count, completed count,
order, and final cumulative link. The worker's authenticated final proof equals
that terminal chain value. Version 1, skip, reorder, omission, surplus,
duplication, replay, cross-plan/runtime/spawn frames, challenge reuse, chain
tampering, early/intermediate final results, and trailing frames fail closed.

The deterministic probe advances from revision 5 to revision 6 with a new exact
bootstrap hash. Provider-turn protocol v3, conformance revision 4 and its hash,
the two existing runtime IDs, public contracts, EventLog/usage semantics, public
ports, Studio, `src/isoworld`, and worker socketlessness remain unchanged.

## Compatibility

The five public Agent Harness v1 schemas, catalog rows and fixtures, generated
Studio types, receipts, EventLog v3, public ports, and `src/isoworld` are
byte-identical. No workflow, dependency, provider SDK, credential, or real
provider is added.

## Proven boundary

Focused pure and real-Linux tests cover the frozen plan/hash, exact GET-then-POST
bytes and fresh sockets, ordinary JSON and hostile decoding, per-step and
aggregate bounds, authenticated cumulative-chain mutations, first-send and
later-step indeterminacy, control boundaries, cleanup precedence, native
deterministic execution, terminal duplicates, concurrency, privacy/recovery,
direct-worker socket denial, governance/fingerprint drift, exact runtime pins,
and public-contract immutability.

## Not proven

Two numeric-loopback connections do not authenticate a server process, prove
that both connections reached the same process, prevent rebinding between
steps, prove that the listener is not externally exposed, or establish provider
identity. No real provider, SDK, credential, vendor telemetry, billing,
Internet route, Windows worker, hosted result, atomic remote transaction, or
production-readiness claim is made. Parent-owned local-service lifecycle and
listener/process attestation remain separate prerequisites.
