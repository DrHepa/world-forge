# ADR-0041: Correlate every private provider tool turn

- Status: accepted
- Date: 2026-08-26

## Context

The private provider request previously carried an arbitrary tuple of JSON
history values. Tool requests had no neutral identifier, so an adapter could
not prove which ordered result answered which call when identical tool and
argument pairs appeared more than once. Hash equality is not correlation: two
intentional calls can have the same existing invocation request hash.

This private ambiguity must be removed before adding a real provider. The fix
must not publish transcripts, change durable evidence, migrate the EventLog, or
introduce a vendor-specific call identifier.

## Decision

`ProviderTurnRequest` replaces arbitrary `history` with an immutable typed
`transcript`. Each completed provider turn contributes exactly one assistant
item containing its private output and ordered tool calls. It is followed
immediately by one tool-result item for every successfully executed call. Each
result binds the same exact tool ID and mandatory `neutral_call_id` in call
order. The name is deliberate: the identifier is provider-neutral execution
correlation and is not claimed to have been issued by a vendor.

Neutral call IDs are exact built-in ASCII strings of one through 64 characters,
begin with an ASCII alphanumeric character, and otherwise use only ASCII
alphanumerics plus `.`, `_`, `:`, or `-`. They are unique across one execution.
Duplicate or reused IDs, orphan results, missing results, reordered results,
tool-ID mismatches, malformed roles, aliases, cycles, hostile scalar types, and
unknown fields fail closed. Identical tool plus argument requests with distinct
neutral IDs remain two valid calls and retain identical durable request hashes.

The kernel preflights the complete provider batch before any tool effect. A
result marked `completed=True` cannot contain a tool call. Once a batch is
accepted, the assistant item is installed before invocation; successful tool
results are appended in order. The next provider turn receives only an exact
sealed snapshot. The complete transient transcript is bounded to 64 KiB in
addition to existing depth, item, frame, turn, and private-field limits. Each
assistant item is independently bounded to exactly 128 calls; that bound is
shared by host build/parse and both self-contained workers.

The authenticated private provider-turn protocol advances from version 1 to
version 2. Its canonical request uses the exact `assistant` and `tool_result`
discriminators, and result tool calls carry `neutral_call_id`; all of these
bytes remain covered by the existing request/result hashes and per-spawn HMAC.
Version 1, untyped history, unknown fields, and cross-runtime frames fail
closed. The conformance runtime advances from revision 2 to 3 and the
deterministic probe from revision 3 to 4, each with a new exact
bootstrap-template hash. Both runtime IDs and the closed two-entry registry are
retained. The loopback side-band protocol and policy remain version 1.

Raw assistant text, call IDs, tool arguments, tool results, and transcript
frames remain transient private memory. They do not enter receipts, events,
the EventLog, SQLite, bounded public errors, stderr, or tracked evidence. The
only durable tool evidence remains the existing invocation ID, sequence, tool
ID, request hash, outcome, artifact identities, and failure codes. Terminal
duplicates remain evidence-only with zero worker, gateway, or tool effects;
open executions remain non-resumable.

## Compatibility

The five public Agent Harness v1 schemas, contract catalog and fixtures,
generated Studio types, receipt shape, EventLog schema v2, `replay_support`,
loopback side-band v1, and `src/isoworld` remain byte-identical. No workflow,
dependency, provider SDK, credential, public schema, or Studio surface is
added.

## Proven boundary

Focused tests cover assistant-first multi-call transcripts, identical requests
with distinct IDs, reuse across turns, completed-plus-calls zero-effect
rejection, exact ordering and tool correlation, malformed discriminators and
hostile types, mutation isolation, cumulative overflow, protocol v1 rejection,
HMAC and cross-runtime rejection, exact runtime revisions and bootstrap hashes,
native conformance next-turn correlation, native revision-4 loopback exchange,
direct-worker socket denial, control precedence, and terminal duplicate
zero-effect behavior.

## Not proven

This is not deterministic provider replay, a real provider/model integration,
vendor token or cost provenance, credential safety, authenticated Studio
review, Windows support, hosted release evidence, or production readiness. The
next blocker is a separate exact usage-provenance contract that distinguishes
source, observed, derived, and unavailable usage without exposing private
provider data.
