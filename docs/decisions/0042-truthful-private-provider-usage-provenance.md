# ADR-0042: Account truthful private provider usage provenance

- Status: accepted
- Date: 2026-08-26

> Supersession note: ADR-0043 advances only the deterministic probe to revision
> 6 and loopback side-band to version 2. Provider-turn v3, conformance revision
> 4, usage evidence, and EventLog v3 remain unchanged.

## Context

The public Agent Harness v1 receipt already contains token and optional cost
totals, but it cannot identify how those values were obtained. Treating a
provider payload, a code-owned measurement, an unavailable metric, and a future
parent-owned price as interchangeable would create false billing and cache
claims. Authenticated worker frames can also contain a valid usage section next
to a malformed result field, so validating the entire nested result before
accounting could discard incurred evidence.

## Decision

Provider protocol v3 carries exact evidence independently for input, output,
cached-input, and cost. Evidence states are `observed`, `derived`, or
`unavailable`; source kinds are closed to `provider_result`,
`code_owned_runtime`, `parent_pricing_policy`, and `none` where applicable.
Available token evidence has an exact nonnegative safe-integer value. Derived
tokens additionally bind the frozen code-owned usage-policy hash. Unavailable
evidence has no value and carries a closed reason. Cached numeric evidence may
not exceed same-turn input; unavailable cached input projects to zero recognized
cache claim. Input or output unavailability is sealed and then fails with
`provider_usage_unavailable`.

Cost and currency are jointly present or absent. Provider-originated money is a
recognized evidence shape but cannot enter the ledger. Only a future
parent-owned exact pricing policy may derive incurred money. Cost unavailability
is allowed without a cost ceiling; an active ceiling fails closed when incurred
cost is unavailable. This ADR adds no parent pricing policy.

The two synthetic runtimes use explicit code-owned one-unit measurement
policies. Those policy documents are hashed into runtime specification,
catalog/selection resolution, governance, and the private request fingerprint.
Conformance advances to revision 4, the deterministic probe to revision 5, and
the authenticated provider protocol to v3. Loopback side-band v1 is unchanged.

After outer frame authentication, execution correlation, runtime binding, and
result-hash validation succeed, the host parses usage separately. The kernel
validates and appends one turn atomically, projects recognized totals, then
applies token/cost breaches and required-availability failure. Cancellation,
deadline, provider/tool revocation, and remaining nested result validation
follow. Therefore valid usage beside a malformed sibling remains accounted,
while invalid outer authentication/runtime/hash evidence salvages nothing.
Selection and policy hashes remain fixed for all turns.

Private `AgentEventLog` schema v3 adds exactly one canonical, hash-bound
`usage_accounting` document for every terminal receipt. Finalization inserts
accounting, receipt, terminal event, and execution state in one transaction.
Replay cross-checks execution ID, receipt hash, and all recognized token and
cost totals. Exact terminal duplicates require byte-identical accounting and
perform no provider, tokenizer, or pricing work. Open and
`recovery_required` executions have no terminal accounting.

The durable document contains only the record mode, closed evidence
states/sources/reasons, safe values, ordered turn index/count, approved opaque
runtime/selection/usage/pricing hashes, recognized totals, receipt hash, and its
canonical content hash. It excludes raw provider payloads and usage objects,
headers, request IDs, transcripts, tool data, endpoints, paths, credentials,
errors, and unsanitized payload hashes.

Ordinary exact v1/v2 stores migrate transactionally to v3. Each legacy terminal
receipt receives `legacy_receipt_totals` accounting without relabeling its old
totals as observed. Detached recovery accepts v1/v2/v3 logical images without
opening, migrating, checkpointing, or changing original main/WAL/SHM/journal
bytes; legacy accounting is synthesized only in detached read semantics.

## Compatibility

The five public Agent Harness v1 schemas, validators, catalog rows, fixtures,
generated Studio types, receipt shape, and `replay_support: not_claimed` remain
unchanged. Receipt usage fields are recognized/accounted ledger totals, not
measurement truth. Cached zero can mean no recognized cache claim, not observed
absence of caching. Null cost/currency means no recognized cost claim, not zero
cost. No cache rate, vendor honesty, billing correctness, or provider telemetry
claim is made.

## Proven boundary

Focused tests cover closed evidence coupling and hostile scalar types, mixed
multi-turn projection, unavailable and numeric cached evidence, budget and
cancellation precedence, malformed nested siblings, outer-authentication
rejection, exact duplicate accounting, legacy migration/recovery, v3 row/hash/
receipt tampering, schema and atomic-fault behavior, raw-sentinel privacy,
protocol/runtime identity pins, and loopback/conformance execution.

## Not proven

No real provider, SDK, credential, vendor tokenizer, parent pricing, invoice,
cache effectiveness, Studio surface, Windows worker, hosted run, or production
readiness is added or claimed. Parent-owned pricing is the next separate slice.
