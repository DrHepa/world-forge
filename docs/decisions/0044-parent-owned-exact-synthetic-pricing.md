# ADR-0044: Derive one parent-owned exact synthetic price

- Status: accepted
- Date: 2026-08-27

## Context

ADR-0042 records truthful per-metric usage provenance but deliberately leaves
all live cost unavailable. Accepting monetary values from a provider worker,
caller, mutable table, floating-point calculation, or opaque matching hash
would let an untrusted boundary choose the ledger currency or incurred amount.
The next bounded step is therefore one code-owned, non-production pricing
authority for the existing deterministic probe only.

## Decision

World Forge owns exactly one immutable synthetic pricing policy. It is bound to
the exact `worldforge_deterministic_probe_provider` runtime ID, revision and
bootstrap content hash, plus that runtime's usage-policy hash. The conformance
runtime is also an exact code-owned identity: its canonical ID, revision,
bootstrap content hash, and usage-policy hash must match, and it remains
unpriced. The closed policy uses the ISO test currency `XTS`,
denominator `4`, uncached-input numerator `2`, cached-input numerator `2`,
output numerator `3`, and rounding mode
`ceiling_at_execution_total_v1`. It is test evidence only: it is not a vendor
price, invoice, tax, discount, quote, billing rate, or freshness claim.

For cumulative recognized input `I`, cached input `C`, and output `O`, the
parent computes:

```text
N = (I - C) * 2 + C * 2 + O * 3
execution_cost = ceil(N / 4)
turn_cost = execution_cost - prior_execution_cost
```

Rounding only the cumulative execution total makes the result invariant under
turn splitting. If cached input is unavailable, the calculation is still exact
only because the registered cached and uncached rates are equal. A calculator
with unequal rates returns unavailable for that evidence and is not registered.
Once an accepted turn is unpriceable, cost remains unavailable for the rest of
the execution.

All policy fields, tokens, rates, intermediate products, sums, totals, and turn
deltas use exact built-in integers bounded by the public safe-integer limit.
Booleans, subclasses, coercion, floats, `Decimal`, negatives, denominator zero,
and intermediate overflow fail closed. No floating-point or decimal arithmetic
is used.

The live pricing transition is constructed only after `begin_execution`
returns a genuinely new durable begin. The worker must supply unavailable cost
evidence. Observed or derived worker money, including zero or the correct
policy hash and currency, never enters the ledger. Valid token evidence is
accounted and the parent derives the authoritative cost first; the execution
then fails with `provider_usage_invalid`. Token-budget breach precedes
cost-budget breach; both precede post-accounting usage-protocol failure,
availability failure, cancellation, approval/provider revocation, and nested
result validation.

Pricing identity and currency bind through runtime specification, catalog,
execution selection, governance pricing facet, private request fingerprint,
usage accounting, public receipt totals, and EventLog. A priced selection may
omit a cost ceiling; its selection currency remains exact `XTS`. When a ceiling
exists, request and selection currency must match. Matching opaque hashes are
not enough: the catalog rejects the policy if it is rebound away from the exact
deterministic-probe runtime triple, usage policy, or currency. Live catalog,
resolved-selection, and provider-accounting-lineage authority is retained only
in private identity-checked weak-reference registries keyed by exact object
identity and the hashes fixed at registration. A collection callback retires
only its exact registered weak reference, so normal completion releases entries
without letting a stale callback remove a newer same-ID registration. Authority
is not embedded as a transferable self-attesting proof in any caller-visible
dataclass. The sole root factory accepts no catalog
or specification; it obtains the closed runtime specifications and builds the
exact code-owned catalog itself. Caller-created or value-identical catalogs,
copies, subclasses, `object.__new__` clones, borrowed capability internals,
owner swaps, coherent post-registration mutation, and arbitrary lineage hashes
cannot mint authority. This is a trusted-same-process/private-module boundary;
arbitrary monkeypatching of those private registries is not claimed as an
attacker boundary. The deterministic probe must carry exactly that canonical
policy and `XTS`; stripping or replacing its pricing is invalid. Conformance
must match its exact canonical triple and usage policy while carrying no pricing
policy or currency, and any non-null pricing claim on any other runtime is
invalid.

The durable begin transaction stores a private canonical provider-accounting
lineage control record containing the resolved runtime-specification and
selection content hashes. The selection hash commits every selection,
fingerprint, and budget facet. EventLog stores a one-way commitment over the
original request fingerprint and this lineage record, while replay returns the
original fingerprint to private callers. This unkeyed commitment is a semantic
consistency linkage: it detects individual and partial lineage/accounting drift
against the accepted request row, but it is not an independent or authenticated
anchor, a MAC, or a full-store authenticity proof. Exact selection fields cannot
be reconstructed from the durable selection hash alone, so this slice does not
claim to re-authorize or recreate the complete selection during replay. In
accordance with ADR-0032, a same-UID process that coherently rewrites the whole
store, commitment, and all state/document hashes remains outside the threat
boundary. This control record is not a public `AgentEvent`, does not consume a
public event sequence, and remains in EventLog schema v3. The kernel writes it
only through a private priced-journal extension. Unpriced conformance continues
to invoke the original public `ExecutionJournal.begin_execution` signature. A
priced execution presented with a legacy journal that lacks the private
extension fails before any provider turn or action rather than omitting lineage.
Finalize and replay require the accounting runtime, selection, usage-policy,
and pricing-policy hashes to match that begin-time evidence. Every priced
finalize and replay also resolves the runtime triple, usage-policy hash,
pricing-policy hash, and `XTS` currency against the exact code-owned policy
before every stored priced turn is deterministically recomputed from its ordered
token evidence. Durable EventLog reconstruction validates the stored semantic
linkage under ADR-0032; it does not mint or emulate the live catalog-resolution
capability. Replay and exact-duplicate handling perform no live repricing or work
spawning.

Exact terminal duplicates return the existing durable bytes with zero provider
turns and zero new live pricing transitions. EventLog may verify the already
stored arithmetic, but it does not call the live pricing entry point. Legacy
v1/v2/v3 receipt-total rows remain conservative historical evidence and are
never repriced.

The provider-turn protocol remains v3, EventLog remains schema v3, and private
usage accounting remains format v1. The conformance runtime stays revision 4;
the deterministic probe stays revision 6 with byte-identical bootstrap content.
There are still exactly two runtime IDs.

## Compatibility

The five public Agent Harness v1 schemas, validators, catalog fixtures,
generated Studio types, receipt shape, `replay_support: not_claimed`, public
ports, and `src/isoworld` remain byte-identical. Existing unpriced conformance
execution remains valid through a journal implementing the prior public
signature. The deterministic probe now records an exact synthetic cost of `2
XTS` minor units for its default one-input/one-output turn with unavailable cache
evidence, and therefore requires the private journal extension.

## Proven boundary

Focused tests cover closed policy identity, exact scalar rejection and
intermediate overflow, policy mutation and catalog drift, equal/unequal cache
rates, cumulative rounding invariance, forged worker money, no-ceiling and
exact/+1 budgets, budget/control precedence, post-begin construction, terminal
duplicate zero-live-pricing behavior, EventLog accounting tamper, legacy
non-repricing, canonical-policy catalog rebinding, opaque priced-accounting
construction, stripped/replaced probe pricing, arbitrary conformance pricing or
identity drift, caller-catalog and copied-resolution rejection, removal of the
generic catalog issuer, `object.__new__`/replacement/subclass/proof-theft and
coherent-mutation attacks against catalog/resolution/live-lineage authority,
legacy public-journal compatibility, priced legacy-journal early rejection,
individual lineage drift, partial joint lineage/accounting rehash with the
accepted request row unchanged, code-owned runtime binding, and unchanged public
port/runtime/protocol identities.

## Not proven

No real provider, SDK, credential, vendor tokenizer, vendor price, invoice,
billing correctness, tax, discount, network call, Windows worker, Studio
surface, hosted run, production readiness, authenticated request-lineage anchor,
coherent same-UID rewrite resistance across all affected projections and hashes,
or resistance to arbitrary
monkeypatching of trusted module-private identity registries is added or claimed.
