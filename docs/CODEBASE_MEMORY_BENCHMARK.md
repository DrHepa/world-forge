# Codebase-memory benchmark recorded-result contracts

World Forge publishes three closed v1 documents for recording an optional,
development-only comparison of direct reads, existing memory, and a candidate
external codebase-memory index:

- `world-forge.codebase_memory_benchmark_plan`
- `world-forge.codebase_memory_benchmark_observation`
- `world-forge.codebase_memory_benchmark_report`

These contracts record supplied identities, counters, guard results, and a
declared decision. They do not execute a benchmark, refresh or query an index,
compute metrics, evaluate gates, authorize adoption, contact a provider, or
change Studio or Harness behavior. The committed fixtures are synthetic
contract examples with absent/incomplete candidate evidence and a truthful
`not_evaluable` report. No actual benchmark or adoption decision has been run.

## Closed evidence boundary

Every document is limited to 1 MiB, JSON depth 64, finite JavaScript-safe
integral numbers, closed objects, and bounded canonical arrays. Its
`content_hash` is SHA-256 over compact, key-sorted UTF-8 JSON excluding only the
top-level `content_hash` field.

Raw prompts, answers, source excerpts, transcripts, paths, hosts, URLs,
endpoints, commands, argument vectors, environment values, secrets,
credentials, network logs, and free-form errors are forbidden recursively.
Numeric input, output, and cached-input token counts are measured counters, not
secret token values. Failures and incomplete evidence use bounded canonical
reason codes.

## Plan

The plan binds one portable source revision and opaque tree/checkout hashes, a
sorted set of one to 64 task identities, and the exact three arms. Its seven
gate thresholds are immutable and repeat ADR-0026's adoption policy. Callers
cannot weaken them. Percentiles use `nearest_rank` and both tree and authorized
egress guard policies are hash-bound.

## Observations

An observation binds one planned task, repetition, and arm. Arm/source mode,
candidate availability, candidate identity nullability, state, refresh timing,
reason codes, and verification guards are locally coherent. The aggregate
validator requires exactly one observation for every planned
task/repetition/arm identity.

## Report

A report references the complete observation inventory and records supplied
per-arm summaries plus all seven fixed gate records. Contract validation checks
only structure and lineage. It intentionally does not recalculate totals,
quality, percentiles, omissions, or gate outcomes. `adopt` is structurally
permitted only when every declared gate passes without reasons; `reject`
requires a failed gate; `not_evaluable` requires a reason.

The Python API is
`worldforge.codebase_memory_benchmark.validate_codebase_memory_benchmark_document`
for one document and
`worldforge.codebase_memory_benchmark.validate_codebase_memory_benchmark_documents`
for aggregate lineage/inventory validation. Neither API performs I/O or an
adoption evaluation.
