# Codebase-memory benchmark recorded-result contracts

World Forge publishes three closed v1 documents for recording an optional,
development-only comparison of direct reads, existing memory, and a candidate
external codebase-memory index:

- `world-forge.codebase_memory_benchmark_plan`
- `world-forge.codebase_memory_benchmark_observation`
- `world-forge.codebase_memory_benchmark_report`

These contracts record supplied identities, counters, guard results, and a
deterministically evaluated decision. The evaluator does not execute a
benchmark, refresh or query an index, score content, inspect a checkout,
authorize adoption outside the report, contact a provider, or change Studio or
Harness behavior. The committed fixtures are synthetic
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

Each recorded input, output, or cached-input token counter is limited to
10,000,000. A plan permits at most 64 tasks and 64 repetitions per task, with
an additional immutable cross-task limit of 256 total trials per arm. One arm
therefore has at most 256 observations and 5,120,000,000 net tokens. With the
smallest nonzero direct-read denominator of one token, the lowest possible exact
reduction is -51,199,999,990,000 basis points; the highest is 10,000. Both the
aggregate and the multiplication performed before floor division remain within
the JavaScript-safe integer range. Evidence outside either bound is invalid
rather than partially evaluated or clamped.

Each observation's critical omission counter is limited to 1,000,000. The
largest candidate-arm aggregate is therefore 256,000,000, which is also exact
and JavaScript-safe.

## Plan

The plan binds one portable source revision and opaque tree/checkout hashes, a
sorted set of one to 64 task identities totaling at most 256 trials per arm,
and the exact three arms. Its seven
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

A report references the complete observation inventory, bounded to at most 768
references across the three arms, and records a count and deterministic metrics
for each arm plus all seven fixed gate records. Net tokens
are input plus output tokens; cached input is reported but never discounted.
Quality uses an integer arithmetic half-up mean. Latencies use nearest-rank p95.
Full and structural reduction use signed floor division in basis points. Gate
records include the measured integer or boolean, or `null` when evidence cannot
be evaluated. Each arm summary is bounded to 256 observations,
5,120,000,000 total net tokens, and 256,000,000 critical omissions.

The 768-reference cap also closes the 1 MiB report envelope. A maximum-length
canonical observation reference is 235 bytes, so all references plus their
array separators occupy at most 181,247 bytes. Even reserving 64 KiB for every
other closed report field, including the maximum bounded reason-code arrays,
the complete document remains below 256 KiB. The maximum-inventory contract
test evaluates four tasks with 64 repetitions, 768 maximum-length references,
and produces a 183,256-byte canonical report.

The pure evaluator first requires completed evidence, passed direct
verification, an available and consistent candidate identity, observed tree and
egress guards, and nonzero direct-read full and structural denominators. Missing
trust or observation evidence produces `not_evaluable` with unmeasured gates.
An explicit tree or egress failure is complete evidence and produces `reject`.
Otherwise, `adopt` requires all seven immutable gates to pass; any measured gate
failure produces `reject`. The existing-memory arm is always summarized but
never substitutes for the direct-read baseline or candidate arm.

The Python API is
`worldforge.codebase_memory_benchmark.validate_codebase_memory_benchmark_document`
for one document and
`worldforge.codebase_memory_benchmark.validate_codebase_memory_benchmark_documents`
for aggregate lineage/inventory validation and exact comparison of the supplied
report with the deterministic evaluator output for those validated inputs. A
standalone report remains locally structural; only the aggregate API establishes
its metric and decision authority. The pure
`worldforge.codebase_memory_benchmark.evaluate_codebase_memory_benchmark`
function evaluates supplied evidence without I/O and returns a canonical report.

The inert CLI accepts only explicit inputs and publishes through the secure
atomic no-replace boundary. Its output is the same compact, key-sorted UTF-8
representation used by the canonical fixture, with one final newline:

```bash
PYTHONPATH=src python -m worldforge evaluate-codebase-memory-benchmark \
  plan.json \
  --observation observation-a.json \
  --observation observation-b.json \
  --observation observation-c.json \
  --output report.json
```

It performs no directory discovery, provider/MCP import, network access, or
external command execution. A successful `not_evaluable` report is an evidence
artifact, not an adoption. No actual A/B/C benchmark has been run and no
candidate has been adopted.
