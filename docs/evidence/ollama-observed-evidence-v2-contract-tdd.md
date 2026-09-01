# Ollama observed-evidence v2 contract foundation — strict TDD evidence

- Date: 2026-09-01
- Revision under test: working tree based on `937f5cbf959d860a052340f18afb3415a74887ba`
- Scope: ADR-0050 correction-policy foundation only
- Result: deterministic contract layer functional; ADR-0050 remains **PARTIAL**
- Availability: `unavailable`
- Production eligibility: `false`

## Boundaries

This evidence covers pure validation of supplied ADR bytes and JSON-compatible
documents. It is not evidence of a controller, Studio v7 authority, host setup,
systemd unit installation, service lifecycle, socket operation, provider SDK,
model load, inference, cancellation, replay, pricing, or production readiness.
No network, install, service/process/socket/model operation, host-configuration
mutation, provider execution, or inference was used. After the source and
documentation bytes settled, the root publisher ran the canonical identity
generator in its supported publication environment and immediately verified
the generated allowlist in check-only mode.

## Baseline

Before creating the new package, a bounded non-native selector ran the existing
architecture, code-owned runtime registry, protocol, provider-catalog,
provider-governance, and public Harness contract tests:

```text
Ran 91 tests in 0.752s
OK
```

The selector deliberately excluded Linux process-launch/native cases and full
test discovery.

## RED → GREEN → TRIANGULATE → REFACTOR

| Task | Layer | RED | GREEN | TRIANGULATE | REFACTOR |
|---|---|---|---|---|---|
| Bind immutable ADR-0046 bytes and isolated ordered vocabulary | unit | New focused module failed import with `ModuleNotFoundError: No module named 'worldforge.provider_evidence'` | Exact byte/table validator passed | Missing, reordered, duplicate, forbidden-alias, non-table drift, type, and encoding cases | Table extraction and LF-terminated registry hashing kept separate; 14 focused methods remained green |
| Define permanent v1 disposition | unit | Canonical builder/validator did not exist | Pinned content and complete-byte vectors passed | ID/hash/type, defect, production, migration, conversion, promotion, and four registry-drift families were re-sealed and rejected | One exact canonical-byte comparison replaces loose field-by-field acceptance |
| Define corrected v2 foundation policy | unit | Canonical builder/validator did not exist | Pinned content and complete-byte vectors passed | Principal, NSS groups, custody, links/writeability, installed socket activation, cloud, loopback, proxy, device, catalog, execution, replay, and pricing drift were re-sealed and rejected | Shared JSON-only canonicalization and detached-copy validation retained 14/14 green |
| Preserve architectural isolation | unit/contract | Package and isolation proof did not exist | AST/import, two-runtime catalog, and protected-byte checks passed | Both runtime identities/revisions/protocols plus 17 protected files were checked | Pure package exports only validation data/functions; no Harness or execution dependency |

The first post-implementation run exposed two errors in the new test harness,
not in production behavior: an overbroad text search treated policy vocabulary
as an imported socket/systemd module, and one mutation helper attempted to write
through a scalar. The test checks were corrected to inspect actual imports and
direct mutations. No acceptance criterion or production policy was weakened.
Later hostile-type triangulation produced a genuine RED in the dispatcher:
unhashable list/dict `expected_format` inputs leaked `TypeError`. Exact type
validation was added before closed-literal membership and the focused method
returned GREEN.

Final focused result after refactor:

```text
Ran 14 tests in 0.062s
OK
```

The 14 methods include 65 named adversarial mutation/type/source variants in
addition to the positive canonical, isolation, identity, and protected-byte
checks.

## Pinned vectors

| Authority | Expected value |
|---|---|
| ADR-0046 raw SHA-256 | `bc4117aa580834984b4847ddb3a81180c6b14f99ba7954f1959abba8f27fbf42` |
| Ordered 86-ID LF-terminated registry SHA-256 | `518cdc4056f8d4ad3cfa9a28b08dcf2324c4b3833f4bc04fd49a9e8b2bc06ed9` |
| v1 disposition content hash | `ec2fa718852dfc55babd1de180a0e799a87e2542555b231fa88f080873c2e99a` |
| v1 complete canonical-byte SHA-256 | `b2367c785c7435d678421fe0abfff2b2a583f123081d3adfbef5255a3642b05d` |
| v2 policy content hash | `c4fbf98a52896901bb46732935a7fbef462b7369105dab5bffcff381a3968f73` |
| v2 complete canonical-byte SHA-256 | `030f2a3432efc21d3f9915cd39575e334c47b24b58770935c5105e8f5d5c1322` |

The v1 vocabulary validator parses only the table between its exact header and
terminator. The forbidden `worldforge_ollama_evidence_custody_handoff_v1`
string remains present in ADR prose but absent from the registry.

## Functional API delivered

`worldforge.provider_evidence.ollama_v2` now supplies:

- immutable ADR/vocabulary constants and `ADR0046VocabularyBinding`;
- `extract_adr0046_vocabulary_ids`, `vocabulary_registry_sha256`, and
  `validate_adr0046_source`;
- `canonical_v1_disposition_document` and
  `validate_v1_disposition_document`;
- `canonical_corrected_evidence_foundation_policy_document` and
  `validate_corrected_evidence_foundation_policy_document`;
- `canonical_ollama_evidence_bytes`, `canonical_ollama_evidence_hash`, and the
  closed dispatcher `validate_ollama_evidence_document`.

All returned documents are detached copies. Validation rejects non-exact JSON
types, missing/extra fields, malformed hashes, re-sealed policy drift, unknown
formats, and v1/v2 cross-acceptance.

## Bounded gates

### Focused plus compatibility tests

One explicit non-native selector combined the 14 new tests with the 91 baseline
architecture/contract/catalog tests:

```text
Ran 105 tests in 0.787s
OK
```

The explicit public contract-catalog compatibility selector also remained
green:

```text
Ran 28 tests in 1.455s
OK
```

### Runtime AI-import audit

```text
OK runtime=src/isoworld ai_imports=0
```

### Compilation

The new package initializer, implementation module, and focused test module
compiled successfully with `PYTHONPYCACHEPREFIX` directed to a fresh `/tmp`
directory.

### Protected byte comparison

`git diff --exit-code HEAD -- ...` reported no difference for the complete
`src/worldforge/agent_harness/` tree, public Harness source, five public Harness
schemas, and seven canonical Harness fixtures. The focused test independently
pins 17 corresponding SHA-256 values. The catalog remains exactly:

```text
worldforge_conformance_provider          revision=4 protocol=3
worldforge_deterministic_probe_provider  revision=6 protocol=3
```

Ollama is not a catalog entry.

### Identity check-only

The root publisher regenerated the canonical allowlist after final source and
documentation bytes. Generation and the immediate check-only verification both
reported:

```text
legacy identity allowlist: entries=306 occurrences=1072
```

The entry and occurrence counts remained unchanged; only generator-owned file
hashes moved to the reviewed ADR-0050-A bytes.

## Truthful remaining work

- real evidence controller: **ABSENT**
- Studio Director domain/Store/protocol/UI v7 authority: **ABSENT**
- dedicated host principal and sealed copied roots: **NOT PREPARED**
- installed socket/service units and native lifecycle evidence: **ABSENT**
- real model load/inference and observed cleanup evidence: **ABSENT**
- provider catalog/adapter, deterministic provider replay, and pricing:
  **ABSENT**

Therefore ADR-0050 is not complete and this document records no synthetic or
native Ollama PASS.
