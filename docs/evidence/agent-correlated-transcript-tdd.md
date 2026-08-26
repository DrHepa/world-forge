# Correlated provider transcript TDD evidence

- Date: 2026-08-26
- Base revision: `2eb2dd65e7e5f72966f251125f129631bdbc23b4`
- Mode: strict TDD

## TDD Cycle Evidence

| Task | Test file | Layer | Safety Net | RED | GREEN | TRIANGULATE | REFACTOR |
|---|---|---|---|---|---|---|---|
| Typed assistant-first transcript and execution-wide neutral call correlation | `tests/test_agent_correlated_transcript.py`, `tests/test_agent_execution_kernel.py` | Unit/integration | 192/192 focused Harness tests passed with real Linux permissions | Import failed because `ProviderAssistantTranscriptItem` did not exist | 6/6 new tests passed after minimum ports/kernel/protocol implementation | Multi-call order, identical requests with distinct IDs, reuse, completed-plus-calls, overflow, privacy, hostile IDs, and malformed ordering covered; 244/244 focused tests passed | Transcript sealing/correlation helpers extracted; Ruff/format and focused tests stayed green |
| Private protocol v2 and exact code-owned runtime revisions | `tests/test_agent_correlated_transcript.py`, `tests/test_agent_worker_supervisor.py`, `tests/test_agent_runtime_dispatch.py`, `tests/test_agent_loopback_gateway.py` | Integration/native Linux | Included in the 192/192 baseline | Version-2 frame assertions and typed transcript imports failed against protocol v1 | Exact v2 request/result round trips passed | v1, unknown/untyped/malformed transcript, HMAC, cross-runtime, conformance revision 3, probe revision 4, native next-turn results, loopback gateway, and socket denial covered | Canonical serializers and worker validators share exact field/order rules; 244/244 stayed green after formatting |
| Exact 128-call host/embedded protocol parity | `tests/test_agent_correlated_transcript.py` | Unit/integration/native Linux | 6/6 correlated-transcript tests passed before the review fix | 8 protocol tests produced two failures and one error: host build accepted 129, the patched host bound was inactive, and no centralized embedded token existed; both real workers already accepted 128 and rejected 129 | 8/8 protocol tests passed after adding the shared exact built-in bound to host build/parse and embedding it into both self-contained workers | Aggregate 256-record, 64 KiB transcript, and 256 KiB outer-frame boundaries remain behaviorally distinct; tuple subclasses fail closed; host and embedded mutation-sensitivity checks pass; both real workers reject 129 before the conformance action | Generated bootstrap bytes remained exact, so protocol v2, conformance revision 3/hash `581acc1e...`, and probe revision 4/hash `8d162770...` correctly stayed unchanged; 249/249 affected tests passed after focused formatting |
| Compatibility, privacy, and governance documentation | `tests/test_agent_event_log.py`, `tests/test_architecture.py`, `tests/test_contract_catalog.py`, `tests/test_identity_audit.py` | Integration/governance | Public contract/runtime bytes captured before edits | Existing arbitrary-history and completed-plus-call fakes failed under the new contract | Code-owned fakes and exact expectations were updated atomically | 77/77 governance tests passed; contract, identity, and runtime audits passed; public byte diff stayed empty | Canonical identity evidence regenerated once successfully after settled source/docs changes |

## Test Summary

- Tests added: 11 focused correlated-transcript tests with adversarial subcases, including five parity/boundary regressions.
- Focused real Linux Harness suite: 249/249 passed.
- Governance suite: 77/77 passed.
- Ruff: all `src` and `tests` checks passed; 334 files format-clean.
- Temporary compile: `src` and `tests` passed with bytecode redirected outside the checkout.
- Full discovery was intentionally stopped after 30 minutes while still progressing through unrelated multigenre asset-processing tests; no failure had been reported. The bounded affected suites above are the acceptance evidence for this slice.
