# Ordered loopback operation plan TDD evidence

- Date: 2026-08-27
- Base: `24644b42fe2cbb7c7d5bb2cd9646c4022bfb22fc`
- Mode: strict RED -> GREEN -> REFACTOR
- Scope: private Agent Harness loopback gateway, side-band, supervisor wiring,
  deterministic probe identity, focused tests, and architecture documentation

## Safety net

The initial affected command used unavailable `python`; the corrected
`python3` command ran 46 tests. Thirty-six pure tests passed and ten native
socket/process cases were blocked by the managed sandbox's `EPERM`, not by a
repository assertion. The same native paths were subsequently run on the real
Linux host.

## TDD cycle evidence

| Task | Test file | Layer | Safety net | RED | GREEN | TRIANGULATE | REFACTOR |
|---|---|---|---|---|---|---|---|
| Fixed policy and exact GET-then-POST sockets | `tests/test_agent_loopback_gateway.py` | Unit/integration | 36 pure passed; native sandbox-blocked | Policy v2, plan hash, ordinary JSON, fresh-socket order, and global-effect tests failed against v1 one-POST code | New immutable plan and sequential gateway passed | Added first-send syscall, later-step failure, hostile number/depth, raw cumulative overflow, and forbidden-helper cases | Extracted frozen step policy, connection, request, parser, and failure-normalization helpers; focused tests remained green |
| Side-band v2 cumulative proof | `tests/test_agent_loopback_gateway.py` | Unit | Existing v1 side-band tests passed | Context rejected plan fields and could not build two-step records | Context/request plan bindings and combined response chain passed | Added v1, skip, reorder, omit, surplus, duplicate, challenge-reuse, cross-plan, and terminal-chain mutations | Centralized correlation, seed/link/terminal derivation, and exact record reconstruction; focused tests remained green |
| Runtime/supervisor/worker integration | `tests/test_agent_loopback_gateway.py`, `tests/test_agent_runtime_dispatch.py` | Real Linux integration | Existing runtime registry/conformance tests passed | Revision-5 worker could not validate v2 context or terminal chain | Revision-6 worker completed exact native GET then POST and returned only after domain-empty proof | Native early-final, deadline, concurrency, terminal duplicate, privacy/open recovery, and direct-socket denial paths passed | Provider-turn v3 and conformance revision/hash stayed pinned; two runtime IDs remained exact |
| Documentation and identity | documentation/audit gates | Static | Existing docs described one POST and side-band v1 | Architecture assertions were stale | ADR-0043, README, architecture, supersession notes, and this evidence describe v2 accurately | Public-byte and identity audits cover forbidden contract drift | No public schema/catalog/fixture/generated-type or `src/isoworld` changes |
| Review C1: ordinary JSON `null` | `tests/test_agent_loopback_gateway.py` | Real Linux integration | Existing object-valued native GET-then-POST passed | Step 0, step 1, and both `null` cases each raised `provider_boundary_indeterminate` because `None` doubled as no-response state | A private unique sentinel preserves valid `null` through canonical response hashing, side-band framing, worker validation, final proof, and domain-empty return | All three ordered placements pass while existing missing-response, exception, and hostile-value tests remain retained | Replaced only the ambiguous internal state marker; public response values remain ordinary JSON |
| Review C2: complete semantic authority hash | `tests/test_agent_loopback_gateway.py`, `tests/test_agent_runtime_dispatch.py` | Unit/runtime identity | Existing plan hash covered order, step operations, and bounds only | New authority assertions failed because `ordered_plan` and semantic clusters were absent | The host and exact embedded worker mirror one closed document covering deadline, lifecycle, request, response, JSON, aggregate, effect, and order policy | Independent mutations of every cluster change plan, policy, runtime spec, catalog, and selection hashes; native exchange proves host/worker parity | Kept gateway/side-band v2, provider-turn v3, conformance rev4, probe rev6, and exactly two runtime IDs |
| Review C3: deadline anchor event | `tests/test_agent_loopback_gateway.py` | Unit/runtime seam | Existing shared-deadline and private-minimum tests passed | Frozen authority lookup failed because `deadline_policy.anchor_event` was absent | Host and worker bind the exact post-validation/post-turn-lock, pre-scratch/process anchor token | A delayed scratch seam advances beyond the two-second plan budget while the private deadline remains three seconds; unchanged `started` fails before socket creation | Reused the existing capture/pass path; no deadline reset or new clock was introduced |
| Closure C4: first HTTP header terminator | `tests/test_agent_loopback_gateway.py` | Parser/native integration | Strict status/header/length/EOF rejection tests passed | Legal leading, trailing, and interior JSON CRLF whitespace was rejected because the parser counted all `CRLF CRLF` sequences | The parser splits only the first terminator and treats every later byte solely as the exact-length ordinary-JSON body | Native GET and POST responses with repeated delimiters pass; surplus, trailer-like, header-like, obs-fold, bare-LF-header, and malformed JSON cases remain rejected | Plan/worker authority now binds `first_crlf_crlf` and header-section-only bare-LF rejection |

## Final focused evidence

After remediation sources settled:

- `PYTHONPATH=src python3 -m unittest tests.test_agent_loopback_gateway tests.test_agent_runtime_dispatch -q`: 60 passed on real Linux.
- `PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_agent_*.py' -q`: 384 passed on real Linux.
- pinned Ruff check and format-check covered all `src` and `tests`: 336 files formatted.
- single-process temporary compile, runtime/contract/identity audits, identity-generator check, protected public-byte diff, and `git diff --check` passed.
- the one settled-source canonical identity generation reported 299 entries and 1040 occurrences.

Native tests use only ephemeral numeric loopback and code-owned local workers;
they do not contact an external network or a real provider.
