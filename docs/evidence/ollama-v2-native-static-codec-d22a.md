# Ollama v2 D2.2a static codec/build evidence

- Scope: probe-only C17 codec and reproducible Linux/aarch64 static build identity
- Result: `codec_implementation_state: built`
- Authority boundary: `effect_interpreter_state: absent`
- Availability: `availability: unavailable`
- Production: `production_eligible: false`

## Behavior exercised

The two project-authored MIT-licensed probes accept only a connected
`AF_UNIX/SOCK_SEQPACKET` endpoint on standard input. The initiator sends one
fixed `NEGOTIATE` record and closes its write direction. The responder requires
that EOF before returning one fixed `UNAVAILABLE_TERMINAL` record and closing
its write direction; the initiator requires the final EOF. Neither record can
encode an effect, method, path, argv, environment, provider request, service
operation, or filesystem mutation.

The negotiation body is also self-describing: `negotiate_type` at body offset
16 is `1`, `unavailable_type` at body offset 18 is `2`, and `message_count` is
`2`. Lock-driven golden and real-process tests bind every negotiation and
terminal body field to the checked-in protocol lock, both encoders, and both
decoders.

EOF is accepted only when `ppoll` reports `POLLRDHUP`/`POLLHUP` and `recvmsg`
observes no record data, `MSG_EOR`, credentials, rights, or other ancillary
state. A zero-length `SOCK_SEQPACKET` record is therefore rejected both before
and together with peer shutdown, in either transcript direction.

Both launcher endpoints enable `SO_PASSCRED` before the children start. Each
probe reasserts it, receives exactly one `SCM_CREDENTIALS`, rejects and closes
all `SCM_RIGHTS`, rejects truncation and ancillary drift, and uses timerfd plus
`ppoll` against an absolute `CLOCK_BOOTTIME` deadline. `SO_PEERCRED` and message
credentials are retained as separate launcher observations; they are
observational only, not authentication, and are never compared as an
authorization test.

The random nonce, packet chain, deadline, and hashes detect malformed or
misordered records within this one transcript. The protocol has no secret or
durable state and therefore does not prove replay protection, peer
authentication, installation custody, or dispatch authority.

## Build evidence boundary

Checked-in protocol and source locks are verified without invoking the driver.
The exact build profile is validated against one immutable module-level field
vector on every construction; parser acceptance is therefore independent of
whether the canonical factory has run, call repetition, or concurrent order.
The source manifest must exactly equal the fixed ten-entry path/role census;
missing, extra, relabelled, reordered, or case-aliased entries fail before a
driver query. All ten canonical source entries remain open by verified
descriptor, and both clean build roots are materialized exclusively from retained bytes. The original named paths, retained descriptors, identities,
and bytes are checked again after driver queries, after each build, and
immediately before publication. Deleted, replaced, in-place modified, and
replace-then-restore test fixtures all fail without publishing an archive.
Authoritative publication requires direct source-file execution of
`scripts/build_ollama_v2_native.py`. Normal import, `-m`, run-path, cached, and
sourceless entry modes cannot publish. The driver loads the build-contract
`.py` with a source-only loader: it opens the exact regular file without
following symlinks, reads the bytes, and compiles and executes those bytes
directly. It does not consult cached bytecode. Timestamp-valid, checked-hash,
unchecked-hash, stale, and malicious marker pyc fixtures are ignored.

The active build-driver and build-contract source bytes, SHA-256 digests,
module objects/specifications, absolute origins, and path identities are
frozen. Before any driver query, the retained canonical `build_driver_source`
and `contract_source` entries must match those active bytes and hashes exactly.
A copied source root is accepted only when those two declared files are
byte-identical to the active implementation; a fresh byte-identical copied
tree also runs its own source-file CLI successfully. Active module origins and
source identities are checked again immediately before publication, so a late
replacement cannot publish an output.

The 126-entry toolchain role/path census is independently bound by the
canonical build profile and must also match exactly before a query. The
inventory identities are respectively
`7f4a7ac2ed2c5a5c892abddf0fedb87689cacd29fdd1cd735fed75ac92682100`
and `acdb15daa9f8e16853a78fcda554629af82405df19ecf4273b7ef07c87df0331`.
Locked executable and input bytes are verified before the first driver query.
Driver-reported built-in specs are verified after that query and before compilation.
Every canonical toolchain file is opened without following symlinks and retained
by descriptor. Each file and every ancestor in its canonical path must be
root-owned and not group/world-writable on this local reference host. The GCC
driver is executed through its retained `/proc/self/fd/<n>` descriptor with its
canonical path as `argv[0]`. All toolchain path identities and bytes are checked
again after the driver queries, after each of the two builds, and immediately
before publication.

Before the first driver query, a bounded stdlib ELF parser resolves the five
executed tool binaries, driver-reported `lto-wrapper`, and linker-loaded
`liblto_plugin.so` through their complete declared direct and recursive
`DT_NEEDED` graph. The fourteen exact runtime providers are the dynamic loader,
libc, libisl, libmpc, libmpfr, libgmp, zlib, zstd, libopcodes, libbfd, libctf,
Jansson, libm, and libsframe. The exact `/etc/ld.so.cache` bytes are a separate
locked input, every used cache entry must resolve to the declared canonical
provider, and RPATH, RUNPATH, dynamic audit/filter tags, `LD_PRELOAD`,
`LD_AUDIT`, `LD_LIBRARY_PATH`, and `/etc/ld.so.preload` are rejected. The same
resolution is repeated with the byte/identity checks after queries and builds.

A separate bounded GNU ld-script parser accepts only the fixed
`OUTPUT_FORMAT`, `GROUP`, `INPUT`, and nested `AS_NEEDED` grammar plus safe
absolute, relative, and `-l` references. It resolves through the fixed local
search policy, rejects unsupported syntax, ambiguity, omission, relabelling,
or drift, and requires every selected regular file in the exact census. The
newly explicit roots are
`/usr/lib/gcc/aarch64-linux-gnu/13/libgcc_s.so` and the existing
`/usr/lib/aarch64-linux-gnu/libc.so`; their closure includes
`/usr/lib/aarch64-linux-gnu/libc_nonshared.a`, `libgcc_s.so.1`, `libgcc.a`,
`libc.so.6`, and the loader. Each successful authoritative link now derives its
system-input census from captured GCC `-v` and GNU ld `--trace` diagnostics and
rejects an omitted or undeclared input. Those diagnostics bind
`/usr/libexec/gcc/aarch64-linux-gnu/13/liblto_plugin.so` and
`/usr/libexec/gcc/aarch64-linux-gnu/13/lto-wrapper` in addition to the traced
CRT, archive, script, shared-library, libc, and loader inputs. The immutable
build profile field `compiler_link_diagnostic_sha256` pins the normalized
complete transcript at
`0d599bda5372f0455f4f2566cf7c31d6f28a2b260e8a9d1473dc91115ce608bc`.
The verifier maps every traced path to its retained toolchain-lock role,
normalizes only the two generated objects, output path, and GCC resolution
temporary, and hashes every ordered stdout and stderr line. It rejects extra, reordered, duplicated, suppressed, malformed, or localized diagnostics; no
unclassified line is ignored. The system/toolchain trace path spellings remain
byte-exact, including GCC's legitimate `../../../` segments. Only those exact
generated paths are substituted; symlink and lexical aliases such as `/./`,
alternate `/../`, or duplicate slashes are rejected even when they resolve to
the same retained input bytes. A separate
non-authoritative syscall trace confirmed that the linker opened `liblto_plugin.so`;
GCC successfully statted but did not open or execute `lto-wrapper` in this
non-LTO build. That syscall trace corroborates the captured diagnostics but is
not build authority; this evidence does not claim a syscall-complete OS-input closure.

These exact implementation-status fields are part of the build profile:
`driver_descriptor_bound: true`, `subtool_paths_pre_post_verified: true`, and
`same_principal_or_root_coherent_substitution_resistant: false`. GCC still
resolves and executes subordinate tools and inputs internally; their retained
descriptors cannot be forced through every GCC sub-invocation. Pre/post checks
can detect drift but cannot exclude a coherent replace-and-restore inside one
invocation. Retaining the ten source inputs likewise binds materialized build
bytes and detects the tested late drift. Active-source correlation binds the
declared driver and contract files to the directly executed and source-loaded
local code, but the running Python process and same-principal boundary are not
independent custody. It does not close or attest the Python interpreter or
standard library and cannot resist hostile in-memory code modification.
Therefore `source_custody_verified: false`,
`python_interpreter_custody_verified: false`,
`python_stdlib_custody_verified: false`, and
`hostile_in_memory_code_resistance_verified: false` remain exact documentary
limitations, not additional manifest claims. This local result establishes
the exact declared executable, direct and recursive ELF runtime-library,
header, and captured successful link-input closure under this root-owned
reference profile. It is
not the kernel, locale database, or malicious-root inputs, does not establish
installation custody, does not resist malicious root, and does not claim
stronger host authority.

The fixed GCC 13.3.0/binutils 2.42/glibc 2.39 profile is built in two
differently named roots with prefix maps. It uses
`-fstack-protector-strong` plus `-Wstack-protector`; the exact dynamic-symbol
census requires `__stack_chk_fail` and `__stack_chk_guard`. The build accepts
only byte-identical AArch64 PIE outputs and build IDs. A strict stdlib ELF
reader checks every `PT_NOTE` within its own segment, the interpreter, the
exact `libc.so.6` plus locked `ld-linux-aarch64.so.1` dependencies, symbol and
version requirements, exact sections, RELRO, NOW, PIE, NX stack, and absence
of W+X, RPATH, RUNPATH, and TEXTREL. Whole-ELF SHA-256 is authoritative; the
GNU SHA-1 build ID is correlation only.

The deterministic native tar is separate from the universal Python wheel. The
sdist verifier owns an independent immutable copy of the exact ten path/role
pairs rather than deriving completeness from the archive lock. It requires
exact nested keys and scalar types, NFC text, safe canonical path order,
casefold uniqueness, nonzero byte hashes, and valid per-entry content hashes
before comparing archive bytes. The `py3-none-any` wheel contains no C
header/source, native builder, or ELF.

## Explicitly absent

`installed: false`, `root_custody_verified: false`,
`source_custody_verified: false`, `host_execution_enabled: false`,
`native_evidence_verified: false`, `provider_execution_enabled: false`,
`catalog_admitted: false`, `production_eligible: false`, and
`availability: unavailable` remain invariant. No systemd, account, provider,
model, network, installation, host-mutation, or inference action was performed.

## TDD Cycle Evidence

The table records the cumulative writer-observed cycle for the three final
remediations relevant to publication. A **Writer-reported historical RED** is a
contemporaneous terminal result retained in the writer handoff; it is not a
freshly reproducible failing state now that the fix is present. The exact shell
command or elapsed time is marked unretained rather than reconstructed where it
was not captured durably. **Current independently reproducible GREEN** is the
current candidate command and result shown below. Git history does not prove
this chronology; this evidence record reports the executed TDD sequence.

| Task | Test file | Layer | Safety net | RED | GREEN | Triangulate | Refactor |
|---|---|---|---|---|---|---|---|
| Final7: actual link-input and LTO-plugin closure | `tests/test_ollama_v2_native_build_d22a.py` | Local build integration | Writer reported the prior focused candidate green; its exact count and timing were not retained in this record. | **Writer-reported historical RED.** Current test IDs corresponding to the three writer-reported historical RED assertions are `test_authoritative_link_diagnostics_bind_observed_inputs_to_lock`, `test_undeclared_actual_link_input_blocks_bundle_publication`, and `test_toolchain_manifest_requires_all_126_fixed_entries_before_driver_query`. The original full command, elapsed time, and exact test selection were not retained, and the historical execution was not independently reconstructed. Reported result: three selected tests failed for absent captured diagnostics, acceptance of an undeclared successful link input, and the stale 124-entry census; documentation assertions also failed. | Historical final7 focused GREEN: 34/34, elapsed time unretained. **Current independently reproducible GREEN:** `env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest tests.test_ollama_v2_native_build_contracts_d22a tests.test_ollama_v2_native_build_d22a` → 36/36 in 21.363s, `OK`. | Real GCC `-v`, GNU ld `--trace`, and corroborating syscall evidence distinguished the opened `liblto_plugin.so` from the statted but unexecuted `lto-wrapper`; omission, relabel, drift, and undeclared-input cases failed closed. | Replaced two self-consistent expected sets with captured-link validation and expanded the exact census from 124 to 126 entries. |
| Final8: locked `unavailable_type` and fail-closed complete diagnostic transcript | `tests/test_ollama_v2_native_build_d22a.py`; `tests/test_ollama_v2_native_build_contracts_d22a.py` | Unit plus local build/transport integration | Focused 34/34 in 17.006s before production/native changes. | **Writer-reported historical RED.** Recorded two-test scope: `test_protocol_lock_body_fields_bind_encoders_decoders_and_goldens` and `test_successful_link_diagnostics_are_closed_canonical_and_complete`; the exact launcher prefix was not retained. Result: 2 tests in 5.926s, `FAILED (failures=7, errors=1)`—the encoder emitted `1` where the lock required `2`, six mutated stderr transcripts still published, and the diagnostic profile pin was absent. | Historical two-test GREEN: 2/2 in 2.353s; historical focused GREEN: 36/36 in 19.595s. **Current independently reproducible GREEN:** the current focused command above → 36/36 in 21.363s, `OK`. | Lock-to-encoder-to-decoder-to-golden checks cover every body field; malformed, localized, extra, reordered, duplicated, and suppressed stdout/stderr cases block publication; real initiator/responder transport remained green. | Kept the protocol lock authoritative, encoded terminal type `2`, removed duplicated input-role expectations, and pinned the complete normalized ordered transcript. |
| Final9: preserve lexical trace identity | `tests/test_ollama_v2_native_build_d22a.py` | Local build integration | `env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest tests.test_ollama_v2_native_build_d22a.D22ANativeBuildTests.test_successful_link_diagnostics_are_closed_canonical_and_complete -v` → 1/1 in 5.215s, `OK`. | **Writer-reported historical RED.** The same targeted command → 1 test in 8.553s, `FAILED (failures=4)`: symlink, `/./`, alternate `/../`, and duplicate-slash aliases all published. | The same targeted command → 1/1 in 5.882s, `OK`. **Current independently reproducible GREEN:** the current focused command above → 36/36 in 21.363s, `OK`. | The exact-GCC-spelling plus alias test pair passed 2/2 in 6.522s; the closed transcript test now covers 15 mutation cases and explicitly freezes the six legitimate ordered `../../../` trace lines. | Raw ordered system/toolchain spellings remain in the transcript hash; only exact generated paths are substituted, while resolved-path role/byte mapping remains a separate parity check. |

## Validation record

Local Linux/aarch64 validation on 2026-09-04 produced:

- 6/6 pure build-contract tests passed, including fresh-process, repeated, and
  concurrent parser-order checks;
- 30/30 native build, ELF, wire, ancillary, transcript, direct-entry,
  source-only/pyc, source-lineage, source-custody, tool-runtime/linker-script
  and captured-link closure, exact diagnostic/lexical-alias, mutation, and
  reproducibility tests passed in an approved non-privileged socket run;
- the combined focused contract/native suite passed 36/36;
- the focused sdist/wheel boundary test passed;
- all 99 protected D2.1 regression tests passed;
- the runtime import audit reported `ai_imports=0`;
- the no-replace builder emitted
  `/tmp/wf-d22a-final9-a-20260904/world-forge-ollama-v2-codec-d22a-linux-aarch64.tar.gz`
  with SHA-256
  `f4d42ba92a4cfa692130549194f452d56aac6d331c4ebbf4d7c05ff54e41c371`;
- an independent second requested output root at
  `/tmp/wf-d22a-final9-b-20260904` produced the byte-identical tar and
  SHA-256.

The final canonical content hashes are source manifest
`0c2c93e4d8a9f2c63c597a1f0bf92a06692877316877948afcc825928dc418a5`,
build profile
`103524a1551e569383591a1f629484da2135e53c246194b6e9a3fa02b4cb9fdc`,
toolchain manifest
`b7069bf93d6d10f54846144ba4102a9bff95cbf141a28b0c3702e1839f4646e6`,
static bundle manifest
`511f1373ea67692c5d071572ddc7c7ada306a572b1ebca1bec47946839d3e5a2`,
and two-root receipt
`527e37feffb5f9601b17f9c78e2a417cf82898c192afc2c211549a860b2b6396`.

Focused Ruff check and format-check passed. The repository-wide Ruff command
still reports 127 pre-existing findings and its format check reports 32
pre-existing unformatted files outside this tranche. Root and a fresh reviewer
independently ran
`test_release_builder_uses_git_archive_and_publishes_reproducible_artifacts`
using the isolated D2.2a packaging venv under `/tmp` with `build==1.5.0`,
`setuptools==83.0.0`, and `wheel==0.47.0`; each passed 1/1 in approximately 32 seconds.
The selector built a real sdist and wheel and exercised a source-free wheel install,
`pip check`, isolated import, and `audit-contracts`. Root's subsequent full
`M5ReleaseBuilderTests` run passed 21/21 in 38.626s. The test cleanup removed the
temporary release artifacts, so no sdist or wheel SHA-256 is retained or claimed here.

Root canonically regenerated `contracts/legacy-identity-allowlist.json`; its
immediately following identity check-only passed: `entries=306 occurrences=1072`.
That result preceded this evidence-only reconciliation; the required check-only
result after these documentation and guard edits is reported separately rather
than silently rewriting the allowlist.

Sandbox execution may reject `SO_PASSCRED` with `EPERM`; only the separately
approved non-privileged local socket run above counts as codec behavior
evidence. This is local codec/build evidence, not hosted, installed, custody,
provider, effect, or production evidence.
