# Code-owned local-service attestation TDD evidence

- Date: 2026-08-29
- Base: `c2f97bb255bac44414d50b985493e61440924212`
- Mode: strict RED -> GREEN -> REFACTOR
- Scope: private local-service launch authority, lease, custody, process and
  listener attestation, authenticated handoff, exact cleanup, portable imports,
  focused regression tests, documentation, and generated identity evidence

## Evidence boundary

Native execution in this record is Linux `aarch64`, CPython `3.12.3`,
`/usr/bin/python3` only. The service uses one parent-prebound ephemeral numeric
IPv4 loopback listener and does not contact an external network or real
provider.

Clean subprocess tests replace `sys.platform` with representative `win32` and
`darwin` values and remove Linux-only `subprocess`, `os`, and `signal`
attributes before importing the package. Those tests prove portable import and
explicit pre-side-effect rejection. They are simulations, not native Windows or
macOS execution.

Python 3.11, native x86_64, actual Windows/macOS, hosted CI, full test discovery,
and real providers/models/APIs remain `UNTESTED` or `PENDING`. No result below
changes those classifications.

## Safety net

Before the original local-service module existed, 179 focused existing tests
covered the loopback gateway, worker supervisor, runtime dispatch, provider
governance, and parent pricing on the real Linux host. After the first
local-service increment, the original native local-service file passed 11/11
before later security cases were added. Managed-sandbox attempts that failed
with `socket(): EPERM` were classified as environment failures and were not
counted as native product evidence.

Protected byte pins captured the execution kernel, public ports, EventLog,
worker/bootstrap/protocol, loopback protocol, and five public Agent Harness
schemas before integration. Those pins stayed unchanged throughout the slice.

## RED -> GREEN -> REFACTOR cycles

| Slice | RED evidence | GREEN evidence | Refactor/triangulation |
|---|---|---|---|
| Closed policy, lease, and fixed service | The first local-service tests failed import because `worldforge.agent_harness.local_service` did not exist. | Exact fixed selection, one-use `127.0.0.1:0` lease, native GET then POST, HMAC readiness, terminal duplicate, privacy, timeout, and cleanup cases passed. | Removed the production ready-frame builder seam; hostile tests build signed bytes without adding runtime authority. |
| Immutable concrete recipe | The recipe test raised `AttributeError` for the missing `_code_owned_local_service_launch_recipe`. | Exact executable identity/bytes, bootstrap, argv, environment, FD/filter/self-test hashes, issued policy identity, and drift-with-zero-effects cases passed. | Launch uses captured recipe values rather than mutable globals; weak registries do not retain dead authority. |
| Full attestation and owner identity | Seven mutations (`bootstrap_hash`, `fd_census_hash`, `network_filter_hash`, `runtime_hash`, `self_test_hash`, `service_revision`, and `mac`) were initially accepted instead of raising. A canonical-policy tamper also reached bind port 7. | Every attestation field, lease/recipe/policy identity, copy, subclass, `object.__new__` forgery, owner swap, and replay now fails closed. | Canonical snapshots validate before live `/proc` facts and share one serializer. |
| Pre-secret process proof | The gate test observed `['data']` rather than `['blocked']` before the spawned child had been proven. | The configuration/HMAC pipe stays empty until exact PID/PPID/start, executable/bytes, cmdline, root, cwd, four-key environment, signal mask, and FD-role proof. Substituted children and extra pipe/file/socket descriptors fail closed. | Stable bounded sampling handles Python import-time descriptors without releasing the secret. Direct `/proc/self/fd` evidence corrected stdin `/dev/null` from an assumed read-only mode to the actual `O_RDWR` contract. |
| Structural custody and observer-only listener proof | A stopped service after spawn but before proof/handoff survived broker death. Early inode discovery admitted unrelated and PID-reused same-UID holders to a tracked kill set, skipped inaccessible candidates, and excluded older candidates. | The child installs exact `PR_SET_PDEATHSIG/SIGKILL` custody plus the immediate PPID check; the fixed bootstrap proves `PR_GET_PDEATHSIG` and `SigBlk` before configuration. Inode scanning only observes absence, never retains or signals, and inaccessible/changing/older holders prevent proof. | The authenticated main-parent handoff retains an exact pidfd before secret release. Broker loss before fencing remains indeterminate even when kernel custody cleans the child. |
| Cleanup branch and private Pipe closure | A control-latched cleanup branch omitted `listener_inode`; a pre-handoff holder could survive classification. The private spawn-Pipe barrier had an always-true deadline branch and could hang after early setup failure. | Cancellation, timeout, exception, broker-death, and boundary branches all propagate the inode absence obligation. Every private wait is bounded and every setup failure closes/joins its Pipe/process resources. | Cleanup signals only exactly retained PID/start/pidfd identities, then requires fixed-point domain-empty and observer-only listener-absent proof. |
| Executable custody hashes | Mutating captured installer/factory defaults or substituting code/dependencies could run a fake/no-op `prctl` while policy validation still passed. Nonzero `prctl`, errno, PPID mismatch, and no-op libc behavior lacked direct closure. | Policy/recipe snapshots bind installer and factory code, defaults, dependencies, single-thread checker, native `prctl` address/ABI, launch contract, and proof protocol. Every mutation rejects before service action; exact call, errno, PPID race, no-op state, normal lifecycle, and privileged-exec exclusion pass. | Setuid, setgid, and file-capability executables are excluded so exec cannot clear `PDEATHSIG`. |
| Mutable `Popen`, cwd, signals, and ctypes | Mutating `_CANONICAL_POPEN.__init__` on the same class passed validation and redirected the live child cwd. A signal handler or mutable `ctypes.CDLL` lookup could change launch behavior between validation and exec. | The post-spawn cwd device/inode is bound before secret release; exact class/method/default/native mutations fail closed. Signals are blocked before the single-thread fence and restored from the exact prior mask. | Broad Python `Popen` execution was replaced with a fixed low-level launcher rather than trying to fingerprint an open-ended mutable call graph. |
| Audit-safe low-level launcher and typed fingerprint | A synchronous `subprocess.Popen` audit hook replaced `subprocess._fork_exec` after validation; shallow transitive globals such as `os.fsencode` remained mutable. Tuple/list/frozenset/bytes and incomplete function-state fingerprints could collide. | The audit event occurs before pre-exec construction; the launcher revalidates after callbacks and invokes only its captured `_fork_exec` and immutable values. Typed canonical fingerprints cover bytes, ordered/unordered containers, code, defaults, keyword defaults, closures, transitive globals, recursion, and cycles. | Signal blocking moved before the first thread check; both pre- and post-audit fences require one thread and no trace/profile callback. |
| Post-audit closure and exact pidfd handle | An audit hook walking the launcher frame could mutate a preconstructed `prctl`/signal-restorer closure; probes authenticated with `PDEATHSIG=0` or roughly 60 signals still blocked. The first private handle used raw PID kill, omitted class descriptors, and did not retry EINTR. | Pre-exec and process-handle objects are constructed only after the audit callback and full revalidation. The child reports the actual signal mask. Immediate pidfd open, `waitid(P_PIDFD)`, `pidfd_send_signal`, EINTR retries, external-reap/PID-reuse cases, double-close, destructor, and zombie cleanup pass. | The handle owns only the exact pidfd and streams; it never signals a reused raw PID or globally reaps children. |
| Portable imports and lazy authority | The focused clean-process command first produced three failures: simulated `win32` and `darwin` imports reached missing `signal.SIGSTOP`, and the Linux control expected a not-yet-defined `_LINUX_AUTHORITY`. | Both clean unsupported-host imports succeed without native symbols; construction rejects with the governed unsupported reason before policy/catalog/journal/bind/spawn/provider action. A clean Linux process lazily seals one stable authority and stable hashes. | All Linux bindings, policy/recipe construction, and native fingerprints moved behind one lock-guarded per-process loader. Portable module definitions remain native-symbol-free. |
| Exact Python runtime preflight | A clean CPython 3.12 subprocess simulated Linux CPython 3.11 and expected `worker_containment_unavailable` with zero effects. Before the fix, the root factory called `code_owned_local_service_launch_policy` and surfaced its guard `AssertionError`. | The public root factory now rejects implementation, major, or minor mismatch with the exact governed unsupported reason before policy, catalog, provider initialization, or any audited socket/bind/connect/spawn effect. | The regression triangulates simulated CPython 3.11, PyPy 3.12, and CPython 4.0 rejection; existing clean Linux CPython 3.12 and simulated `win32`/`darwin` cases remain green. These are simulations, not native execution evidence for those runtimes. |
| Exact execution environment | Earlier launch recipes pinned only three environment keys. | The launched child observes exactly `LC_CTYPE=C.UTF-8`, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONIOENCODING=utf-8`, and `PYTHONUTF8=1`, matching the immutable recipe and no other key. | The exact environment bytes and hash participate in both stable policy and concrete recipe validation. |

The focused portable-import RED selected
`test_clean_unsupported_hosts_import_before_native_preflight` and
`test_clean_linux_import_lazily_seals_stable_authority_hashes` in the existing
Python 3.12 verification environment. It first failed three subprocess subcases
as described above and then passed 2/2 after the lazy-loader change.

The exact-runtime preflight RED selected
`test_clean_linux_cpython_311_rejects_before_service_authority`. It failed 1/1
in 0.107 seconds because the action list contained
`code_owned_local_service_launch_policy` and the exception was
`AssertionError`, rather than the required empty list and
`ProviderBoundaryUnsupported`. The minimal root-factory preflight then passed
1/1 in 0.092 seconds. Triangulation with simulated PyPy 3.12 and CPython 4.0,
the existing CPython 3.12 lazy-authority control, and the existing portable-host
cases passed 3/3 in 0.740 seconds. No native Python 3.11, PyPy, or Python 4.0
process ran.

## Final settled evidence

Earlier independent read-only reviews returned `SAFE` on the pre-remediation
code. A later release review identified the missing root-factory runtime
preflight and stale identity-publication status recorded above. This writer
record contains the resulting remediation and bounded gates; it does not
preclaim the required post-remediation independent verdict. No missing timing
is inferred:

- `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src /usr/bin/python3 -m unittest tests.test_agent_local_service -v`: **48/48 passed** in 9.796 seconds.
- `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src /usr/bin/python3 -m unittest tests.test_agent_local_service tests.test_agent_loopback_gateway tests.test_agent_worker_supervisor tests.test_agent_runtime_dispatch tests.test_agent_provider_governance tests.test_agent_parent_pricing -v`: **227/227 passed** in 30.566 seconds.
- `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src /usr/bin/python3 -m unittest tests.test_agent_execution_kernel tests.test_agent_harness_contracts tests.test_architecture -v`: **124/124 passed**.
- `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src /usr/bin/python3 -m unittest tests.test_agent_worker_egress -v`: **17/17 passed** in an isolated interpreter.
- Ruff check and format-check passed for all seven affected Python files:
  `local_service.py`, `process_supervisor.py`, `provider_catalog.py`,
  `supervisor.py`, `worker_registry.py`, `test_agent_local_service.py`, and
  `test_agent_worker_supervisor.py`.
- Focused `py_compile` passed with every output path under `/tmp`.
- `worldforge audit-contracts --source-root .` passed with **130 contracts**.
- `worldforge audit-runtime src/isoworld` passed with **`ai_imports=0`**.
- Identity publication is **PASS**. After explicit user authorization, the
  canonical escalated write-mode process exited 0 with exact output
  `legacy identity allowlist: entries=299 occurrences=1040`; this was the one
  successful publication. Historically, two earlier processes exited before
  writing (an unnecessary legacy slug in a temporary-interpreter path, then
  unavailable secure publication primitives), and one escalation request was
  rejected before process creation. The final generator `--check` and
  `worldforge audit-identities --source-root .` both pass with the synchronized
  **299 entries / 1040 occurrences** inventory.
- The protected public-byte test and base-diff check passed. Execution kernel,
  public ports, EventLog, worker/bootstrap/protocol, loopback protocol, and five
  public Agent Harness schemas remain byte-identical to the base revision.
- `git diff --check` passed, and final process/scratch inspection found no live
  matching service, broker, worker, multiprocessing helper, or retained
  `worldforge-worker-*` scratch directory.

No full discovery, native cross-platform execution, hosted CI, network access,
dependency installation, or real-provider execution was performed for this
evidence update.
