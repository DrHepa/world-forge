from __future__ import annotations

import gc
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import weakref
from pathlib import Path
from unittest import mock

from tests.agent_harness_fakes import (
    FakeCancellation,
    FakeClock,
    FakeJournal,
    FakeProvider,
    FakeTool,
)
from worldforge.agent_harness import (
    AgentExecutionKernel,
    CapabilityBroker,
    ExecutionLimits,
    ExecutionRequest,
    KernelError,
)
from worldforge.agent_harness import event_log as event_log_module
from worldforge.agent_harness.event_log import (
    AGENT_EVENT_LOG_DATABASE_NAME,
    AGENT_EVENT_LOG_SCHEMA_VERSION,
    AgentEventLog,
    AgentEventLogConflict,
    AgentEventLogCorrupt,
    AgentEventLogError,
    AgentEventLogIndeterminate,
    AgentExecutionCoordinator,
)
from worldforge.agent_harness.ports import (
    ProviderTurnResult,
    ProviderUsage,
    ToolCall,
    ToolResult,
)
from worldforge.agent_harness.records import build_event, build_receipt
from worldforge.agent_harness_contracts import (
    AGENT_CAPABILITY_GRANT_FORMAT,
    AGENT_EXECUTION_RECEIPT_FORMAT,
    AGENT_MEMORY_PROJECTION_FORMAT,
    AGENT_WORKER_ACTIVATION_FORMAT,
    MAX_SAFE_INTEGER,
    canonical_agent_harness_hash,
    validate_agent_harness_documents,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "examples/multigenre-contracts/agent-harness-minimal"


def _wait_for_child_marker(process: subprocess.Popen, marker: Path) -> None:
    deadline = time.monotonic() + 10.0
    while not marker.exists():
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise AssertionError(
                f"child exited before marker: rc={process.returncode} "
                f"stdout={stdout!r} stderr={stderr!r}"
            )
        if time.monotonic() >= deadline:
            process.kill()
            stdout, stderr = process.communicate()
            raise AssertionError(f"child marker timeout: stdout={stdout!r} stderr={stderr!r}")
        time.sleep(0.01)


def _child_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = str(ROOT / "src")
    return environment


def _store_byte_evidence(root: Path) -> dict[str, tuple[int, int, int, str]]:
    evidence: dict[str, tuple[int, int, int, str]] = {}
    for path in sorted(root.iterdir(), key=lambda item: item.name):
        info = path.stat(follow_symlinks=False)
        payload = path.read_bytes()
        evidence[path.name] = (
            info.st_dev,
            info.st_ino,
            info.st_size,
            hashlib.sha256(payload).hexdigest(),
        )
    return evidence


def _commit_wal_then_crash(database: Path, mutation: str) -> None:
    child_source = """
import os
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
connection.execute("PRAGMA journal_mode = WAL")
connection.execute("PRAGMA wal_autocheckpoint = 0")
mutation = sys.argv[2]
if mutation == "unknown_version":
    connection.execute(
        "UPDATE schema_meta SET value = '999' WHERE key = 'schema_version'"
    )
elif mutation == "schema_corrupt":
    connection.execute("DROP TABLE receipts")
elif mutation == "foreign_key_corrupt":
    connection.execute("PRAGMA foreign_keys = OFF")
    connection.execute(
        "INSERT INTO events(execution_id, sequence, event_id, event_hash, event_json) "
        "VALUES ('execution_orphan', 0, 'event_orphan', ?, ?)",
        ("f" * 64, b"{}"),
    )
else:
    raise AssertionError(mutation)
connection.commit()
os._exit(0)
"""
    child = subprocess.run(
        [sys.executable, "-B", "-c", child_source, str(database), mutation],
        env=_child_environment(),
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if child.returncode != 0:
        raise AssertionError(
            f"WAL crash fixture failed: rc={child.returncode} "
            f"stdout={child.stdout!r} stderr={child.stderr!r}"
        )


def _leave_hot_rollback_journal_then_crash(database: Path) -> None:
    child_source = """
import os
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
connection.execute("PRAGMA journal_mode = DELETE")
connection.execute("PRAGMA synchronous = FULL")
connection.execute("PRAGMA cache_size = 1")
connection.execute("PRAGMA cache_spill = ON")
connection.execute("BEGIN IMMEDIATE")
connection.execute(
    "UPDATE schema_meta SET value = '999' WHERE key = 'schema_version'"
)
connection.execute("CREATE TABLE recovery_spill (payload BLOB NOT NULL)")
for _ in range(64):
    connection.execute("INSERT INTO recovery_spill(payload) VALUES (zeroblob(8192))")
os._exit(0)
"""
    child = subprocess.run(
        [sys.executable, "-B", "-c", child_source, str(database)],
        env=_child_environment(),
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if child.returncode != 0:
        raise AssertionError(
            f"rollback-journal crash fixture failed: rc={child.returncode} "
            f"stdout={child.stdout!r} stderr={child.stderr!r}"
        )


def _documents() -> tuple[dict[str, object], dict[str, object]]:
    activation = json.loads((FIXTURES / "worker-activation.json").read_text("utf-8"))
    grant = json.loads((FIXTURES / "capability-grant.json").read_text("utf-8"))
    return activation, grant


def _documents_for(execution_id: str) -> tuple[dict[str, object], dict[str, object]]:
    activation, grant = _documents()
    activation["execution_id"] = execution_id
    activation["content_hash"] = canonical_agent_harness_hash(activation)
    grant["execution_id"] = execution_id
    grant["activation"] = {
        "id": activation["activation_id"],
        "content_hash": activation["content_hash"],
    }
    grant["content_hash"] = canonical_agent_harness_hash(grant)
    validate_agent_harness_documents(activation, grant)
    return activation, grant


def _event(
    activation: dict[str, object],
    grant: dict[str, object],
    events: list[dict[str, object]],
    event_type: str,
) -> dict[str, object]:
    sequence = len(events)
    subject_format = AGENT_WORKER_ACTIVATION_FORMAT
    subject_id = str(activation["activation_id"])
    subject_hash = str(activation["content_hash"])
    if event_type == "grant.issued":
        subject_format = AGENT_CAPABILITY_GRANT_FORMAT
        subject_id = str(grant["grant_id"])
        subject_hash = str(grant["content_hash"])
    return build_event(
        event_id=f"durable_event_{sequence:03d}",
        log_id="log_durable_01",
        execution_id=str(activation["execution_id"]),
        sequence=sequence,
        previous_event_hash=None if not events else str(events[-1]["content_hash"]),
        event_type=event_type,
        subject_format=subject_format,
        subject_id=subject_id,
        subject_hash=subject_hash,
    )


def _receipt(
    activation: dict[str, object],
    grant: dict[str, object],
    *,
    outcome: str = "succeeded",
) -> dict[str, object]:
    failure_codes: list[str] = []
    if outcome == "failed":
        failure_codes = ["provider_failed"]
    elif outcome == "cancelled":
        failure_codes = ["cancel_requested"]
    return build_receipt(
        receipt_id="receipt_durable_01",
        activation=activation,
        grant=grant,
        tool_invocations=[],
        result_artifacts=[],
        usage={
            "input_tokens": 3,
            "output_tokens": 2,
            "cached_input_tokens": 1,
            "duration_ms": 4,
            "cost_minor_units": 0,
            "currency": "USD",
        },
        outcome=outcome,
        failure_codes=failure_codes,
    )


def _terminal_records(
    *, outcome: str = "succeeded"
) -> tuple[
    dict[str, object],
    dict[str, object],
    list[dict[str, object]],
    dict[str, object],
]:
    activation, grant = _documents()
    events: list[dict[str, object]] = []
    for event_type in ("worker.activated", "grant.issued", "execution.started"):
        events.append(_event(activation, grant, events, event_type))
    if outcome == "cancelled":
        events.append(_event(activation, grant, events, "execution.cancel_requested"))
    receipt = _receipt(activation, grant, outcome=outcome)
    receipt_event = build_event(
        event_id=f"durable_event_{len(events):03d}",
        log_id="log_durable_01",
        execution_id=str(activation["execution_id"]),
        sequence=len(events),
        previous_event_hash=str(events[-1]["content_hash"]),
        event_type="execution.receipt_recorded",
        subject_format=AGENT_EXECUTION_RECEIPT_FORMAT,
        subject_id=str(receipt["receipt_id"]),
        subject_hash=str(receipt["content_hash"]),
    )
    return activation, grant, events, receipt_event, receipt


class AgentEventLogTests(unittest.TestCase):
    def _append_prefix(
        self,
        log: AgentEventLog,
        activation: dict[str, object],
        events: list[dict[str, object]],
    ) -> None:
        for sequence, event in enumerate(events):
            log.append_event(
                str(activation["execution_id"]),
                event,
                expected_sequence=sequence,
                expected_previous_hash=(
                    None if sequence == 0 else str(events[sequence - 1]["content_hash"])
                ),
                expected_generation=sequence,
            )

    def _assert_recovery_is_blocked(self, root: Path) -> None:
        try:
            unexpected = AgentEventLog.recovery(root)
        except AgentEventLogConflict as exc:
            self.assertEqual("event_log_recovery_active", exc.reason_code)
            return
        unexpected.close()
        self.fail("exclusive recovery opened while an ordinary session was live")

    def test_success_is_durable_canonical_and_replays_after_reopen(self) -> None:
        activation, grant, events, receipt_event, receipt = _terminal_records()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "agent-log"
            with AgentEventLog(root) as log:
                self.assertTrue(
                    log.begin_execution(
                        str(activation["execution_id"]),
                        "log_durable_01",
                        activation,
                        grant,
                        request_fingerprint="a" * 64,
                    )
                )
                self._append_prefix(log, activation, events)
                log.finalize(
                    str(activation["execution_id"]),
                    receipt,
                    receipt_event,
                    expected_sequence=len(events),
                    expected_previous_hash=str(events[-1]["content_hash"]),
                    expected_generation=len(events),
                )
                first = log.replay_records(str(activation["execution_id"]))
                self.assertEqual("terminal", first.state)
                self.assertEqual(len(events) + 1, first.generation)
                self.assertEqual(len(events) + 1, len(first.event_bytes))
                self.assertEqual(
                    receipt,
                    json.loads(first.receipt_bytes.decode("utf-8")),
                )
                mode = log.connection.execute("PRAGMA journal_mode").fetchone()[0]
                synchronous = log.connection.execute("PRAGMA synchronous").fetchone()[0]
                foreign_keys = log.connection.execute("PRAGMA foreign_keys").fetchone()[0]
                self.assertEqual("wal", str(mode).casefold())
                self.assertEqual(2, synchronous)
                self.assertEqual(1, foreign_keys)

            with AgentEventLog(root) as reopened:
                second = reopened.replay_records(str(activation["execution_id"]))
                self.assertEqual(first, second)
                self.assertEqual(AGENT_EVENT_LOG_SCHEMA_VERSION, reopened.schema_version)
                decoded_events = [json.loads(item) for item in second.event_bytes]
                validate_agent_harness_documents(activation, grant, decoded_events, receipt)

    def test_exact_terminal_duplicate_is_evidence_only_and_different_fingerprint_conflicts(
        self,
    ) -> None:
        activation, grant, events, receipt_event, receipt = _terminal_records()
        with tempfile.TemporaryDirectory() as temporary, AgentEventLog(temporary) as log:
            self.assertTrue(
                log.begin_execution(
                    str(activation["execution_id"]),
                    "log_durable_01",
                    activation,
                    grant,
                    request_fingerprint="a" * 64,
                )
            )
            self._append_prefix(log, activation, events)
            log.finalize(
                str(activation["execution_id"]),
                receipt,
                receipt_event,
                expected_sequence=3,
                expected_previous_hash=str(events[-1]["content_hash"]),
                expected_generation=3,
            )
            log.finalize(
                str(activation["execution_id"]),
                receipt,
                receipt_event,
                expected_sequence=3,
                expected_previous_hash=str(events[-1]["content_hash"]),
                expected_generation=3,
            )
            different_receipt = dict(receipt)
            different_receipt["receipt_id"] = "receipt_durable_other"
            different_receipt["content_hash"] = canonical_agent_harness_hash(different_receipt)
            with self.assertRaises(AgentEventLogConflict):
                log.finalize(
                    str(activation["execution_id"]),
                    different_receipt,
                    receipt_event,
                    expected_sequence=3,
                    expected_previous_hash=str(events[-1]["content_hash"]),
                    expected_generation=3,
                )
            self.assertFalse(
                log.begin_execution(
                    str(activation["execution_id"]),
                    "log_durable_01",
                    activation,
                    grant,
                    request_fingerprint="a" * 64,
                )
            )
            with self.assertRaises(AgentEventLogConflict):
                log.begin_execution(
                    str(activation["execution_id"]),
                    "log_durable_01",
                    activation,
                    grant,
                    request_fingerprint="b" * 64,
                )
            log.connection.execute(
                "UPDATE receipts SET receipt_hash = ? WHERE execution_id = ?",
                ("f" * 64, activation["execution_id"]),
            )
            log.connection.commit()
            with self.assertRaisesRegex(AgentEventLogCorrupt, "event_log_projection_corrupt"):
                log.begin_execution(
                    str(activation["execution_id"]),
                    "log_durable_01",
                    activation,
                    grant,
                    request_fingerprint="a" * 64,
                )
            with self.assertRaisesRegex(AgentEventLogCorrupt, "event_log_projection_corrupt"):
                log.finalize(
                    str(activation["execution_id"]),
                    receipt,
                    receipt_event,
                    expected_sequence=3,
                    expected_previous_hash=str(events[-1]["content_hash"]),
                    expected_generation=3,
                )

    def test_append_and_finalize_use_sequence_head_and_generation_cas(self) -> None:
        activation, grant, events, receipt_event, receipt = _terminal_records()
        with tempfile.TemporaryDirectory() as temporary:
            first = AgentEventLog(temporary)
            second = AgentEventLog(temporary)
            self.addCleanup(first.close)
            self.addCleanup(second.close)
            first.begin_execution(
                str(activation["execution_id"]),
                "log_durable_01",
                activation,
                grant,
                request_fingerprint="a" * 64,
            )
            with self.assertRaisesRegex(AgentEventLogError, "event_log_request_invalid"):
                first.append_event(
                    str(activation["execution_id"]),
                    events[0],
                    expected_sequence=MAX_SAFE_INTEGER + 1,
                    expected_previous_hash=None,
                    expected_generation=MAX_SAFE_INTEGER + 1,
                )
            # Simulate a hostile/stale second live writer; durable CAS must still win.
            second._owned_executions.add(str(activation["execution_id"]))
            first.append_event(
                str(activation["execution_id"]),
                events[0],
                expected_sequence=0,
                expected_previous_hash=None,
                expected_generation=0,
            )
            with self.assertRaisesRegex(AgentEventLogConflict, "event_log_append_conflict"):
                second.append_event(
                    str(activation["execution_id"]),
                    events[0],
                    expected_sequence=0,
                    expected_previous_hash=None,
                    expected_generation=0,
                )
            for sequence, event in enumerate(events[1:], 1):
                first.append_event(
                    str(activation["execution_id"]),
                    event,
                    expected_sequence=sequence,
                    expected_previous_hash=str(events[sequence - 1]["content_hash"]),
                    expected_generation=sequence,
                )
            with self.assertRaisesRegex(AgentEventLogConflict, "event_log_finalize_conflict"):
                second.finalize(
                    str(activation["execution_id"]),
                    receipt,
                    receipt_event,
                    expected_sequence=3,
                    expected_previous_hash=str(events[-1]["content_hash"]),
                    expected_generation=2,
                )
            first.finalize(
                str(activation["execution_id"]),
                receipt,
                receipt_event,
                expected_sequence=3,
                expected_previous_hash=str(events[-1]["content_hash"]),
                expected_generation=3,
            )

    def test_crash_prefix_is_only_marked_recovery_required_and_never_reopened(self) -> None:
        activation, grant, events, _, _ = _terminal_records()
        with tempfile.TemporaryDirectory() as temporary:
            with AgentEventLog(temporary) as log:
                log.begin_execution(
                    str(activation["execution_id"]),
                    "log_durable_01",
                    activation,
                    grant,
                    request_fingerprint="a" * 64,
                )
                log.append_event(
                    str(activation["execution_id"]),
                    events[0],
                    expected_sequence=0,
                    expected_previous_hash=None,
                    expected_generation=0,
                )

            with AgentEventLog(temporary) as reopened:
                open_rows = reopened.list_open(limit=10)
                self.assertEqual(1, len(open_rows))
                prefix = open_rows[0]
                self.assertEqual(str(activation["execution_id"]), prefix.execution_id)
                with self.assertRaises(AgentEventLogConflict):
                    reopened.append_event(
                        prefix.execution_id,
                        events[1],
                        expected_sequence=prefix.next_sequence,
                        expected_previous_hash=prefix.head_hash,
                        expected_generation=prefix.generation,
                    )
                with self.assertRaisesRegex(
                    AgentEventLogConflict, "event_log_recovery_session_required"
                ):
                    reopened.mark_recovery_required(
                        prefix.execution_id,
                        expected_sequence=prefix.next_sequence,
                        expected_previous_hash=prefix.head_hash,
                        expected_generation=prefix.generation,
                    )

            with AgentEventLog.recovery(temporary) as recovery:
                with self.assertRaises(AgentEventLogConflict):
                    recovery.mark_recovery_required(
                        prefix.execution_id,
                        expected_sequence=prefix.next_sequence,
                        expected_previous_hash=prefix.head_hash,
                        expected_generation=prefix.generation + 1,
                    )
                recovered = recovery.mark_recovery_required(
                    prefix.execution_id,
                    expected_sequence=prefix.next_sequence,
                    expected_previous_hash=prefix.head_hash,
                    expected_generation=prefix.generation,
                )
                self.assertEqual("recovery_required", recovered.state)
                self.assertEqual(prefix.generation + 1, recovered.generation)
                self.assertEqual((), recovery.list_open(limit=10))
                with self.assertRaises(AgentEventLogConflict):
                    recovery.begin_execution(
                        str(activation["execution_id"]),
                        "log_durable_01",
                        activation,
                        grant,
                        request_fingerprint="a" * 64,
                    )
                with self.assertRaises(AgentEventLogConflict):
                    recovery.append_event(
                        str(activation["execution_id"]),
                        events[1],
                        expected_sequence=1,
                        expected_previous_hash=str(events[0]["content_hash"]),
                        expected_generation=recovered.generation,
                    )

    def test_list_open_has_bounded_stable_pagination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, AgentEventLog(temporary) as log:
            for index in range(4):
                execution_id = f"execution_page_{index:02d}"
                activation, grant = _documents_for(execution_id)
                log.begin_execution(
                    execution_id,
                    f"log_page_{index:02d}",
                    activation,
                    grant,
                    request_fingerprint=f"{index:064x}",
                )
            first = log.list_open(limit=2)
            second = log.list_open(limit=2, after_execution_id=first[-1].execution_id)
            self.assertEqual(
                ["execution_page_00", "execution_page_01"],
                [item.execution_id for item in first],
            )
            self.assertEqual(
                ["execution_page_02", "execution_page_03"],
                [item.execution_id for item in second],
            )
            with self.assertRaisesRegex(AgentEventLogError, "event_log_request_invalid"):
                log.list_open(limit=101)

    def test_begin_and_append_reconcile_an_exception_after_commit(self) -> None:
        activation, grant, events, _, _ = _terminal_records()
        stages = {"after_begin_commit", "after_append_commit"}

        def fail_once(stage: str) -> None:
            if stage in stages:
                stages.remove(stage)
                raise RuntimeError(f"private ambiguous {stage}")

        with (
            tempfile.TemporaryDirectory() as temporary,
            AgentEventLog(temporary, fault_hook=fail_once) as log,
        ):
            self.assertTrue(
                log.begin_execution(
                    str(activation["execution_id"]),
                    "log_durable_01",
                    activation,
                    grant,
                    request_fingerprint="a" * 64,
                )
            )
            log.append_event(
                str(activation["execution_id"]),
                events[0],
                expected_sequence=0,
                expected_previous_hash=None,
                expected_generation=0,
            )
            replay = log.replay_records(str(activation["execution_id"]))
            self.assertEqual(1, replay.next_sequence)
            self.assertEqual(str(events[0]["content_hash"]), replay.head_hash)
            self.assertEqual(set(), stages)

    def test_begin_reconciliation_poisoned_when_fresh_evidence_differs(self) -> None:
        activation, grant, _, _, _ = _terminal_records()
        holder: dict[str, AgentEventLog] = {}

        def substitute_committed_fingerprint(stage: str) -> None:
            if stage != "after_begin_commit":
                return
            log = holder["log"]
            row = log.connection.execute(
                "SELECT * FROM executions WHERE execution_id = ?",
                (activation["execution_id"],),
            ).fetchone()
            values = event_log_module.AgentEventLog._row_state_values(row)
            values["request_fingerprint"] = "b" * 64
            log.connection.execute(
                """
                UPDATE executions SET request_fingerprint = ?, state_hash = ?
                WHERE execution_id = ?
                """,
                (
                    "b" * 64,
                    event_log_module._state_hash(**values),
                    activation["execution_id"],
                ),
            )
            log.connection.commit()
            raise RuntimeError("private substituted reconciliation evidence")

        with (
            tempfile.TemporaryDirectory() as temporary,
            AgentEventLog(temporary, fault_hook=substitute_committed_fingerprint) as log,
        ):
            holder["log"] = log
            with self.assertRaisesRegex(
                AgentEventLogIndeterminate, "event_log_begin_indeterminate"
            ):
                log.begin_execution(
                    str(activation["execution_id"]),
                    "log_durable_01",
                    activation,
                    grant,
                    request_fingerprint="a" * 64,
                )
            self.assertIn(str(activation["execution_id"]), log._indeterminate_executions)

    def test_begin_and_append_precommit_faults_remain_indeterminate_without_partial_rows(
        self,
    ) -> None:
        activation, grant, events, _, _ = _terminal_records()
        begin_stages = {"before_begin_commit"}

        def fail_begin(stage: str) -> None:
            if stage in begin_stages:
                begin_stages.remove(stage)
                raise RuntimeError("private begin fault")

        with (
            tempfile.TemporaryDirectory() as temporary,
            AgentEventLog(temporary, fault_hook=fail_begin) as log,
        ):
            with self.assertRaisesRegex(
                AgentEventLogIndeterminate, "event_log_begin_indeterminate"
            ):
                log.begin_execution(
                    str(activation["execution_id"]),
                    "log_durable_01",
                    activation,
                    grant,
                    request_fingerprint="a" * 64,
                )
            with self.assertRaisesRegex(AgentEventLogConflict, "event_log_execution_conflict"):
                log.begin_execution(
                    str(activation["execution_id"]),
                    "log_durable_01",
                    activation,
                    grant,
                    request_fingerprint="a" * 64,
                )
            self.assertEqual((), log.list_open(limit=10))

        append_stages = {"before_append_commit"}

        def fail_append(stage: str) -> None:
            if stage in append_stages:
                append_stages.remove(stage)
                raise RuntimeError("private append fault")

        with tempfile.TemporaryDirectory() as temporary:
            with AgentEventLog(temporary, fault_hook=fail_append) as log:
                log.begin_execution(
                    str(activation["execution_id"]),
                    "log_durable_01",
                    activation,
                    grant,
                    request_fingerprint="a" * 64,
                )
                with self.assertRaisesRegex(
                    AgentEventLogIndeterminate, "event_log_append_indeterminate"
                ):
                    log.append_event(
                        str(activation["execution_id"]),
                        events[0],
                        expected_sequence=0,
                        expected_previous_hash=None,
                        expected_generation=0,
                    )
                replay = log.replay_records(str(activation["execution_id"]))
                self.assertEqual(0, replay.next_sequence)
                self.assertEqual((), replay.event_bytes)
                with self.assertRaisesRegex(AgentEventLogConflict, "event_log_writer_not_owned"):
                    log.append_event(
                        str(activation["execution_id"]),
                        events[0],
                        expected_sequence=0,
                        expected_previous_hash=None,
                        expected_generation=0,
                    )
            with AgentEventLog.recovery(temporary) as recovery:
                recovered = recovery.mark_recovery_required(
                    str(activation["execution_id"]),
                    expected_sequence=0,
                    expected_previous_hash=None,
                    expected_generation=0,
                )
                self.assertEqual("recovery_required", recovered.state)

    def test_append_reconciliation_requires_the_exact_immediate_open_post_state(
        self,
    ) -> None:
        activation, grant, events, receipt_event, receipt = _terminal_records()

        for post_state in ("later_open", "recovery_required", "terminal"):
            with self.subTest(post_state=post_state), tempfile.TemporaryDirectory() as temporary:
                holder: dict[str, AgentEventLog] = {}

                def mutate_after_commit(
                    stage: str,
                    target: str = post_state,
                    logs: dict[str, AgentEventLog] = holder,
                ) -> None:
                    if stage != "after_append_commit":
                        return
                    log = logs["log"]
                    log._fault_hook = None
                    if target == "later_open":
                        log.append_event(
                            str(activation["execution_id"]),
                            events[1],
                            expected_sequence=1,
                            expected_previous_hash=str(events[0]["content_hash"]),
                            expected_generation=1,
                        )
                    elif target == "recovery_required":
                        row = log.connection.execute(
                            "SELECT * FROM executions WHERE execution_id = ?",
                            (activation["execution_id"],),
                        ).fetchone()
                        values = log._row_state_values(row)
                        values.update(state="recovery_required", generation=2)
                        log.connection.execute(
                            """
                            UPDATE executions
                            SET state = 'recovery_required', generation = 2, state_hash = ?
                            WHERE execution_id = ?
                            """,
                            (
                                event_log_module._state_hash(**values),
                                activation["execution_id"],
                            ),
                        )
                        log.connection.commit()
                    else:
                        log.append_event(
                            str(activation["execution_id"]),
                            events[1],
                            expected_sequence=1,
                            expected_previous_hash=str(events[0]["content_hash"]),
                            expected_generation=1,
                        )
                        log.append_event(
                            str(activation["execution_id"]),
                            events[2],
                            expected_sequence=2,
                            expected_previous_hash=str(events[1]["content_hash"]),
                            expected_generation=2,
                        )
                        log.finalize(
                            str(activation["execution_id"]),
                            receipt,
                            receipt_event,
                            expected_sequence=3,
                            expected_previous_hash=str(events[2]["content_hash"]),
                            expected_generation=3,
                        )
                    raise RuntimeError(f"ambiguous append followed by {target}")

                with AgentEventLog(temporary, fault_hook=mutate_after_commit) as log:
                    holder["log"] = log
                    log.begin_execution(
                        str(activation["execution_id"]),
                        "log_durable_01",
                        activation,
                        grant,
                        request_fingerprint="a" * 64,
                    )
                    with self.assertRaisesRegex(
                        AgentEventLogIndeterminate, "event_log_append_indeterminate"
                    ):
                        log.append_event(
                            str(activation["execution_id"]),
                            events[0],
                            expected_sequence=0,
                            expected_previous_hash=None,
                            expected_generation=0,
                        )
                    self.assertNotIn(str(activation["execution_id"]), log._owned_executions)
                    self.assertIn(str(activation["execution_id"]), log._indeterminate_executions)

    def test_finalize_is_atomic_across_faults_and_reconciles_after_commit(self) -> None:
        rollback_stages = (
            "after_finalize_receipt_insert",
            "after_finalize_event_insert",
            "before_finalize_state_update",
            "before_finalize_commit",
        )
        for failed_stage in rollback_stages:
            with self.subTest(stage=failed_stage), tempfile.TemporaryDirectory() as temporary:
                activation, grant, events, receipt_event, receipt = _terminal_records()

                def fail(stage: str, expected_stage: str = failed_stage) -> None:
                    if stage == expected_stage:
                        raise RuntimeError(f"private fault {stage}")

                with AgentEventLog(temporary, fault_hook=fail) as log:
                    log.begin_execution(
                        str(activation["execution_id"]),
                        "log_durable_01",
                        activation,
                        grant,
                        request_fingerprint="a" * 64,
                    )
                    self._append_prefix(log, activation, events)
                    with self.assertRaises(AgentEventLogIndeterminate):
                        log.finalize(
                            str(activation["execution_id"]),
                            receipt,
                            receipt_event,
                            expected_sequence=3,
                            expected_previous_hash=str(events[-1]["content_hash"]),
                            expected_generation=3,
                        )
                    replay = log.replay_records(str(activation["execution_id"]))
                    self.assertEqual("open", replay.state)
                    self.assertEqual(3, replay.next_sequence)
                    self.assertIsNone(replay.receipt_bytes)
                    with self.assertRaisesRegex(
                        AgentEventLogConflict, "event_log_writer_not_owned"
                    ):
                        log.finalize(
                            str(activation["execution_id"]),
                            receipt,
                            receipt_event,
                            expected_sequence=3,
                            expected_previous_hash=str(events[-1]["content_hash"]),
                            expected_generation=3,
                        )
                with AgentEventLog.recovery(temporary) as recovery:
                    recovered = recovery.mark_recovery_required(
                        str(activation["execution_id"]),
                        expected_sequence=3,
                        expected_previous_hash=str(events[-1]["content_hash"]),
                        expected_generation=3,
                    )
                    self.assertEqual("recovery_required", recovered.state)

        stages = {"after_finalize_commit"}

        def fail_after_commit(stage: str) -> None:
            if stage in stages:
                stages.remove(stage)
                raise RuntimeError("private ambiguous commit")

        with (
            tempfile.TemporaryDirectory() as temporary,
            AgentEventLog(temporary, fault_hook=fail_after_commit) as log,
        ):
            activation, grant, events, receipt_event, receipt = _terminal_records()
            log.begin_execution(
                str(activation["execution_id"]),
                "log_durable_01",
                activation,
                grant,
                request_fingerprint="a" * 64,
            )
            self._append_prefix(log, activation, events)
            log.finalize(
                str(activation["execution_id"]),
                receipt,
                receipt_event,
                expected_sequence=3,
                expected_previous_hash=str(events[-1]["content_hash"]),
                expected_generation=3,
            )
            self.assertEqual(
                "terminal",
                log.replay_records(str(activation["execution_id"])).state,
            )
            self.assertEqual(set(), stages)

    def test_coordinator_returns_terminal_evidence_without_reexecuting_duplicate(self) -> None:
        activation, grant = _documents()
        request = ExecutionRequest(
            activation=activation,
            grant=grant,
            log_id="log_kernel_01",
            receipt_id="receipt_kernel_01",
            event_id_prefix="kernel_event",
            invocation_id_prefix="kernel_invocation",
            limits=ExecutionLimits(
                max_turns=2,
                max_tool_calls=1,
                max_total_tokens=20,
                max_cost_minor_units=10,
                currency="USD",
                max_duration_ms=100,
                deadline_ms=2_000,
            ),
            private_input={
                "secret": "PRIVATE_COORDINATOR_INPUT",
                "credential": "PRIVATE_CREDENTIAL_VALUE",
                "path": "/private/operational/path",
            },
        )
        tool = FakeTool(
            "source.read",
            "tool.invoke",
            ToolResult({"history": "PRIVATE_TOOL_OUTPUT"}),
        )
        provider = FakeProvider(
            [
                ProviderTurnResult(
                    private_output={"payload": "PRIVATE_COORDINATOR_OUTPUT"},
                    usage=ProviderUsage(3, 2, 1, 0, "USD"),
                    tool_calls=(
                        ToolCall(
                            "source.read",
                            {
                                "arguments": "PRIVATE_TOOL_ARGUMENTS",
                                "provider_payload": "PRIVATE_PROVIDER_PAYLOAD",
                            },
                        ),
                    ),
                    completed=True,
                ),
                ProviderTurnResult(
                    private_output="MUST_NOT_EXECUTE",
                    usage=ProviderUsage(3, 2, 1, 0, "USD"),
                    completed=True,
                ),
            ]
        )
        with tempfile.TemporaryDirectory() as temporary, AgentEventLog(temporary) as log:
            kernel = AgentExecutionKernel(
                provider=provider,
                broker=CapabilityBroker(tools=(tool,)),
                journal=log,
                clock=FakeClock(),
                cancellation=FakeCancellation(),
            )
            coordinator = AgentExecutionCoordinator(kernel=kernel, event_log=log)
            first = coordinator.execute(request)
            self.assertEqual("executed", first.disposition)
            self.assertIsNotNone(first.result)
            self.assertEqual(1, len(provider.requests))
            second = coordinator.execute(request)
            self.assertEqual("existing_terminal", second.disposition)
            self.assertIsNone(second.result)
            self.assertEqual(first.records, second.records)
            self.assertEqual(1, len(provider.requests))
            with self.assertRaisesRegex(KernelError, "execution_already_recorded"):
                kernel.execute(request)
            self.assertEqual(1, len(provider.requests))

            kernel.journal = FakeJournal()
            with self.assertRaisesRegex(AgentEventLogError, "event_log_coordinator_mismatch"):
                coordinator.execute(request)
            self.assertEqual(1, len(provider.requests))
            kernel.journal = log

            before_changes = log.connection.total_changes
            before_provider_calls = len(provider.requests)
            replay = log.replay_records(str(activation["execution_id"]))
            self.assertEqual("terminal", replay.state)
            self.assertEqual(
                "not_claimed",
                json.loads(replay.receipt_bytes)["replay_support"],
            )
            self.assertEqual(before_changes, log.connection.total_changes)
            self.assertEqual(before_provider_calls, len(provider.requests))
            for suffix in ("", "-wal", "-shm", "-journal"):
                path = Path(f"{log.database_path}{suffix}")
                if path.exists():
                    payload = path.read_bytes()
                    for sentinel in (
                        b"PRIVATE_COORDINATOR_INPUT",
                        b"PRIVATE_CREDENTIAL_VALUE",
                        b"/private/operational/path",
                        b"PRIVATE_COORDINATOR_OUTPUT",
                        b"PRIVATE_TOOL_ARGUMENTS",
                        b"PRIVATE_PROVIDER_PAYLOAD",
                        b"PRIVATE_TOOL_OUTPUT",
                        b"MUST_NOT_EXECUTE",
                    ):
                        self.assertNotIn(sentinel, payload)

    def test_unsealable_private_input_has_no_identity_and_can_never_deduplicate(
        self,
    ) -> None:
        activation, grant = _documents()
        touched: list[str] = []

        class HostilePrivateInput(dict):
            def __repr__(self) -> str:
                touched.append("repr")
                raise AssertionError("hostile repr called")

            def __hash__(self) -> int:
                touched.append("hash")
                raise AssertionError("hostile hash called")

            def __eq__(self, _other: object) -> bool:
                touched.append("eq")
                raise AssertionError("hostile equality called")

            def items(self):
                touched.append("items")
                raise AssertionError("hostile items called")

        private_input = HostilePrivateInput(secret="PRIVATE_HOSTILE_INPUT_SENTINEL")
        request = ExecutionRequest(
            activation=activation,
            grant=grant,
            log_id="log_kernel_01",
            receipt_id="receipt_kernel_01",
            event_id_prefix="kernel_event",
            invocation_id_prefix="kernel_invocation",
            limits=ExecutionLimits(
                max_turns=2,
                max_tool_calls=1,
                max_total_tokens=20,
                max_cost_minor_units=10,
                currency="USD",
                max_duration_ms=100,
                deadline_ms=2_000,
            ),
            private_input=private_input,
        )
        provider = FakeProvider([])
        with tempfile.TemporaryDirectory() as temporary, AgentEventLog(temporary) as log:
            kernel = AgentExecutionKernel(
                provider=provider,
                broker=CapabilityBroker(),
                journal=log,
                clock=FakeClock(),
                cancellation=FakeCancellation(),
            )
            coordinator = AgentExecutionCoordinator(kernel=kernel, event_log=log)
            first = coordinator.execute(request)
            self.assertEqual("executed", first.disposition)
            self.assertEqual("failed", first.result.outcome)
            self.assertEqual(["private_field_invalid"], first.result.receipt["failure_codes"])
            self.assertIsNone(first.records.request_fingerprint)
            self.assertEqual([], provider.requests)
            self.assertEqual([], touched)

            with self.assertRaisesRegex(KernelError, "journal_begin_ambiguous"):
                coordinator.execute(request)
            self.assertEqual([], provider.requests)
            self.assertEqual([], touched)
            with self.assertRaisesRegex(AgentEventLogConflict, "event_log_execution_conflict"):
                log.begin_execution(
                    str(activation["execution_id"]),
                    "log_kernel_01",
                    activation,
                    grant,
                    request_fingerprint=None,
                )

            for suffix in ("", "-wal", "-shm", "-journal"):
                path = Path(f"{log.database_path}{suffix}")
                if path.exists():
                    self.assertNotIn(b"PRIVATE_HOSTILE_INPUT_SENTINEL", path.read_bytes())

    def test_replay_rejects_state_document_lifecycle_and_schema_tampering(self) -> None:
        tamper_kinds = (
            "state",
            "document",
            "relational",
            "receipt_relational",
            "lifecycle",
        )
        for tamper_kind in tamper_kinds:
            with self.subTest(kind=tamper_kind), tempfile.TemporaryDirectory() as temporary:
                activation, grant, events, receipt_event, receipt = _terminal_records()
                with AgentEventLog(temporary) as log:
                    log.begin_execution(
                        str(activation["execution_id"]),
                        "log_durable_01",
                        activation,
                        grant,
                        request_fingerprint="a" * 64,
                    )
                    if tamper_kind == "lifecycle":
                        invalid = _event(activation, grant, [], "grant.issued")
                        payload = json.dumps(
                            invalid,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode("utf-8")
                        row = log.connection.execute(
                            "SELECT * FROM executions WHERE execution_id = ?",
                            (activation["execution_id"],),
                        ).fetchone()
                        values = event_log_module.AgentEventLog._row_state_values(row)
                        values.update(
                            generation=1,
                            next_sequence=1,
                            head_hash=invalid["content_hash"],
                        )
                        log.connection.execute(
                            """
                            INSERT INTO events(
                                execution_id, sequence, event_id, event_hash, event_json
                            )
                            VALUES (?, 0, ?, ?, ?)
                            """,
                            (
                                activation["execution_id"],
                                invalid["event_id"],
                                invalid["content_hash"],
                                payload,
                            ),
                        )
                        log.connection.execute(
                            """
                            UPDATE executions
                            SET generation = 1, next_sequence = 1, head_hash = ?, state_hash = ?
                            WHERE execution_id = ?
                            """,
                            (
                                invalid["content_hash"],
                                event_log_module._state_hash(**values),
                                activation["execution_id"],
                            ),
                        )
                    else:
                        self._append_prefix(log, activation, events)
                        log.finalize(
                            str(activation["execution_id"]),
                            receipt,
                            receipt_event,
                            expected_sequence=3,
                            expected_previous_hash=str(events[-1]["content_hash"]),
                            expected_generation=3,
                        )
                        if tamper_kind == "state":
                            log.connection.execute(
                                "UPDATE executions SET generation = generation + 1"
                            )
                        elif tamper_kind == "document":
                            log.connection.execute(
                                "UPDATE events SET event_json = ? WHERE sequence = 0",
                                (b"{}",),
                            )
                        elif tamper_kind == "relational":
                            log.connection.execute(
                                "UPDATE events SET event_hash = ? WHERE sequence = 0",
                                ("f" * 64,),
                            )
                        else:
                            log.connection.execute(
                                "UPDATE receipts SET receipt_hash = ?",
                                ("f" * 64,),
                            )
                    log.connection.commit()
                    with self.assertRaises(AgentEventLogCorrupt):
                        log.replay_records(str(activation["execution_id"]))

        with tempfile.TemporaryDirectory() as temporary:
            with AgentEventLog(temporary) as log:
                log.connection.execute("ALTER TABLE events ADD COLUMN forged TEXT")
                log.connection.commit()
            with self.assertRaises(AgentEventLogCorrupt):
                AgentEventLog(temporary)

    def test_unknown_private_schema_version_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with AgentEventLog(temporary) as log:
                database = log.database_path
            connection = sqlite3.connect(database)
            connection.execute("UPDATE schema_meta SET value = '999' WHERE key = 'schema_version'")
            connection.commit()
            connection.close()
            with self.assertRaisesRegex(AgentEventLogCorrupt, "event_log_version_unsupported"):
                AgentEventLog(temporary)

        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / AGENT_EVENT_LOG_DATABASE_NAME
            connection = sqlite3.connect(database)
            connection.executescript(
                """
                CREATE TABLE schema_meta (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL);
                INSERT INTO schema_meta(key, value) VALUES ('schema_version', '999');
                CREATE TABLE future_private_table (future_value TEXT NOT NULL);
                """
            )
            connection.close()
            (Path(temporary) / "agent-events.lock").write_bytes(b"\0")
            with self.assertRaisesRegex(AgentEventLogCorrupt, "event_log_version_unsupported"):
                AgentEventLog(temporary)
            connection = sqlite3.connect(database)
            names = [
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
                )
            ]
            connection.close()
            self.assertEqual(["future_private_table", "schema_meta"], names)

    def test_startup_rejects_orphan_rows_and_exact_sql_schema_drift(self) -> None:
        for table in ("events", "receipts"):
            with self.subTest(table=table), tempfile.TemporaryDirectory() as temporary:
                with AgentEventLog(temporary) as log:
                    database = log.database_path
                connection = sqlite3.connect(database)
                connection.execute("PRAGMA foreign_keys = OFF")
                if table == "events":
                    connection.execute(
                        """
                        INSERT INTO events(
                            execution_id, sequence, event_id, event_hash, event_json
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        ("execution_orphan", 0, "event_orphan", "a" * 64, b"{}"),
                    )
                else:
                    connection.execute(
                        """
                        INSERT INTO receipts(
                            execution_id, receipt_id, receipt_hash, receipt_json
                        ) VALUES (?, ?, ?, ?)
                        """,
                        ("execution_orphan", "receipt_orphan", "b" * 64, b"{}"),
                    )
                connection.commit()
                connection.close()
                with self.assertRaisesRegex(AgentEventLogCorrupt, "event_log_storage_corrupt"):
                    AgentEventLog(temporary)

        with tempfile.TemporaryDirectory() as temporary:
            with AgentEventLog(temporary) as log:
                database = log.database_path
            connection = sqlite3.connect(database)
            connection.executescript(
                """
                PRAGMA foreign_keys = OFF;
                DROP TABLE receipts;
                CREATE TABLE receipts (
                    execution_id TEXT PRIMARY KEY NOT NULL
                        REFERENCES executions(execution_id),
                    receipt_id TEXT NOT NULL UNIQUE ON CONFLICT IGNORE,
                    receipt_hash TEXT NOT NULL UNIQUE,
                    receipt_json BLOB NOT NULL
                );
                """
            )
            connection.close()
            with self.assertRaisesRegex(AgentEventLogCorrupt, "event_log_schema_corrupt"):
                AgentEventLog(temporary)

    def test_sqlitex_schema_objects_and_receipt_deleting_trigger_are_never_hidden(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with AgentEventLog(temporary) as log:
                database = log.database_path
            connection = sqlite3.connect(database)
            connection.execute("CREATE TABLE sqlitex_hidden (value TEXT NOT NULL)")
            connection.commit()
            connection.close()
            with self.assertRaisesRegex(AgentEventLogCorrupt, "event_log_schema_corrupt"):
                AgentEventLog(temporary)

        activation, grant, events, receipt_event, receipt = _terminal_records()
        with tempfile.TemporaryDirectory() as temporary, AgentEventLog(temporary) as log:
            log.begin_execution(
                str(activation["execution_id"]),
                "log_durable_01",
                activation,
                grant,
                request_fingerprint="a" * 64,
            )
            self._append_prefix(log, activation, events)
            log.connection.execute(
                """
                CREATE TRIGGER sqlitex_delete_receipt
                AFTER INSERT ON events
                WHEN NEW.sequence = 3
                BEGIN
                    DELETE FROM receipts WHERE execution_id = NEW.execution_id;
                END
                """
            )
            log.connection.commit()
            with self.assertRaisesRegex(AgentEventLogCorrupt, "event_log_schema_corrupt"):
                log.finalize(
                    str(activation["execution_id"]),
                    receipt,
                    receipt_event,
                    expected_sequence=3,
                    expected_previous_hash=str(events[-1]["content_hash"]),
                    expected_generation=3,
                )
            self.assertEqual(
                0,
                log.connection.execute("SELECT COUNT(*) FROM receipts").fetchone()[0],
            )
            state = log.connection.execute(
                "SELECT state, generation FROM executions WHERE execution_id = ?",
                (activation["execution_id"],),
            ).fetchone()
            self.assertEqual(("open", 3), tuple(state))

    def test_writable_schema_internal_names_are_still_exact_manifest_drift(self) -> None:
        activation, grant, events, _, _ = _terminal_records()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "store"
            with AgentEventLog(root) as log:
                log.begin_execution(
                    str(activation["execution_id"]),
                    "log_durable_01",
                    activation,
                    grant,
                    request_fingerprint="a" * 64,
                )
                self._append_prefix(log, activation, events)
                database = log.database_path

            connection = sqlite3.connect(database)
            connection.execute("CREATE TABLE hidden_payload (value TEXT NOT NULL)")
            schema_version = connection.execute("PRAGMA schema_version").fetchone()[0]
            connection.execute("PRAGMA writable_schema = ON")
            connection.execute(
                """
                UPDATE sqlite_schema
                SET name = 'sqlite_hidden_table',
                    tbl_name = 'sqlite_hidden_table',
                    sql = 'CREATE TABLE sqlite_hidden_table (value TEXT NOT NULL)'
                WHERE type = 'table' AND name = 'hidden_payload'
                """
            )
            connection.execute(
                """
                INSERT INTO sqlite_schema(type, name, tbl_name, rootpage, sql)
                VALUES ('trigger', 'sqlite_hidden_delete_receipt', 'events', 0, ?)
                """,
                (
                    "CREATE TRIGGER sqlite_hidden_delete_receipt "
                    "AFTER INSERT ON events WHEN NEW.sequence = 3 "
                    "BEGIN DELETE FROM receipts "
                    "WHERE execution_id = NEW.execution_id; END",
                ),
            )
            connection.execute(f"PRAGMA schema_version = {schema_version + 1}")
            connection.execute("PRAGMA writable_schema = OFF")
            connection.commit()
            injected = connection.execute(
                """
                SELECT type, name, sql FROM sqlite_schema
                WHERE name IN (?, ?) ORDER BY type, name
                """,
                ("sqlite_hidden_table", "sqlite_hidden_delete_receipt"),
            ).fetchall()
            connection.close()
            self.assertEqual(
                [("table", "sqlite_hidden_table"), ("trigger", "sqlite_hidden_delete_receipt")],
                [(row[0], row[1]) for row in injected],
            )
            self.assertTrue(all(type(row[2]) is str for row in injected))

            connection = sqlite3.connect(database)
            connection.execute("BEGIN")
            connection.execute(
                """
                INSERT INTO receipts(execution_id, receipt_id, receipt_hash, receipt_json)
                VALUES (?, 'receipt_probe', ?, ?)
                """,
                (activation["execution_id"], "b" * 64, b"{}"),
            )
            self.assertEqual(
                1,
                connection.execute("SELECT COUNT(*) FROM receipts").fetchone()[0],
            )
            connection.execute(
                """
                INSERT INTO events(execution_id, sequence, event_id, event_hash, event_json)
                VALUES (?, 3, 'event_probe', ?, ?)
                """,
                (activation["execution_id"], "c" * 64, b"{}"),
            )
            self.assertEqual(
                0,
                connection.execute("SELECT COUNT(*) FROM receipts").fetchone()[0],
            )
            connection.rollback()
            connection.close()

            with self.assertRaisesRegex(AgentEventLogCorrupt, "event_log_schema_corrupt"):
                AgentEventLog(root)

            connection = sqlite3.connect(database)
            state = connection.execute(
                "SELECT state, generation FROM executions WHERE execution_id = ?",
                (activation["execution_id"],),
            ).fetchone()
            event_count = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            receipt_count = connection.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
            connection.close()
            self.assertEqual(("open", 3), state)
            self.assertEqual((3, 0), (event_count, receipt_count))

    def test_recovery_never_creates_or_repairs_an_invalid_existing_store(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "missing"
            with AgentEventLog(root) as log:
                database = log.database_path
                lock = log.lock_path
            database.unlink()
            self.assertEqual({lock.name}, {path.name for path in root.iterdir()})
            with self.assertRaisesRegex(AgentEventLogError, "event_log_recovery_store_missing"):
                AgentEventLog.recovery(root)
            self.assertFalse(database.exists())
            self.assertEqual({lock.name}, {path.name for path in root.iterdir()})

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "replaced"
            with AgentEventLog(root) as log:
                database = log.database_path
            replacement = base / "replacement.sqlite3"
            shutil.copyfile(database, replacement)
            namespace = {path.name for path in root.iterdir()}
            real_connect = sqlite3.connect

            def replace_before_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
                os.replace(replacement, database)
                return real_connect(*args, **kwargs)

            with mock.patch.object(
                event_log_module.sqlite3,
                "connect",
                side_effect=replace_before_connect,
            ):
                with self.assertRaisesRegex(AgentEventLogError, "event_log_path_substituted"):
                    AgentEventLog.recovery(root)
            self.assertEqual(namespace, {path.name for path in root.iterdir()})

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "empty"
            with AgentEventLog(root) as log:
                database = log.database_path
            database.unlink()
            database.touch(mode=0o600)
            namespace = {path.name for path in root.iterdir()}
            before = database.read_bytes()
            with self.assertRaisesRegex(AgentEventLogCorrupt, "event_log_schema_corrupt"):
                AgentEventLog.recovery(root)
            self.assertEqual(before, database.read_bytes())
            self.assertEqual(namespace, {path.name for path in root.iterdir()})

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "unknown"
            with AgentEventLog(root) as log:
                database = log.database_path
            connection = sqlite3.connect(database)
            connection.execute("UPDATE schema_meta SET value = '999' WHERE key = 'schema_version'")
            connection.commit()
            connection.close()
            namespace = {path.name for path in root.iterdir()}
            with self.assertRaisesRegex(AgentEventLogCorrupt, "event_log_version_unsupported"):
                AgentEventLog.recovery(root)
            connection = sqlite3.connect(database)
            version = connection.execute(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'"
            ).fetchone()[0]
            tables = tuple(
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name"
                )
            )
            connection.close()
            self.assertEqual("999", version)
            self.assertEqual(("events", "executions", "receipts", "schema_meta"), tables)
            self.assertEqual(namespace, {path.name for path in root.iterdir()})

    def test_failed_recovery_never_mutates_crash_surviving_wal_bytes(self) -> None:
        cases = (
            ("unknown_version", "event_log_version_unsupported"),
            ("schema_corrupt", "event_log_schema_corrupt"),
            ("foreign_key_corrupt", "event_log_storage_corrupt"),
        )
        for mutation, reason_code in cases:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "store"
                with AgentEventLog(root) as log:
                    database = log.database_path
                stable_main = database.read_bytes()
                _commit_wal_then_crash(database, mutation)
                self.assertEqual(stable_main, database.read_bytes())
                self.assertTrue(Path(f"{database}-wal").is_file())
                before = _store_byte_evidence(root)
                parent_namespace = {path.name for path in root.parent.iterdir()}

                with self.assertRaisesRegex(AgentEventLogCorrupt, reason_code):
                    AgentEventLog.recovery(root)

                self.assertEqual(before, _store_byte_evidence(root))
                self.assertEqual(parent_namespace, {path.name for path in root.parent.iterdir()})

    def test_failed_recovery_never_mutates_a_corrupt_crash_wal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "store"
            with AgentEventLog(root) as log:
                database = log.database_path
            _commit_wal_then_crash(database, "unknown_version")
            wal = Path(f"{database}-wal")
            payload = bytearray(wal.read_bytes())
            self.assertGreater(len(payload), 64)
            payload[-1] ^= 0xFF
            wal.write_bytes(payload)
            before = _store_byte_evidence(root)
            parent_namespace = {path.name for path in root.parent.iterdir()}

            with self.assertRaises(AgentEventLogError):
                AgentEventLog.recovery(root)

            self.assertEqual(before, _store_byte_evidence(root))
            self.assertEqual(parent_namespace, {path.name for path in root.parent.iterdir()})

    def test_failed_recovery_never_mutates_a_checksum_corrupt_hot_journal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "store"
            with AgentEventLog(root) as log:
                database = log.database_path
            _leave_hot_rollback_journal_then_crash(database)
            journal = Path(f"{database}-journal")
            payload = bytearray(journal.read_bytes())
            self.assertGreater(len(payload), 512)
            self.assertEqual(bytes.fromhex("d9d505f920a163d7"), payload[:8])
            sector_size = int.from_bytes(payload[20:24], "big")
            page_size = int.from_bytes(payload[24:28], "big")
            self.assertGreaterEqual(sector_size, 512)
            self.assertGreaterEqual(page_size, 512)
            payload[sector_size + 4 + page_size - 200] ^= 0xFF
            journal.write_bytes(payload)
            before = _store_byte_evidence(root)
            parent_namespace = {path.name for path in root.parent.iterdir()}

            with self.assertRaises(AgentEventLogError):
                AgentEventLog.recovery(root)

            self.assertEqual(before, _store_byte_evidence(root))
            self.assertEqual(parent_namespace, {path.name for path in root.parent.iterdir()})

    def test_lifecycle_rejects_memory_reorder_partial_terminal_and_append_after_terminal(
        self,
    ) -> None:
        activation, grant, events, receipt_event, receipt = _terminal_records()
        with tempfile.TemporaryDirectory() as temporary, AgentEventLog(temporary) as log:
            log.begin_execution(
                str(activation["execution_id"]),
                "log_durable_01",
                activation,
                grant,
                request_fingerprint="a" * 64,
            )
            reordered = _event(activation, grant, [], "grant.issued")
            with self.assertRaises(AgentEventLogConflict):
                log.append_event(
                    str(activation["execution_id"]),
                    reordered,
                    expected_sequence=0,
                    expected_previous_hash=None,
                    expected_generation=0,
                )
            memory_event = build_event(
                event_id="durable_event_memory",
                log_id="log_durable_01",
                execution_id=str(activation["execution_id"]),
                sequence=0,
                previous_event_hash=None,
                event_type="memory.projected",
                subject_format=AGENT_MEMORY_PROJECTION_FORMAT,
                subject_id="memory_projection_01",
                subject_hash="f" * 64,
            )
            with mock.patch.object(
                event_log_module,
                "_lifecycle_fold",
                wraps=event_log_module._lifecycle_fold,
            ) as reducer:
                with self.assertRaisesRegex(AgentEventLogConflict, "event_log_lifecycle_conflict"):
                    log.append_event(
                        str(activation["execution_id"]),
                        memory_event,
                        expected_sequence=0,
                        expected_previous_hash=None,
                        expected_generation=0,
                    )
                self.assertTrue(
                    any(
                        call.args[0] and call.args[0][-1]["event_type"] == "memory.projected"
                        for call in reducer.call_args_list
                    )
                )
            log.append_event(
                str(activation["execution_id"]),
                events[0],
                expected_sequence=0,
                expected_previous_hash=None,
                expected_generation=0,
            )
            failed_receipt = _receipt(activation, grant, outcome="failed")
            partial_terminal = build_event(
                event_id="durable_event_001",
                log_id="log_durable_01",
                execution_id=str(activation["execution_id"]),
                sequence=1,
                previous_event_hash=str(events[0]["content_hash"]),
                event_type="execution.receipt_recorded",
                subject_format=AGENT_EXECUTION_RECEIPT_FORMAT,
                subject_id=str(failed_receipt["receipt_id"]),
                subject_hash=str(failed_receipt["content_hash"]),
            )
            with self.assertRaises(AgentEventLogConflict):
                log.finalize(
                    str(activation["execution_id"]),
                    failed_receipt,
                    partial_terminal,
                    expected_sequence=1,
                    expected_previous_hash=str(events[0]["content_hash"]),
                    expected_generation=1,
                )

        with tempfile.TemporaryDirectory() as temporary, AgentEventLog(temporary) as log:
            log.begin_execution(
                str(activation["execution_id"]),
                "log_durable_01",
                activation,
                grant,
                request_fingerprint="a" * 64,
            )
            self._append_prefix(log, activation, events)
            log.finalize(
                str(activation["execution_id"]),
                receipt,
                receipt_event,
                expected_sequence=3,
                expected_previous_hash=str(events[-1]["content_hash"]),
                expected_generation=3,
            )
            with self.assertRaises(AgentEventLogConflict):
                log.append_event(
                    str(activation["execution_id"]),
                    events[0],
                    expected_sequence=4,
                    expected_previous_hash=str(receipt_event["content_hash"]),
                    expected_generation=4,
                )

    def test_cancelled_lifecycle_requires_cancel_event_and_accepts_bounded_five_events(
        self,
    ) -> None:
        activation, grant, events, receipt_event, receipt = _terminal_records(outcome="cancelled")
        self.assertEqual(4, len(events))
        with tempfile.TemporaryDirectory() as temporary, AgentEventLog(temporary) as log:
            log.begin_execution(
                str(activation["execution_id"]),
                "log_durable_01",
                activation,
                grant,
                request_fingerprint="a" * 64,
            )
            self._append_prefix(log, activation, events)
            contradictory_receipt = _receipt(activation, grant, outcome="succeeded")
            contradictory_event = build_event(
                event_id="durable_event_004",
                log_id="log_durable_01",
                execution_id=str(activation["execution_id"]),
                sequence=4,
                previous_event_hash=str(events[-1]["content_hash"]),
                event_type="execution.receipt_recorded",
                subject_format=AGENT_EXECUTION_RECEIPT_FORMAT,
                subject_id=str(contradictory_receipt["receipt_id"]),
                subject_hash=str(contradictory_receipt["content_hash"]),
            )
            with self.assertRaisesRegex(AgentEventLogConflict, "event_log_lifecycle_conflict"):
                log.finalize(
                    str(activation["execution_id"]),
                    contradictory_receipt,
                    contradictory_event,
                    expected_sequence=4,
                    expected_previous_hash=str(events[-1]["content_hash"]),
                    expected_generation=4,
                )
            log.finalize(
                str(activation["execution_id"]),
                receipt,
                receipt_event,
                expected_sequence=4,
                expected_previous_hash=str(events[-1]["content_hash"]),
                expected_generation=4,
            )
            replay = log.replay_records(str(activation["execution_id"]))
            self.assertEqual("terminal", replay.state)
            self.assertEqual(5, replay.next_sequence)

    @unittest.skipUnless(os.name == "posix", "link and substitution proof uses POSIX semantics")
    def test_persistence_boundary_rejects_root_database_sidecar_links_and_substitution(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            actual = base / "actual"
            actual.mkdir()
            alias = base / "alias"
            alias.symlink_to(actual, target_is_directory=True)
            with self.assertRaisesRegex(AgentEventLogError, "event_log_path_unsafe"):
                AgentEventLog(alias)

        for attack in ("database_symlink", "database_hardlink"):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "store"
                with AgentEventLog(root):
                    pass
                database = root / AGENT_EVENT_LOG_DATABASE_NAME
                target = root / "foreign.bin"
                target.write_bytes(b"foreign")
                if attack == "database_symlink":
                    database.unlink()
                    database.symlink_to(target)
                else:
                    os.link(database, root / "database-copy")
                with self.assertRaises(AgentEventLogError):
                    AgentEventLog(root)

        for suffix in ("-wal", "-shm", "-journal"):
            for attack in ("symlink", "hardlink"):
                with (
                    self.subTest(suffix=suffix, attack=attack),
                    tempfile.TemporaryDirectory() as temporary,
                ):
                    root = Path(temporary) / "store"
                    with AgentEventLog(root):
                        pass
                    database = root / AGENT_EVENT_LOG_DATABASE_NAME
                    target = root / "foreign.bin"
                    target.write_bytes(b"foreign")
                    sidecar = Path(f"{database}{suffix}")
                    if sidecar.exists():
                        sidecar.unlink()
                    if attack == "symlink":
                        sidecar.symlink_to(target)
                    else:
                        os.link(target, sidecar)
                    with self.assertRaises(AgentEventLogError):
                        AgentEventLog(root)

        with tempfile.TemporaryDirectory() as temporary, AgentEventLog(temporary) as log:
            log.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            original = Path(f"{log.database_path}.original")
            log.database_path.rename(original)
            shutil.copy2(original, log.database_path)
            with self.assertRaisesRegex(AgentEventLogError, "event_log_path_substituted"):
                log.list_open(limit=1)

        for suffix in ("-wal", "-shm", "-journal"):
            with self.subTest(suffix=suffix, attack="replacement_or_appearance"):
                with tempfile.TemporaryDirectory() as temporary, AgentEventLog(temporary) as log:
                    sidecar = Path(f"{log.database_path}{suffix}")
                    if sidecar.exists():
                        original = Path(f"{sidecar}.original")
                        sidecar.rename(original)
                        shutil.copy2(original, sidecar)
                    else:
                        sidecar.write_bytes(b"appeared")
                    with self.assertRaisesRegex(AgentEventLogError, "event_log_path_substituted"):
                        log.list_open(limit=1)

            for attack in ("disappearance", "hardlink"):
                with self.subTest(suffix=suffix, attack=attack):
                    with (
                        tempfile.TemporaryDirectory() as temporary,
                        AgentEventLog(temporary) as log,
                    ):
                        sidecar = Path(f"{log.database_path}{suffix}")
                        if not sidecar.exists():
                            continue
                        if attack == "disappearance":
                            sidecar.unlink()
                        else:
                            os.link(sidecar, Path(f"{sidecar}.copy"))
                        with self.assertRaises(AgentEventLogError):
                            log.list_open(limit=1)

    def test_shared_sessions_and_exclusive_recovery_are_process_fenced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "store"
            with AgentEventLog(root):
                child = subprocess.run(
                    [
                        sys.executable,
                        "-B",
                        "-c",
                        (
                            "import sys; "
                            "from worldforge.agent_harness.event_log import AgentEventLog; "
                            "log=AgentEventLog(sys.argv[1]); "
                            "print(log.schema_version); log.close()"
                        ),
                        str(root),
                    ],
                    cwd=ROOT,
                    env=_child_environment(),
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(0, child.returncode, child.stderr)
                self.assertEqual("1", child.stdout.strip())
                with self.assertRaisesRegex(AgentEventLogConflict, "event_log_recovery_active"):
                    AgentEventLog.recovery(root)

            with AgentEventLog.recovery(root) as recovery:
                self.assertEqual(AGENT_EVENT_LOG_SCHEMA_VERSION, recovery.schema_version)
                with self.assertRaisesRegex(AgentEventLogConflict, "event_log_recovery_active"):
                    AgentEventLog(root)

    @unittest.skipUnless(hasattr(os, "fork"), "fork ownership proof requires POSIX fork")
    def test_forked_child_cannot_use_or_unlock_the_parent_store(self) -> None:
        activation, grant, events, _, _ = _terminal_records()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "store"
            ordinary = AgentEventLog(root)
            ordinary_reference = weakref.ref(ordinary)

            def close_parent_if_needed() -> None:
                retained = ordinary_reference()
                if retained is not None:
                    retained.close()

            self.addCleanup(close_parent_if_needed)
            ordinary.begin_execution(
                str(activation["execution_id"]),
                "log_durable_01",
                activation,
                grant,
                request_fingerprint="a" * 64,
            )

            read_descriptor, write_descriptor = os.pipe()
            child = os.fork()
            if child == 0:
                os.close(read_descriptor)
                observations: list[str] = []
                try:
                    ordinary.append_event(
                        str(activation["execution_id"]),
                        events[0],
                        expected_sequence=0,
                        expected_previous_hash=None,
                        expected_generation=0,
                    )
                    observations.append("mutation_allowed")
                except AgentEventLogError as exc:
                    observations.append(exc.reason_code)
                try:
                    ordinary.close()
                    observations.append("child_closed")
                except BaseException as exc:
                    observations.append(type(exc).__name__)
                os.write(write_descriptor, json.dumps(observations).encode("utf-8"))
                os.close(write_descriptor)
                os._exit(0)

            os.close(write_descriptor)
            payload = os.read(read_descriptor, 4096)
            os.close(read_descriptor)
            waited, status = os.waitpid(child, 0)
            self.assertEqual(child, waited)
            self.assertEqual(0, status)
            self.assertEqual(
                ["event_log_process_mismatch", "child_closed"],
                json.loads(payload),
            )

            self._assert_recovery_is_blocked(root)
            self.assertEqual(1, len(ordinary.list_open(limit=1)))
            replay = ordinary.replay_records(str(activation["execution_id"]))
            self.assertEqual((0, ()), (replay.next_sequence, replay.event_bytes))

            second = os.fork()
            if second == 0:
                del ordinary
                gc.collect()
                os._exit(0)
            waited, status = os.waitpid(second, 0)
            self.assertEqual(second, waited)
            self.assertEqual(0, status)
            self._assert_recovery_is_blocked(root)

            ordinary.close()
            with AgentEventLog.recovery(root) as recovery:
                self.assertEqual(1, len(recovery.list_open(limit=1)))

    def test_failed_cross_thread_close_keeps_state_and_recovery_fence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "store"
            log = AgentEventLog(root)
            descriptor = log._lock_descriptor

            def force_cleanup() -> None:
                try:
                    log.connection.close()
                except BaseException:
                    pass
                current = getattr(log, "_lock_descriptor", None)
                if current is not None:
                    try:
                        os.close(current)
                    except OSError:
                        pass
                    log._lock_descriptor = None

            self.addCleanup(force_cleanup)
            failures: list[BaseException] = []

            def close_from_wrong_thread() -> None:
                try:
                    log.close()
                except BaseException as exc:
                    failures.append(exc)

            thread = threading.Thread(target=close_from_wrong_thread)
            thread.start()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(1, len(failures))
            self.assertIsInstance(failures[0], sqlite3.ProgrammingError)
            self.assertFalse(log._closed)
            self.assertEqual(descriptor, log._lock_descriptor)
            self._assert_recovery_is_blocked(root)

            log.close()
            self.assertTrue(log._closed)
            with AgentEventLog.recovery(root) as recovery:
                self.assertEqual(AGENT_EVENT_LOG_SCHEMA_VERSION, recovery.schema_version)

    def test_transaction_rolls_back_and_rethrows_base_exceptions_unchanged(self) -> None:
        activation, grant, events, _, _ = _terminal_records()
        for signal in (KeyboardInterrupt("stop"), SystemExit(17)):
            with self.subTest(signal=type(signal).__name__), tempfile.TemporaryDirectory() as root:
                holder: dict[str, AgentEventLog] = {}

                def interrupt(
                    stage: str,
                    exact: BaseException = signal,
                    logs: dict[str, AgentEventLog] = holder,
                ) -> None:
                    if stage == "before_append_commit":
                        logs["log"]._fault_hook = None
                        raise exact

                with AgentEventLog(root, fault_hook=interrupt) as log:
                    holder["log"] = log
                    log.begin_execution(
                        str(activation["execution_id"]),
                        "log_durable_01",
                        activation,
                        grant,
                        request_fingerprint="a" * 64,
                    )
                    caught: BaseException | None = None
                    try:
                        log.append_event(
                            str(activation["execution_id"]),
                            events[0],
                            expected_sequence=0,
                            expected_previous_hash=None,
                            expected_generation=0,
                        )
                    except BaseException as exc:
                        caught = exc
                    self.assertIs(signal, caught)
                    self.assertFalse(log.connection.in_transaction)
                    event_count = log.connection.execute("SELECT COUNT(*) FROM events").fetchone()[
                        0
                    ]
                    self.assertEqual(0, event_count)
                    replay = log.replay_records(str(activation["execution_id"]))
                    self.assertEqual((0, ()), (replay.next_sequence, replay.event_bytes))

    def test_owner_gc_closes_sqlite_then_lock_without_leaking_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "store"
            log = AgentEventLog(root)
            descriptor = log._lock_descriptor
            reference = weakref.ref(log)

            def close_leaked_descriptor() -> None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

            self.addCleanup(close_leaked_descriptor)
            self._assert_recovery_is_blocked(root)
            del log
            gc.collect()
            self.assertIsNone(reference())
            with self.assertRaises(OSError):
                os.fstat(descriptor)
            with AgentEventLog.recovery(root) as recovery:
                self.assertEqual(AGENT_EVENT_LOG_SCHEMA_VERSION, recovery.schema_version)

    def test_recovery_waits_for_live_kernel_and_os_exit_without_provider_race(self) -> None:
        child_source = """
import sys
import time
from pathlib import Path

from tests.agent_harness_fakes import FakeCancellation, FakeClock
from tests.test_agent_execution_kernel import _documents, _request, _usage
from worldforge.agent_harness import AgentExecutionKernel, CapabilityBroker
from worldforge.agent_harness.event_log import AgentEventLog
from worldforge.agent_harness.ports import ProviderTurnResult

root, ready, release, provider_marker = map(Path, sys.argv[1:])

class PausingBroker(CapabilityBroker):
    def activate(self, execution_id):
        lease = super().activate(execution_id)
        ready.write_bytes(b"ready")
        while not release.exists():
            time.sleep(0.01)
        return lease

class MarkerProvider:
    def turn(self, _request):
        provider_marker.write_bytes(b"called")
        return ProviderTurnResult("done", _usage(), completed=True)

activation, grant = _documents()
with AgentEventLog(root) as journal:
    kernel = AgentExecutionKernel(
        provider=MarkerProvider(),
        broker=PausingBroker(),
        journal=journal,
        clock=FakeClock(),
        cancellation=FakeCancellation(),
    )
    kernel.execute(_request(activation, grant))
"""
        exit_source = """
import os
import sys
from pathlib import Path
from worldforge.agent_harness.event_log import AgentEventLog

journal = AgentEventLog(sys.argv[1])
Path(sys.argv[2]).write_bytes(b"ready")
os._exit(0)
"""
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "store"
            ready = base / "ready"
            release = base / "release"
            provider_marker = base / "provider"
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-B",
                    "-c",
                    child_source,
                    str(root),
                    str(ready),
                    str(release),
                    str(provider_marker),
                ],
                cwd=ROOT,
                env=_child_environment(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                _wait_for_child_marker(process, ready)
                self.assertFalse(provider_marker.exists())
                with self.assertRaisesRegex(AgentEventLogConflict, "event_log_recovery_active"):
                    AgentEventLog.recovery(root)
                self.assertFalse(provider_marker.exists())
            finally:
                release.write_bytes(b"release")
                stdout, stderr = process.communicate(timeout=10)
                if process.returncode != 0:
                    self.fail(
                        f"paused kernel child failed: rc={process.returncode} "
                        f"stdout={stdout!r} stderr={stderr!r}"
                    )
            self.assertTrue(provider_marker.exists())
            with AgentEventLog.recovery(root) as recovery:
                self.assertEqual((), recovery.list_open(limit=10))

            ready.unlink()
            abrupt = subprocess.Popen(
                [
                    sys.executable,
                    "-B",
                    "-c",
                    exit_source,
                    str(root),
                    str(ready),
                ],
                cwd=ROOT,
                env=_child_environment(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            _wait_for_child_marker(abrupt, ready)
            stdout, stderr = abrupt.communicate(timeout=10)
            self.assertEqual(0, abrupt.returncode, f"{stdout!r} {stderr!r}")
            with AgentEventLog.recovery(root) as recovery:
                self.assertEqual(AGENT_EVENT_LOG_SCHEMA_VERSION, recovery.schema_version)

    def test_ordinary_and_recovery_sessions_restrict_mutating_apis(self) -> None:
        activation, grant, events, receipt_event, receipt = _terminal_records()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "store"
            with AgentEventLog(root) as ordinary:
                ordinary.begin_execution(
                    str(activation["execution_id"]),
                    "log_durable_01",
                    activation,
                    grant,
                    request_fingerprint="a" * 64,
                )
                with self.assertRaisesRegex(
                    AgentEventLogConflict, "event_log_recovery_session_required"
                ):
                    ordinary.mark_recovery_required(
                        str(activation["execution_id"]),
                        expected_sequence=0,
                        expected_previous_hash=None,
                        expected_generation=0,
                    )

            with AgentEventLog.recovery(root) as recovery:
                for operation in (
                    lambda: recovery.begin_execution(
                        str(activation["execution_id"]),
                        "log_durable_01",
                        activation,
                        grant,
                        request_fingerprint="a" * 64,
                    ),
                    lambda: recovery.append_event(
                        str(activation["execution_id"]),
                        events[0],
                        expected_sequence=0,
                        expected_previous_hash=None,
                        expected_generation=0,
                    ),
                    lambda: recovery.finalize(
                        str(activation["execution_id"]),
                        receipt,
                        receipt_event,
                        expected_sequence=0,
                        expected_previous_hash=None,
                        expected_generation=0,
                    ),
                ):
                    with self.subTest(operation=operation):
                        with self.assertRaisesRegex(
                            AgentEventLogConflict, "event_log_recovery_read_only"
                        ):
                            operation()
                prefix = recovery.list_open(limit=1)[0]
                recovered = recovery.mark_recovery_required(
                    prefix.execution_id,
                    expected_sequence=prefix.next_sequence,
                    expected_previous_hash=prefix.head_hash,
                    expected_generation=prefix.generation,
                )
                self.assertEqual("recovery_required", recovered.state)

    @unittest.skipUnless(os.name == "posix", "lock attack proof uses POSIX semantics")
    def test_recovery_lock_rejects_links_replacement_disappearance_and_bad_bytes(self) -> None:
        lock_name = "agent-events.lock"
        for attack in ("symlink", "hardlink", "bad_bytes"):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "store"
                root.mkdir()
                target = root / "foreign"
                target.write_bytes(b"foreign")
                lock = root / lock_name
                if attack == "symlink":
                    lock.symlink_to(target)
                elif attack == "hardlink":
                    os.link(target, lock)
                else:
                    lock.write_bytes(b"X")
                with self.assertRaises(AgentEventLogError):
                    AgentEventLog(root)

        for attack in ("replacement", "disappearance", "hardlink_after_open"):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "store"
                with AgentEventLog(root) as log:
                    lock = root / lock_name
                    if attack == "replacement":
                        original = root / "original.lock"
                        lock.rename(original)
                        lock.write_bytes(b"\0")
                    elif attack == "disappearance":
                        lock.unlink()
                    else:
                        os.link(lock, root / "lock-copy")
                    with self.assertRaises(AgentEventLogError):
                        log.list_open(limit=1)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "store"
            with AgentEventLog(root):
                pass
            lock = root / lock_name
            self.assertEqual(b"\0", lock.read_bytes())
            with AgentEventLog(root):
                self.assertEqual(b"\0", lock.read_bytes())

    def test_platform_lock_seams_fail_closed_and_distinguish_windows_modes(self) -> None:
        self.assertEqual(1, event_log_module._windows_lock_flags(False))
        self.assertEqual(3, event_log_module._windows_lock_flags(True))
        self.assertFalse(event_log_module._windows_drive_type_supported(4))
        self.assertTrue(event_log_module._windows_drive_type_supported(3))
        self.assertTrue(event_log_module._lock_filesystem_type_supported("ext4"))
        self.assertFalse(event_log_module._lock_filesystem_type_supported("nfs4"))
        self.assertFalse(event_log_module._lock_filesystem_type_supported("fuse.unknown"))

        class FakeFunction:
            def __init__(self, result: int) -> None:
                self.result = result
                self.calls: list[tuple[object, ...]] = []

            def __call__(self, *args: object) -> int:
                self.calls.append(args)
                return self.result

        class FakeKernel32:
            def __init__(self, result: int) -> None:
                self.LockFileEx = FakeFunction(result)

        for exclusive, expected_flags in ((False, 1), (True, 3)):
            with self.subTest(exclusive=exclusive):
                kernel32 = FakeKernel32(1)
                event_log_module._windows_lock_handle(
                    42,
                    exclusive=exclusive,
                    kernel32=kernel32,
                    last_error=lambda: 0,
                )
                self.assertEqual(expected_flags, kernel32.LockFileEx.calls[0][1])

        blocked = FakeKernel32(0)
        with self.assertRaisesRegex(AgentEventLogConflict, "event_log_recovery_active"):
            event_log_module._windows_lock_handle(
                42,
                exclusive=True,
                kernel32=blocked,
                last_error=lambda: 33,
            )
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(event_log_module, "_lock_filesystem_supported", return_value=False),
        ):
            with self.assertRaisesRegex(AgentEventLogError, "event_log_lock_unsupported"):
                AgentEventLog(temporary)


if __name__ == "__main__":
    unittest.main()
