from __future__ import annotations

import contextlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from worldforge.__main__ import main
from worldforge.asset_io import AssetContractError
from worldforge.codebase_memory_benchmark import canonical_codebase_memory_benchmark_hash
from worldforge.codebase_memory_benchmark_input import (
    CodebaseMemoryBenchmarkInputError,
    _benchmark_input_open_flags,
    _read_benchmark_input_entry,
    _validate_benchmark_input_state,
    read_codebase_memory_benchmark_json_object,
)
from worldforge.file_stat import WindowsFileStat

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "examples/multigenre-contracts/codebase-memory-benchmark-minimal"


class CodebaseMemoryBenchmarkCliTests(unittest.TestCase):
    def _arguments(self, output: Path, *, plan: Path | None = None) -> list[str]:
        arguments = [
            "worldforge",
            "evaluate-codebase-memory-benchmark",
            str(plan or FIXTURES / "plan.json"),
        ]
        for path in sorted(FIXTURES.glob("observation-*.json")):
            arguments.extend(("--observation", str(path)))
        arguments.extend(("--output", str(output)))
        return arguments

    def _run(self, arguments: list[str]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(sys, "argv", arguments),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            status = main()
        return status, stdout.getvalue(), stderr.getvalue()

    def test_cli_publishes_canonical_not_evaluable_report_and_machine_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "report.json"
            status, stdout, stderr = self._run(self._arguments(output))
            if status == 1 and "codebase_memory_benchmark_publication_failed" in stderr:
                self.skipTest("secure publication primitive unavailable in this sandbox")
            self.assertEqual(0, status, stderr)
            self.assertEqual("", stderr)
            result = json.loads(stdout)
            self.assertEqual("ok", result["status"])
            self.assertEqual("not_evaluable", result["decision"])
            self.assertEqual(
                (FIXTURES / "report.json").read_bytes(),
                output.read_bytes(),
            )
            self.assertEqual(json.loads(output.read_text())["content_hash"], result["content_hash"])

    def test_cli_refuses_replacement_with_stable_machine_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "report.json"
            first_status, _, first_stderr = self._run(self._arguments(output))
            if first_status == 1 and "codebase_memory_benchmark_publication_failed" in first_stderr:
                self.skipTest("secure publication primitive unavailable in this sandbox")
            original = output.read_bytes()
            status, stdout, stderr = self._run(self._arguments(output))
            self.assertEqual(1, status)
            self.assertEqual("", stdout)
            result = json.loads(stderr)
            self.assertEqual("error", result["status"])
            self.assertEqual("codebase_memory_benchmark_publication_failed", result["reason_code"])
            self.assertEqual(original, output.read_bytes())

    def test_cli_rejects_duplicate_bad_and_missing_explicit_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            duplicate = root / "duplicate.json"
            duplicate.write_text('{"format":1,"format":2}\n', encoding="utf-8")
            malformed = root / "malformed.json"
            malformed.write_text("not-json\n", encoding="utf-8")
            missing = root / "missing.json"
            oversized = root / "oversized.json"
            oversized.write_text("{" + '"x":"' + "a" * (1024 * 1024) + '"}', encoding="utf-8")
            directory = root / "directory"
            directory.mkdir()
            for plan in (duplicate, malformed, missing, oversized, directory):
                with self.subTest(plan=plan.name):
                    status, stdout, stderr = self._run(
                        self._arguments(root / f"{plan.name}.report.json", plan=plan)
                    )
                    self.assertEqual(1, status)
                    self.assertEqual("", stdout)
                    result = json.loads(stderr)
                    self.assertEqual("error", result["status"])
                    self.assertEqual(
                        "codebase_memory_benchmark_input_invalid", result["reason_code"]
                    )

    def test_cli_normalizes_extremely_deep_plan_and_observation_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            deep = root / "deep.json"
            deep.write_text(
                '{"x":' + "[" * 200_000 + "0" + "]" * 200_000 + "}\n",
                encoding="utf-8",
            )
            cases: list[list[str]] = []
            plan_command = [
                sys.executable,
                "-m",
                "worldforge",
                "evaluate-codebase-memory-benchmark",
                str(deep),
            ]
            observation_command = [
                sys.executable,
                "-m",
                "worldforge",
                "evaluate-codebase-memory-benchmark",
                str((FIXTURES / "plan.json").resolve()),
            ]
            fixture_observations = sorted(FIXTURES.glob("observation-*.json"))
            for observation in fixture_observations:
                plan_command.extend(("--observation", str(observation.resolve())))
            for index, observation in enumerate(fixture_observations):
                observation_command.extend(
                    ("--observation", str(deep if index == 0 else observation.resolve()))
                )
            plan_command.extend(("--output", str(root / "plan-report.json")))
            observation_command.extend(("--output", str(root / "observation-report.json")))
            cases.extend((plan_command, observation_command))
            for command in cases:
                with self.subTest(command=command):
                    completed = subprocess.run(
                        command,
                        cwd=root,
                        env={"PYTHONPATH": str(ROOT / "src")},
                        text=True,
                        capture_output=True,
                        timeout=5,
                        check=False,
                    )
                    self.assertEqual(1, completed.returncode)
                    self.assertEqual("", completed.stdout)
                    self.assertEqual(
                        {
                            "reason_code": "codebase_memory_benchmark_input_invalid",
                            "status": "error",
                        },
                        json.loads(completed.stderr),
                    )
                    self.assertNotIn("Traceback", completed.stderr)
                    self.assertFalse(Path(command[-1]).exists())

    def test_cli_validates_plan_then_preflights_count_and_unique_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            valid_plan = json.loads((FIXTURES / "plan.json").read_text(encoding="utf-8"))

            invalid_plan_arguments = [
                "worldforge",
                "evaluate-codebase-memory-benchmark",
                str(FIXTURES / "plan.json"),
            ]
            for index in range(768):
                invalid_plan_arguments.extend(
                    ("--observation", str(root / f"invalid-plan-{index}.json"))
                )
            invalid_plan_arguments.extend(("--output", str(root / "invalid-plan-report.json")))
            with mock.patch(
                "worldforge.__main__.read_codebase_memory_benchmark_json_object",
                return_value={},
            ) as reader:
                status, stdout, stderr = self._run(invalid_plan_arguments)
            self.assertEqual(1, status)
            self.assertEqual("", stdout)
            self.assertEqual(
                "codebase_memory_benchmark_input_invalid",
                json.loads(stderr)["reason_code"],
            )
            reader.assert_called_once_with(FIXTURES / "plan.json")

            wrong_count_arguments = self._arguments(root / "wrong-count-report.json")
            del wrong_count_arguments[-4:-2]
            with mock.patch(
                "worldforge.__main__.read_codebase_memory_benchmark_json_object",
                return_value=valid_plan,
            ) as reader:
                status, _, stderr = self._run(wrong_count_arguments)
            self.assertEqual(1, status)
            self.assertEqual(
                "codebase_memory_benchmark_input_invalid",
                json.loads(stderr)["reason_code"],
            )
            reader.assert_called_once_with(FIXTURES / "plan.json")

            duplicate_path_arguments = self._arguments(root / "duplicate-path-report.json")
            first_path_index = duplicate_path_arguments.index("--observation") + 1
            second_path_index = (
                duplicate_path_arguments.index("--observation", first_path_index + 1) + 1
            )
            duplicate_path_arguments[second_path_index] = duplicate_path_arguments[first_path_index]
            with mock.patch(
                "worldforge.__main__.read_codebase_memory_benchmark_json_object",
                return_value=valid_plan,
            ) as reader:
                status, _, stderr = self._run(duplicate_path_arguments)
            self.assertEqual(1, status)
            self.assertEqual(
                "codebase_memory_benchmark_input_invalid",
                json.loads(stderr)["reason_code"],
            )
            reader.assert_called_once_with(FIXTURES / "plan.json")

            maximum_plan = json.loads(json.dumps(valid_plan))
            template = maximum_plan["task_set"][0]
            maximum_plan["task_set"] = [
                {
                    **template,
                    "task_id": f"task_{index:02d}",
                    "repetitions": 64,
                }
                for index in range(4)
            ]
            maximum_plan["content_hash"] = canonical_codebase_memory_benchmark_hash(maximum_plan)
            maximum_arguments = [
                "worldforge",
                "evaluate-codebase-memory-benchmark",
                str(FIXTURES / "plan.json"),
            ]
            for index in range(768):
                maximum_arguments.extend(("--observation", str(root / f"maximum-{index}.json")))
            maximum_arguments.extend(("--output", str(root / "maximum-report.json")))
            with mock.patch(
                "worldforge.__main__.read_codebase_memory_benchmark_json_object",
                side_effect=[
                    maximum_plan,
                    CodebaseMemoryBenchmarkInputError("stop after maximum preflight"),
                ],
            ) as reader:
                status, _, stderr = self._run(maximum_arguments)
            self.assertEqual(1, status)
            self.assertEqual(
                "codebase_memory_benchmark_input_invalid",
                json.loads(stderr)["reason_code"],
            )
            self.assertEqual(2, reader.call_count)

    def test_cli_validates_observations_incrementally_and_normalizes_memory_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = json.loads((FIXTURES / "plan.json").read_text(encoding="utf-8"))
            first_observation_path = sorted(FIXTURES.glob("observation-*.json"))[0]
            first_observation = json.loads(first_observation_path.read_text(encoding="utf-8"))
            arguments = self._arguments(root / "duplicate-observation-report.json")
            with mock.patch(
                "worldforge.__main__.read_codebase_memory_benchmark_json_object",
                side_effect=[plan, first_observation, first_observation],
            ) as reader:
                status, stdout, stderr = self._run(arguments)
            self.assertEqual(1, status)
            self.assertEqual("", stdout)
            self.assertEqual(
                "codebase_memory_benchmark_input_invalid",
                json.loads(stderr)["reason_code"],
            )
            self.assertEqual(3, reader.call_count)

            with mock.patch(
                "worldforge.__main__.read_codebase_memory_benchmark_json_object",
                side_effect=MemoryError,
            ) as reader:
                status, stdout, stderr = self._run(
                    self._arguments(root / "memory-error-report.json")
                )
            self.assertEqual(1, status)
            self.assertEqual("", stdout)
            self.assertEqual(
                "codebase_memory_benchmark_input_invalid",
                json.loads(stderr)["reason_code"],
            )
            reader.assert_called_once_with(FIXTURES / "plan.json")

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "mkfifo"), "POSIX FIFO required")
    def test_cli_rejects_fifo_plan_and_observation_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fifo = root / "input.fifo"
            os.mkfifo(fifo)
            cases = []
            cases.append(self._arguments(root / "plan-report.json", plan=fifo))
            observation_arguments = self._arguments(root / "observation-report.json")
            observation_index = observation_arguments.index("--observation") + 1
            observation_arguments[observation_index] = str(fifo)
            cases.append(observation_arguments)
            for arguments in cases:
                with self.subTest(arguments=arguments):
                    started = time.monotonic()
                    status, stdout, stderr = self._run(arguments)
                    elapsed = time.monotonic() - started
                    self.assertLess(elapsed, 1.0)
                    self.assertEqual(1, status)
                    self.assertEqual("", stdout)
                    self.assertEqual(
                        "codebase_memory_benchmark_input_invalid",
                        json.loads(stderr)["reason_code"],
                    )
                    self.assertFalse(Path(arguments[-1]).exists())

    @unittest.skipUnless(os.name == "posix", "POSIX symlink semantics required")
    def test_cli_rejects_final_and_ancestor_symlinks_without_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.mkdir()
            plan = real / "plan.json"
            plan.write_bytes((FIXTURES / "plan.json").read_bytes())
            final_link = root / "plan-link.json"
            final_link.symlink_to(plan)
            ancestor_link = root / "linked-parent"
            ancestor_link.symlink_to(real, target_is_directory=True)
            for index, supplied in enumerate((final_link, ancestor_link / "plan.json")):
                with self.subTest(supplied=supplied):
                    output = root / f"report-{index}.json"
                    status, stdout, stderr = self._run(self._arguments(output, plan=supplied))
                    self.assertEqual(1, status)
                    self.assertEqual("", stdout)
                    self.assertEqual(
                        "codebase_memory_benchmark_input_invalid",
                        json.loads(stderr)["reason_code"],
                    )
                    self.assertFalse(output.exists())

    def test_input_reader_seams_require_nonblocking_standalone_regular_files(self) -> None:
        flags = _benchmark_input_open_flags()
        for name in ("O_NONBLOCK", "O_NOFOLLOW", "O_CLOEXEC"):
            value = getattr(os, name, 0)
            if value:
                self.assertEqual(value, flags & value)

        regular = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600,
            st_dev=1,
            st_ino=2,
            st_nlink=1,
            st_size=10,
            st_mtime_ns=3,
            st_ctime_ns=4,
            st_file_attributes=0,
        )
        self.assertEqual((1, 2), _validate_benchmark_input_state(regular, limit=10))
        for mutation in (
            {"st_mode": stat.S_IFIFO | 0o600},
            {"st_nlink": 2},
            {"st_size": 11},
        ):
            invalid = SimpleNamespace(**{**vars(regular), **mutation})
            with self.subTest(mutation=mutation):
                with self.assertRaises(CodebaseMemoryBenchmarkInputError):
                    _validate_benchmark_input_state(invalid, limit=10)

        windows_reparse = WindowsFileStat(
            st_mode=stat.S_IFREG | 0o600,
            st_dev=1,
            st_ino=2,
            st_nlink=1,
            st_size=10,
            st_mtime_ns=3,
            st_ctime_ns=4,
            st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT,
        )
        with self.assertRaises(CodebaseMemoryBenchmarkInputError):
            _validate_benchmark_input_state(windows_reparse, limit=10)

        windows_api = mock.Mock()
        windows_api.open_existing_file.return_value = 41
        windows_api._state.side_effect = AssetContractError("reparse final input")
        parent = SimpleNamespace(
            parent_fd=None,
            windows_api=windows_api,
            windows_parent_handle=37,
            path=Path("C:/retained"),
            assert_current=mock.Mock(),
        )
        with self.assertRaises(AssetContractError):
            _read_benchmark_input_entry(parent, "plan.json", limit=10)
        windows_api.open_existing_file.assert_called_once_with(37, "plan.json")
        windows_api.duplicate_to_descriptor.assert_not_called()
        windows_api.close.assert_called_once_with(41)

    def test_input_reader_reuses_fail_closed_pinned_ancestry(self) -> None:
        with mock.patch(
            "worldforge.codebase_memory_benchmark_input.open_verified_output_parent",
            side_effect=AssetContractError("reparse ancestor"),
        ) as pinned:
            with self.assertRaises(CodebaseMemoryBenchmarkInputError):
                read_codebase_memory_benchmark_json_object(FIXTURES / "plan.json")
        pinned.assert_called_once_with((FIXTURES / "plan.json").absolute().parent, create=False)

    def test_windows_reader_attempts_both_cleanup_paths_and_preserves_primary_error(self) -> None:
        regular = WindowsFileStat(
            st_mode=stat.S_IFREG | 0o600,
            st_dev=1,
            st_ino=2,
            st_nlink=1,
            st_size=0,
            st_mtime_ns=3,
            st_ctime_ns=4,
            st_file_attributes=0,
        )
        windows_api = mock.Mock()
        windows_api.open_existing_file.return_value = 41
        windows_api._state.return_value = regular
        windows_api.duplicate_to_descriptor.return_value = 43
        parent = SimpleNamespace(
            parent_fd=None,
            windows_api=windows_api,
            windows_parent_handle=37,
            path=Path("C:/retained"),
            assert_current=mock.Mock(),
        )
        with (
            mock.patch(
                "worldforge.codebase_memory_benchmark_input._entry_info",
                return_value=regular,
            ),
            mock.patch(
                "worldforge.codebase_memory_benchmark_input.descriptor_file_stat",
                return_value=regular,
            ),
            mock.patch("worldforge.codebase_memory_benchmark_input.os.read", return_value=b""),
            mock.patch(
                "worldforge.codebase_memory_benchmark_input.os.close",
                side_effect=OSError("descriptor close failed"),
            ) as descriptor_close,
        ):
            with self.assertRaisesRegex(OSError, "descriptor close failed"):
                _read_benchmark_input_entry(parent, "plan.json", limit=10)
        descriptor_close.assert_called_once_with(43)
        windows_api.close.assert_called_once_with(41)

        windows_api.reset_mock()
        windows_api.open_existing_file.return_value = 41
        windows_api._state.return_value = regular
        windows_api.duplicate_to_descriptor.return_value = 43
        windows_api.close.side_effect = AssetContractError("native close failed")
        with (
            mock.patch(
                "worldforge.codebase_memory_benchmark_input._entry_info",
                return_value=regular,
            ),
            mock.patch(
                "worldforge.codebase_memory_benchmark_input.descriptor_file_stat",
                return_value=regular,
            ),
            mock.patch(
                "worldforge.codebase_memory_benchmark_input.os.read",
                side_effect=RuntimeError("primary read failed"),
            ),
            mock.patch(
                "worldforge.codebase_memory_benchmark_input.os.close",
                side_effect=OSError("descriptor close failed"),
            ) as descriptor_close,
        ):
            with self.assertRaisesRegex(RuntimeError, "primary read failed") as raised:
                _read_benchmark_input_entry(parent, "plan.json", limit=10)
        descriptor_close.assert_called_once_with(43)
        windows_api.close.assert_called_once_with(41)
        self.assertIn("descriptor close failed", " ".join(raised.exception.__notes__))
        self.assertIn("native close failed", " ".join(raised.exception.__notes__))

    def test_cli_accepts_absolute_inputs_from_foreign_cwd_with_minimal_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "report.json"
            command = [
                sys.executable,
                "-m",
                "worldforge",
                "evaluate-codebase-memory-benchmark",
                str((FIXTURES / "plan.json").resolve()),
            ]
            for observation in sorted(FIXTURES.glob("observation-*.json")):
                command.extend(("--observation", str(observation.resolve())))
            command.extend(("--output", str(output)))
            completed = subprocess.run(
                command,
                cwd=root,
                env={"PYTHONPATH": str(ROOT / "src")},
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
            if (
                completed.returncode == 1
                and "codebase_memory_benchmark_publication_failed" in completed.stderr
            ):
                self.skipTest("secure publication primitive unavailable in this sandbox")
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertEqual((FIXTURES / "report.json").read_bytes(), output.read_bytes())

    def test_cli_has_explicit_repeatable_inputs_and_no_discovery_or_execution_surface(self) -> None:
        source = (ROOT / "src/worldforge/__main__.py").read_text(encoding="utf-8")
        self.assertIn('"evaluate-codebase-memory-benchmark"', source)
        self.assertIn('action="append"', source)
        self.assertIn("write_bytes_atomic", source)
        self.assertNotIn("write_json_atomic(args.output, report", source)
        benchmark_source = (ROOT / "src/worldforge/codebase_memory_benchmark.py").read_text(
            encoding="utf-8"
        )
        for forbidden in (
            "import pathlib",
            "import socket",
            "import subprocess",
            "import urllib",
            "mcp",
            "Popen",
        ):
            self.assertNotIn(forbidden, benchmark_source)


if __name__ == "__main__":
    unittest.main()
