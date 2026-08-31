#!/usr/bin/env python3
"""Focused unit tests for the OpenSSH compatibility harness."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("run.py")
SPEC = importlib.util.spec_from_file_location("openssh_regress", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {MODULE_PATH}")
openssh_regress = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = openssh_regress
SPEC.loader.exec_module(openssh_regress)


class ManifestTests(unittest.TestCase):
    def test_committed_manifest_is_valid(self) -> None:
        selection = openssh_regress.read_selection(openssh_regress.DEFAULT_SELECTION)

        self.assertEqual(sum(row.disposition == "run" for row in selection), 79)
        self.assertEqual(sum(row.disposition == "skip" for row in selection), 11)
        self.assertTrue(all(row.reason for row in selection if row.disposition != "run"))
        self.assertEqual(
            next(row.disposition for row in selection if row.test == "forwarding"), "run"
        )
        self.assertNotIn("pubkey-priority", {row.test for row in selection})

    def test_pin_includes_an_immutable_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pin_file = Path(directory) / "openssh-version"
            pin_file.write_text(
                "V_10_3_P1\n2d98db98331803cbb820211b2fb0d31a6e71e58e\n",
                encoding="utf-8",
            )
            with mock.patch.object(openssh_regress, "PIN_FILE", pin_file):
                pin = openssh_regress.read_pin()
            self.assertEqual(pin.tag, "V_10_3_P1")
            self.assertEqual(
                pin.commit, "2d98db98331803cbb820211b2fb0d31a6e71e58e"
            )

    def test_manifest_rejects_duplicate_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "selection.tsv"
            rows = ["test\tdisposition\treason"]
            rows.extend(f"test-{index}\trun\t" for index in range(88))
            rows.extend(["duplicate\trun\t", "duplicate\texclude\treason"])
            path.write_text("\n".join(rows) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "duplicate"):
                openssh_regress.read_selection(path)

    def test_tree_inventory_reports_drift(self) -> None:
        selection = [
            openssh_regress.Selection("present", "run", ""),
            openssh_regress.Selection("missing", "skip", "reason"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            regress = Path(directory) / "regress"
            regress.mkdir()
            (regress / "present.sh").touch()
            (regress / "unexpected.sh").touch()

            with self.assertRaisesRegex(ValueError, "missing.*unexpected"):
                openssh_regress.validate_tree_inventory(Path(directory), selection)


class EnvironmentTests(unittest.TestCase):
    def test_reference_environment_names_all_t_exec_helpers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            tree = Path(directory)
            (tree / "Makefile").write_text(
                "TEST_SHELL = /bin/sh\nTEST_MALLOC_OPTIONS = CFGJRSUX\n", encoding="utf-8"
            )
            client = tree / "candidate-bssh"

            env = openssh_regress.reference_environment(tree, client)

        expected = {
            "TEST_SSH_SCP",
            "TEST_SSH_SSH",
            "TEST_SSH_SSHD",
            "TEST_SSH_SSHD_SESSION",
            "TEST_SSH_SSHD_AUTH",
            "TEST_SSH_SSHAGENT",
            "TEST_SSH_SSHADD",
            "TEST_SSH_SSHKEYGEN",
            "TEST_SSH_SSHPKCS11HELPER",
            "TEST_SSH_SSHKEYSCAN",
            "TEST_SSH_SFTP",
            "TEST_SSH_PKCS11_HELPER",
            "TEST_SSH_SK_HELPER",
            "TEST_SSH_SFTPSERVER",
        }
        self.assertTrue(expected.issubset(env))
        self.assertEqual(env["TEST_SSH_SSH"], str(client))
        self.assertEqual(env["MALLOC_OPTIONS"], "CFGJRSUX")

    def test_process_timeout_terminates_the_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = openssh_regress.run_process(
                [sys.executable, "-c", "import time; time.sleep(5)"],
                Path(directory),
                {},
                1,
            )

        self.assertTrue(result.timed_out)
        self.assertLess(result.duration_ms, 4_000)

    def test_process_output_and_log_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "output.log"
            with (
                mock.patch.object(openssh_regress, "MAX_CAPTURE_BYTES", 128),
                mock.patch.object(openssh_regress, "MAX_LOG_BYTES", 256),
            ):
                result = openssh_regress.run_process(
                    [
                        sys.executable,
                        "-c",
                        "import sys; sys.stdout.write(chr(120) * 2048)",
                    ],
                    Path(directory),
                    {},
                    5,
                    log_path,
                )
            log_size = log_path.stat().st_size

        self.assertIn("output truncated by harness", result.output)
        self.assertLessEqual(len(result.output.encode()), 168)
        self.assertLessEqual(log_size, 256)


    def test_detached_output_holder_cannot_defeat_timeout(self) -> None:
        child_pid = None
        try:
            with tempfile.TemporaryDirectory() as directory:
                result = openssh_regress.run_process(
                    [
                        sys.executable,
                        "-c",
                        "import subprocess,time; p=subprocess.Popen([chr(47)+chr(98)+chr(105)+chr(110)+chr(47)+chr(115)+chr(108)+chr(101)+chr(101)+chr(112), str(10)], start_new_session=True); print(p.pid, flush=True); time.sleep(10)",
                    ],
                    Path(directory),
                    {},
                    1,
                )
                child_pid = int(result.output.splitlines()[0])
            self.assertTrue(result.timed_out)
            self.assertLess(result.duration_ms, 5_000)
        finally:
            if child_pid is not None:
                try:
                    openssh_regress.os.killpg(
                        child_pid, openssh_regress.signal.SIGKILL
                    )
                except ProcessLookupError:
                    pass

    def test_log_cleanup_requires_ownership_marker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unowned = root / "unowned-logs"
            unowned.mkdir()
            important = unowned / "important"
            important.write_text("keep", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unowned"):
                openssh_regress.reset_log_directory(unowned)
            self.assertEqual(important.read_text(encoding="utf-8"), "keep")

            owned = root / "owned-logs"
            openssh_regress.reset_log_directory(owned)
            transient = owned / "old.log"
            transient.write_text("stale", encoding="utf-8")
            openssh_regress.reset_log_directory(owned)
            self.assertFalse(transient.exists())
            self.assertTrue((owned / ".bssh-openssh-regress").is_file())


class ClassificationTests(unittest.TestCase):
    def test_candidate_failure_is_genuine_only_when_reference_passes(self) -> None:
        failed = openssh_regress.ProcessResult(1, 10, "FAIL: candidate\n", False)
        passed = openssh_regress.ProcessResult(0, 12, "ok\n", False)
        with mock.patch.object(openssh_regress, "run_one", side_effect=[failed, passed]):
            result = openssh_regress.classify(
                Path("tree"), Path("bssh"), Path("ssh"), "sample", 1, Path("logs")
            )

        self.assertEqual(result.verdict, "fail")
        self.assertEqual(result.first_failure_line, "FAIL: candidate")

    def test_candidate_failure_is_environmental_when_reference_fails(self) -> None:
        candidate = openssh_regress.ProcessResult(1, 10, "FAIL: candidate\n", False)
        reference = openssh_regress.ProcessResult(1, 12, "FATAL: environment\n", False)
        with mock.patch.object(openssh_regress, "run_one", side_effect=[candidate, reference]):
            result = openssh_regress.classify(
                Path("tree"), Path("bssh"), Path("ssh"), "sample", 1, Path("logs")
            )

        self.assertEqual(result.verdict, "environmental")
        self.assertEqual(result.reference_first_failure_line, "FATAL: environment")

    def test_upstream_skip_is_not_retried(self) -> None:
        skipped = openssh_regress.ProcessResult(0, 10, "SKIPPED: unavailable\n", False)
        with mock.patch.object(openssh_regress, "run_one", return_value=skipped) as run_one:
            result = openssh_regress.classify(
                Path("tree"), Path("bssh"), Path("ssh"), "sample", 1, Path("logs")
            )

        self.assertEqual(result.verdict, "skip")
        run_one.assert_called_once()


    def test_failed_skip_marker_is_retried(self) -> None:
        failed = openssh_regress.ProcessResult(1, 10, "SKIPPED: partial\nFAIL\n", False)
        passed = openssh_regress.ProcessResult(0, 12, "ok\n", False)
        with mock.patch.object(
            openssh_regress, "run_one", side_effect=[failed, passed]
        ) as run_one:
            result = openssh_regress.classify(
                Path("tree"), Path("bssh"), Path("ssh"), "sample", 1, Path("logs")
            )

        self.assertEqual(result.verdict, "fail")
        self.assertEqual(run_one.call_count, 2)


if __name__ == "__main__":
    unittest.main()
