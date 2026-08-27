#!/usr/bin/env python3
"""Run selected OpenSSH regress tests against bssh and a reference client."""

from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import re
import signal
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
DEFAULT_WORK_DIR = REPO_ROOT / "target" / "openssh-regress"
DEFAULT_RESULTS = DEFAULT_WORK_DIR / "results.json"
DEFAULT_BASELINE = HERE / "baseline.json"
DEFAULT_SELECTION = HERE / "selection.tsv"
PIN_FILE = HERE / "openssh-version"
MAX_CAPTURE_BYTES = 1024 * 1024
MAX_LOG_BYTES = 16 * 1024 * 1024
TRUNCATION_NOTICE = b"\n...[output truncated by harness]...\n"
FAILURE_PATTERN = re.compile(
    r"(?:^|\b)(?:FAIL(?:ED)?|FATAL|ERROR|Error|error|timed out|unexpected argument)(?:\b|:)",
)


@dataclass(frozen=True)
class Pin:
    tag: str
    commit: str


@dataclass(frozen=True)
class Selection:
    test: str
    disposition: str
    reason: str


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    duration_ms: int
    output: str
    timed_out: bool


@dataclass(frozen=True)
class TestResult:
    test: str
    verdict: str
    duration_ms: int | None
    first_failure_line: str | None
    reference_first_failure_line: str | None = None


def read_pin() -> Pin:
    lines = PIN_FILE.read_text(encoding="utf-8").splitlines()
    if len(lines) != 2:
        raise ValueError(f"{PIN_FILE} must contain an OpenSSH tag and commit")
    tag, commit = lines
    if not re.fullmatch(r"V_[0-9]+_[0-9]+_P[0-9]+", tag):
        raise ValueError(f"invalid OpenSSH tag in {PIN_FILE}: {tag!r}")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError(f"invalid OpenSSH commit in {PIN_FILE}: {commit!r}")
    return Pin(tag, commit)


def read_selection(path: Path) -> list[Selection]:
    rows: list[Selection] = []
    with path.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(
            (line for line in stream if not line.startswith("#")), delimiter="\t"
        )
        if reader.fieldnames != ["test", "disposition", "reason"]:
            raise ValueError("selection.tsv must have test, disposition, reason columns")
        for raw in reader:
            row = Selection(
                test=raw["test"],
                disposition=raw["disposition"],
                reason=raw["reason"] or "",
            )
            if row.disposition not in {"run", "skip", "exclude"}:
                raise ValueError(f"invalid disposition for {row.test}: {row.disposition}")
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", row.test):
                raise ValueError(f"invalid test name: {row.test}")
            if row.disposition != "run" and not row.reason:
                raise ValueError(f"{row.test} needs an exclusion reason")
            rows.append(row)
    names = [row.test for row in rows]
    if len(names) != len(set(names)):
        raise ValueError("selection.tsv contains duplicate test names")
    candidate_count = sum(row.disposition in {"run", "skip"} for row in rows)
    if candidate_count != 89:
        raise ValueError(
            f"selection.tsv must contain 89 candidate tests, found {candidate_count}"
        )
    return rows


def validate_tree_inventory(tree: Path, selection: list[Selection]) -> None:
    declared = {row.test for row in selection}
    tracked = subprocess.run(
        ["git", "ls-files", ":(glob)regress/*.sh"],
        cwd=tree,
        check=False,
        capture_output=True,
        text=True,
    )
    if tracked.returncode == 0 and tracked.stdout.strip():
        available = {Path(line).stem for line in tracked.stdout.splitlines()}
    else:
        available = {path.stem for path in (tree / "regress").glob("*.sh")}
    missing = sorted(declared - available)
    unexpected = sorted(available - declared)
    if missing or unexpected:
        details = []
        if missing:
            details.append(f"missing from pinned tree: {', '.join(missing)}")
        if unexpected:
            details.append(f"missing from selection.tsv: {', '.join(unexpected)}")
        raise ValueError("manifest drift: " + "; ".join(details))


def platform_key() -> str:
    system = platform.system().lower()
    return "macos" if system == "darwin" else system


def run_checked(command: list[str], cwd: Path) -> None:
    print(f"+ {' '.join(command)}", flush=True)
    subprocess.run(command, cwd=cwd, check=True)


def ensure_bssh(path: Path | None) -> Path:
    if path is None:
        run_checked(["cargo", "build", "--locked", "--bin", "bssh"], REPO_ROOT)
        path = REPO_ROOT / "target" / "debug" / "bssh"
    resolved = path.expanduser().resolve()
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise FileNotFoundError(f"bssh binary is not executable: {resolved}")
    return resolved


def ensure_openssh(path: Path | None, work_dir: Path, pin: Pin, jobs: int) -> Path:
    managed_clone = path is None
    if path is None:
        path = work_dir / f"openssh-portable-{pin.tag}"
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            run_checked(
                [
                    "git",
                    "clone",
                    "--depth",
                    "1",
                    "--branch",
                    pin.tag,
                    "https://github.com/openssh/openssh-portable.git",
                    str(path),
                ],
                REPO_ROOT,
            )
    resolved = path.expanduser().resolve()
    if managed_clone:
        actual_commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=resolved,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if actual_commit != pin.commit:
            raise ValueError(
                f"OpenSSH {pin.tag} resolved to {actual_commit}, expected {pin.commit}"
            )
    if not (resolved / "Makefile").exists():
        privsep_path = work_dir / "privsep"
        privsep_path.mkdir(parents=True, exist_ok=True)
        run_checked(["autoreconf"], resolved)
        run_checked(["./configure", f"--with-privsep-path={privsep_path}"], resolved)
    run_checked(["make", f"-j{jobs}", "all", "regress-binaries"], resolved)
    required = [
        "ssh",
        "sshd",
        "sshd-session",
        "sshd-auth",
        "sftp-server",
        "regress/test-exec.sh",
    ]
    missing = [name for name in required if not (resolved / name).exists()]
    if missing:
        raise FileNotFoundError(f"reference tree is missing: {', '.join(missing)}")
    return resolved


def make_value(makefile: Path, name: str, default: str = "") -> str:
    match = re.search(
        rf"^{re.escape(name)}\s*=\s*(.*)$", makefile.read_text(encoding="utf-8"), re.M
    )
    return match.group(1).strip().strip(chr(34)) if match else default


def reference_environment(tree: Path, client: Path) -> dict[str, str]:
    makefile = tree / "Makefile"
    env = os.environ.copy()
    helpers = {
        "TEST_SSH_SCP": "scp",
        "TEST_SSH_SSH": str(client),
        "TEST_SSH_SSHD": "sshd",
        "TEST_SSH_SSHD_SESSION": "sshd-session",
        "TEST_SSH_SSHD_AUTH": "sshd-auth",
        "TEST_SSH_SSHAGENT": "ssh-agent",
        "TEST_SSH_SSHADD": "ssh-add",
        "TEST_SSH_SSHKEYGEN": "ssh-keygen",
        "TEST_SSH_SSHPKCS11HELPER": "ssh-pkcs11-helper",
        "TEST_SSH_SSHKEYSCAN": "ssh-keyscan",
        "TEST_SSH_SFTP": "sftp",
        "TEST_SSH_PKCS11_HELPER": "ssh-pkcs11-helper",
        "TEST_SSH_SK_HELPER": "ssh-sk-helper",
        "TEST_SSH_SFTPSERVER": "sftp-server",
    }
    for name, value in helpers.items():
        env[name] = value if name == "TEST_SSH_SSH" else str(tree / value)
    env.update(
        {
            "BUILDDIR": str(tree),
            "OBJ": str(tree / "regress"),
            "PATH": f"{tree}{os.pathsep}{env.get('PATH', '')}",
            "TEST_SHELL": make_value(makefile, "TEST_SHELL", "/bin/sh"),
            "TEST_SSH_MODULI_FILE": str(tree / "moduli"),
            "TEST_SSH_IPV6": make_value(makefile, "TEST_SSH_IPV6", "yes"),
            "TEST_SSH_UTF8": make_value(makefile, "TEST_SSH_UTF8", "yes"),
            "EXEEXT": make_value(makefile, "EXEEXT"),
            "EGREP": make_value(makefile, "EGREP"),
            "OPENSSL_BIN": make_value(makefile, "OPENSSL_BIN", "openssl"),
            "TEST_MALLOC_OPTIONS": make_value(makefile, "TEST_MALLOC_OPTIONS"),
        }
    )
    env["MALLOC_OPTIONS"] = env["TEST_MALLOC_OPTIONS"]
    env["TEST_ENV"] = f'MALLOC_OPTIONS="{env["TEST_MALLOC_OPTIONS"]}"'
    env.setdefault("SUDO", "")
    optional = {
        "TEST_SSH_PLINK": "PLINK",
        "TEST_SSH_PUTTYGEN": "PUTTYGEN",
        "TEST_SSH_CONCH": "CONCH",
        "TEST_SSH_DROPBEAR": "DROPBEAR",
        "TEST_SSH_DROPBEARKEY": "DROPBEARKEY",
        "TEST_SSH_DROPBEARCONVERT": "DROPBEARCONVERT",
        "TEST_SSH_DBCLIENT": "DBCLIENT",
        "TEST_SSH_TMUX": "TMUX",
    }
    for env_name, make_name in optional.items():
        env[env_name] = make_value(makefile, make_name)
    return env


def run_process(
    command: list[str],
    cwd: Path,
    env: dict[str, str],
    timeout: int,
    log_path: Path | None = None,
) -> ProcessResult:
    started = time.monotonic()
    capture_head = bytearray()
    capture_tail = bytearray()
    capture_truncated = False
    log_truncated = False
    log_written = 0
    log_stream = None
    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_stream = log_path.open("wb")
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    assert process.stdout is not None
    os.set_blocking(process.stdout.fileno(), False)
    stop_reader = threading.Event()

    def drain_output() -> None:
        nonlocal capture_truncated, log_truncated, log_written
        assert process.stdout is not None
        empty_after_stop = False
        while True:
            try:
                chunk = os.read(process.stdout.fileno(), 64 * 1024)
            except BlockingIOError:
                if stop_reader.is_set():
                    if empty_after_stop:
                        break
                    empty_after_stop = True
                else:
                    stop_reader.wait(0.05)
                continue
            except (OSError, ValueError):
                break
            if not chunk:
                break
            empty_after_stop = False
            raw_chunk = chunk
            head_remaining = MAX_CAPTURE_BYTES // 2 - len(capture_head)
            if head_remaining > 0:
                capture_head.extend(chunk[:head_remaining])
                chunk = chunk[head_remaining:]
            if chunk:
                capture_tail.extend(chunk)
                tail_limit = MAX_CAPTURE_BYTES // 2
                if len(capture_tail) > tail_limit:
                    del capture_tail[:-tail_limit]
                    capture_truncated = True
            if log_stream is not None:
                log_remaining = MAX_LOG_BYTES - log_written
                if log_remaining > 0:
                    written = log_stream.write(raw_chunk[:log_remaining])
                    log_written += written
                if len(raw_chunk) > log_remaining:
                    log_truncated = True

    reader = threading.Thread(target=drain_output, name="openssh-regress-log", daemon=True)
    reader.start()
    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(process.pid, signal.SIGINT)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
    stop_reader.set()
    reader.join(timeout=1)
    assert process.stdout is not None
    if reader.is_alive():
        os.close(process.stdout.fileno())
        reader.join(timeout=1)
    if reader.is_alive():
        raise RuntimeError("output reader did not stop after pipe closure")
    try:
        process.stdout.close()
    except (OSError, ValueError):
        pass
    if log_stream is not None:
        if log_truncated:
            log_stream.seek(max(0, MAX_LOG_BYTES - len(TRUNCATION_NOTICE)))
            log_stream.write(TRUNCATION_NOTICE)
            log_stream.truncate()
        log_stream.close()
    captured = bytes(capture_head)
    if capture_truncated:
        captured += TRUNCATION_NOTICE
    captured += bytes(capture_tail)
    output = captured.decode("utf-8", errors="replace")
    duration_ms = round((time.monotonic() - started) * 1000)
    return ProcessResult(process.returncode, duration_ms, output, timed_out)


def first_failure(result: ProcessResult) -> str | None:
    if result.timed_out:
        return "timed out"
    lines = [line.strip() for line in result.output.splitlines() if line.strip()]
    for line in lines:
        if FAILURE_PATTERN.search(line):
            return line[:1000]
    return lines[0][:1000] if result.returncode != 0 and lines else None


def run_one(
    tree: Path, client: Path, name: str, timeout: int, log_dir: Path, client_label: str
) -> ProcessResult:
    script = tree / "regress" / f"{name}.sh"
    if not script.is_file():
        raise FileNotFoundError(f"selected test is absent from pinned tree: {script}")
    env = reference_environment(tree, client)
    command = [
        env["TEST_SHELL"],
        str(tree / "regress" / "test-exec.sh"),
        str(tree / "regress"),
        str(script),
    ]
    result = run_process(
        command,
        tree / "regress",
        env,
        timeout,
        log_dir / f"{name}-{client_label}.log",
    )
    if result.timed_out:
        stop_stale_sshd(tree)
    return result


def stop_stale_sshd(tree: Path) -> None:
    pidfile = tree / "regress" / "pidfile"
    if not pidfile.is_file():
        return
    raw_pid = pidfile.read_text(encoding="utf-8").strip()
    if not raw_pid.isdigit() or int(raw_pid) < 2:
        raise RuntimeError(f"refusing invalid stale sshd pid: {raw_pid!r}")
    pid = int(raw_pid)
    command = subprocess.run(
        ["ps", "-p", str(pid), "-o", "comm="],
        check=False,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not command:
        pidfile.unlink(missing_ok=True)
        return
    if not Path(command).name.startswith("sshd"):
        raise RuntimeError(f"refusing to stop non-sshd process {pid}: {command}")
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pidfile.unlink(missing_ok=True)
        return
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if not pidfile.exists():
            return
        time.sleep(0.1)
    current_command = subprocess.run(
        ["ps", "-p", str(pid), "-o", "comm="],
        check=False,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if current_command and current_command != command:
        raise RuntimeError(
            f"refusing to stop reused pid {pid}: {current_command}"
        )
    if current_command:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    pidfile.unlink(missing_ok=True)


def classify(
    tree: Path, bssh: Path, reference: Path, name: str, timeout: int, log_dir: Path
) -> TestResult:
    candidate = run_one(tree, bssh, name, timeout, log_dir, "candidate")
    skip_line = next(
        (line.strip() for line in candidate.output.splitlines() if line.startswith("SKIPPED:")),
        None,
    )
    if (
        skip_line is not None
        and candidate.returncode == 0
        and not candidate.timed_out
    ):
        return TestResult(name, "skip", candidate.duration_ms, skip_line)
    if candidate.returncode == 0 and not candidate.timed_out:
        return TestResult(name, "pass", candidate.duration_ms, None)
    baseline = run_one(tree, reference, name, timeout, log_dir, "reference")
    verdict = "fail" if baseline.returncode == 0 and not baseline.timed_out else "environmental"
    return TestResult(
        name,
        verdict,
        candidate.duration_ms,
        first_failure(candidate),
        first_failure(baseline) if verdict == "environmental" else None,
    )


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def reset_log_directory(path: Path) -> None:
    marker = path / ".bssh-openssh-regress"
    marker_contents = "bssh OpenSSH regress logs\n"
    if path.exists():
        owned = marker.is_file() and marker.read_text(encoding="utf-8") == marker_contents
        if not owned:
            raise ValueError(f"refusing to remove unowned log directory: {path}")
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=False)
    marker.write_text(marker_contents, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bssh", type=Path, help="use this prebuilt bssh binary")
    parser.add_argument("--openssh-tree", type=Path, help="use this configured reference tree")
    parser.add_argument("--work-dir", type=Path, default=DEFAULT_WORK_DIR)
    parser.add_argument("--selection", type=Path, default=DEFAULT_SELECTION)
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--timeout", type=int, default=120, help="seconds per client run")
    parser.add_argument("--jobs", type=int, default=max(1, min(os.cpu_count() or 1, 4)))
    parser.add_argument("--test", action="append", help="run only the named selected test")
    parser.add_argument("--list", action="store_true", help="validate and list the manifest")
    parser.add_argument("--update-baseline", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    pin = read_pin()
    tag = pin.tag
    selection = read_selection(args.selection)
    runnable = [row for row in selection if row.disposition == "run"]
    declared_skips = [row for row in selection if row.disposition == "skip"]
    excluded = [row for row in selection if row.disposition == "exclude"]
    if args.test:
        wanted = set(args.test)
        missing = wanted - {row.test for row in runnable}
        if missing:
            raise ValueError(f"tests are not runnable: {', '.join(sorted(missing))}")
        runnable = [row for row in runnable if row.test in wanted]
    if args.list:
        print(
            f"OpenSSH {tag}: {len(runnable)} runnable, "
            f"{len(declared_skips)} permanent skips, {len(excluded)} excluded"
        )
        for row in selection:
            print(f"{row.disposition:7} {row.test} {row.reason}")
        return 0
    if args.timeout < 1:
        raise ValueError("--timeout must be positive")
    if not 1 <= args.jobs <= 32:
        raise ValueError("--jobs must be between 1 and 32")
    if args.test and args.update_baseline:
        raise ValueError("--update-baseline requires the complete selected suite")
    work_dir = args.work_dir.resolve()
    log_dir = work_dir / "logs"
    reset_log_directory(log_dir)
    args.results.expanduser().unlink(missing_ok=True)
    bssh = ensure_bssh(args.bssh)
    tree = ensure_openssh(args.openssh_tree, work_dir, pin, args.jobs)
    validate_tree_inventory(tree, selection)
    results: list[TestResult] = []
    for index, row in enumerate(runnable, start=1):
        print(f"[{index}/{len(runnable)}] {row.test}", flush=True)
        result = classify(tree, bssh, tree / "ssh", row.test, args.timeout, log_dir)
        results.append(result)
        print(f"  {result.verdict} ({result.duration_ms} ms)", flush=True)
    verdicts = ["pass", "skip", "fail", "environmental"]
    counts = {
        name: sum(result.verdict == name for result in results) for name in verdicts
    }
    denominator = counts["pass"] + counts["fail"]
    payload = {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "openssh_tag": tag,
        "platform": platform_key(),
        "selection": {
            "runnable": len(runnable),
            "permanent_skips": [asdict(row) for row in declared_skips],
            "excluded": [asdict(row) for row in excluded],
        },
        "score": {"passed": counts["pass"], "eligible": denominator, "verdicts": counts},
        "results": [asdict(result) for result in sorted(results, key=lambda item: item.test)],
    }
    write_json(args.results, payload)
    baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
    baseline_tag = baseline.get("openssh_tag")
    if baseline_tag != tag and not args.update_baseline:
        raise ValueError(
            f"baseline tag {baseline_tag!r} does not match pinned OpenSSH tag {tag!r}"
        )
    key = platform_key()
    if args.update_baseline:
        baseline.setdefault("minimum_pass", {})[key] = counts["pass"]
        baseline.setdefault("minimum_eligible", {})[key] = denominator
        baseline["openssh_tag"] = tag
        write_json(args.baseline, baseline)
    minimum = baseline.get("minimum_pass", {}).get(key)
    minimum_eligible = baseline.get("minimum_eligible", {}).get(key)
    if minimum is None:
        raise ValueError(f"baseline has no minimum_pass entry for {key}")
    if minimum_eligible is None:
        raise ValueError(f"baseline has no minimum_eligible entry for {key}")
    print(
        f"score: {counts['pass']}/{denominator}; suite skips: {counts['skip']}; "
        f"permanent skips: {len(declared_skips)}; environmental: "
        f"{counts['environmental']}; required pass floor: "
        f"{minimum}; required eligible floor: {minimum_eligible}",
        flush=True,
    )
    if args.test:
        return 0
    if denominator < minimum_eligible:
        print(
            f"eligible result regression: {denominator} < {minimum_eligible}",
            file=sys.stderr,
        )
        return 1
    if counts["pass"] < minimum:
        print(f"score regression: {counts['pass']} < {minimum}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        print(f"openssh-regress: {error}", file=sys.stderr)
        raise SystemExit(2) from error
