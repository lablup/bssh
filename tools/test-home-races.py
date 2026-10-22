#!/usr/bin/env python3
"""Repeat HOME readers and a HOME writer together, preserving failure diagnostics.

Build with `cargo test --lib --no-run`, then pass the emitted test executable:
    python3 tools/test-home-races.py target/debug/deps/bssh-HASH /tmp/home-races
Each process still runs parallel test threads; process-level parallelism alone
cannot reproduce a race on process-local environment variables.
"""

import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import subprocess
import time

FILTERS = [
    "ssh::known_hosts::tests",
    "known_hosts_command_output_is_reused_for_the_plain_key_fallback",
    "config::tests::test_expand_tilde",
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--runs", type=int, default=1000)
    parser.add_argument("--jobs", type=int, default=8)
    args = parser.parse_args()
    if args.runs < 1 or args.jobs < 1:
        parser.error("runs and jobs must be positive")
    binary = args.binary.resolve(strict=True)
    # Never overwrite evidence from an earlier baseline or verification run.
    args.output.mkdir(parents=True, exist_ok=False)
    command = [str(binary), *FILTERS, "--test-threads=8", "--nocapture"]
    listing = subprocess.check_output(
        [str(binary), *FILTERS, "--list"], text=True, timeout=30
    )
    for name in ["expands_home_directory_tokens_and_tilde",
                 "expands_full_known_hosts_token_set_and_environment",
                 "known_hosts_command_output_is_reused_for_the_plain_key_fallback",
                 "config::tests::test_expand_tilde"]:
        if name not in listing:
            parser.error(f"test binary is missing {name}")
    (args.output / "tests.txt").write_text(listing)
    environment = dict(os.environ, RUST_BACKTRACE="1")

    def run(index):
        try:
            result = subprocess.run(
                command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                env=environment, timeout=30, check=False,
            )
            output, code = result.stdout, result.returncode
        except subprocess.TimeoutExpired as error:
            output = (error.stdout or b"") + b"\nTimed out after 30 seconds\n"
            code = 124
        (args.output / f"{index:04}.log").write_bytes(output)
        return code

    started = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        codes = list(pool.map(run, range(args.runs)))
    summary = {
        "command": command, "jobs": args.jobs, "runs": len(codes),
        "failed_runs": [i for i, code in enumerate(codes) if code != 0],
        "seconds": round(time.monotonic() - started, 2),
    }
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return int(bool(summary["failed_runs"]))


if __name__ == "__main__":
    raise SystemExit(main())
