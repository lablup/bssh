# OpenSSH compatibility regression harness

The compatibility harness runs a pinned subset of the OpenSSH portable regression suite with bssh as the client and the pinned OpenSSH build as the server and reference client. The tag and immutable commit pin are stored together in `tests/openssh-regress/openssh-version`; changing that file deliberately starts a fresh reference build.

## Run locally

The full run needs a C toolchain, OpenSSL development headers, zlib development headers, Git, Make, Python 3.11 or newer, and the Rust toolchain declared by this repository. On Debian or Ubuntu, install `build-essential autoconf automake libssl-dev zlib1g-dev`; macOS runners can use the Xcode command-line tools and Homebrew `autoconf`, `automake`, and `openssl@3`.

Run the manifest self-tests before starting the substantially longer compatibility suite:

```console
make openssh-regress-selftest
make openssh-regress-list
make openssh-regress
```

The first full invocation builds `target/debug/bssh`, clones `V_10_3_P1` under `target/openssh-regress/`, configures and builds the reference binaries, and runs every selected test. Later invocations reuse both build trees. Use `--bssh` or `--openssh-tree` with `tests/openssh-regress/run.py` to supply prebuilt trees, `--timeout` to change the per-test limit, and repeated `--test NAME` arguments for focused diagnosis.

`make openssh-regress-update` writes the full per-test table to `tests/openssh-regress/results.json` and updates the current platform's minimum passing and eligible-result floors in `baseline.json`. Review both diffs before committing them. Never update the baseline merely to make an unexplained regression green.

## Interpret results

Each runnable test receives one of three scored verdict classes:

- `pass`: bssh completed the test successfully.
- `fail`: bssh failed or timed out, while the same test passed with the pinned OpenSSH reference client. This is a bssh compatibility failure.
- `environmental`: both bssh and the OpenSSH reference client failed or timed out. This does not count against the eligible score because the environment cannot establish the expected behavior.

An upstream `SKIPPED:` result is reported as `skip` and excluded from the eligible denominator. Permanent candidate skips are declared with reasons in `selection.tsv`; tests outside the selected client suite remain listed as `exclude` rows for auditability. Neither class is reported as a bssh failure.

The score is `pass / (pass + fail)`. CI compares both the pass count and the environment-valid result count with platform-specific floors in `baseline.json`, uploads the generated JSON table even on failure, and fails when either count drops below its floor. Durations are milliseconds, and `first_failure_line` is the first diagnostic line selected from the captured combined harness output; per-test logs are streamed under `target/openssh-regress/logs/` and capped at 16 MiB each.

The complete #275 implementation run recorded in `tests/openssh-regress/results.json` measured 60 pass, nine fail, four environmental, and six upstream skips on Linux: 60/69 eligible tests. The `agent`, `banner`, `connect-uri`, and `portnum` suites account for the final four passes over the preceding 56/69 measurement. Both Linux and macOS now enforce the epic's 60-pass floor; CI supplies the platform-specific verification on each pull request.

The eligible floors remain 67 on Linux and 65 on macOS. The current Linux run produced 69 eligible results from 79 runnable rows after six upstream skips and four environmental results. The lower eligible floors preserve bounded tolerance for platform-specific environmental failures while still rejecting a collapsed all-environmental run. Focused `--test` runs report verdicts without enforcing full-suite floors.

## Candidate inventory

The pinned manifest contains 79 runnable client tests and 11 permanent candidate skips, preserving a 90-test candidate inventory. Another 25 server-only or otherwise out-of-scope rows remain explicitly excluded, accounting for all 115 shell tests in the pinned tree. `forwarding` remains runnable because it covers local, remote, and standard-input forwarding; the out-of-scope X11 and tun-device features do not justify skipping it. `allow-deny-users` is excluded as a pure sshd configuration test, while `sftp-chroot` and `reconfigure` remain reasoned permanent sshd-side skips.

The historical measurement in issue #275 reported 116 shell tests and listed `pubkey-priority` as an environmental failure. The exact `V_10_3_P1` tree contains 115 shell tests and its `LTESTS` inventory has no `pubkey-priority`. The committed `results.json` now records the complete current 79-row run, while every run validates `selection.tsv` against the pinned tree and rejects invented or stale test names.
