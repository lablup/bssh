# bssh benchmark and interop harness

Scripts for measuring `bssh-server` SFTP performance relative to OpenSSH on
the same host, capturing CPU flamegraphs, and validating interoperability
with third-party SFTP client stacks (sshj, paramiko).

This harness produced the measurements recorded in issues
[#225](https://github.com/lablup/bssh/issues/225) and
[#226](https://github.com/lablup/bssh/issues/226), and found the paramiko
read-path hang tracked in [#227](https://github.com/lablup/bssh/issues/227).
Background: [#187](https://github.com/lablup/bssh/issues/187) and PR
[#224](https://github.com/lablup/bssh/pull/224).

## Layout

| Script | Purpose |
|---|---|
| `bench.sh` | Relative SFTP throughput: OpenSSH sshd vs bssh-server (optionally plus a baseline bssh build) |
| `profile.sh` | `perf` CPU profile and flamegraph of bssh-server during uploads |
| `interop/paramiko_test.py` | Round-trip integrity check with paramiko (Python SSH stack, used by Ansible) |
| `interop/sshj/run-sshj.sh` | Round-trip integrity and negotiation check with sshj (Java SSH stack, used by Cyberduck) |
| `lib.sh` | Shared setup: keys, configs, test file, server lifecycle, timed transfers |

All servers run on loopback only, with keys and configs generated fresh under
`BENCH_DIR`. Nothing touches the user's real SSH configuration.

## Prerequisites

- A release build of the server: `cargo build --release --bin bssh-server`
  (for `profile.sh`, prefer `CARGO_PROFILE_RELEASE_DEBUG=true cargo build --release --bin bssh-server` so stacks resolve)
- OpenSSH client (`ssh`, `sftp`, `ssh-keygen`); OpenSSH server (`/usr/sbin/sshd`) for `bench.sh`
- `profile.sh`: `perf`, `kernel.perf_event_paranoid <= 2`, and optionally `cargo install inferno` for SVG output
- `interop/paramiko_test.py`: `pip install paramiko`
- `interop/sshj/`: a JDK (`javac`/`java`, set `JAVA_HOME` if not on PATH), then `./fetch-deps.sh` once to download the pinned jars into `lib/` (not committed)

## Configuration

Everything is an environment variable with a default (see `lib.sh`):

| Variable | Default | Meaning |
|---|---|---|
| `BENCH_DIR` | `${TMPDIR:-/dev/shm}/bssh-bench-$USER` | Working directory (keys, configs, test file, results) |
| `BSSH_SERVER_BIN` | `target/release/bssh-server` | Server binary under test |
| `BSSH_BASELINE_BIN` | unset | Optional second binary for before/after comparison (`bench.sh`) |
| `BSSH_PORT` / `SSHD_PORT` | `22200` / `22022` | Loopback ports |
| `FILE_SIZE_MIB` | `2048` | Test file size |
| `RUNS` | `3` | Timed runs per direction |
| `SERVER_CORE` / `CLIENT_CORE` | unset (no pinning) | `taskset` core lists; pin the server to one core to emulate a single-core container |
| `CIPHER` | `chacha20-poly1305@openssh.com` | Cipher forced on OpenSSH-client transfers |
| `PROFILE_UPLOADS`, `PERF_FREQ`, `PERF_CALLGRAPH` | `3`, `499`, `fp` | `profile.sh` knobs |

## Examples

```bash
# Single-core relative benchmark (the #187 scenario), cores 8 and 9:
SERVER_CORE=8 CLIENT_CORE=9 tools/bench/bench.sh

# Before/after against an older build:
BSSH_BASELINE_BIN=/path/to/old/bssh-server tools/bench/bench.sh

# Flamegraph of the upload path:
CARGO_PROFILE_RELEASE_DEBUG=true cargo build --release --bin bssh-server
SERVER_CORE=8 CLIENT_CORE=9 tools/bench/profile.sh

# sshj interop (2 GiB round trip, negotiation log included):
tools/bench/interop/sshj/fetch-deps.sh
tools/bench/interop/sshj/run-sshj.sh

# paramiko interop; --no-prefetch works today, the default reproduces #227:
. tools/bench/lib.sh && bench_setup && start_bssh
python3 tools/bench/interop/paramiko_test.py \
  --user "$USER" --key "$BENCH_DIR/bench_key_rsa" \
  --file "$BENCH_DIR/testfile_2048M" --remote-dir "$BENCH_DIR/up" --no-prefetch
stop_servers
```

## Methodology notes

- Loopback removes the NIC bottleneck, so absolute numbers exceed any real
  network; the point is the ratio between servers measured under identical
  conditions. Pin both servers to the same single core (`SERVER_CORE`) to
  reproduce the CPU-bound single-core container scenario from #187.
- Every transfer is verified byte-for-byte (`cmp`) before it counts.
- Keep `BENCH_DIR` on tmpfs (the default) so disk I/O does not dominate.
- Timing includes the SSH handshake; with multi-GiB files its share is a few
  percent and identical across servers.

## Known issues

- `interop/paramiko_test.py` with default prefetch currently hangs against
  bssh-server (pre-existing server bug, not a #224 regression); tracked in
  [#227](https://github.com/lablup/bssh/issues/227). Once fixed, the default
  invocation doubles as the regression test.
- FileZilla and WinSCP are GUI-only and cannot run headless; both use
  PuTTY-derived transports, so a `psftp` (putty-tools) check is the closest
  scriptable proxy if needed.
