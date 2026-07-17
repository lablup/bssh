#!/bin/bash
# Shared helpers for the bssh benchmark and interop harness.
# All configuration comes from environment variables; see README.md.

set -u

REPO_ROOT=${REPO_ROOT:-$(git -C "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" rev-parse --show-toplevel 2>/dev/null || pwd)}
BENCH_DIR=${BENCH_DIR:-${TMPDIR:-/dev/shm}/bssh-bench-$(id -un)}
BSSH_SERVER_BIN=${BSSH_SERVER_BIN:-$REPO_ROOT/target/release/bssh-server}
SSHD_BIN=${SSHD_BIN:-/usr/sbin/sshd}
BSSH_PORT=${BSSH_PORT:-22200}
SSHD_PORT=${SSHD_PORT:-22022}
FILE_SIZE_MIB=${FILE_SIZE_MIB:-2048}
RUNS=${RUNS:-3}
SERVER_CORE=${SERVER_CORE:-}
CLIENT_CORE=${CLIENT_CORE:-}
CIPHER=${CIPHER:-chacha20-poly1305@openssh.com}
SFTP_BIN=${SFTP_BIN:-/usr/bin/sftp}
SSH_BIN=${SSH_BIN:-/usr/bin/ssh}
TIMEOUT_BIN=${TIMEOUT_BIN:-timeout}
XFER_TIMEOUT=${XFER_TIMEOUT:-600}
USER_NAME=$(id -un)
BSSH_PID=
SSHD_PID=

# Echo a taskset prefix for the given core list, or nothing when unset.
pin() {
  [ -n "$1" ] && echo "taskset -c $1"
}

ssh_opts() {
  echo "-i $BENCH_DIR/bench_key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o Ciphers=$CIPHER -o BatchMode=yes"
}

# Create keys, server configs, and the random test file (idempotent).
bench_setup() {
  mkdir -p "$BENCH_DIR/up" "$BENCH_DIR/dl"
  chmod 700 "$BENCH_DIR"
  [ -f "$BENCH_DIR/bench_key" ] || ssh-keygen -q -t ed25519 -N '' -f "$BENCH_DIR/bench_key"
  # RSA in PEM format: paramiko and sshj both parse it without extra support code.
  [ -f "$BENCH_DIR/bench_key_rsa" ] || ssh-keygen -q -t rsa -b 3072 -m PEM -N '' -f "$BENCH_DIR/bench_key_rsa"
  [ -f "$BENCH_DIR/host_key" ] || ssh-keygen -q -t ed25519 -N '' -f "$BENCH_DIR/host_key"
  cat "$BENCH_DIR/bench_key.pub" "$BENCH_DIR/bench_key_rsa.pub" > "$BENCH_DIR/authorized_keys"
  chmod 600 "$BENCH_DIR/authorized_keys"

  TEST_FILE=$BENCH_DIR/testfile_${FILE_SIZE_MIB}M
  [ -f "$TEST_FILE" ] || dd if=/dev/urandom of="$TEST_FILE" bs=1M count="$FILE_SIZE_MIB" status=none

  cat > "$BENCH_DIR/bssh-server.yaml" <<EOF
server:
  bind_address: "127.0.0.1"
  port: $BSSH_PORT
  host_keys:
    - $BENCH_DIR/host_key
auth:
  methods:
    - publickey
  publickey:
    authorized_keys_pattern: "$BENCH_DIR/authorized_keys"
EOF
  chmod 600 "$BENCH_DIR/bssh-server.yaml"

  cat > "$BENCH_DIR/sshd_config" <<EOF
Port $SSHD_PORT
ListenAddress 127.0.0.1
HostKey $BENCH_DIR/host_key
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile $BENCH_DIR/authorized_keys
StrictModes no
Subsystem sftp internal-sftp
LogLevel ERROR
PidFile $BENCH_DIR/sshd.pid
EOF
}

# Start bssh-server; optional $1 overrides the binary (e.g. a baseline build).
start_bssh() {
  local bin=${1:-$BSSH_SERVER_BIN}
  [ -x "$bin" ] || { echo "FATAL: bssh-server binary not found: $bin (build with: cargo build --release --bin bssh-server)" >&2; return 1; }
  $(pin "$SERVER_CORE") "$bin" run -c "$BENCH_DIR/bssh-server.yaml" -D 2>>"$BENCH_DIR/bssh.log" &
  BSSH_PID=$!
  sleep 2
  echo "ls /" | "$TIMEOUT_BIN" 15 "$SFTP_BIN" $(ssh_opts) -q -P "$BSSH_PORT" -b - "$USER_NAME@127.0.0.1" >/dev/null 2>&1 \
    || { echo "FATAL: bssh-server not reachable on port $BSSH_PORT" >&2; tail -5 "$BENCH_DIR/bssh.log" >&2; return 1; }
}

start_sshd() {
  [ -x "$SSHD_BIN" ] || { echo "FATAL: sshd not found: $SSHD_BIN (install openssh-server)" >&2; return 1; }
  $(pin "$SERVER_CORE") "$SSHD_BIN" -f "$BENCH_DIR/sshd_config" -D -e 2>>"$BENCH_DIR/sshd.log" &
  SSHD_PID=$!
  sleep 2
  "$TIMEOUT_BIN" 15 "$SSH_BIN" $(ssh_opts) -p "$SSHD_PORT" "$USER_NAME@127.0.0.1" true 2>/dev/null \
    || { echo "FATAL: sshd not reachable on port $SSHD_PORT" >&2; tail -5 "$BENCH_DIR/sshd.log" >&2; return 1; }
}

stop_servers() {
  [ -n "$BSSH_PID" ] && kill "$BSSH_PID" 2>/dev/null
  [ -n "$SSHD_PID" ] && kill "$SSHD_PID" 2>/dev/null
  wait 2>/dev/null
  BSSH_PID=
  SSHD_PID=
}

# One timed transfer via the OpenSSH sftp client.
# $1 = port, $2 = up|dl. Prints integer MiB/s on success, FAIL(rc=N) otherwise.
# Every transfer is integrity-checked with cmp before it counts.
sftp_xfer() {
  local port=$1 dir=$2 dest cmd rc t0 t1
  if [ "$dir" = up ]; then
    dest="$BENCH_DIR/up/x$$"
    cmd="put $TEST_FILE $dest"
  else
    dest="$BENCH_DIR/dl/x$$"
    cmd="get $TEST_FILE $dest"
  fi
  rm -f "$dest"
  t0=$(date +%s.%N)
  echo "$cmd" | $(pin "$CLIENT_CORE") "$TIMEOUT_BIN" "$XFER_TIMEOUT" "$SFTP_BIN" $(ssh_opts) -q -P "$port" -b - "$USER_NAME@127.0.0.1" >/dev/null 2>&1
  rc=$?
  t1=$(date +%s.%N)
  if [ $rc -ne 0 ] || ! cmp -s "$TEST_FILE" "$dest"; then
    echo "FAIL(rc=$rc)"
  else
    awk -v s="$FILE_SIZE_MIB" -v a="$t0" -v b="$t1" 'BEGIN{printf "%.0f", s/(b-a)}'
  fi
  rm -f "$dest"
}
