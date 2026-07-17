#!/bin/bash
# Relative SFTP throughput: OpenSSH sshd vs bssh-server on the same host.
#
# Runs both servers on loopback (optionally pinned to the same CPU core to
# emulate a single-core container) and measures timed uploads and downloads
# with the OpenSSH sftp client. Set BSSH_BASELINE_BIN to also measure an
# older bssh-server build for a before/after comparison.
#
# Example (single-core scenario, big cores 8 and 9):
#   SERVER_CORE=8 CLIENT_CORE=9 tools/bench/bench.sh
#
# See README.md for all configuration variables and methodology notes.

set -u
cd "$(dirname "$0")"
. ./lib.sh

bench_setup

measure() {
  local label=$1 port=$2 dir vals i
  for dir in up dl; do
    vals=""
    for i in $(seq 1 "$RUNS"); do
      vals="$vals $(sftp_xfer "$port" "$dir")"
    done
    echo "RESULT $label $dir$vals"
  done
}

echo "# cipher: $CIPHER, file: ${FILE_SIZE_MIB} MiB, runs: $RUNS, server core: ${SERVER_CORE:-unpinned}, client core: ${CLIENT_CORE:-unpinned}"
echo "# results are MiB/s per run; every transfer is integrity-checked with cmp"

if start_sshd; then
  measure openssh "$SSHD_PORT"
  stop_servers
fi

if start_bssh; then
  measure bssh "$BSSH_PORT"
  stop_servers
fi

if [ -n "${BSSH_BASELINE_BIN:-}" ]; then
  if start_bssh "$BSSH_BASELINE_BIN"; then
    measure bssh-baseline "$BSSH_PORT"
    stop_servers
  fi
fi
