#!/bin/bash
# Capture a CPU profile (and flamegraph, when inferno is installed) of
# bssh-server while it serves SFTP uploads.
#
# Requirements:
#   - kernel.perf_event_paranoid <= 2 (sudo sysctl kernel.perf_event_paranoid=1)
#   - a bssh-server release build, ideally with debug symbols:
#       CARGO_PROFILE_RELEASE_DEBUG=true cargo build --release --bin bssh-server
#   - optional: cargo install inferno (for SVG flamegraph generation)
#
# See README.md for configuration variables.

set -u
cd "$(dirname "$0")"
. ./lib.sh

PARANOID=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo "?")
if [ "$PARANOID" != "?" ] && [ "$PARANOID" -gt 2 ]; then
  echo "kernel.perf_event_paranoid=$PARANOID forbids unprivileged profiling." >&2
  echo "Fix with: sudo sysctl kernel.perf_event_paranoid=1" >&2
  exit 1
fi

bench_setup
start_bssh || exit 1

perf record -F "${PERF_FREQ:-499}" -g --call-graph "${PERF_CALLGRAPH:-fp}" \
  -o "$BENCH_DIR/perf.data" -p "$BSSH_PID" 2>/dev/null &
PERF_PID=$!
sleep 1

for i in $(seq 1 "${PROFILE_UPLOADS:-3}"); do
  echo "upload $i: $(sftp_xfer "$BSSH_PORT" up) MiB/s"
done

kill -INT "$PERF_PID" 2>/dev/null
wait "$PERF_PID" 2>/dev/null
stop_servers

if command -v inferno-collapse-perf >/dev/null 2>&1 && command -v inferno-flamegraph >/dev/null 2>&1; then
  perf script -i "$BENCH_DIR/perf.data" 2>/dev/null | inferno-collapse-perf > "$BENCH_DIR/stacks.folded"
  inferno-flamegraph --title "bssh-server SFTP upload (${FILE_SIZE_MIB} MiB x ${PROFILE_UPLOADS:-3}, $CIPHER)" \
    "$BENCH_DIR/stacks.folded" > "$BENCH_DIR/flamegraph.svg"
  echo "flamegraph: $BENCH_DIR/flamegraph.svg"
else
  echo "inferno not found (cargo install inferno); raw profile kept at $BENCH_DIR/perf.data"
fi

echo "top symbols (self time):"
perf report -i "$BENCH_DIR/perf.data" --stdio --no-children --sort symbol -g none --percent-limit 1.0 2>/dev/null \
  | grep -vE "^#|^[[:space:]]*$" | head -15
