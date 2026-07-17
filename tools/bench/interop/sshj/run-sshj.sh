#!/bin/bash
# Compile and run the sshj interop check against a locally started bssh-server.
#
# Requires a JDK (javac + java). Set JAVA_HOME to use a specific one, and run
# ./fetch-deps.sh once to populate lib/. See ../../README.md for the
# configuration variables shared with the rest of the harness.

set -u
cd "$(dirname "$0")"
. ../../lib.sh

JAVA=${JAVA_HOME:+$JAVA_HOME/bin/}java
JAVAC=${JAVA_HOME:+$JAVA_HOME/bin/}javac
command -v "$JAVAC" >/dev/null 2>&1 || { echo "FATAL: javac not found; install a JDK or set JAVA_HOME" >&2; exit 1; }
[ -f lib/sshj-0.38.0.jar ] || { echo "FATAL: jars missing; run ./fetch-deps.sh first" >&2; exit 1; }

CP=$(ls lib/*.jar | tr '\n' ':')
"$JAVAC" -cp "$CP" SshjTest.java || exit 1

bench_setup
start_bssh || exit 1

"$JAVA" -cp "$CP." \
  -Dorg.slf4j.simpleLogger.log.net.schmizz.sshj.transport=debug \
  -Dorg.slf4j.simpleLogger.log.net.schmizz.sshj.connection=debug \
  SshjTest "$BSSH_PORT" "$USER_NAME" "$BENCH_DIR/bench_key_rsa" \
  "$TEST_FILE" "$BENCH_DIR/up/sshj_up" "$BENCH_DIR/dl/sshj_down" "$BENCH_DIR" \
  > "$BENCH_DIR/sshj-run.out" 2> "$BENCH_DIR/sshj-debug.log"
RC=$?
stop_servers

echo "=== exit: $RC ==="
cat "$BENCH_DIR/sshj-run.out"
echo "=== integrity ==="
if cmp -s "$TEST_FILE" "$BENCH_DIR/dl/sshj_down"; then
  echo "ROUNDTRIP_INTEGRITY_OK"
else
  echo "ROUNDTRIP_INTEGRITY_FAIL"
  RC=1
fi
rm -f "$BENCH_DIR/dl/sshj_down"
echo "=== negotiation (client debug log) ==="
grep -iE "Negotiated algorithms|Sending SSH_MSG_KEXINIT|Received SSH_MSG_KEXINIT" "$BENCH_DIR/sshj-debug.log" | head -5
exit $RC
