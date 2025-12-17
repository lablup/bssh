#!/usr/bin/env bash
# Basic pdsh compatibility tests

set -euo pipefail

# Disable errexit for arithmetic expressions (workaround for (()) returning 1 on 0)
set +e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test configuration
TEST_HOST="${BSSH_TEST_HOST:-localhost}"
TEST_USER="${BSSH_TEST_USER:-$USER}"
PDSH_CMD="${PDSH_CMD:-bssh --pdsh-compat}"
VERBOSE="${BSSH_TEST_VERBOSE:-0}"

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Helper functions
log_test() {
    echo -e "${YELLOW}[TEST]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

run_test() {
    TESTS_RUN=$((TESTS_RUN + 1))
    local test_name="$1"
    shift
    local expected_exit="$1"
    shift

    log_test "$test_name"

    if [ "$VERBOSE" = "1" ]; then
        echo "Command: $*"
    fi

    local output
    local exit_code

    if output=$("$@" 2>&1); then
        exit_code=0
    else
        exit_code=$?
    fi

    if [ "$VERBOSE" = "1" ]; then
        echo "Output: $output"
        echo "Exit code: $exit_code"
    fi

    if [ "$exit_code" -eq "$expected_exit" ]; then
        log_pass "$test_name"
        return 0
    else
        log_fail "$test_name (expected exit $expected_exit, got $exit_code)"
        return 1
    fi
}

# Test suite
echo "================================"
echo "pdsh Basic Compatibility Tests"
echo "================================"
echo "Test host: $TEST_HOST"
echo "Test user: $TEST_USER"
echo "Command: $PDSH_CMD"
echo

# Test 1: Basic command execution
run_test "Basic command execution" 0 \
    ${PDSH_CMD} -w "$TEST_HOST" "echo hello"

# Test 2: Command with output verification
run_test "Output verification" 0 \
    bash -c "$PDSH_CMD -w '$TEST_HOST' 'echo test' | grep -q 'test'"

# Test 3: Query mode
run_test "Query mode (-q)" 0 \
    ${PDSH_CMD} -w "$TEST_HOST" -q

# Test 4: Query mode output verification
run_test "Query mode output" 0 \
    bash -c "$PDSH_CMD -w '$TEST_HOST' -q | grep -q '$TEST_HOST'"

# Test 5: No prefix mode (-N)
run_test "No prefix mode (-N)" 0 \
    bash -c "$PDSH_CMD -w '$TEST_HOST' -N 'echo test' | grep -q '^test$'"

# Test 6: Command with exit code 0
run_test "Exit code 0 command" 0 \
    ${PDSH_CMD} -w "$TEST_HOST" "true"

# Test 7: Command with exit code 1
run_test "Exit code 1 command" 1 \
    ${PDSH_CMD} -w "$TEST_HOST" "false"

# Test 8: User specification
if [ "$TEST_USER" != "root" ]; then
    run_test "User specification (-l)" 0 \
        ${PDSH_CMD} -w "$TEST_HOST" -l "$TEST_USER" "whoami"
fi

# Test 9: Multiple commands with semicolon
run_test "Multiple commands" 0 \
    ${PDSH_CMD} -w "$TEST_HOST" "echo first && echo second"

# Test 10: Command with quotes
run_test "Command with quotes" 0 \
    ${PDSH_CMD} -w "$TEST_HOST" "echo 'quoted string'"

# Test 11: Command with pipe
run_test "Command with pipe" 0 \
    ${PDSH_CMD} -w "$TEST_HOST" "echo test | grep test"

# Test 12: Long command
run_test "Long command" 0 \
    ${PDSH_CMD} -w "$TEST_HOST" "echo this is a very long command with many words"

# Test 13: Empty command (should fail with non-zero exit)
# Note: The exact exit code may vary; we test that it's non-zero
if ${PDSH_CMD} -w "$TEST_HOST" "" >/dev/null 2>&1; then
    log_fail "Empty command (should fail) - expected non-zero exit"
else
    log_pass "Empty command (should fail)"
fi
TESTS_RUN=$((TESTS_RUN + 1))

# Test 14: Hostname output
run_test "Hostname command" 0 \
    ${PDSH_CMD} -w "$TEST_HOST" "hostname"

# Test 15: Environment variable access
run_test "Environment variable" 0 \
    bash -c "${PDSH_CMD} -w '$TEST_HOST' 'echo \$PATH' | grep -q '/'"

# Summary
echo
echo "================================"
echo "Test Summary"
echo "================================"
echo "Tests run:    $TESTS_RUN"
echo "Tests passed: $TESTS_PASSED"
echo "Tests failed: $TESTS_FAILED"
echo

if [ "$TESTS_FAILED" -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed.${NC}"
    exit 1
fi
