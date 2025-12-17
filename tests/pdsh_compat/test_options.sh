#!/usr/bin/env bash
# pdsh option mapping tests

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

    log_test "$test_name"

    if [ "$VERBOSE" = "1" ]; then
        echo "Command: $*"
    fi

    if "$@" >/dev/null 2>&1; then
        log_pass "$test_name"
        return 0
    else
        log_fail "$test_name"
        return 1
    fi
}

# Test suite
echo "====================================="
echo "pdsh Option Mapping Tests"
echo "====================================="
echo "Test host: $TEST_HOST"
echo "Command: $PDSH_CMD"
echo

# Test 1: -w (host specification)
run_test "Option -w (hosts)" \
    $PDSH_CMD -w "$TEST_HOST" "echo test"

# Test 2: -l (user specification)
run_test "Option -l (user)" \
    $PDSH_CMD -w "$TEST_HOST" -l "$TEST_USER" "whoami"

# Test 3: -N (no prefix)
((TESTS_RUN++))
log_test "Option -N (no prefix)"
output=$($PDSH_CMD -w "$TEST_HOST" -N "echo test" 2>&1)
if echo "$output" | grep -q "^\[" ; then
    log_fail "Option -N (output still has prefix)"
else
    log_pass "Option -N (no prefix)"
fi

# Test 4: -q (query mode)
run_test "Option -q (query mode)" \
    $PDSH_CMD -w "$TEST_HOST" -q

# Test 5: -f (fanout/parallel)
run_test "Option -f (fanout)" \
    $PDSH_CMD -w "$TEST_HOST" -f 5 "echo test"

# Test 6: -t (connect timeout)
run_test "Option -t (connect timeout)" \
    $PDSH_CMD -w "$TEST_HOST" -t 10 "echo test"

# Test 7: -u (command timeout)
run_test "Option -u (command timeout)" \
    $PDSH_CMD -w "$TEST_HOST" -u 5 "echo test"

# Test 8: -x (exclude hosts)
((TESTS_RUN++))
log_test "Option -x (exclude)"
output=$($PDSH_CMD -w "host1,host2,host3" -x "host2" -q 2>&1)
if echo "$output" | grep -q "host1" && \
   echo "$output" | grep -q "host3" && \
   ! echo "$output" | grep -q "host2"; then
    log_pass "Option -x (exclude)"
else
    log_fail "Option -x (exclude)"
fi

# Test 9: -b (batch mode)
run_test "Option -b (batch mode)" \
    $PDSH_CMD -w "$TEST_HOST" -b "echo test"

# Test 10: -k (fail-fast)
run_test "Option -k (fail-fast)" \
    $PDSH_CMD -w "$TEST_HOST" -k "echo test"

# Test 11: Combined options -w -f -t
run_test "Combined options (-w -f -t)" \
    $PDSH_CMD -w "$TEST_HOST" -f 10 -t 5 "echo test"

# Test 12: Combined options -w -l -N
run_test "Combined options (-w -l -N)" \
    $PDSH_CMD -w "$TEST_HOST" -l "$TEST_USER" -N "echo test"

# Test 13: Combined options -w -x -q
((TESTS_RUN++))
log_test "Combined options (-w -x -q)"
output=$($PDSH_CMD -w "test[1-5]" -x "test[3-4]" -q 2>&1)
expected_count=3
actual_count=$(echo "$output" | wc -l | tr -d ' ')
if [ "$actual_count" -eq "$expected_count" ]; then
    log_pass "Combined options (-w -x -q)"
else
    log_fail "Combined options (-w -x -q) - expected $expected_count hosts, got $actual_count"
fi

# Test 14: All timeout options
run_test "All timeout options (-t -u)" \
    $PDSH_CMD -w "$TEST_HOST" -t 10 -u 60 "echo test"

# Test 15: Fanout with query
((TESTS_RUN++))
log_test "Fanout with query (-f -q)"
output=$($PDSH_CMD -w "host[1-3]" -f 2 -q 2>&1)
if [ "$(echo "$output" | wc -l | tr -d ' ')" -eq 3 ]; then
    log_pass "Fanout with query (-f -q)"
else
    log_fail "Fanout with query (-f -q)"
fi

# Test 16: Exclusion with glob pattern
((TESTS_RUN++))
log_test "Exclusion with glob (-x 'pattern*')"
output=$($PDSH_CMD -w "web1,web2,db1,db2" -x "db*" -q 2>&1)
if echo "$output" | grep -q "web1" && \
   echo "$output" | grep -q "web2" && \
   ! echo "$output" | grep -q "db"; then
    log_pass "Exclusion with glob (-x 'pattern*')"
else
    log_fail "Exclusion with glob (-x 'pattern*')"
fi

# Test 17: User with hostlist expression
run_test "User with hostlist (-l with -w expression)" \
    $PDSH_CMD -w "localhost" -l "$TEST_USER" "echo test"

# Test 18: No prefix with multiple outputs
((TESTS_RUN++))
log_test "No prefix with command output (-N)"
output=$($PDSH_CMD -w "$TEST_HOST" -N "echo line1; echo line2" 2>&1)
line_count=$(echo "$output" | grep -v "^\[" | wc -l | tr -d ' ')
if [ "$line_count" -ge 2 ]; then
    log_pass "No prefix with command output (-N)"
else
    log_fail "No prefix with command output (-N)"
fi

# Test 19: Query with username
((TESTS_RUN++))
log_test "Query with username (-l -q)"
output=$($PDSH_CMD -w "test@host1,test@host2" -q 2>&1)
if echo "$output" | grep -q "test@host1" && \
   echo "$output" | grep -q "test@host2"; then
    log_pass "Query with username (-l -q)"
else
    log_fail "Query with username (-l -q)"
fi

# Test 20: Complex exclusion pattern
((TESTS_RUN++))
log_test "Complex exclusion pattern"
output=$($PDSH_CMD -w "prod[1-10],staging[1-5]" -x "staging*" -q 2>&1)
if echo "$output" | grep -q "prod" && \
   ! echo "$output" | grep -q "staging"; then
    log_pass "Complex exclusion pattern"
else
    log_fail "Complex exclusion pattern"
fi

# Summary
echo
echo "====================================="
echo "Test Summary"
echo "====================================="
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
