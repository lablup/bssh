#!/usr/bin/env bash
# Hostlist expression compatibility tests

set -euo pipefail

# Disable errexit for arithmetic expressions (workaround for (()) returning 1 on 0)
set +e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test configuration
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

run_query_test() {
    TESTS_RUN=$((TESTS_RUN + 1))
    local test_name="$1"
    local hostlist="$2"
    shift 2
    local expected_hosts=("$@")

    log_test "$test_name"

    if [ "$VERBOSE" = "1" ]; then
        echo "Hostlist: $hostlist"
        echo "Expected: ${expected_hosts[*]}"
    fi

    local output
    if ! output=$($PDSH_CMD -w "$hostlist" -q 2>&1); then
        log_fail "$test_name (command failed)"
        return 1
    fi

    if [ "$VERBOSE" = "1" ]; then
        echo "Output: $output"
    fi

    # Convert output to array
    local -a actual_hosts
    mapfile -t actual_hosts <<< "$output"

    # Check count
    if [ "${#actual_hosts[@]}" -ne "${#expected_hosts[@]}" ]; then
        log_fail "$test_name (expected ${#expected_hosts[@]} hosts, got ${#actual_hosts[@]})"
        return 1
    fi

    # Check each host
    for expected_host in "${expected_hosts[@]}"; do
        if ! echo "$output" | grep -q "^${expected_host}$"; then
            log_fail "$test_name (missing host: $expected_host)"
            return 1
        fi
    done

    log_pass "$test_name"
    return 0
}

# Test suite
echo "====================================="
echo "pdsh Hostlist Expression Tests"
echo "====================================="
echo "Command: $PDSH_CMD"
echo

# Test 1: Simple range
run_query_test "Simple range [1-3]" "test[1-3]" \
    "test1" "test2" "test3"

# Test 2: Single value range
run_query_test "Single value [5]" "test[5]" \
    "test5"

# Test 3: Zero-padded range
run_query_test "Zero-padded [01-03]" "node[01-03]" \
    "node01" "node02" "node03"

# Test 4: Comma-separated values
run_query_test "Comma-separated [1,3,5]" "host[1,3,5]" \
    "host1" "host3" "host5"

# Test 5: Mixed range and values
run_query_test "Mixed [1-2,5,7-8]" "server[1-2,5,7-8]" \
    "server1" "server2" "server5" "server7" "server8"

# Test 6: Cartesian product (simple)
run_query_test "Cartesian product [1-2]-[a-b]" "node[1-2]-[a-b]" \
    "node1-a" "node1-b" "node2-a" "node2-b"

# Test 7: Domain suffix
run_query_test "With domain suffix" "web[1-2].example.com" \
    "web1.example.com" "web2.example.com"

# Test 8: With port number
run_query_test "With port number" "host[1-2]:2222" \
    "host1:2222" "host2:2222"

# Test 9: With username
run_query_test "With username" "admin@host[1-2]" \
    "admin@host1" "admin@host2"

# Test 10: Complex expression
run_query_test "Complex expression" "rack[1-2]-node[1-2]" \
    "rack1-node1" "rack1-node2" "rack2-node1" "rack2-node2"

# Test 11: Comma-separated simple hosts (no expansion)
run_query_test "Comma-separated hosts" "host1,host2,host3" \
    "host1" "host2" "host3"

# Test 12: Mixed hosts and expressions
run_query_test "Mixed hosts and expressions" "web[1-2],db1,cache" \
    "web1" "web2" "db1" "cache"

# Test 13: Large range
run_query_test "Large range [1-10]" "node[1-10]" \
    "node1" "node2" "node3" "node4" "node5" \
    "node6" "node7" "node8" "node9" "node10"

# Test 14: Exclusion with range
((TESTS_RUN++))
log_test "Exclusion with range"
output=$($PDSH_CMD -w "host[1-5]" -x "host[2-4]" -q 2>&1)
if echo "$output" | grep -q "host1" && \
   echo "$output" | grep -q "host5" && \
   ! echo "$output" | grep -q "host2" && \
   ! echo "$output" | grep -q "host3" && \
   ! echo "$output" | grep -q "host4"; then
    log_pass "Exclusion with range"
else
    log_fail "Exclusion with range"
fi

# Test 15: Exclusion with glob pattern
((TESTS_RUN++))
log_test "Exclusion with glob pattern"
output=$($PDSH_CMD -w "web1,web2,db1,db2" -x "db*" -q 2>&1)
if echo "$output" | grep -q "web1" && \
   echo "$output" | grep -q "web2" && \
   ! echo "$output" | grep -q "db1" && \
   ! echo "$output" | grep -q "db2"; then
    log_pass "Exclusion with glob pattern"
else
    log_fail "Exclusion with glob pattern"
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
