#!/bin/bash

# Quick test script for bssh-server PTY and exec functionality
# This script assumes the server is already running and keys are set up
# Use test_bssh_server.sh for full automated testing

echo "=== BSSH Server Quick Test ==="
echo

# Configuration - can be overridden via environment variables
TEST_PORT="${BSSH_TEST_PORT:-2222}"
TEST_USER="${BSSH_TEST_USER:-$USER}"
TEST_HOST="${BSSH_TEST_HOST:-127.0.0.1}"
KEY_PATH="${BSSH_TEST_KEY:-/tmp/bssh_test_client_key}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if key exists
if [ ! -f "$KEY_PATH" ]; then
    echo -e "${RED}Error: Client key not found at $KEY_PATH${NC}"
    echo "Either run test_bssh_server.sh for full automated setup, or set BSSH_TEST_KEY"
    exit 1
fi

# Check if server is running
if ! nc -z "$TEST_HOST" "$TEST_PORT" 2>/dev/null; then
    echo -e "${RED}Error: No server running on $TEST_HOST:$TEST_PORT${NC}"
    echo "Start the server first, or use test_bssh_server.sh"
    exit 1
fi

# Use full path to avoid any shell aliases (e.g., ssh -> bssh)
# Use -F /dev/null to ignore user's ssh config which may override port settings
SSH_CMD="/usr/bin/ssh"
SSH_OPTS="-F /dev/null -i $KEY_PATH -p $TEST_PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"

echo "Configuration:"
echo "  Host: $TEST_HOST:$TEST_PORT"
echo "  User: $TEST_USER"
echo "  Key: $KEY_PATH"
echo

# Note: Server has rate limiting (5 burst, 1/sec refill). Add delays between tests.

# Test 1: Basic exec
echo "--- Test 1: Basic exec (echo) ---"
output=$($SSH_CMD $SSH_OPTS "$TEST_USER@$TEST_HOST" "echo HELLO_BSSH" 2>/dev/null)
if echo "$output" | grep -q "HELLO_BSSH"; then
    echo -e "${GREEN}[PASS]${NC} Basic exec"
else
    echo -e "${RED}[FAIL]${NC} Basic exec - got: $output"
fi
sleep 1

# Test 2: whoami
echo
echo "--- Test 2: whoami ---"
output=$($SSH_CMD $SSH_OPTS "$TEST_USER@$TEST_HOST" "whoami" 2>/dev/null)
if [ "$output" = "$TEST_USER" ]; then
    echo -e "${GREEN}[PASS]${NC} whoami returned: $output"
else
    echo -e "${YELLOW}[WARN]${NC} whoami returned: $output (expected: $TEST_USER)"
fi
sleep 1

# Test 3: pwd
echo
echo "--- Test 3: pwd ---"
output=$($SSH_CMD $SSH_OPTS "$TEST_USER@$TEST_HOST" "pwd" 2>/dev/null)
echo "pwd returned: $output"
if [ -n "$output" ]; then
    echo -e "${GREEN}[PASS]${NC} pwd works"
else
    echo -e "${RED}[FAIL]${NC} pwd returned empty"
fi
sleep 1

# Test 4: PTY shell
echo
echo "--- Test 4: PTY interactive shell ---"
output=$(echo -e "echo PTY_OUTPUT_TEST\nexit" | $SSH_CMD -tt $SSH_OPTS "$TEST_USER@$TEST_HOST" 2>/dev/null | tr -d '\r')
if echo "$output" | grep -q "PTY_OUTPUT_TEST"; then
    echo -e "${GREEN}[PASS]${NC} PTY shell works"
else
    echo -e "${RED}[FAIL]${NC} PTY shell - output:"
    echo "$output"
fi
sleep 1

# Test 5: Exit code (2 connections)
echo
echo "--- Test 5: Exit code propagation ---"
$SSH_CMD $SSH_OPTS "$TEST_USER@$TEST_HOST" "exit 0" 2>/dev/null; exit0=$?
sleep 1
$SSH_CMD $SSH_OPTS "$TEST_USER@$TEST_HOST" "exit 42" 2>/dev/null; exit42=$?
if [ $exit0 -eq 0 ] && [ $exit42 -eq 42 ]; then
    echo -e "${GREEN}[PASS]${NC} Exit codes: 0->$exit0, 42->$exit42"
else
    echo -e "${RED}[FAIL]${NC} Exit codes: 0->$exit0, 42->$exit42"
fi
sleep 1

# Test 6: Long output
echo
echo "--- Test 6: Long output (seq 1 100) ---"
output=$($SSH_CMD $SSH_OPTS "$TEST_USER@$TEST_HOST" "seq 1 100" 2>/dev/null)
lines=$(echo "$output" | wc -l | tr -d ' ')
if [ "$lines" -eq 100 ]; then
    echo -e "${GREEN}[PASS]${NC} Long output: $lines lines"
else
    echo -e "${RED}[FAIL]${NC} Long output: expected 100, got $lines lines"
    # Debug: show what we got
    echo "  First 5 lines: $(echo "$output" | head -5 | tr '\n' ' ')"
fi

echo
echo "=== Quick test complete ==="
