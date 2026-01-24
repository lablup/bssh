#!/bin/bash

# Test script for bssh-server PTY and exec functionality
# This script tests the SSH server implementation with PTY shell sessions

set -e

echo "=== BSSH Server Test Script ==="
echo

# Configuration
TEST_PORT="${BSSH_TEST_PORT:-2222}"
TEST_USER="${BSSH_TEST_USER:-$USER}"
TEST_HOST="${BSSH_TEST_HOST:-127.0.0.1}"
TEST_DIR="/tmp/bssh_server_test_$$"
KEY_DIR="$TEST_DIR/keys"
AUTH_DIR="$TEST_DIR/auth"
CONFIG_FILE="$TEST_DIR/config.yaml"
SERVER_LOG="$TEST_DIR/server.log"
SERVER_PID_FILE="$TEST_DIR/server.pid"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0

# Cleanup function
cleanup() {
    echo
    echo "=== Cleanup ==="

    # Kill server if running
    if [ -f "$SERVER_PID_FILE" ]; then
        SERVER_PID=$(cat "$SERVER_PID_FILE")
        if ps -p "$SERVER_PID" > /dev/null 2>&1; then
            echo "Stopping bssh-server (PID: $SERVER_PID)..."
            kill "$SERVER_PID" 2>/dev/null || true
            sleep 1
            # Force kill if still running
            if ps -p "$SERVER_PID" > /dev/null 2>&1; then
                kill -9 "$SERVER_PID" 2>/dev/null || true
            fi
        fi
    fi

    # Remove test directory
    if [ -d "$TEST_DIR" ]; then
        rm -rf "$TEST_DIR"
        echo "Removed test directory: $TEST_DIR"
    fi
}

# Set up trap for cleanup on exit
trap cleanup EXIT INT TERM

# Helper function to print test result
print_result() {
    local test_name="$1"
    local result="$2"

    if [ "$result" = "PASS" ]; then
        echo -e "${GREEN}[PASS]${NC} $test_name"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}[FAIL]${NC} $test_name"
        ((TESTS_FAILED++))
    fi
}

# Setup test environment
setup_environment() {
    echo "=== Setting up test environment ==="
    echo "Test directory: $TEST_DIR"
    echo "Port: $TEST_PORT"
    echo "User: $TEST_USER"
    echo

    # Create directories
    mkdir -p "$KEY_DIR"
    mkdir -p "$AUTH_DIR/$TEST_USER"

    # Generate host key
    echo "Generating host key..."
    ssh-keygen -t ed25519 -f "$KEY_DIR/host_key" -N "" -C "bssh_test_host" -q

    # Generate client key
    echo "Generating client key..."
    ssh-keygen -t ed25519 -f "$KEY_DIR/client_key" -N "" -C "bssh_test_client" -q

    # Set up authorized keys
    cp "$KEY_DIR/client_key.pub" "$AUTH_DIR/$TEST_USER/authorized_keys"
    echo "Authorized keys set up for user: $TEST_USER"

    # Create config file
    cat > "$CONFIG_FILE" << EOF
server:
  bind_address: 0.0.0.0
  port: $TEST_PORT
  host_keys:
    - $KEY_DIR/host_key
auth:
  methods:
    - publickey
  publickey:
    authorized_keys_dir: $AUTH_DIR
shell:
  default: /bin/sh
logging:
  level: info
EOF

    echo "Configuration file created: $CONFIG_FILE"
    echo
}

# Start the bssh-server
start_server() {
    echo "=== Starting bssh-server ==="

    # Check if binary exists
    local BINARY="./target/release/bssh-server"
    if [ ! -f "$BINARY" ]; then
        BINARY="./target/debug/bssh-server"
    fi

    if [ ! -f "$BINARY" ]; then
        echo -e "${RED}Error: bssh-server binary not found!${NC}"
        echo "Please build with: cargo build --release"
        exit 1
    fi

    echo "Using binary: $BINARY"

    # Start server in background
    "$BINARY" -c "$CONFIG_FILE" > "$SERVER_LOG" 2>&1 &
    echo $! > "$SERVER_PID_FILE"
    SERVER_PID=$(cat "$SERVER_PID_FILE")

    echo "Server started with PID: $SERVER_PID"

    # Wait for server to be ready
    echo "Waiting for server to be ready..."
    local max_attempts=30
    local attempt=0
    while [ $attempt -lt $max_attempts ]; do
        if nc -z "$TEST_HOST" "$TEST_PORT" 2>/dev/null; then
            echo "Server is ready!"
            return 0
        fi
        sleep 0.5
        ((attempt++))
    done

    echo -e "${RED}Error: Server failed to start within 15 seconds${NC}"
    echo "Server log:"
    cat "$SERVER_LOG"
    exit 1
}

# SSH options for tests
# Use full path to avoid any shell aliases (e.g., ssh -> bssh)
# Use -F /dev/null to ignore user's ssh config which may override port settings
SSH_CMD="/usr/bin/ssh"
SSH_OPTS="-F /dev/null -i $KEY_DIR/client_key -p $TEST_PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"

# Test 1: Basic SSH connection with command
test_basic_exec() {
    echo
    echo "--- Test: Basic SSH command execution ---"

    local output
    output=$($SSH_CMD $SSH_OPTS "$TEST_USER@$TEST_HOST" "echo HELLO_BSSH" 2>/dev/null)

    if echo "$output" | grep -q "HELLO_BSSH"; then
        print_result "Basic exec command" "PASS"
        return 0
    else
        print_result "Basic exec command" "FAIL"
        echo "  Expected: HELLO_BSSH"
        echo "  Got: $output"
        return 1
    fi
}

# Test 2: PWD command
test_pwd() {
    echo
    echo "--- Test: pwd command ---"

    local output
    output=$($SSH_CMD $SSH_OPTS "$TEST_USER@$TEST_HOST" "pwd" 2>/dev/null)

    if [ -n "$output" ] && [ "$output" = "/" ] || [ -d "$output" ]; then
        print_result "pwd command" "PASS"
        return 0
    else
        print_result "pwd command" "FAIL"
        echo "  Output: $output"
        return 1
    fi
}

# Test 3: whoami command
test_whoami() {
    echo
    echo "--- Test: whoami command ---"

    local output
    output=$($SSH_CMD $SSH_OPTS "$TEST_USER@$TEST_HOST" "whoami" 2>/dev/null)

    if [ "$output" = "$TEST_USER" ]; then
        print_result "whoami command" "PASS"
        return 0
    else
        print_result "whoami command" "FAIL"
        echo "  Expected: $TEST_USER"
        echo "  Got: $output"
        return 1
    fi
}

# Test 4: Command with arguments
test_command_args() {
    echo
    echo "--- Test: Command with arguments ---"

    local output
    output=$($SSH_CMD $SSH_OPTS "$TEST_USER@$TEST_HOST" "echo hello world" 2>/dev/null)

    if [ "$output" = "hello world" ]; then
        print_result "Command with arguments" "PASS"
        return 0
    else
        print_result "Command with arguments" "FAIL"
        echo "  Expected: hello world"
        echo "  Got: $output"
        return 1
    fi
}

# Test 5: Exit code propagation
test_exit_code() {
    echo
    echo "--- Test: Exit code propagation ---"

    # Test successful command
    $SSH_CMD $SSH_OPTS "$TEST_USER@$TEST_HOST" "exit 0" 2>/dev/null
    local exit_success=$?

    # Test failed command
    $SSH_CMD $SSH_OPTS "$TEST_USER@$TEST_HOST" "exit 42" 2>/dev/null
    local exit_fail=$?

    if [ $exit_success -eq 0 ] && [ $exit_fail -eq 42 ]; then
        print_result "Exit code propagation" "PASS"
        return 0
    else
        print_result "Exit code propagation" "FAIL"
        echo "  Expected: exit 0 -> 0, exit 42 -> 42"
        echo "  Got: exit 0 -> $exit_success, exit 42 -> $exit_fail"
        return 1
    fi
}

# Test 6: PTY interactive shell (basic)
test_pty_shell() {
    echo
    echo "--- Test: PTY interactive shell ---"

    local output
    output=$(echo -e "echo PTY_TEST_OUTPUT\nexit" | $SSH_CMD -tt $SSH_OPTS "$TEST_USER@$TEST_HOST" 2>/dev/null | tr -d '\r')

    if echo "$output" | grep -q "PTY_TEST_OUTPUT"; then
        print_result "PTY interactive shell" "PASS"
        return 0
    else
        print_result "PTY interactive shell" "FAIL"
        echo "  Expected output containing: PTY_TEST_OUTPUT"
        echo "  Got: $output"
        return 1
    fi
}

# Test 7: PTY shell commands sequence
test_pty_commands() {
    echo
    echo "--- Test: PTY shell command sequence ---"

    local output
    output=$(cat << 'EOF' | $SSH_CMD -tt $SSH_OPTS "$TEST_USER@$TEST_HOST" 2>/dev/null | tr -d '\r'
pwd
echo "MARKER_START"
echo "TEST_VALUE_123"
echo "MARKER_END"
exit
EOF
)

    if echo "$output" | grep -q "TEST_VALUE_123"; then
        print_result "PTY shell command sequence" "PASS"
        return 0
    else
        print_result "PTY shell command sequence" "FAIL"
        echo "  Expected output containing: TEST_VALUE_123"
        echo "  Got: $output"
        return 1
    fi
}

# Test 8: Multiple connections
test_multiple_connections() {
    echo
    echo "--- Test: Multiple simultaneous connections ---"

    local pid1 pid2 pid3
    local output1 output2 output3

    # Start three connections in parallel
    output1=$($SSH_CMD $SSH_OPTS "$TEST_USER@$TEST_HOST" "echo conn1" 2>/dev/null) &
    pid1=$!
    output2=$($SSH_CMD $SSH_OPTS "$TEST_USER@$TEST_HOST" "echo conn2" 2>/dev/null) &
    pid2=$!
    output3=$($SSH_CMD $SSH_OPTS "$TEST_USER@$TEST_HOST" "echo conn3" 2>/dev/null) &
    pid3=$!

    # Wait for all to complete
    wait $pid1; local exit1=$?
    wait $pid2; local exit2=$?
    wait $pid3; local exit3=$?

    if [ $exit1 -eq 0 ] && [ $exit2 -eq 0 ] && [ $exit3 -eq 0 ]; then
        print_result "Multiple simultaneous connections" "PASS"
        return 0
    else
        print_result "Multiple simultaneous connections" "FAIL"
        echo "  Exit codes: $exit1, $exit2, $exit3"
        return 1
    fi
}

# Test 9: Long output handling
test_long_output() {
    echo
    echo "--- Test: Long output handling ---"

    local output
    output=$($SSH_CMD $SSH_OPTS "$TEST_USER@$TEST_HOST" "seq 1 1000" 2>/dev/null)

    local line_count
    line_count=$(echo "$output" | wc -l | tr -d ' ')

    if [ "$line_count" -eq 1000 ]; then
        print_result "Long output handling" "PASS"
        return 0
    else
        print_result "Long output handling" "FAIL"
        echo "  Expected 1000 lines"
        echo "  Got: $line_count lines"
        return 1
    fi
}

# Test 10: Connection error handling
# Note: Stderr in exec mode is a known limitation
test_connection_error() {
    echo
    echo "--- Test: Connection error handling ---"

    # Try connecting to wrong port - should fail gracefully
    local output
    output=$($SSH_CMD -F /dev/null -i "$KEY_DIR/client_key" -p 29999 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=2 "$TEST_USER@$TEST_HOST" "echo test" 2>&1)
    local exit_code=$?

    if [ $exit_code -ne 0 ]; then
        print_result "Connection error handling" "PASS"
        return 0
    else
        print_result "Connection error handling" "FAIL"
        echo "  Expected non-zero exit code for failed connection"
        echo "  Got: $exit_code"
        return 1
    fi
}

# Main test execution
main() {
    echo "Starting bssh-server tests..."
    echo "=============================="
    echo

    # Setup
    setup_environment
    start_server

    echo
    echo "=== Running Tests ==="
    echo "(Note: 1s delay between tests to respect rate limiting)"

    # Run all tests (continue even if individual tests fail)
    # Server has rate limiting (5 burst, 1/sec refill) - add delays
    set +e

    test_basic_exec
    sleep 1
    test_pwd
    sleep 1
    test_whoami
    sleep 1
    test_command_args
    sleep 2  # test_exit_code uses 2 connections
    test_exit_code
    sleep 1
    test_pty_shell
    sleep 1
    test_pty_commands
    sleep 3  # test_multiple_connections uses 3 parallel connections
    test_multiple_connections
    sleep 1
    test_long_output
    sleep 1
    test_connection_error

    set -e

    # Print summary
    echo
    echo "=============================="
    echo "=== Test Summary ==="
    echo "=============================="
    echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"
    echo

    if [ $TESTS_FAILED -gt 0 ]; then
        echo -e "${RED}Some tests failed!${NC}"
        echo "Server log:"
        tail -50 "$SERVER_LOG"
        exit 1
    else
        echo -e "${GREEN}All tests passed!${NC}"
        exit 0
    fi
}

# Run main
main "$@"
