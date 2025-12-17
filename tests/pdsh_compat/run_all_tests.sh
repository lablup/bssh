#!/usr/bin/env bash
# Run all pdsh compatibility tests

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Test configuration
export BSSH_TEST_HOST="${BSSH_TEST_HOST:-localhost}"
export BSSH_TEST_USER="${BSSH_TEST_USER:-$USER}"
export PDSH_CMD="${PDSH_CMD:-bssh --pdsh-compat}"
export BSSH_TEST_VERBOSE="${BSSH_TEST_VERBOSE:-0}"

# Test suite counters
SUITES_RUN=0
SUITES_PASSED=0
SUITES_FAILED=0
TOTAL_TESTS=0
TOTAL_PASSED=0
TOTAL_FAILED=0

echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}pdsh Compatibility Test Suite${NC}"
echo -e "${BLUE}=========================================${NC}"
echo "Test host: $BSSH_TEST_HOST"
echo "Test user: $BSSH_TEST_USER"
echo "Command: $PDSH_CMD"
echo "Verbose: $BSSH_TEST_VERBOSE"
echo

# Function to run a test suite
run_test_suite() {
    local test_script="$1"
    local suite_name=$(basename "$test_script" .sh)

    echo -e "${YELLOW}-----------------------------------${NC}"
    echo -e "${YELLOW}Running: $suite_name${NC}"
    echo -e "${YELLOW}-----------------------------------${NC}"
    echo

    ((SUITES_RUN++))

    if "$test_script"; then
        echo -e "${GREEN}✓ $suite_name passed${NC}"
        ((SUITES_PASSED++))
        return 0
    else
        echo -e "${RED}✗ $suite_name failed${NC}"
        ((SUITES_FAILED++))
        return 1
    fi
}

# Make test scripts executable
chmod +x "$SCRIPT_DIR"/*.sh 2>/dev/null || true

# Run test suites
run_test_suite "$SCRIPT_DIR/test_basic.sh"
echo

run_test_suite "$SCRIPT_DIR/test_hostlist.sh"
echo

run_test_suite "$SCRIPT_DIR/test_options.sh"
echo

# Final summary
echo
echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}Final Test Summary${NC}"
echo -e "${BLUE}=========================================${NC}"
echo "Test suites run:    $SUITES_RUN"
echo "Test suites passed: $SUITES_PASSED"
echo "Test suites failed: $SUITES_FAILED"
echo

if [ "$SUITES_FAILED" -eq 0 ]; then
    echo -e "${GREEN}=========================================${NC}"
    echo -e "${GREEN}All test suites passed!${NC}"
    echo -e "${GREEN}=========================================${NC}"
    exit 0
else
    echo -e "${RED}=========================================${NC}"
    echo -e "${RED}Some test suites failed.${NC}"
    echo -e "${RED}=========================================${NC}"
    exit 1
fi
