#!/bin/bash

# Test script for glob pattern support in bssh

echo "=== BSSH Glob Pattern Test Script ==="
echo

# Create test files
TEST_DIR="/tmp/bssh_glob_test_$(date +%s)"
mkdir -p "$TEST_DIR"

echo "Creating test files in $TEST_DIR..."
echo "Test file 1" > "$TEST_DIR/test1.txt"
echo "Test file 2" > "$TEST_DIR/test2.txt"
echo "Config file" > "$TEST_DIR/config.conf"
echo "Log file 1" > "$TEST_DIR/app1.log"
echo "Log file 2" > "$TEST_DIR/app2.log"
echo "README" > "$TEST_DIR/README.md"

ls -la "$TEST_DIR"
echo

# Test configuration
HOST="${1:-localhost}"
USER="${2:-$USER}"

echo "Test configuration:"
echo "  Host: $HOST"
echo "  User: $USER"
echo

# Test 1: Upload multiple txt files
echo "=== Test 1: Upload multiple .txt files ==="
./target/debug/bssh -H "$USER@$HOST" upload "$TEST_DIR/*.txt" "/tmp/bssh_upload/"
echo

# Test 2: Upload all log files
echo "=== Test 2: Upload all .log files ==="
./target/debug/bssh -H "$USER@$HOST" upload "$TEST_DIR/*.log" "/tmp/bssh_upload/"
echo

# Test 3: Download with glob pattern
echo "=== Test 3: Download files with glob pattern ==="
mkdir -p /tmp/bssh_downloads
./target/debug/bssh -H "$USER@$HOST" download "/tmp/bssh_upload/*.txt" "/tmp/bssh_downloads/"
echo

# Test 4: Upload all files
echo "=== Test 4: Upload all files from directory ==="
./target/debug/bssh -H "$USER@$HOST" upload "$TEST_DIR/*" "/tmp/bssh_upload_all/"
echo

# Check results
echo "=== Checking uploaded files on remote ==="
ssh "$USER@$HOST" "ls -la /tmp/bssh_upload/ 2>/dev/null || echo 'Directory not found'"
echo

echo "=== Checking downloaded files ==="
ls -la /tmp/bssh_downloads/
echo

# Cleanup
echo "=== Cleanup ==="
rm -rf "$TEST_DIR"
rm -rf /tmp/bssh_downloads
ssh "$USER@$HOST" "rm -rf /tmp/bssh_upload /tmp/bssh_upload_all 2>/dev/null || true"

echo "Test complete!"