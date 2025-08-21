#!/bin/bash

# Test script for SFTP upload and download functionality

echo "=== SFTP Test Script ==="
echo

# Create a test file
TEST_FILE="/tmp/sftp_test_$(date +%s).txt"
echo "This is a test file for SFTP functionality" > "$TEST_FILE"
echo "Created at: $(date)" >> "$TEST_FILE"
echo "Test file created: $TEST_FILE"
echo

# Set test parameters
HOST="localhost"  # Change this to your test host
USER="$USER"      # Change this to your test user

echo "Test configuration:"
echo "  Host: $HOST"
echo "  User: $USER"
echo

# Test upload
echo "1. Testing SFTP upload..."
./target/debug/bssh -H "$USER@$HOST" upload "$TEST_FILE" "/tmp/uploaded_test.txt"
echo

# Test download
echo "2. Testing SFTP download..."
mkdir -p /tmp/downloads
./target/debug/bssh -H "$USER@$HOST" download "/tmp/uploaded_test.txt" "/tmp/downloads"
echo

# Verify download
if [ -f "/tmp/downloads/${HOST}_uploaded_test.txt" ]; then
    echo "✓ Download successful!"
    echo "Downloaded file content:"
    cat "/tmp/downloads/${HOST}_uploaded_test.txt"
else
    echo "✗ Download failed - file not found"
fi

# Cleanup
rm -f "$TEST_FILE"
echo
echo "Test complete!"