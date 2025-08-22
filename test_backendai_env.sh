#!/bin/bash
# Test script for Backend.AI environment variable support

echo "Testing Backend.AI environment variable support..."
echo "================================================="
echo

# Set Backend.AI environment variables
export BACKENDAI_CLUSTER_HOSTS="node1.example.com,node2.example.com,node3.example.com"
export BACKENDAI_CLUSTER_HOST="node1.example.com"
export BACKENDAI_CLUSTER_ROLE="main"

echo "Environment variables set:"
echo "  BACKENDAI_CLUSTER_HOSTS=$BACKENDAI_CLUSTER_HOSTS"
echo "  BACKENDAI_CLUSTER_HOST=$BACKENDAI_CLUSTER_HOST"
echo "  BACKENDAI_CLUSTER_ROLE=$BACKENDAI_CLUSTER_ROLE"
echo

# Build the project
echo "Building bssh..."
cargo build --release 2>/dev/null || cargo build --release

echo
echo "Test 1: List clusters (should show 'backendai' cluster)"
echo "---------------------------------------------------------"
./target/release/bssh list

echo
echo "Test 2: Execute command without -c flag (should auto-detect Backend.AI)"
echo "------------------------------------------------------------------------"
./target/release/bssh "echo test" 2>&1 | head -20

echo
echo "Test 3: Interactive mode without -c flag"
echo "-----------------------------------------"
echo "Command: ./target/release/bssh interactive --help"
./target/release/bssh interactive --help

echo
echo "Test 4: Ping nodes (connectivity test)"
echo "---------------------------------------"
./target/release/bssh ping 2>&1 | head -20

echo
echo "Cleaning up environment variables..."
unset BACKENDAI_CLUSTER_HOSTS
unset BACKENDAI_CLUSTER_HOST
unset BACKENDAI_CLUSTER_ROLE

echo "Tests complete!"