#!/bin/bash
# Copyright 2025 Lablup Inc. and Jeongkyu Shin
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Example: MPI job with intelligent error handling
#
# This script demonstrates how bssh v1.2.0+ preserves actual exit codes
# from the main rank, enabling sophisticated error handling for MPI workloads.
#
# Exit codes and their meanings:
# - 0: Success
# - 139: SIGSEGV (Segmentation fault)
# - 137: SIGKILL (Out of memory kill)
# - 124: Timeout
# - 1-255: Other errors

set -euo pipefail

# Run MPI simulation across cluster
echo "Running MPI simulation..."
bssh -C production exec "mpirun -n 16 ./simulation --config production.yaml"
EXIT_CODE=$?

# Handle different exit codes appropriately
case $EXIT_CODE in
    0)
        echo "✅ Success! Deploying results..."
        deploy_results
        notify_team "Simulation completed successfully"
        ;;

    139)
        echo "❌ Segmentation fault detected!"
        echo "   Collecting core dump for analysis..."
        collect_core_dump
        notify_dev_team "SIGSEGV in simulation - core dump available"
        exit 139
        ;;

    137)
        echo "❌ Out of memory!"
        echo "   Current memory: 64GB"
        echo "   Retrying with increased memory allocation..."
        # Retry with more memory
        bssh -C production exec "mpirun -n 16 --bind-to none ./simulation --config production.yaml --memory 128g"
        ;;

    124)
        echo "⚠️  Timeout detected!"
        echo "   Extending time limit and retrying..."
        # Retry with extended timeout
        bssh --timeout 1200 -C production exec "mpirun -n 16 ./simulation --config production.yaml"
        ;;

    *)
        echo "❌ Unknown error: Exit code $EXIT_CODE"
        echo "   Saving logs and notifying team..."
        save_logs
        notify_team "Simulation failed with exit code $EXIT_CODE"
        exit $EXIT_CODE
        ;;
esac

# Helper functions (implementation not shown)
deploy_results() {
    echo "Deploying results to production storage..."
}

collect_core_dump() {
    echo "Collecting core dump from main rank..."
}

notify_team() {
    echo "Notification: $1"
}

notify_dev_team() {
    echo "Dev team notification: $1"
}

save_logs() {
    echo "Saving logs for analysis..."
}
