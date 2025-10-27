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

# Example: Cluster health check with --require-all-success flag
#
# This script demonstrates using the --require-all-success flag for
# monitoring and health check scenarios where ALL nodes must be operational.
#
# This is the v1.0-v1.1 behavior, preserved via the flag for compatibility.

set -euo pipefail

echo "=== Cluster Health Check ==="
echo

# Check disk space on all nodes (require all to pass)
echo "1. Checking disk space..."
if bssh --require-all-success -C production exec "df -h / | awk 'NR==2 {if (\$5+0 > 90) exit 1}'"; then
    echo "   ✅ Disk space OK on all nodes"
else
    echo "   ❌ CRITICAL: Disk space exceeded on one or more nodes!"
    alert_ops "Disk space critical on production cluster"
    exit 1
fi

# Check memory usage
echo
echo "2. Checking memory usage..."
if bssh --require-all-success -C production exec "free | awk '/Mem:/ {if (\$3/\$2 > 0.95) exit 1}'"; then
    echo "   ✅ Memory usage OK on all nodes"
else
    echo "   ❌ WARNING: High memory usage detected!"
    alert_ops "High memory usage on production cluster"
    exit 1
fi

# Check critical services
echo
echo "3. Checking critical services..."
if bssh --require-all-success -C production exec "systemctl is-active docker nginx"; then
    echo "   ✅ All services running on all nodes"
else
    echo "   ❌ CRITICAL: Service failure detected!"
    alert_ops "Service failure on production cluster"
    exit 1
fi

# Check network connectivity
echo
echo "4. Checking network connectivity..."
if bssh --require-all-success -C production exec "ping -c 1 -W 1 8.8.8.8 > /dev/null"; then
    echo "   ✅ Network connectivity OK on all nodes"
else
    echo "   ❌ CRITICAL: Network connectivity issue!"
    alert_ops "Network connectivity issue on production cluster"
    exit 1
fi

# Check GPU status (if applicable)
echo
echo "5. Checking GPU status..."
if bssh --require-all-success -C production exec "nvidia-smi > /dev/null 2>&1"; then
    echo "   ✅ GPUs operational on all nodes"
else
    echo "   ⚠️  WARNING: GPU check failed (may not have GPUs)"
    # Not critical, continue
fi

echo
echo "=== Health Check Complete ==="
echo "All critical checks passed. Cluster is healthy."

# Update monitoring dashboard
update_health_status "healthy"

# Helper functions
alert_ops() {
    echo "ALERT: $1" >&2
    # In production, this would send to Slack/PagerDuty/etc.
}

update_health_status() {
    echo "Health status: $1"
    # In production, this would update monitoring dashboard
}
