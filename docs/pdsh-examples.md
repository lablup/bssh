# pdsh Compatibility Examples

Real-world examples of common pdsh usage patterns with bssh.

## Table of Contents

- [Basic Operations](#basic-operations)
- [System Administration](#system-administration)
- [Deployment and Configuration](#deployment-and-configuration)
- [Monitoring and Diagnostics](#monitoring-and-diagnostics)
- [Data Collection](#data-collection)
- [Cluster Management](#cluster-management)
- [Advanced Patterns](#advanced-patterns)
- [Scripting Examples](#scripting-examples)

## Basic Operations

### Execute Simple Command

```bash
# Run command on multiple hosts
pdsh -w host1,host2,host3 "uptime"

# Output:
# [host1]  10:30:45 up 5 days,  2:14,  1 user,  load average: 0.15, 0.12, 0.09
# [host2]  10:30:45 up 3 days,  4:22,  2 users,  load average: 0.23, 0.19, 0.17
# [host3]  10:30:45 up 7 days,  1:45,  1 user,  load average: 0.08, 0.11, 0.10
```

### Using Hostlist Expressions

```bash
# Range expansion
pdsh -w node[1-5] "hostname"

# Output:
# [node1] node1
# [node2] node2
# [node3] node3
# [node4] node4
# [node5] node5

# Zero-padded ranges
pdsh -w server[01-10] "hostname"
# Creates: server01, server02, ..., server10

# Cartesian product
pdsh -w rack[1-2]-node[1-4] "hostname"
# Creates: rack1-node1, rack1-node2, ..., rack2-node4 (8 hosts)
```

### Exclude Hosts

```bash
# Exclude specific hosts
pdsh -w node[1-10] -x node5,node7 "df -h /"

# Exclude with wildcards
pdsh -w web1,web2,db1,db2,cache1 -x "db*,cache*" "uptime"
# Runs on: web1, web2

# Exclude range
pdsh -w compute[01-20] -x "compute[15-20]" "nvidia-smi"
# Runs on: compute01-compute14
```

### Query Mode

```bash
# Verify host expansion
pdsh -w node[1-5] -q
# Output:
# node1
# node2
# node3
# node4
# node5

# Check exclusions
pdsh -w node[1-10] -x "node[3-5]" -q
# Output:
# node1
# node2
# node6
# node7
# node8
# node9
# node10
```

## System Administration

### Package Management

```bash
# Update package lists (Ubuntu/Debian)
pdsh -w servers -l root -S "sudo apt update"

# Upgrade packages
pdsh -w servers -l admin -S "sudo apt upgrade -y"

# Install specific package on all hosts
pdsh -w webservers -S "sudo apt install -y nginx"

# Check package version
pdsh -w servers "dpkg -l | grep nginx"

# Clean package cache
pdsh -w servers -S "sudo apt clean"
```

### Service Management

```bash
# Restart service on all web servers
pdsh -w web[1-10] -S "sudo systemctl restart nginx"

# Check service status
pdsh -w app-servers "systemctl status myapp"

# Enable service on boot
pdsh -w servers -S "sudo systemctl enable docker"

# Stop service on specific hosts
pdsh -w cache[1-3] -S "sudo systemctl stop redis"

# Reload configuration
pdsh -w webservers -S "sudo systemctl reload nginx"
```

### User Management

```bash
# Create user on all hosts
pdsh -w servers -S "sudo useradd -m -s /bin/bash deploy"

# Set password
pdsh -w servers -S "echo 'deploy:newpassword' | sudo chpasswd"

# Add user to group
pdsh -w servers -S "sudo usermod -aG docker deploy"

# Check user existence
pdsh -w servers "id deploy"

# Remove user
pdsh -w servers -S "sudo userdel -r olduser"
```

### File System Operations

```bash
# Check disk usage
pdsh -w servers "df -h | grep -E '^/dev/'"

# Check specific directory size
pdsh -w servers "du -sh /var/log"

# Find large files
pdsh -w servers "find /var/log -type f -size +100M"

# Clean up old logs
pdsh -w servers -S "sudo find /var/log -name '*.log' -mtime +30 -delete"

# Check mount points
pdsh -w servers "mount | grep -E '^/dev/'"
```

### System Information

```bash
# Kernel version
pdsh -w servers "uname -r"

# OS version
pdsh -w servers "cat /etc/os-release | grep PRETTY_NAME"

# CPU information
pdsh -w servers "lscpu | grep 'Model name'"

# Memory information
pdsh -w servers "free -h | grep 'Mem:'"

# System uptime
pdsh -w servers "uptime"
```

## Deployment and Configuration

### Application Deployment

```bash
# Pull latest code
pdsh -w app-servers -l deploy "cd /app && git pull origin main"

# Build application
pdsh -w app-servers -l deploy "cd /app && npm install && npm run build"

# Restart application
pdsh -w app-servers -S "sudo systemctl restart myapp"

# Verify deployment
pdsh -w app-servers "curl -s http://localhost:3000/health | jq .version"

# Rollback if needed
pdsh -w app-servers -l deploy "cd /app && git checkout v1.2.3 && npm run build"
```

### Configuration Management

```bash
# Copy configuration file to all hosts
for host in $(pdsh -w web[1-5] -q); do
    scp nginx.conf $host:/tmp/
    ssh $host "sudo mv /tmp/nginx.conf /etc/nginx/ && sudo systemctl reload nginx"
done

# Update configuration value
pdsh -w app-servers -S "sudo sed -i 's/^PORT=.*/PORT=8080/' /etc/myapp/config"

# Validate configuration
pdsh -w webservers "nginx -t"

# Backup configurations
pdsh -w servers --output-dir ./config-backup "cat /etc/myapp/config"

# Compare configurations across hosts
pdsh -w web1,web2 "md5sum /etc/nginx/nginx.conf"
```

### SSL Certificate Deployment

```bash
# Copy certificates
for host in $(pdsh -w webservers -q); do
    scp cert.pem key.pem $host:/tmp/
    ssh $host "sudo mv /tmp/cert.pem /tmp/key.pem /etc/ssl/ && sudo chmod 600 /etc/ssl/key.pem"
done

# Update certificate paths in config
pdsh -w webservers -S "sudo systemctl restart nginx"

# Verify certificates
pdsh -w webservers "sudo openssl x509 -in /etc/ssl/cert.pem -noout -dates"
```

## Monitoring and Diagnostics

### Performance Monitoring

```bash
# CPU usage
pdsh -w servers "top -bn1 | grep 'Cpu(s)'"

# Memory usage
pdsh -w servers "free -m | awk 'NR==2{printf \"%.2f%%\", $3*100/$2}'"

# Disk I/O
pdsh -w servers "iostat -x 1 5"

# Network statistics
pdsh -w servers "ss -s"

# Load average
pdsh -w servers "cat /proc/loadavg"
```

### Log Analysis

```bash
# Search for errors in logs
pdsh -w servers "sudo grep -i error /var/log/syslog | tail -20"

# Count error occurrences
pdsh -w app-servers "sudo grep -c 'ERROR' /var/log/myapp/app.log"

# Find recent warnings
pdsh -w servers "sudo journalctl -p warning --since '1 hour ago' | tail -10"

# Monitor active connections
pdsh -w webservers "ss -tan | awk '{print $1}' | sort | uniq -c"

# Check for specific log patterns
pdsh -w servers "sudo grep '404' /var/log/nginx/access.log | wc -l"
```

### Health Checks

```bash
# HTTP endpoint check
pdsh -w webservers "curl -s -o /dev/null -w '%{http_code}' http://localhost/"

# Port check
pdsh -w servers "nc -zv localhost 3306"

# Service status
pdsh -w app-servers "systemctl is-active myapp"

# Process check
pdsh -w servers "pgrep -c nginx"

# Disk space check
pdsh -w servers "df -h / | awk 'NR==2 {print $5}' | sed 's/%//'"
```

## Data Collection

### Gathering System Metrics

```bash
# Collect system info to files
pdsh -w servers --output-dir ./metrics-$(date +%Y%m%d) "
    echo '=== System Info ===' &&
    uname -a &&
    echo '=== CPU ===' &&
    lscpu &&
    echo '=== Memory ===' &&
    free -h &&
    echo '=== Disk ===' &&
    df -h
"

# Collect network statistics
pdsh -w servers --output-dir ./network-stats "
    ss -tan state established |
    awk '{print \$5}' |
    cut -d: -f1 |
    sort |
    uniq -c |
    sort -rn
"

# Collect running processes
pdsh -w servers --output-dir ./processes "ps auxf"
```

### Inventory Management

```bash
# Hardware inventory
pdsh -w servers -N "
    echo \"Hostname: \$(hostname)\"
    echo \"CPU: \$(lscpu | grep 'Model name' | cut -d: -f2 | xargs)\"
    echo \"Memory: \$(free -h | awk 'NR==2{print \$2}')\"
    echo \"Disk: \$(df -h / | awk 'NR==2{print \$2}')\"
    echo '---'
"

# Software inventory
pdsh -w servers "dpkg -l | grep -E 'nginx|postgresql|redis' | awk '{print \$2,\$3}'"

# Network configuration
pdsh -w servers "ip -4 addr show | grep inet | awk '{print \$2}'"
```

### Log Collection

```bash
# Collect last 100 lines of logs
pdsh -w app-servers --output-dir ./logs "sudo tail -100 /var/log/myapp/app.log"

# Collect logs from specific time range
pdsh -w servers --output-dir ./system-logs "
    sudo journalctl --since '2025-01-17 10:00' --until '2025-01-17 11:00'
"

# Collect error logs only
pdsh -w webservers --output-dir ./error-logs "
    sudo grep -i error /var/log/nginx/error.log
"
```

## Cluster Management

### Database Cluster

```bash
# Check database cluster status
pdsh -w db[1-3] "sudo -u postgres psql -c 'SELECT pg_is_in_recovery();'"

# Perform vacuum
pdsh -w db[1-3] "sudo -u postgres psql -d mydb -c 'VACUUM ANALYZE;'"

# Check replication lag
pdsh -w db-replica[1-2] "
    sudo -u postgres psql -c '
        SELECT EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp()));
    '
"

# Backup all databases
pdsh -w db-servers "
    sudo -u postgres pg_dumpall | gzip > /backup/db-\$(hostname)-\$(date +%Y%m%d).sql.gz
"
```

### Web Server Cluster

```bash
# Rolling restart with fanout=1 (one at a time)
pdsh -w web[1-10] -f 1 -S "
    sudo systemctl restart nginx &&
    sleep 5 &&
    curl -f http://localhost/health
"

# Update SSL certificates
pdsh -w web[1-5] -S "
    sudo certbot renew &&
    sudo systemctl reload nginx
"

# Check upstream health
pdsh -w web[1-5] "
    curl -s http://localhost/status | jq .upstreams
"
```

### Cache Cluster

```bash
# Redis cluster info
pdsh -w cache[1-6] "redis-cli INFO replication | grep role"

# Flush cache on all nodes
pdsh -w cache[1-6] "redis-cli FLUSHALL"

# Check memory usage
pdsh -w cache[1-6] "redis-cli INFO memory | grep used_memory_human"

# Memcached stats
pdsh -w cache[1-4] "echo stats | nc localhost 11211 | grep 'STAT curr_items'"
```

## Advanced Patterns

### Conditional Execution

```bash
# Execute only if file exists
pdsh -w servers "
    [ -f /etc/myapp/config ] &&
    sudo systemctl restart myapp ||
    echo 'Config file not found'
"

# Check and install if missing
pdsh -w servers "
    dpkg -l nginx >/dev/null 2>&1 ||
    sudo apt install -y nginx
"

# Update only if version is old
pdsh -w servers "
    current=\$(myapp --version | cut -d' ' -f2)
    if [ \"\$current\" != \"2.0.0\" ]; then
        sudo /opt/update-myapp.sh
    fi
"
```

### Parallel File Transfer

```bash
# Upload file to all hosts
for host in $(pdsh -w servers -q); do
    scp localfile.txt $host:/tmp/ &
done
wait

# Download files from all hosts
mkdir -p downloads
for host in $(pdsh -w servers -q); do
    scp $host:/var/log/myapp.log downloads/$host-myapp.log &
done
wait

# Sync directory to all hosts
for host in $(pdsh -w servers -q); do
    rsync -avz ./app/ $host:/opt/app/ &
done
wait
```

### Failover and High Availability

```bash
# Check primary and failover to secondary if down
pdsh -w db-primary "pg_isready" ||
pdsh -w db-secondary -S "sudo -u postgres pg_ctl promote -D /var/lib/postgresql/data"

# Health check with timeout
pdsh -w webservers -u 5 "curl -f -m 3 http://localhost/health" ||
echo "Some web servers are unhealthy"

# Graceful service migration
pdsh -w old-servers -f 1 "
    # Drain connections
    sudo systemctl stop myapp
    sleep 30
" &&
pdsh -w new-servers -f 1 "
    # Start service
    sudo systemctl start myapp
    sleep 5
"
```

### Batch Processing

```bash
# Process data files in parallel
pdsh -w worker[1-10] -f 5 "
    /opt/process-data.sh /data/batch-\$(hostname).csv
"

# Distributed grep across log files
pdsh -w servers "
    zgrep 'ERROR' /var/log/app-\$(date -d yesterday +%Y%m%d).log.gz
" > aggregated-errors.txt

# Parallel compression
pdsh -w servers "
    find /var/log -name '*.log' -mtime +7 -exec gzip {} \\;
"
```

## Scripting Examples

### Health Check Script

```bash
#!/bin/bash
# health-check.sh - Check cluster health

CLUSTER="production"
FAILED=0

echo "=== Cluster Health Check ==="
echo "Date: $(date)"
echo

# Check all hosts are reachable
echo "Connectivity Check:"
if pdsh -w $CLUSTER -t 5 "echo ok" >/dev/null 2>&1; then
    echo "✓ All hosts reachable"
else
    echo "✗ Some hosts unreachable"
    FAILED=1
fi

# Check disk space
echo
echo "Disk Space Check:"
pdsh -w $CLUSTER "
    usage=\$(df -h / | awk 'NR==2 {print \$5}' | sed 's/%//')
    if [ \$usage -gt 90 ]; then
        echo \"\$(hostname): ✗ Disk usage: \${usage}%\"
        exit 1
    else
        echo \"\$(hostname): ✓ Disk usage: \${usage}%\"
    fi
" || FAILED=1

# Check memory
echo
echo "Memory Check:"
pdsh -w $CLUSTER "
    mem_available=\$(free -m | awk 'NR==2{printf \"%d\", \$7*100/\$2}')
    if [ \$mem_available -lt 10 ]; then
        echo \"\$(hostname): ✗ Low memory: \${mem_available}% available\"
        exit 1
    else
        echo \"\$(hostname): ✓ Memory: \${mem_available}% available\"
    fi
" || FAILED=1

# Check critical services
echo
echo "Service Check:"
pdsh -w $CLUSTER "
    systemctl is-active nginx >/dev/null 2>&1 || {
        echo \"\$(hostname): ✗ nginx not running\"
        exit 1
    }
    echo \"\$(hostname): ✓ nginx running\"
" || FAILED=1

echo
if [ $FAILED -eq 0 ]; then
    echo "=== All checks passed ==="
    exit 0
else
    echo "=== Some checks failed ==="
    exit 1
fi
```

### Rolling Deployment Script

```bash
#!/bin/bash
# rolling-deploy.sh - Deploy application with rolling restart

CLUSTER="webservers"
APP_PATH="/opt/myapp"
VERSION="$1"

if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version>"
    exit 1
fi

echo "=== Rolling Deployment ==="
echo "Cluster: $CLUSTER"
echo "Version: $VERSION"
echo

# Get list of hosts
HOSTS=$(pdsh -w $CLUSTER -q)

# Deploy to each host sequentially
for host in $HOSTS; do
    echo "--- Deploying to $host ---"

    # Deploy new version
    ssh $host "
        cd $APP_PATH &&
        git fetch &&
        git checkout $VERSION &&
        npm install &&
        npm run build
    " || {
        echo "✗ Deployment failed on $host"
        exit 1
    }

    # Restart service
    ssh $host "sudo systemctl restart myapp" || {
        echo "✗ Restart failed on $host"
        exit 1
    }

    # Wait for health check
    sleep 5
    if ssh $host "curl -f http://localhost:3000/health" >/dev/null 2>&1; then
        echo "✓ $host is healthy"
    else
        echo "✗ Health check failed on $host"
        exit 1
    fi

    echo
done

echo "=== Deployment complete ==="
```

### Automated Backup Script

```bash
#!/bin/bash
# cluster-backup.sh - Backup configurations and data from cluster

CLUSTER="production"
BACKUP_DIR="/backups/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

echo "=== Cluster Backup ==="
echo "Cluster: $CLUSTER"
echo "Backup directory: $BACKUP_DIR"
echo

# Backup system configurations
echo "Backing up configurations..."
pdsh -w $CLUSTER --output-dir "$BACKUP_DIR/configs" "
    tar czf - /etc/nginx /etc/myapp 2>/dev/null
" || echo "Warning: Some config backups failed"

# Backup application data
echo "Backing up application data..."
for host in $(pdsh -w $CLUSTER -q); do
    echo "  - $host"
    ssh $host "sudo tar czf /tmp/app-data-$(hostname).tar.gz /var/lib/myapp" &&
    scp $host:/tmp/app-data-$(hostname).tar.gz "$BACKUP_DIR/" &&
    ssh $host "rm /tmp/app-data-$(hostname).tar.gz"
done

# Backup databases
echo "Backing up databases..."
pdsh -w db-servers "
    sudo -u postgres pg_dump mydb | gzip > /tmp/mydb-\$(hostname).sql.gz
"
for host in $(pdsh -w db-servers -q); do
    scp $host:/tmp/mydb-$(hostname).sql.gz "$BACKUP_DIR/"
    ssh $host "rm /tmp/mydb-$(hostname).sql.gz"
done

# Create backup manifest
echo "Creating manifest..."
{
    echo "Backup Date: $(date)"
    echo "Cluster: $CLUSTER"
    echo "Files:"
    ls -lh "$BACKUP_DIR"
} > "$BACKUP_DIR/MANIFEST.txt"

echo
echo "=== Backup complete ==="
echo "Location: $BACKUP_DIR"
```

### Monitoring Script with Alerts

```bash
#!/bin/bash
# monitor-cluster.sh - Monitor cluster and send alerts

CLUSTER="production"
ALERT_EMAIL="ops@example.com"
ALERT_THRESHOLD_CPU=80
ALERT_THRESHOLD_MEM=90
ALERT_THRESHOLD_DISK=85

check_cpu() {
    pdsh -w $CLUSTER "
        cpu_usage=\$(top -bn1 | grep 'Cpu(s)' | awk '{print \$2}' | cut -d'%' -f1 | cut -d'.' -f1)
        if [ \$cpu_usage -gt $ALERT_THRESHOLD_CPU ]; then
            echo \"\$(hostname): CPU \${cpu_usage}%\"
        fi
    "
}

check_memory() {
    pdsh -w $CLUSTER "
        mem_usage=\$(free | awk 'NR==2{printf \"%.0f\", \$3*100/\$2}')
        if [ \$mem_usage -gt $ALERT_THRESHOLD_MEM ]; then
            echo \"\$(hostname): Memory \${mem_usage}%\"
        fi
    "
}

check_disk() {
    pdsh -w $CLUSTER "
        df -h | awk 'NR>1 {
            usage=int(\$5)
            if (usage > $ALERT_THRESHOLD_DISK) {
                print \"\$(hostname): \" \$6 \" \" usage \"%\"
            }
        }'
    "
}

# Run checks
CPU_ALERTS=$(check_cpu)
MEM_ALERTS=$(check_memory)
DISK_ALERTS=$(check_disk)

# Send alert if issues found
if [ -n "$CPU_ALERTS" ] || [ -n "$MEM_ALERTS" ] || [ -n "$DISK_ALERTS" ]; then
    {
        echo "Cluster Alerts - $(date)"
        echo
        [ -n "$CPU_ALERTS" ] && echo "CPU Alerts:" && echo "$CPU_ALERTS"
        [ -n "$MEM_ALERTS" ] && echo "Memory Alerts:" && echo "$MEM_ALERTS"
        [ -n "$DISK_ALERTS" ] && echo "Disk Alerts:" && echo "$DISK_ALERTS"
    } | mail -s "Cluster Alert: $CLUSTER" "$ALERT_EMAIL"
fi
```

## See Also

- [pdsh Migration Guide](pdsh-migration.md) - Migration instructions
- [pdsh Options Reference](pdsh-options.md) - Complete option mapping
- [bssh README](../README.md) - Full feature documentation

---

**Note**: This document is maintained as part of the bssh project. For the latest version, see https://github.com/lablup/bssh/blob/main/docs/pdsh-examples.md
