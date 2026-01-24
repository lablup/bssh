# Audit Logging Guide

[Back to Documentation Index](./README.md)

This guide covers setting up and using audit logging in bssh-server for security monitoring,
compliance, and troubleshooting.

## Table of Contents

- [Overview](#overview)
- [Configuration](#configuration)
- [Audit Events](#audit-events)
- [Exporters](#exporters)
- [Log Analysis](#log-analysis)
- [Integration Examples](#integration-examples)
- [Best Practices](#best-practices)

## Overview

bssh-server provides comprehensive audit logging that captures security-relevant events including:

- Authentication attempts (success and failure)
- Session lifecycle (start, end, duration)
- Command execution
- File operations (read, write, delete, rename)
- Security events (IP blocks, suspicious activity)

Audit logs can be exported to multiple destinations simultaneously for flexibility in log management.

## Configuration

### Basic Configuration

Enable audit logging with file output:

```yaml
audit:
  enabled: true
  exporters:
    - type: file
      path: /var/log/bssh/audit.log
```

### Multiple Exporters

Send logs to multiple destinations:

```yaml
audit:
  enabled: true
  exporters:
    # Local file for backup/compliance
    - type: file
      path: /var/log/bssh/audit.log

    # OpenTelemetry for observability platform
    - type: otel
      endpoint: http://otel-collector:4317

    # Logstash for ELK stack
    - type: logstash
      host: logstash.example.com
      port: 5044
```

## Audit Events

### Event Types

| Event Type | Description | Logged Fields |
|------------|-------------|---------------|
| `AuthSuccess` | Successful authentication | user, method, client_ip |
| `AuthFailure` | Failed authentication attempt | user, method, client_ip, reason |
| `AuthRateLimited` | Authentication rate limited | client_ip, attempts |
| `SessionStart` | Session started | session_id, user, client_ip |
| `SessionEnd` | Session ended | session_id, user, duration |
| `CommandExecuted` | Command executed | session_id, user, command |
| `CommandBlocked` | Command blocked by policy | session_id, user, command, reason |
| `FileOpenRead` | File opened for reading | path, user |
| `FileOpenWrite` | File opened for writing | path, user |
| `FileRead` | File read operation | path, bytes |
| `FileWrite` | File write operation | path, bytes |
| `FileClose` | File closed | path |
| `FileUploaded` | File upload completed | path, bytes, user |
| `FileDownloaded` | File download completed | path, bytes, user |
| `FileDeleted` | File deleted | path, user |
| `FileRenamed` | File renamed | path, dest_path, user |
| `DirectoryCreated` | Directory created | path, user |
| `DirectoryDeleted` | Directory deleted | path, user |
| `DirectoryListed` | Directory listed | path, user |
| `TransferDenied` | Transfer blocked by filter | path, rule, user |
| `TransferAllowed` | Transfer explicitly allowed | path, rule, user |
| `IpBlocked` | IP address blocked | client_ip, reason |
| `IpUnblocked` | IP address unblocked | client_ip |
| `SuspiciousActivity` | Suspicious activity detected | client_ip, details |

### Event Structure

Each audit event contains:

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2026-01-24T12:00:00.000Z",
  "event_type": "AuthSuccess",
  "session_id": "session-123",
  "user": "johndoe",
  "client_ip": "192.168.1.100",
  "protocol": "ssh",
  "result": "success",
  "details": {
    "method": "publickey",
    "key_type": "ssh-ed25519"
  }
}
```

## Exporters

### File Exporter

Writes events to a file in JSON Lines format (one JSON object per line).

```yaml
audit:
  exporters:
    - type: file
      path: /var/log/bssh/audit.log
```

**Output Format:**
```json
{"id":"...","timestamp":"2026-01-24T12:00:00Z","event_type":"SessionStart",...}
{"id":"...","timestamp":"2026-01-24T12:00:01Z","event_type":"CommandExecuted",...}
```

**File Rotation:**

Use logrotate for log rotation:

```bash
# /etc/logrotate.d/bssh
/var/log/bssh/*.log {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root
    postrotate
        # Signal bssh-server to reopen log files if needed
        systemctl reload bssh-server 2>/dev/null || true
    endscript
}
```

### OpenTelemetry Exporter

Sends events to an OpenTelemetry Collector via OTLP/gRPC.

```yaml
audit:
  exporters:
    - type: otel
      endpoint: http://otel-collector:4317
```

**OpenTelemetry Collector Configuration:**

```yaml
# otel-collector-config.yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317

processors:
  batch:
    timeout: 1s
    send_batch_size: 100

exporters:
  # Export to Jaeger
  jaeger:
    endpoint: jaeger:14250
    tls:
      insecure: true

  # Export to Elasticsearch
  elasticsearch:
    endpoints: ["https://elasticsearch:9200"]
    logs_index: bssh-audit

  # Export to file
  file:
    path: /var/log/otel/bssh-audit.json

service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [batch]
      exporters: [elasticsearch, file]
```

### Logstash Exporter

Sends events directly to Logstash over TCP.

```yaml
audit:
  exporters:
    - type: logstash
      host: logstash.example.com
      port: 5044
```

**Logstash Configuration:**

```ruby
# logstash.conf
input {
  tcp {
    port => 5044
    codec => json_lines
  }
}

filter {
  # Parse timestamp
  date {
    match => ["timestamp", "ISO8601"]
  }

  # Add geo-IP for client addresses
  if [client_ip] {
    geoip {
      source => "client_ip"
    }
  }

  # Tag security events
  if [event_type] in ["AuthFailure", "IpBlocked", "SuspiciousActivity"] {
    mutate {
      add_tag => ["security_event"]
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "bssh-audit-%{+YYYY.MM.dd}"
  }
}
```

## Log Analysis

### Common Queries

**Failed Authentication Attempts:**
```bash
# From JSON Lines file
grep '"event_type":"AuthFailure"' /var/log/bssh/audit.log | \
  jq -r '[.timestamp, .user, .client_ip] | @tsv'
```

**Sessions by User:**
```bash
grep '"event_type":"SessionStart"' /var/log/bssh/audit.log | \
  jq -r '.user' | sort | uniq -c | sort -rn
```

**File Transfers:**
```bash
grep -E '"event_type":"(FileUploaded|FileDownloaded)"' /var/log/bssh/audit.log | \
  jq -r '[.timestamp, .event_type, .user, .path, .bytes] | @tsv'
```

**Blocked IPs:**
```bash
grep '"event_type":"IpBlocked"' /var/log/bssh/audit.log | \
  jq -r '[.timestamp, .client_ip, .details.reason] | @tsv'
```

### Elasticsearch Queries

**Authentication Failures in Last Hour:**
```json
{
  "query": {
    "bool": {
      "must": [
        {"term": {"event_type": "AuthFailure"}},
        {"range": {"timestamp": {"gte": "now-1h"}}}
      ]
    }
  },
  "aggs": {
    "by_ip": {
      "terms": {"field": "client_ip"}
    }
  }
}
```

**Top Users by Session Count:**
```json
{
  "query": {
    "term": {"event_type": "SessionStart"}
  },
  "aggs": {
    "by_user": {
      "terms": {"field": "user", "size": 10}
    }
  }
}
```

## Integration Examples

### Grafana Dashboard

Create alerts for security events:

```yaml
# Grafana alert rule
groups:
  - name: bssh-security
    rules:
      - alert: HighAuthFailureRate
        expr: |
          sum(rate(bssh_auth_failures_total[5m])) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: High authentication failure rate

      - alert: IPBlocked
        expr: |
          increase(bssh_ip_blocked_total[1m]) > 0
        for: 0m
        labels:
          severity: info
        annotations:
          summary: IP address blocked due to failed auth attempts
```

### SIEM Integration

**Splunk:**

Configure HTTP Event Collector (HEC) via OpenTelemetry Collector:

```yaml
exporters:
  splunk_hec:
    token: "<your-hec-token>"
    endpoint: "https://splunk:8088/services/collector"
    source: "bssh-server"
    sourcetype: "bssh:audit"
```

**Datadog:**

```yaml
exporters:
  datadog:
    api:
      key: "<your-api-key>"
    logs:
      enabled: true
```

### Security Automation

**Automatic IP Blocking with fail2ban:**

```ini
# /etc/fail2ban/filter.d/bssh.conf
[Definition]
failregex = "event_type":"AuthFailure".*"client_ip":"<HOST>"
ignoreregex =

# /etc/fail2ban/jail.d/bssh.conf
[bssh]
enabled = true
filter = bssh
logpath = /var/log/bssh/audit.log
maxretry = 5
bantime = 3600
findtime = 600
```

## Best Practices

### 1. Enable Audit Logging in Production

Always enable audit logging for production deployments:

```yaml
audit:
  enabled: true
```

### 2. Use Multiple Exporters

Send logs to multiple destinations for redundancy:

```yaml
audit:
  exporters:
    - type: file
      path: /var/log/bssh/audit.log
    - type: otel
      endpoint: http://otel-collector:4317
```

### 3. Protect Audit Logs

Secure audit log files:

```bash
chmod 600 /var/log/bssh/audit.log
chown root:root /var/log/bssh/audit.log
```

### 4. Retain Logs Appropriately

Configure retention based on compliance requirements:
- SOC 2: Minimum 1 year
- HIPAA: Minimum 6 years
- PCI DSS: Minimum 1 year
- GDPR: As long as necessary, minimize data

### 5. Monitor Security Events

Set up alerts for:
- High authentication failure rates
- IP blocks
- Unusual session patterns
- Suspicious file access

### 6. Regular Log Review

Schedule regular review of audit logs:
- Daily: Security events (AuthFailure, IpBlocked)
- Weekly: Session patterns, user activity
- Monthly: Overall trends, compliance reports

### 7. Avoid Logging Sensitive Data

Be aware that command execution events may contain sensitive data. Consider:
- Filtering commands before logging
- Encrypting audit logs at rest
- Restricting access to audit logs

## Troubleshooting

### Logs Not Being Written

1. Check if audit is enabled:
   ```yaml
   audit:
     enabled: true
   ```

2. Verify file permissions:
   ```bash
   ls -la /var/log/bssh/
   ```

3. Check disk space:
   ```bash
   df -h /var/log
   ```

### OpenTelemetry Connection Failed

1. Verify endpoint is reachable:
   ```bash
   nc -zv otel-collector 4317
   ```

2. Check collector logs:
   ```bash
   docker logs otel-collector
   ```

### High Log Volume

1. Consider sampling for high-traffic deployments
2. Adjust log rotation settings
3. Filter verbose events (FileRead/FileWrite)

## See Also

- [Server Configuration](./architecture/server-configuration.md)
- [Security Guide](./security.md)
- [Container Deployment](./container-deployment.md)
