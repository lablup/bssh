# Container Deployment Guide

[Back to Documentation Index](./README.md)

This guide covers deploying bssh-server in containerized environments including Docker and Kubernetes.

## Table of Contents

- [Docker Deployment](#docker-deployment)
- [Docker Compose](#docker-compose)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Configuration Best Practices](#configuration-best-practices)
- [Health Checks](#health-checks)
- [Logging and Monitoring](#logging-and-monitoring)

## Docker Deployment

### Dockerfile

Create a minimal Dockerfile for bssh-server:

```dockerfile
FROM debian:bookworm-slim

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Create bssh user and directories
RUN useradd -m -s /bin/bash bsshuser \
    && mkdir -p /etc/bssh /var/log/bssh \
    && chmod 755 /etc/bssh /var/log/bssh

# Copy binaries
COPY --chmod=755 bssh-server /usr/local/bin/
COPY --chmod=755 bssh-keygen /usr/local/bin/

# Generate host keys at build time (or mount at runtime)
RUN bssh-keygen -t ed25519 -f /etc/bssh/ssh_host_ed25519_key -y -q

# Copy configuration
COPY server.yaml /etc/bssh/server.yaml

# Expose SSH port
EXPOSE 22

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD nc -z localhost 22 || exit 1

# Run server
ENTRYPOINT ["bssh-server"]
CMD ["-c", "/etc/bssh/server.yaml", "-D"]
```

### Minimal Configuration for Containers

```yaml
# server.yaml for container deployment
server:
  bind_address: "0.0.0.0"
  port: 22
  host_keys:
    - /etc/bssh/ssh_host_ed25519_key
  max_connections: 100
  timeout: 300
  keepalive_interval: 60

auth:
  methods:
    - publickey
  publickey:
    authorized_keys_dir: /etc/bssh/authorized_keys

shell:
  default: /bin/bash
  command_timeout: 3600

sftp:
  enabled: true

scp:
  enabled: true

security:
  max_auth_attempts: 5
  ban_time: 300
  max_sessions_per_user: 10
  idle_timeout: 3600
```

### Build and Run

```bash
# Build the image
docker build -t bssh-server:latest .

# Run with mounted authorized_keys
docker run -d \
  --name bssh-server \
  -p 2222:22 \
  -v /path/to/authorized_keys:/etc/bssh/authorized_keys/myuser/authorized_keys:ro \
  bssh-server:latest

# Connect
ssh -p 2222 myuser@localhost
```

### Runtime Host Key Generation

For production, generate host keys at runtime to ensure each container has unique keys:

```dockerfile
FROM debian:bookworm-slim

# ... base setup ...

# Entrypoint script for key generation
COPY --chmod=755 entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
```

```bash
#!/bin/bash
# entrypoint.sh

# Generate host key if not exists
if [ ! -f /etc/bssh/ssh_host_ed25519_key ]; then
    echo "Generating host key..."
    bssh-keygen -t ed25519 -f /etc/bssh/ssh_host_ed25519_key -y -q
fi

# Start server
exec bssh-server -c /etc/bssh/server.yaml -D "$@"
```

## Docker Compose

### Basic Setup

```yaml
# docker-compose.yml
version: '3.8'

services:
  bssh-server:
    image: bssh-server:latest
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "2222:22"
    volumes:
      - ./config/server.yaml:/etc/bssh/server.yaml:ro
      - ./authorized_keys:/etc/bssh/authorized_keys:ro
      - ssh_host_keys:/etc/bssh/keys
    environment:
      - BSSH_PORT=22
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "nc", "-z", "localhost", "22"]
      interval: 30s
      timeout: 5s
      retries: 3

volumes:
  ssh_host_keys:
```

### With Audit Logging

```yaml
# docker-compose.yml with audit logging
version: '3.8'

services:
  bssh-server:
    image: bssh-server:latest
    ports:
      - "2222:22"
    volumes:
      - ./config/server.yaml:/etc/bssh/server.yaml:ro
      - ./authorized_keys:/etc/bssh/authorized_keys:ro
      - audit_logs:/var/log/bssh
    depends_on:
      - otel-collector
    restart: unless-stopped

  otel-collector:
    image: otel/opentelemetry-collector:latest
    ports:
      - "4317:4317"
    volumes:
      - ./otel-config.yaml:/etc/otel/config.yaml:ro
    command: ["--config=/etc/otel/config.yaml"]

volumes:
  audit_logs:
```

### Environment Variable Configuration

```yaml
services:
  bssh-server:
    image: bssh-server:latest
    environment:
      - BSSH_PORT=22
      - BSSH_BIND_ADDRESS=0.0.0.0
      - BSSH_HOST_KEY=/etc/bssh/ssh_host_ed25519_key
      - BSSH_AUTH_METHODS=publickey
      - BSSH_AUTHORIZED_KEYS_DIR=/etc/bssh/authorized_keys
      - BSSH_SHELL=/bin/bash
      - BSSH_MAX_CONNECTIONS=100
```

## Kubernetes Deployment

### ConfigMap for Configuration

```yaml
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: bssh-server-config
data:
  server.yaml: |
    server:
      bind_address: "0.0.0.0"
      port: 22
      host_keys:
        - /etc/bssh/keys/ssh_host_ed25519_key
      max_connections: 100

    auth:
      methods:
        - publickey
      publickey:
        authorized_keys_dir: /etc/bssh/authorized_keys

    shell:
      default: /bin/bash

    sftp:
      enabled: true

    scp:
      enabled: true

    security:
      max_auth_attempts: 5
      ban_time: 300
```

### Secret for Host Keys

```yaml
# secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: bssh-host-keys
type: Opaque
data:
  # Base64-encoded host key (generate with bssh-server gen-host-key, then base64 encode)
  ssh_host_ed25519_key: <base64-encoded-private-key>
```

### Deployment

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bssh-server
  labels:
    app: bssh-server
spec:
  replicas: 1
  selector:
    matchLabels:
      app: bssh-server
  template:
    metadata:
      labels:
        app: bssh-server
    spec:
      containers:
      - name: bssh-server
        image: bssh-server:latest
        ports:
        - containerPort: 22
          name: ssh
        args:
        - "-c"
        - "/etc/bssh/server.yaml"
        - "-D"
        volumeMounts:
        - name: config
          mountPath: /etc/bssh/server.yaml
          subPath: server.yaml
          readOnly: true
        - name: host-keys
          mountPath: /etc/bssh/keys
          readOnly: true
        - name: authorized-keys
          mountPath: /etc/bssh/authorized_keys
          readOnly: true
        resources:
          requests:
            memory: "64Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "500m"
        livenessProbe:
          tcpSocket:
            port: 22
          initialDelaySeconds: 5
          periodSeconds: 10
        readinessProbe:
          tcpSocket:
            port: 22
          initialDelaySeconds: 5
          periodSeconds: 5
        securityContext:
          readOnlyRootFilesystem: true
          runAsNonRoot: false  # Required for port 22
      volumes:
      - name: config
        configMap:
          name: bssh-server-config
      - name: host-keys
        secret:
          secretName: bssh-host-keys
          defaultMode: 0600
      - name: authorized-keys
        configMap:
          name: bssh-authorized-keys
```

### Service

```yaml
# service.yaml
apiVersion: v1
kind: Service
metadata:
  name: bssh-server
spec:
  type: LoadBalancer  # or NodePort, ClusterIP
  ports:
  - port: 22
    targetPort: 22
    name: ssh
  selector:
    app: bssh-server
```

### Complete Kubernetes Deployment

```bash
# Create namespace
kubectl create namespace bssh

# Generate host key and create secret
bssh-server gen-host-key -t ed25519 -o /tmp/ssh_host_ed25519_key -y
kubectl create secret generic bssh-host-keys \
  --from-file=ssh_host_ed25519_key=/tmp/ssh_host_ed25519_key \
  -n bssh
rm /tmp/ssh_host_ed25519_key

# Create authorized keys configmap
kubectl create configmap bssh-authorized-keys \
  --from-file=myuser/authorized_keys=$HOME/.ssh/id_ed25519.pub \
  -n bssh

# Apply configuration
kubectl apply -f configmap.yaml -n bssh
kubectl apply -f deployment.yaml -n bssh
kubectl apply -f service.yaml -n bssh

# Check status
kubectl get pods -n bssh
kubectl get svc -n bssh
```

## Configuration Best Practices

### 1. Use Read-Only Mounts

Mount configuration and keys as read-only to prevent modification:

```yaml
volumes:
  - name: config
    mountPath: /etc/bssh/server.yaml
    readOnly: true
```

### 2. Separate Host Keys Per Instance

For security, each container instance should have unique host keys. Use:
- Init containers to generate keys
- Persistent volumes for key storage
- Or accept ephemeral keys for disposable containers

### 3. Resource Limits

Always set resource limits:

```yaml
resources:
  requests:
    memory: "64Mi"
    cpu: "100m"
  limits:
    memory: "256Mi"
    cpu: "500m"
```

### 4. Security Context

Minimize container privileges:

```yaml
securityContext:
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
    add:
      - NET_BIND_SERVICE  # Only if binding to port < 1024
```

## Health Checks

### TCP Health Check

```bash
# Simple TCP check
nc -z localhost 22
```

### SSH Banner Check

```bash
# Check SSH banner
timeout 5 bash -c 'echo | nc localhost 22' | grep -q SSH
```

### Docker Health Check

```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD nc -z localhost 22 || exit 1
```

### Kubernetes Probes

```yaml
livenessProbe:
  tcpSocket:
    port: 22
  initialDelaySeconds: 5
  periodSeconds: 10
  failureThreshold: 3

readinessProbe:
  tcpSocket:
    port: 22
  initialDelaySeconds: 5
  periodSeconds: 5
```

## Logging and Monitoring

### Log Collection with Audit

```yaml
# server.yaml
audit:
  enabled: true
  exporters:
    - type: file
      path: /var/log/bssh/audit.log
```

### OpenTelemetry Integration

```yaml
# server.yaml
audit:
  enabled: true
  exporters:
    - type: otel
      endpoint: http://otel-collector:4317
```

### Prometheus Metrics (via OTEL)

Configure OpenTelemetry Collector to export metrics to Prometheus:

```yaml
# otel-config.yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317

exporters:
  prometheus:
    endpoint: 0.0.0.0:8889

service:
  pipelines:
    metrics:
      receivers: [otlp]
      exporters: [prometheus]
```

## See Also

- [Quick Start Guide](./quick-start.md)
- [Server Configuration](./architecture/server-configuration.md)
- [Audit Logging](./audit-logging.md)
- [Security Guide](./security.md)
