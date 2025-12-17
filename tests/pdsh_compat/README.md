# pdsh Compatibility Test Suite

This directory contains integration tests for pdsh compatibility mode.

## Test Files

- **test_basic.sh** - Basic command execution tests
- **test_hostlist.sh** - Hostlist expression expansion tests
- **test_options.sh** - Option mapping tests
- **test_edge_cases.sh** - Edge cases and error handling

## Running Tests

### Prerequisites

1. **bssh must be installed** and in PATH
2. **Test hosts must be accessible** via SSH
3. **SSH keys must be configured** for passwordless authentication

### Setup

Configure test hosts in environment variables:

```bash
export BSSH_TEST_HOSTS="localhost"
export BSSH_TEST_USER="$USER"
```

For multi-host tests:

```bash
export BSSH_TEST_HOSTS="host1,host2,host3"
export BSSH_TEST_USER="testuser"
```

### Run All Tests

```bash
cd tests/pdsh_compat
./run_all_tests.sh
```

### Run Individual Tests

```bash
./test_basic.sh
./test_hostlist.sh
./test_options.sh
./test_edge_cases.sh
```

## Test Coverage

### Basic Tests (`test_basic.sh`)
- Simple command execution
- Multiple hosts
- Query mode
- Exit codes

### Hostlist Tests (`test_hostlist.sh`)
- Range expansion (`host[1-5]`)
- Zero-padded ranges (`node[01-10]`)
- Cartesian products (`rack[1-2]-node[1-3]`)
- Comma-separated lists

### Options Tests (`test_options.sh`)
- Host selection (`-w`)
- Exclusion (`-x`)
- Fanout (`-f`)
- Timeouts (`-t`, `-u`)
- Output control (`-N`)
- Batch mode (`-b`)
- Fail-fast (`-k`)

### Edge Cases (`test_edge_cases.sh`)
- Invalid hostlist syntax
- Connection failures
- Command timeouts
- Missing hosts
- Glob patterns in exclusions

## CI Integration

These tests can be run in CI/CD pipelines:

```yaml
# Example GitHub Actions
- name: Run pdsh compatibility tests
  env:
    BSSH_TEST_HOSTS: "localhost"
    BSSH_TEST_USER: "runner"
  run: |
    cd tests/pdsh_compat
    ./run_all_tests.sh
```

## Test Environment

Tests assume:
- SSH server running on test hosts
- Passwordless SSH authentication configured
- User has permission to execute test commands
- Test hosts have standard Unix utilities (echo, hostname, etc.)

## Troubleshooting

### SSH Connection Issues

```bash
# Test SSH connectivity first
ssh $BSSH_TEST_USER@$BSSH_TEST_HOSTS "echo test"

# Check SSH keys
ssh-add -l
```

### Test Failures

Run tests with verbose mode:

```bash
BSSH_TEST_VERBOSE=1 ./test_basic.sh
```

### Permission Issues

Ensure test user has appropriate permissions:

```bash
# Test as current user
export BSSH_TEST_USER="$USER"
export BSSH_TEST_HOSTS="localhost"
```

## Contributing

When adding new tests:

1. Follow existing test structure
2. Add descriptive test names
3. Include both positive and negative test cases
4. Update this README with new test coverage
5. Ensure tests can run in CI environment

## License

These tests are part of the bssh project and licensed under Apache 2.0.
