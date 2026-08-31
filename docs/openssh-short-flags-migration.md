# Migrating bssh Short Flags for 3.0

bssh 3.0 assigns seven single-letter options their OpenSSH meanings. Existing
bssh automation must use long options for the displaced cluster and pdsh-style
features.

## Release-status note

This is the target contract for 3.0. The source tree still reports version
2.4.3 while the compatibility epic is being implemented. The requirement to
warn in a final 2.x release before reassignment is a release-history
requirement: this documentation and the 3.0 implementation do not, by
themselves, prove that such a warning was shipped. Release notes must not mark
that requirement complete without evidence from a published 2.x release.

## Script rewrites

| Former bssh use | Rewrite for 3.0 | What the short flag means in 3.0 |
|-----------------|-----------------|----------------------------------|
| `-N` to remove node prefixes | `--no-prefix` | Do not execute a remote command |
| `-f PATTERN` to filter hosts | `--filter PATTERN` | Go to the background after authentication |
| `-C CLUSTER` to select a cluster | `--cluster CLUSTER` | Enable SSH compression |
| `-A` to authenticate with the local agent | `--use-agent` | Forward the authentication agent to the remote host |
| `-S` to prompt for a sudo password | `--sudo-password` | Set the multiplexing `ControlPath`; it now requires a path |
| `-k` to stop on the first failed node | `--fail-fast` | Disable GSSAPI credential delegation |
| `-b` to use single-stage Ctrl+C handling | `--batch` | Bind the client to a source address; it now requires an address |

For example:

```bash
# Before 3.0
bssh -C production -f 'web*' -A -S -k -b 'sudo systemctl restart nginx'

# 3.0
bssh --cluster production --filter 'web*' --use-agent \
  --sudo-password --fail-fast --batch 'sudo systemctl restart nginx'
```

The authentication meanings of `-A` and `--use-agent` are deliberately
different. `--use-agent` lets bssh use a local agent to authenticate the
connection. OpenSSH-compatible `-A` makes that agent available to processes on
the remote host, which expands the trust boundary and should be enabled only
when needed.

## OpenSSH-compatible examples

Use `-N` for a forwarding-only connection:

```bash
bssh -N -L 8080:internal.example.com:80 user@gateway.example.com
```

Use `-S` to select a connection-sharing socket:

```bash
bssh -M -S ~/.ssh/bssh-%C user@host
bssh -S ~/.ssh/bssh-%C user@host uptime
```

Use the long bssh options when selecting clusters or changing multi-node
output behavior:

```bash
bssh --cluster production --filter 'web*' --no-prefix --stream uptime
bssh --cluster production --fail-fast --batch deploy.sh
```

## pdsh compatibility mode

The pdsh parser remains separate from the native bssh parser. Its established
short options keep their pdsh meanings when any of these activation methods is
used:

```bash
bssh --pdsh-compat -w host[1-5] -f 2 -N -b -k -S uptime
pdsh -w host[1-5] -f 2 -N -b -k -S uptime
BSSH_PDSH_COMPAT=1 bssh -w host[1-5] -f 2 -N -b -k -S uptime
```

In pdsh mode, `-f` is fanout, `-N` removes the hostname prefix, `-b` selects
batch interrupt handling, `-k` is fail-fast, and `-S` returns the largest
remote exit status. The pdsh-compatible parser does not expose bssh's cluster,
agent-authentication, or sudo-password extensions. Use native bssh mode and
the long options `--cluster`, `--use-agent`, and `--sudo-password` for those
features.

## Migration checklist

1. Replace all displaced bssh short options with the long forms in the table.
2. Keep pdsh short options only in scripts that explicitly activate pdsh mode.
3. Review every former `-A`: authentication-agent forwarding is more
   security-sensitive than local agent authentication.
4. Add `-N` to forwarding-only SSH invocations that should not open a shell.
5. Test wrappers and aliases because `-S` and `-b` now require values.
