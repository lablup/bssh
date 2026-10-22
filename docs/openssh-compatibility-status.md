# OpenSSH compatibility status and remaining contracts

Full OpenSSH command compatibility is the target, not a claim about the current release. A regression score, accepted option, or working bssh-to-bssh control socket does not establish a complete replacement. Residual work after [#314](https://github.com/lablup/bssh/issues/314) is tracked in [#327](https://github.com/lablup/bssh/issues/327) (destination-constrained agent keys) and [#328](https://github.com/lablup/bssh/issues/328) (FIDO host-key phases of `hostkey-agent`); [#281](https://github.com/lablup/bssh/issues/281) was closed in favor of #314.

## Measurement boundary

The reference is OpenSSH portable `V_10_3_P1`, immutable commit `2d98db98331803cbb820211b2fb0d31a6e71e58e`. The harness executes the candidate bssh binary against the reference server and reruns failures with the reference client. See the [harness guide](openssh-regress.md) for reproduction commands, verdicts, floors and artifacts. Focused results do not replace the full macOS and Ubuntu matrix.

The compatibility contract concerns single-destination SSH invocation. Parallel/cluster extensions use documented long options; pdsh compatibility is a separate mode and does not redefine ordinary SSH short options. Command behavior, SSH server wire interoperability and local OpenSSH control-socket interoperability are distinct contracts.

Historical [workflow run 33457298369](https://github.com/lablup/bssh/actions/runs/33457298369) measured macOS 60/66 eligible (six failures, seven environmental, six upstream skips), Ubuntu 61/69 eligible (eight failures, four environmental, six upstream skips). These measurements predate this follow-up and are not fresh integrated-HEAD evidence. The committed `tests/openssh-regress/results.json` is also historical.

## Residual compatibility ledger

This ledger records contracts still requiring implementation or verification, not a claim inferred from fixture coverage. Update behavior and validation evidence together before removing a row.

| Area | Remaining contract | Evidence boundary |
|---|---|---|
| Dynamic forwarding | Local SOCKS4/4A/5; remote dynamic `-R [bind_address:]port`, destination restrictions and cancellation | Historical `dynamic-forward` fails on both platforms. Passing its local `-D` section does not establish remote dynamic support. |
| Percent/environment | Directive-specific tokens and environment expansion, trusted `Match exec`, explicitly permitted shell `LocalCommand` | Historical `percent` fails on both platforms. Shell semantics must retain `PermitLocalCommand` gating and untrusted-input boundaries. |
| Rekey | Actual byte/time-triggered exchange and truthful KEX/NEWKEYS diagnostics | `rekey` passes on Linux (114.3 s candidate, 114.5 s reference) after the client stopped padding every connection by 0.6 s; the manifest minimum is 180 s. macOS remains environmental (the reference client also exceeds the limit there). |
| Agent | Destination-constrained identities (`session-bind@openssh.com`) | Every `agent-restrict` phase that does not need a constrained key passes on Linux; the eight constrained phases fail until russh exposes the binding tuple. Tracked in #327. |
| Host certificates | FIDO (`sk-*`) host keys and certificates | `hostkey-agent` passes every plain and non-FIDO certificate phase and `multiple hostkeys`; the two `sk-*-cert-v01@openssh.com` phases fail because bssh does not advertise FIDO host-key types. Tracked in #328. |
| Multiplexing | OpenSSH mux-v4 local protocol, raw `-O proxy`, complete channel reporting, allocated remote-port replies | `multiplex` passes on Linux (72.1 s) including TCP and Unix-domain `-O forward`/`-O cancel`, when the regress directory path fits `sockaddr_un`. Control sockets still use framed JSON; passenger reuse is not OpenSSH-master interoperability. |
| Jump hosts | CLI/config parsing, SSH URI hops, `none`, multihop transport/authentication | Historical `proxyjump` fails on both platforms. Parser tests alone do not establish transport behavior. |
| Remote copy | Remote-to-remote copy invocation, transport selection, integrity and exit status | Historical Ubuntu `scp3` fails; macOS environmental. |

## Current safety boundaries

Host-aware file preprocessing is the only path that gives trusted `Match exec` OpenSSH shell semantics. Other parser callers use direct execution: the executable name is fixed before percent-token expansion, percent tokens are expanded only in later arguments, and expanded whitespace stays within its original argument. Command-line hostnames reject whitespace, control bytes and shell metacharacters; remote users entering trusted shell-token paths additionally reject whitespace, `$` and backslashes. These restrictions are intentional fail-closed differences until expansion is context-aware.

The Unix `ProcessStdin` adapter makes read-only FIFOs nonblocking while owned, uses per-call nonblocking reads for sockets so shared write behavior is unchanged, and routes regular files through Tokio's file adapter. A FIFO opened with `O_RDWR` is explicitly unsupported because changing its shared file-description flags could affect another user of stdin; other non-pipe/socket devices retain the existing blocking adapter and are not claimed cancellation-safe.

The implemented control socket is bssh's private framed-JSON protocol. Its passenger reuse, `-O proxy` session behavior and status commands do not imply compatibility with OpenSSH mux-v4 masters or raw proxy streams.

Unix-domain forwarding (`-L`/`-R` with a socket path on either side, including `-O forward`/`-O cancel`) never unlinks an existing path before binding and refuses to serve a bound path that is a symlink or not a socket; the listener socket is owner-only (mode 0600) without any mode change through the path name: on Linux the unbound socket is narrowed before `bind(2)` so the node is created 0600; elsewhere it is bound in a private `mkdtemp` directory beside the path, narrowed there with `fchmodat(AT_SYMLINK_NOFOLLOW)`, and moved into place without replacing anything (`renamex_np(RENAME_EXCL)` on macOS, `link(2)` then `unlink(2)` on other BSDs), so the node never appears at the path with a wider mode. Only a socket node is removed on shutdown. `StreamLocalBindUnlink` and `StreamLocalBindMask` are still parsed without a runtime consumer; the OpenSSH defaults (`no`, `0177`) are what the implementation applies.

Host certificates are accepted only after full validation: a `@cert-authority` line (in a known_hosts file or in the `KnownHostsCommand` output, which receives the certificate as `%K`/`%t` and runs once per check) naming the host (or `HostKeyAlias`) with the signing CA key, host certificate type, a principal matching the host name (principals may be case-sensitive wildcard patterns, as in OpenSSH, and are read only after the CA signature verifies), no critical options, a CA signature algorithm permitted by `CASignatureAlgorithms`, the validity window, a verified signature, and no revocation by `@revoked` lines in either source or by any `RevokedHostKeys` file (plain key lists; a KRL or unreadable file anywhere in the list fails closed). On a non-default port a CA line for the bare host name also matches, as OpenSSH's portless retry does. Without a matching CA the certified key is checked as a plain host key, but only if `HostKeyAlgorithms` permits its plain type, so a certificate-only list never falls back to known_hosts or first-use recording; a pinned key (`ServerCheckMethod::PublicKey`/`PublicKeyFile`) never consults CA lines; with a matching CA any other validation failure refuses the connection instead of downgrading, which is stricter than OpenSSH. `HostKeyAlgorithms` accepts certificate names and advertises the certificate form of every default algorithm; russh always sends certificate names ahead of plain names, so a mixed list cannot interleave them, and a certificate-only list yields no plain algorithm at all. `@cert-authority` host fields follow OpenSSH matching, including hashed (`|1|`) entries and `!pattern` negations that exclude a host from the CA's scope. A `RevokedHostKeys` path that cannot be expanded refuses every host key instead of disabling revocation, and `RevokedHostKeys` applies to certificates under `StrictHostKeyChecking=no` as it does to plain keys.

## ssh_config integration

Each first-wave directive in #281 has a runtime consumer and behavior/policy test. Registry tests in `src/ssh/ssh_config/parser/options/support.rs` enforce one classification per keyword/alias. `canonical_unimplemented_and_unknown_diagnostics_use_real_source_and_log_file` checks named, source-located, once-only warnings. These checks prevent silent discard, not all semantic incompatibility.

Named-regress acceptance is separate: historical results include candidate failures in `dynamic-forward`, `percent` and `rekey`, environmental `forwarding`, and a whitespace-path-related `ssh-tty` skip. Environmental evidence is not a candidate pass. #281 stays open until integrated regression and behavior requirements are satisfied or explicitly revised.

## Previously excluded scope

[#275](https://github.com/lablup/bssh/issues/275) excluded GSSAPI, PKCS#11/FIDO middleware, X11, tun forwarding, KRL generation, CA signing, sshd configuration tests and PuTTY/Dropbear/Twisted conch/ssh.com interoperability. Manifest rows preserve reasons. `cert-userkey`, named by #281, is permanently skipped for CA signing; it must not be marked passed.

These exclusions bounded the original score-gated epic, not full compatibility. Revisit them explicitly for a broader replacement contract. Distinguish server-only tooling and third-party interoperability from the desired `ssh(1)` surface instead of silently declaring them implemented. Unsupported configuration requires explicit diagnostics until runtime support exists.

## Dependency boundary: destination-constrained agents

`agent-restrict` requires OpenSSH `session-bind@openssh.com` before agent identity listing. russh 0.64.1 does not expose the complete proof tuple: the exact negotiated host-key/certificate blob, initial KEX session ID, and server KEX signature. Binding a plain key instead of the certificate blob loses certificate-principal constraints; replacing the initial proof after rekey is also incorrect. Direct authentication and forwarded agent connections require distinct binding modes. Constraints must never be dropped to make authentication succeed.

[PR #317](https://github.com/lablup/bssh/pull/317) removed the maintained russh fork after required APIs landed upstream; [PR #320](https://github.com/lablup/bssh/pull/320) similarly returned SFTP to upstream. Full constrained-agent support therefore needs an explicit dependency decision: preferably add a typed binding API upstream and consume a published release; alternatively use a temporary immutable revision of the official upstream after merge. A contributor-fork bridge or vendored implementation requires separate approval, a removal plan, and the same protocol tests. No such dependency change is implied by this ledger or by the existing agent-authentication fixes.

## Follow-up validation checkpoints

The following focused checks were performed on a Linux aarch64 host while closing #314. They are not a full integrated two-platform result and do not lower either committed score floor. The regress directory on that host is longer than `sockaddr_un` allows, so the pinned harness classifies `multiplex` and `agent-restrict` as environmental there (the reference client fails the same way); the Unix-socket phases were run through a short symlinked OBJ directory instead.

- `rekey`: pinned harness passes in 114.3 s (reference client 114.5 s on the same host, 105 s of it sleeping); the manifest minimum was raised to 180 s with those numbers.
- `multiplex`: passes in 72.1 s through the short OBJ path, including the TCP `forward` phase, Unix-domain `forward`, and the TCP and Unix `-O forward`/`-O cancel` phases.
- `hostkey-agent`: every plain key type, every non-FIDO certificate type, and `multiple hostkeys` pass; only the two `sk-*` certificate phases fail (#328). An explicit certificate-only `HostKeyAlgorithms` restriction is now honored instead of being widened to the default certificate list.
- `agent-restrict`: through the short OBJ path, every phase passes except the eight that need `session-bind@openssh.com` (#327), including the certificate hosts `host_d` and `host_e` in the `w/o agent` and unrestricted phases.

The earlier macOS checkpoints from the first #314 follow-up are kept below for history.

- `dynamic-forward`: pinned harness passes (35.3 seconds), including local and remote dynamic SOCKS phases.
- `percent`: pinned harness passes (42.977 seconds) after destination User/Port is reflected in trusted file preprocessing.
- `rekey`: pinned harness passes (142.750 seconds). Diagnostic lines come from actual completed KEX events and respect the effective debug LogLevel; no synthetic exchange counts are emitted.
- `proxyjump`: pinned harness passes (4.887 seconds). Five focused parser/chain tests also pass.
- `scp3`: candidate now completes all legacy SCP and SFTP cases instead of hanging on the first pipe-backed session; candidate and reference encounter the same macOS symlink/unsafe temporary-path failure, so the pinned verdict remains environmental (7.519 seconds), not pass. An explicit legacy `scp -O -3` 1 MiB remote-to-remote copy succeeds with matching bytes. The cancellable pipe/socket stdin helper has five passing focused tests, including regular-file routing, buffered-socket draining and fail-closed `O_RDWR` FIFO handling.
- `multiplex`: pinned test remains failed (78.3 seconds), with Unix-domain forwarding and control forward/cancel failures. Endpoint/negotiated-algorithm `conninfo`, check/exit/stop, status and TCP phases pass. Snapshot SHA-256: `bc9ca3e4f9d672d3416a9f3a8fe8a538d8db3e2f8b19f8028fbee6085551c58b`. Passing passenger-emulated proxy phases does not establish raw mux-v4 proxy support.
- `agent-restrict` (historical): unrestricted/offline-private-key phase passes; destination restrictions remain blocked on the upstream binding API.
- `hostkey-agent` (historical): plain host-key algorithms pass; the certificate slice of that time was removed.

Security regression coverage preserves trusted-file-only shell Match execution, bounded SOCKS negotiation, and first-obtained fail-closed `PermitRemoteOpen`. Host-certificate authority validation, certificate revocation and `CASignatureAlgorithms` policy are implemented and covered by unit tests in `src/ssh/tokio_client/host_certificate.rs` and `host_verification.rs`.

The binding API proposal is [russh PR #794](https://github.com/Eugeny/russh/pull/794). Dependency adoption is conditional on upstream merge: only an immutable merged revision from the official upstream may be used temporarily, followed by a crates.io release. An unmerged contributor branch is not an approved dependency. Current code must continue to fail closed on unsupported agent constraints.

Remaining control details include complete forwarding-channel enumeration, allocated remote-port replies, multiplexed `-W`, TTY-failure notifications and `~user` expansion. Unix-domain forwarding is implemented; raw mux-v4 interoperability is not. Eager `zlib` is validated; delayed `zlib@openssh.com` is not advertised. Non-pipe/socket character-device stdin still uses the existing blocking adapter; the SCP fix does not claim every stdin source is cancellation-safe.
