#!/usr/bin/env python3
"""SFTP interop check against bssh-server using paramiko.

Uploads a file, downloads it back, and verifies byte-for-byte integrity.

Known issue: with paramiko's default prefetch (a burst of READ requests for
the whole file), the download currently hangs against bssh-server; see
https://github.com/lablup/bssh/issues/227. Until that is fixed, the default
invocation reproduces the bug (bounded by --timeout), and --no-prefetch
exercises the sequential read path, which completes.

Requires: pip install paramiko
"""

import argparse
import filecmp
import os
import signal
import sys
import time

import paramiko


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=22200)
    parser.add_argument("--user", required=True)
    parser.add_argument("--key", required=True, help="RSA private key in PEM format")
    parser.add_argument("--file", required=True, help="local test file to round-trip")
    parser.add_argument("--remote-dir", required=True, help="writable directory on the server")
    parser.add_argument(
        "--no-prefetch",
        action="store_true",
        help="download sequentially instead of with paramiko's read-ahead burst",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=120,
        help="hard limit in seconds for the whole round trip (default 120)",
    )
    args = parser.parse_args()

    def on_timeout(signum, frame):
        print(f"TIMEOUT after {args.timeout}s (see lablup/bssh#227)", flush=True)
        # os._exit: paramiko worker threads survive SystemExit and would keep
        # the interpreter (and any calling script) alive after the timeout.
        os._exit(2)

    signal.signal(signal.SIGALRM, on_timeout)
    signal.alarm(args.timeout)

    transport = paramiko.Transport((args.host, args.port))
    transport.banner_timeout = 15
    transport.connect(
        username=args.user, pkey=paramiko.RSAKey.from_private_key_file(args.key)
    )
    print("remote version:", transport.remote_version, flush=True)
    sftp = paramiko.SFTPClient.from_transport(transport)
    channel = sftp.get_channel()
    print(
        "server max packet:", channel.out_max_packet_size,
        "window:", channel.out_window_size,
        flush=True,
    )

    remote = f"{args.remote_dir}/paramiko_roundtrip"
    local_back = args.file + ".paramiko_back"

    t0 = time.time()
    sftp.put(args.file, remote)
    t1 = time.time()
    sftp.get(remote, local_back, prefetch=not args.no_prefetch)
    t2 = time.time()
    print(
        f"put {t1 - t0:.1f}s, get {t2 - t1:.1f}s (prefetch={not args.no_prefetch})",
        flush=True,
    )

    sftp.remove(remote)
    sftp.close()
    transport.close()
    signal.alarm(0)

    if not filecmp.cmp(args.file, local_back, shallow=False):
        print("INTEGRITY FAIL", flush=True)
        return 1
    print("OK", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
