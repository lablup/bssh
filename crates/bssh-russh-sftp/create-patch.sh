#!/bin/bash
# create-patch.sh — placeholder
#
# As of upstream russh-sftp 2.3.0 (perf serde_bytes #83 + write pipelined #85),
# this fork carries only a single non-upstreamed delta — the
# `read_to_writer_pipelined` helper, proposed in AspectUnk/russh-sftp#91.
# That helper lives directly in src/client/fs/file.rs, so no patch file is
# needed.
#
# When future local-only changes accumulate again, re-introduce the
# diff-extraction logic here (the obsolete sftp-serde-bytes-perf.patch tooling
# is available in git history as a starting point).

echo "No patches to create — single in-tree delta lives at src/client/fs/file.rs::read_to_writer_pipelined."
exit 0
