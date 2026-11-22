#!/usr/bin/env python3
"""Make vendored crates survive dpkg-source.

dpkg-source leaves out of the source tarball every file that matches its
default tar-ignore patterns (object files, static and shared libraries, VCS
metadata, editor backups). Cargo verifies each vendored crate against its
.cargo-checksum.json, so a listed file that never reaches the Launchpad
builder fails the offline build ("failed to calculate checksum of ...").
ring 0.17 ships prebuilt Windows objects in pregenerated/*.o, for example.

Delete those files from vendor/ and from the checksum lists before the source
package is built. With --check, only report checksum entries that would still
be dropped, and exit non-zero if any remain.
"""

import fnmatch
import json
import subprocess
import sys
from pathlib import Path, PurePosixPath

# dpkg's built-in defaults (Dpkg::Source::Package::get_default_tar_ignore_pattern),
# used when the running dpkg cannot be asked.
FALLBACK_TAR_IGNORE = [
    "*.a", "*.la", "*.o", "*.so", ".*.sw?", "*/*~", ",,*", ".[#~]*",
    ".arch-ids", ".arch-inventory", ".be", ".bzr", ".bzr.backup", ".bzr.tags",
    ".bzrignore", ".cvsignore", ".deps", ".git", ".gitattributes", ".gitignore",
    ".gitmodules", ".gitreview", ".hg", ".hgignore", ".hgsigs", ".hgtags",
    ".mailmap", ".mtn-ignore", ".shelf", ".svn", "CVS", "DEADJOE", "RCS",
    "_MTN", "_darcs", "{arch}",
]


def tar_ignore_patterns() -> list[str]:
    try:
        out = subprocess.run(
            [
                "perl", "-MDpkg::Source::Package", "-e",
                'print join("\\n", Dpkg::Source::Package::get_default_tar_ignore_pattern())',
            ],
            check=True, capture_output=True, text=True,
        ).stdout.split()
    except (OSError, subprocess.CalledProcessError):
        out = []
    return sorted(set(out) | set(FALLBACK_TAR_IGNORE))


def should_strip(rel_path: str, patterns: list[str]) -> bool:
    path = PurePosixPath(rel_path)
    if rel_path.endswith(".orig") or any(part.startswith(".") for part in path.parts):
        return True
    # tar --exclude drops any file or directory whose name matches, which also
    # drops everything under an excluded directory; patterns with a slash
    # match a trailing run of path components.
    parts = path.parts
    for p in patterns:
        if "/" in p:
            if any(fnmatch.fnmatchcase("/".join(parts[i:]), p) for i in range(len(parts))):
                return True
        elif any(fnmatch.fnmatchcase(part, p) for part in parts):
            return True
    return False


def main() -> int:
    check_only = "--check" in sys.argv[1:]
    vendor_root = Path("vendor")
    if not vendor_root.is_dir():
        raise SystemExit("vendor directory not found")

    patterns = tar_ignore_patterns()
    offenders = []
    for checksum_file in sorted(vendor_root.rglob(".cargo-checksum.json")):
        crate_dir = checksum_file.parent
        data = json.loads(checksum_file.read_text())
        files = data.get("files", {})

        removed = [rel for rel in files if should_strip(rel, patterns)]
        if check_only:
            offenders.extend(f"{checksum_file}: {rel}" for rel in removed)
            continue

        for rel_path in removed:
            files.pop(rel_path, None)
            target = crate_dir / rel_path
            if target.exists():
                target.unlink()

        if removed:
            checksum_file.write_text(
                json.dumps(data, separators=(",", ":"), sort_keys=True) + "\n"
            )
            print(f"sanitized {checksum_file} ({len(removed)} entries dpkg-source would drop)")

    if offenders:
        raise SystemExit(
            "vendor checksums still reference files dpkg-source drops:\n"
            + "\n".join(offenders[:50])
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
