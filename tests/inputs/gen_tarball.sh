#!/bin/bash
#
# Generates a deterministic POSIX (ustar) tar archive used by tests/tarball.rs.
#
# The archive layout and file contents are pinned here and asserted in the test,
# so the extractor (currently external `tar`, soon to be replaced) can be verified
# to produce exactly these files with exactly these contents.

cd "$(dirname "$0")" || exit 1

python3 - <<'PY'
import io
import tarfile

# Pinned contents -- keep in sync with tests/tarball.rs
files = {
    "testdir/hello.txt":       b"Hello, binwalk-ng tarball!\n",
    "testdir/readme.md":       b"# Tarball test fixture\n",
    "testdir/nested/data.bin": b"\xAB" * 256,
}

with tarfile.open("tarball.bin", "w", format=tarfile.USTAR_FORMAT) as tar:
    for name, data in files.items():
        info = tarfile.TarInfo(name)
        info.size = len(data)
        # Fully deterministic metadata so the fixture is reproducible.
        info.mtime = 0
        info.mode = 0o644
        info.uid = 0
        info.gid = 0
        info.uname = ""
        info.gname = ""
        tar.addfile(info, io.BytesIO(data))
PY
