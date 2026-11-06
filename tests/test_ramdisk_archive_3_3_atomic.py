from __future__ import annotations

import shlex
import subprocess
import tarfile
from pathlib import Path

from test_ramdisk_archive_3_3_guards import archive_harness


def test_archive_is_staged_beside_its_destination(tmp_path: Path) -> None:
    """A cross-filesystem PHP rename may copy, so tar must stage beside the final archive."""
    harness = archive_harness(tmp_path, ramdisk=True)
    observed = tmp_path / "tar-destination"
    wrapper = tmp_path / "tar"
    wrapper.write_text(
        "#!/bin/sh\n"
        f'printf \'%s\\n\' "$2" > {shlex.quote(str(observed))}\n'
        'exec /usr/bin/tar "$@"\n'
    )
    wrapper.chmod(0o700)
    result = subprocess.run(["php", str(harness), "update"], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    archive = tmp_path / "etc/aliastables.tar.bz2"
    staged = Path(observed.read_text().strip())
    assert staged.parent == archive.parent, f"staged {staged}, destination {archive}"
    assert staged != archive, "tar must not write the final archive in place"
    assert not staged.exists(), f"staging file was not consumed: {staged}"
    with tarfile.open(archive, "r:bz2") as contents:
        member = contents.extractfile(str(tmp_path).lstrip("/") + "/aliases/pfB_test.txt")
        assert member is not None
        assert member.read() == b"192.0.2.17\n"
