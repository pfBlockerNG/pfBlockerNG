"""Detect a signature-only delta between two catalogue archives (issue #2675).

ECDSA signing is randomised (OpenSSL implements no deterministic RFC 6979), so
signing an UNCHANGED catalogue payload with the SAME key still rewrites every
`.sig` member — see build-repo-portable.py's "Catalogue signing" comment
block. scripts/publish-pkg-repo.sh uses this module to tell that apart from a
real change before deciding whether a republish is a NOOP.

A delta is signature-only when the two zstd-tar archives (`packagesite.pkg` /
`data.pkg`, as written by build-repo-portable.py's `write_zstd_tar`) carry the
SAME member-NAME set, at least one member's name ends `.sig`, and every
member whose name does NOT end `.sig` is byte-identical. Comparing by member
name is equivalent to (and simpler than) inspecting `meta.conf`'s
signature_type: a `.pub` difference (key rotation) or any payload/member-set
change already fails one of those two conditions.

stdlib-only. Reuses pfb_pkg.zstd_decompress — never shells out to `tar`
(bsdtar and GNU tar diverge on zstd; see .agents/policy/testing.md).
"""

from __future__ import annotations

import argparse
import io
import sys
import tarfile
from pathlib import Path

try:
    from scripts.pfb_pkg import PkgError, zstd_decompress
except ImportError:  # script directory is also a direct import root
    from pfb_pkg import PkgError, zstd_decompress

# Errors any of these raise, while reading a catalogue archive, mean "not a
# readable zstd catalogue archive" rather than a bug in this module.
_READ_ERRORS = (OSError, PkgError, tarfile.TarError, EOFError, ValueError)


def _read_members(path: Path) -> dict[str, tuple[bytes, bytes]]:
    """Every member of the zstd tar at ``path`` as ``name -> (type, content)``.

    A non-regular member (directory, symlink, hardlink, device) contributes its
    link target in place of file data: dropping such members instead would let an
    archive that gained or lost one compare equal to one that did not. A duplicate
    name is rejected outright — keeping the last of them leaves a shadowed member
    that could differ unseen.
    """
    tar_bytes = zstd_decompress(path.read_bytes())
    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tf:
        members: dict[str, tuple[bytes, bytes]] = {}
        for ti in tf.getmembers():
            if ti.name in members:
                raise PkgError(f"{path}: duplicate archive member {ti.name!r}")
            if not ti.isfile():
                members[ti.name] = (ti.type, ti.linkname.encode())
                continue
            extracted = tf.extractfile(ti)
            if extracted is None:
                raise PkgError(f"{path}: member {ti.name!r} carries no data")
            members[ti.name] = (ti.type, extracted.read())
        return members


def public_key_members(archive: str | Path) -> list[bytes] | None:
    """The bytes of every member whose name ends `.pub`, or None if ``archive``
    cannot be read as a zstd catalogue archive.

    Returned verbatim, `$PKGSIGN:` header included, because that is what the
    archive holds: the publishers compare this against a freshly derived member
    to decide whether a destination already carries the key they sign with.
    """
    try:
        members = _read_members(Path(archive))
    except _READ_ERRORS:
        return None
    return [data for name, (_kind, data) in sorted(members.items()) if name.endswith(".pub")]


def sig_only_reason(old_archive: str | Path, new_archive: str | Path) -> str | None:
    """None when ``new_archive`` differs from ``old_archive`` ONLY in members
    whose name ends `.sig`; otherwise a one-line reason it does not.

    Never raises: an unreadable file, a truncated/non-zstd/non-tar archive, or
    a corrupt-archive PkgError from pfb_pkg all become a returned reason
    instead — this is the CLI's sole source of its stderr diagnostic.
    """
    old_path, new_path = Path(old_archive), Path(new_archive)
    try:
        old_members = _read_members(old_path)
    except _READ_ERRORS as exc:
        return f"{old_path}: cannot read as a zstd catalogue archive: {exc}"
    try:
        new_members = _read_members(new_path)
    except _READ_ERRORS as exc:
        return f"{new_path}: cannot read as a zstd catalogue archive: {exc}"

    old_names, new_names = set(old_members), set(new_members)
    if old_names != new_names:
        return (
            f"member sets differ: only in old={sorted(old_names - new_names)}, "
            f"only in new={sorted(new_names - old_names)}"
        )

    sig_names = {name for name in old_names if name.endswith(".sig")}
    if not sig_names:
        return "no .sig member present — not a signature-only delta"

    for name in sorted(old_names - sig_names):
        if old_members[name] != new_members[name]:
            return f"member {name!r} differs"
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Exit 0 iff NEW_ARCHIVE differs from OLD_ARCHIVE only in `.sig` "
            "members (a re-signed, otherwise-unchanged catalogue); exit 1 "
            "otherwise, with a one-line reason on stderr."
        )
    )
    parser.add_argument("old_archive")
    parser.add_argument("new_archive")
    args = parser.parse_args(argv)

    reason = sig_only_reason(args.old_archive, args.new_archive)
    if reason is not None:
        print(f"catalogue_sig_only: {reason}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
