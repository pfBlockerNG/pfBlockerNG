"""Tests for scripts/catalogue_sig_only.py (issue #2675 step 2).

ECDSA signing is randomised (OpenSSL implements no deterministic RFC 6979), so
re-signing an UNCHANGED catalogue payload with the SAME key still rewrites the
`.sig` member — see build-repo-portable.py's "Catalogue signing" comment
block. This module tells that apart from a real change (payload edit, key
rotation, added/removed member) so scripts/publish-pkg-repo.sh can skip
publishing a republish that changed nothing but its own signature.

Fixtures reuse scripts/build-repo-portable.py's own signed-catalogue output
(via tests/test_build_repo_portable.py's make_pkg/_gen_key/brp helpers) for
the real-catalogue rows, so the wire format under test is the one the
publisher actually emits — not a hand-rolled approximation. Rows that only
need control over the archive's member SET (added/removed member) build a
minimal raw zstd-tar directly; libpkg framing is irrelevant to those.
"""

from __future__ import annotations

import io
import sys
import tarfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import catalogue_sig_only as cso  # noqa: E402
import pfb_pkg  # noqa: E402
import test_build_repo_portable as tbrp  # noqa: E402  (make_pkg / _gen_key / brp)


def _build(tmp_path: Path, out_name: str, *, sign_key: Path | None, payload: bytes = b"hey") -> Path:
    """Build one signed-or-unsigned catalogue tree; return its packagesite.pkg."""
    in_dir = tmp_path / out_name / "in"
    in_dir.mkdir(parents=True)
    tbrp.make_pkg(in_dir / "demo-1.0_1.pkg", payload=payload)
    out = tmp_path / out_name / "out"
    tbrp.brp.build_repo(in_dir, out, sign_key=sign_key)
    return out / "packagesite.pkg"


def _write_raw_tar(path: Path, members: dict[str, bytes]) -> None:
    """A minimal zstd-tar carrying exactly `members` — no libpkg framing."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    path.write_bytes(pfb_pkg.zstd_compress(raw.getvalue(), RuntimeError, "zstd unavailable"))


def _write_tar_with_entries(path: Path, entries: list[tarfile.TarInfo], payloads: dict[str, bytes]) -> None:
    """A zstd-tar built from explicit TarInfo entries, so a test can place a
    directory, a symlink, or two members of the same name."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        for info in entries:
            if info.isfile():
                data = payloads[info.name]
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
            else:
                tf.addfile(info)
    path.write_bytes(pfb_pkg.zstd_compress(raw.getvalue(), RuntimeError, "zstd unavailable"))


def _file_entry(name: str) -> tarfile.TarInfo:
    return tarfile.TarInfo(name=name)


def _dir_entry(name: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name=name)
    info.type = tarfile.DIRTYPE
    return info


def _symlink_entry(name: str, target: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name=name)
    info.type = tarfile.SYMTYPE
    info.linkname = target
    return info


# --------------------------------------------------------------------------- #
# Non-regular and duplicate members — invisible to a regular-files-only read
# --------------------------------------------------------------------------- #


def test_a_directory_member_present_on_one_side_only_is_not_signature_only(tmp_path: Path) -> None:
    """A member the two archives do not share is a real difference whatever its type.
    Reading only regular files would drop it from both name sets and report None."""
    payloads = {"packagesite.yaml": b"payload", "packagesite.yaml.sig": b"sig-a"}
    old = tmp_path / "old.pkg"
    new = tmp_path / "new.pkg"
    _write_tar_with_entries(old, [_file_entry("packagesite.yaml"), _file_entry("packagesite.yaml.sig")], payloads)
    _write_tar_with_entries(
        new,
        [_file_entry("packagesite.yaml"), _file_entry("packagesite.yaml.sig"), _dir_entry("extra/")],
        {**payloads, "packagesite.yaml.sig": b"sig-b"},
    )
    assert cso.sig_only_reason(old, new) is not None


def test_a_symlink_member_retargeted_is_not_signature_only(tmp_path: Path) -> None:
    """Same name, same (empty) data, different link target — a real change."""
    payloads = {"packagesite.yaml": b"payload", "packagesite.yaml.sig": b"sig-a"}
    old = tmp_path / "old.pkg"
    new = tmp_path / "new.pkg"
    _write_tar_with_entries(
        old,
        [_file_entry("packagesite.yaml"), _file_entry("packagesite.yaml.sig"), _symlink_entry("link", "here")],
        payloads,
    )
    _write_tar_with_entries(
        new,
        [_file_entry("packagesite.yaml"), _file_entry("packagesite.yaml.sig"), _symlink_entry("link", "elsewhere")],
        {**payloads, "packagesite.yaml.sig": b"sig-b"},
    )
    assert cso.sig_only_reason(old, new) is not None


def test_a_duplicate_member_name_is_rejected(tmp_path: Path) -> None:
    """Two members of one name: the later would mask the earlier, so the comparison
    cannot claim to have compared the archive. Rejected as unreadable, which
    publishes the target rather than dropping it."""
    old = tmp_path / "old.pkg"
    new = tmp_path / "new.pkg"
    _write_tar_with_entries(
        old,
        [_file_entry("packagesite.yaml"), _file_entry("packagesite.yaml.sig")],
        {"packagesite.yaml": b"payload", "packagesite.yaml.sig": b"sig-a"},
    )
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        for name, data in (
            ("packagesite.yaml", b"payload-shadowed"),
            ("packagesite.yaml", b"payload"),
            ("packagesite.yaml.sig", b"sig-b"),
        ):
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    new.write_bytes(pfb_pkg.zstd_compress(raw.getvalue(), RuntimeError, "zstd unavailable"))
    assert cso.sig_only_reason(old, new) is not None


# --------------------------------------------------------------------------- #
# Row 1 — same payload, re-signed with the SAME key -> signature-only (exit 0)
# --------------------------------------------------------------------------- #


def test_resigned_unchanged_payload_is_signature_only(tmp_path: Path) -> None:
    key = tbrp._gen_key(tmp_path / "repo.key")
    old = _build(tmp_path, "a", sign_key=key)
    new = _build(tmp_path, "b", sign_key=key)
    assert old.read_bytes() != new.read_bytes(), "ECDSA signing must be randomised for this test to mean anything"
    assert cso.sig_only_reason(old, new) is None


def test_cli_exit_0_for_a_signature_only_delta(tmp_path: Path) -> None:
    key = tbrp._gen_key(tmp_path / "repo.key")
    old = _build(tmp_path, "a", sign_key=key)
    new = _build(tmp_path, "b", sign_key=key)
    assert cso.main([str(old), str(new)]) == 0


# --------------------------------------------------------------------------- #
# Row 2 — payload differs -> a real change
# --------------------------------------------------------------------------- #


def test_changed_payload_is_not_signature_only(tmp_path: Path) -> None:
    key = tbrp._gen_key(tmp_path / "repo.key")
    old = _build(tmp_path, "a", sign_key=key, payload=b"hey")
    new = _build(tmp_path, "b", sign_key=key, payload=b"bye")
    reason = cso.sig_only_reason(old, new)
    assert reason is not None
    assert "packagesite.yaml" in reason


# --------------------------------------------------------------------------- #
# Row 3 — key rotation: the .pub member differs -> a real change
# --------------------------------------------------------------------------- #


def test_key_rotation_is_not_signature_only(tmp_path: Path) -> None:
    key_a = tbrp._gen_key(tmp_path / "a.key")
    key_b = tbrp._gen_key(tmp_path / "b.key")
    old = _build(tmp_path, "a", sign_key=key_a)
    new = _build(tmp_path, "b", sign_key=key_b)
    reason = cso.sig_only_reason(old, new)
    assert reason is not None
    assert "packagesite.yaml.pub" in reason


# --------------------------------------------------------------------------- #
# Row 4 — a member was added or removed -> a real change
# --------------------------------------------------------------------------- #


def test_added_member_is_not_signature_only(tmp_path: Path) -> None:
    old, new = tmp_path / "old.pkg", tmp_path / "new.pkg"
    _write_raw_tar(old, {"packagesite.yaml": b"same", "packagesite.yaml.sig": b"sig-a"})
    _write_raw_tar(new, {"packagesite.yaml": b"same", "packagesite.yaml.sig": b"sig-b", "extra": b"x"})
    reason = cso.sig_only_reason(old, new)
    assert reason is not None
    assert "member sets differ" in reason


def test_removed_member_is_not_signature_only(tmp_path: Path) -> None:
    old, new = tmp_path / "old.pkg", tmp_path / "new.pkg"
    _write_raw_tar(old, {"packagesite.yaml": b"same", "packagesite.yaml.sig": b"sig-a"})
    _write_raw_tar(new, {"packagesite.yaml": b"same"})
    reason = cso.sig_only_reason(old, new)
    assert reason is not None
    assert "member sets differ" in reason


# --------------------------------------------------------------------------- #
# Row 5 — unsigned, byte-identical -> not a signature-only delta (no .sig at
# all: there is nothing to attribute the (absent) difference to)
# --------------------------------------------------------------------------- #


def test_unsigned_byte_identical_is_not_signature_only(tmp_path: Path) -> None:
    old = _build(tmp_path, "a", sign_key=None)
    new = _build(tmp_path, "b", sign_key=None)
    assert old.read_bytes() == new.read_bytes(), "unsigned output must be deterministic for this test to mean anything"
    reason = cso.sig_only_reason(old, new)
    assert reason is not None
    assert ".sig" in reason


# --------------------------------------------------------------------------- #
# Row 6 — unreadable / truncated / not a zstd tar -> a reason, never a
# traceback
# --------------------------------------------------------------------------- #


def test_missing_file_is_not_signature_only(tmp_path: Path) -> None:
    key = tbrp._gen_key(tmp_path / "repo.key")
    new = _build(tmp_path, "b", sign_key=key)
    reason = cso.sig_only_reason(tmp_path / "does-not-exist.pkg", new)
    assert reason is not None


def test_truncated_archive_is_not_signature_only(tmp_path: Path) -> None:
    key = tbrp._gen_key(tmp_path / "repo.key")
    old = _build(tmp_path, "a", sign_key=key)
    new = _build(tmp_path, "b", sign_key=key)
    truncated = tmp_path / "truncated.pkg"
    truncated.write_bytes(new.read_bytes()[:10])
    reason = cso.sig_only_reason(old, truncated)
    assert reason is not None


def test_not_a_zstd_tar_is_not_signature_only(tmp_path: Path) -> None:
    key = tbrp._gen_key(tmp_path / "repo.key")
    old = _build(tmp_path, "a", sign_key=key)
    garbage = tmp_path / "garbage.pkg"
    garbage.write_bytes(b"not a catalogue archive at all")
    reason = cso.sig_only_reason(old, garbage)
    assert reason is not None


def test_cli_reports_a_diagnostic_never_a_traceback(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    garbage = tmp_path / "garbage.pkg"
    garbage.write_bytes(b"nope")
    rc = cso.main([str(garbage), str(garbage)])
    captured = capsys.readouterr()
    assert rc == 1
    assert "Traceback" not in captured.err
    assert captured.err.strip() != ""


# --------------------------------------------------------------------------- #
# Drift pin — the shell filter names the catalogue archives literally
# --------------------------------------------------------------------------- #


def test_the_shell_filter_names_exactly_the_builders_catalogue_archives() -> None:
    """`filter_signature_only_touched` in publish-pkg-repo.sh matches the two
    catalogue archives by name. Renaming one in the builder without renaming it
    there fails nothing else: the match simply stops firing, every republish
    resumes committing a fresh randomised signature, and the #2389 stage gate
    starts booting live VMs for it again."""
    script = (Path(__file__).resolve().parents[1] / "scripts" / "publish-pkg-repo.sh").read_text(encoding="utf-8")
    body = script[script.index("filter_signature_only_touched() {") :]
    body = body[: body.index("\n}\n")]
    archives = tbrp.brp._CATALOG_PKG_FILES
    assert archives == {"packagesite.pkg", "data.pkg"}, "teach the shell filter about the new set"
    for name in archives:
        assert name in body, f"{name} is a catalogue archive the shell filter does not name"
