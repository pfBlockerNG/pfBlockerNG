"""issue #3125 -- the DNSBL module fingerprint: digest + applied-marker writer.

WHY THIS FILE EXISTS
--------------------
PHP's ``pfb_unbound_python('enabled')`` restarts the Resolver iff the fingerprint
marker (``pfb_py_module.applied``) disagrees with
``sha256(pfb_unbound.py) ++ sha256(pfb_dnsbl_regex_rules.py)`` as staged in the
chroot. These two functions are the Python half of that cross-language contract:
fixed file order (``pfb_unbound.py`` FIRST), no separator, lowercase hex; the
marker write is atomic temp + ``os.replace`` and best-effort (``False`` on
OSError, one stderr line, never raises).
"""

from __future__ import annotations

import hashlib
from typing import Any

import pfb_unbound as P

# issue #3125: the cross-language parity constant -- sha256(b"a") ++ sha256(b"b").
# PythonModuleFingerprintTest.php pins the IDENTICAL literal; if either language
# ever changes the digest recipe (order, separator, case, algorithm) one of the
# two pins fails.
PARITY_FP = (
    "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
    "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d"
)
EMPTY_FP = hashlib.sha256(b"").hexdigest() * 2


def _write(tmp_path: Any, name: str, data: bytes) -> str:
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


def test_fingerprint_two_files_is_concatenated_sha256_in_order(tmp_path: Any) -> None:
    """P1: digest is sha256(first) ++ sha256(second), 128 lowercase hex chars --
    and swapping the pair changes it (order is part of the contract)."""
    first = _write(tmp_path, "pfb_unbound.py", b"first")
    second = _write(tmp_path, "pfb_dnsbl_regex_rules.py", b"second")
    expected = hashlib.sha256(b"first").hexdigest() + hashlib.sha256(b"second").hexdigest()

    assert len(expected) == 128
    assert P._module_fingerprint((first, second)) == expected
    assert P._module_fingerprint((second, first)) != expected


def test_fingerprint_missing_path_returns_none(tmp_path: Any) -> None:
    """P2: any unreadable member poisons the whole fingerprint -> None."""
    present = _write(tmp_path, "pfb_unbound.py", b"x")
    missing = str(tmp_path / "absent.py")

    assert P._module_fingerprint((missing, present)) is None
    assert P._module_fingerprint((present, missing)) is None


def test_write_applied_happy_path_writes_marker_atomically(tmp_path: Any) -> None:
    """P3: marker content is fingerprint + newline and no .tmp sidecar survives."""
    marker = str(tmp_path / "pfb_py_module.applied")

    assert P._module_write_applied(marker, PARITY_FP) is True
    with open(marker, encoding="utf-8") as fh:
        assert fh.read() == PARITY_FP + "\n"
    assert not (tmp_path / "pfb_py_module.applied.tmp").exists()


def test_write_applied_unwritable_dir_returns_false_without_raising(tmp_path: Any) -> None:
    """P4: OSError from the temp write degrades to False -- never an exception.

    Permission-denied needs a non-root uid; the not-a-directory shape below is
    OSError (ENOTDIR) under EVERY uid, so the run stays meaningful as root too."""
    import os

    if os.geteuid() != 0:
        locked = tmp_path / "locked"
        locked.mkdir()
        locked.chmod(0o555)
        marker = str(locked / "pfb_py_module.applied")
    else:
        blocker = tmp_path / "blocker"
        blocker.write_bytes(b"a regular file, not a directory")
        marker = str(blocker / "pfb_py_module.applied")

    assert P._module_write_applied(marker, PARITY_FP) is False
    assert not (tmp_path / "locked" / "pfb_py_module.applied.tmp").exists()


def test_fingerprint_matches_php_pinned_parity_literal(tmp_path: Any) -> None:
    """P5: for bytes b"a", b"b" the digest equals the literal pinned in BOTH
    languages (see PythonModuleFingerprintTest.php)."""
    a = _write(tmp_path, "a", b"a")
    b = _write(tmp_path, "b", b"b")

    assert P._module_fingerprint((a, b)) == PARITY_FP


def test_fingerprint_empty_files_is_sha256_of_empty_pair(tmp_path: Any) -> None:
    """Hostile (brief S5): an emptied shipped file is still a STRING digest --
    the sha256-of-empty pair -- so it compares normally, no special case."""
    a = _write(tmp_path, "a", b"")
    b = _write(tmp_path, "b", b"")

    fp = P._module_fingerprint((a, b))
    assert isinstance(fp, str)
    assert fp == EMPTY_FP


def test_init_fingerprints_the_shipped_pair_in_php_order() -> None:
    """The pair init hashes is a module constant in PHP's order -- pfb_unbound.py
    FIRST -- so the marker can never be written in an order PHP will not match."""
    assert P.PFB_MODULE_CODE_FILES == ("pfb_unbound.py", "pfb_dnsbl_regex_rules.py")
