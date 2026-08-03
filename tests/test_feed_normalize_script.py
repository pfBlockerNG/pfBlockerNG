"""pfb_feed_normalize.py (issue #1797): detection + conversion contract.

Runs the shipped script under the DEV interpreter (sys.executable — dev/CI
tooling; the appliance reaches it only through the ``pfb_python.sh`` package wrapper).
Skips when charset_normalizer is not installed in the dev environment.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("charset_normalizer")

SCRIPT = Path(__file__).resolve().parent.parent / "src/usr/local/pkg/pfblockerng/pfb_feed_normalize.py"


def run_script(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_latin1_body_converts_to_utf8_with_zero_replacements(tmp_path: Path) -> None:
    src = tmp_path / "feed.orig"
    dst = tmp_path / "feed.conv"
    # A realistic Latin-1 body — large enough for deterministic detection.
    src.write_bytes(b"b\xfccher-stra\xdfe.example.com\ncaf\xe9.example.com\n" * 200)

    proc = run_script(str(src), str(dst))

    assert proc.returncode == 0, f"stderr: {proc.stderr!r}"
    encoding, count = proc.stdout.split()
    assert int(count) == 0, f"a total single-byte codec must decode every byte, got {count} replacements ({encoding})"
    out = dst.read_bytes().decode("utf-8")  # must not raise
    assert "bücher" in out
    assert "café" in out


def test_replacement_count_is_reported_on_stdout(tmp_path: Path) -> None:
    src = tmp_path / "feed.orig"
    dst = tmp_path / "feed.conv"
    # A pre-existing U+FFFD rides through the count — the wrong-guess signal
    # channel itself is what this pins.
    src.write_bytes(("ok.example.com\n" * 50 + "bad�.example.com\n").encode("utf-8"))

    proc = run_script(str(src), str(dst))

    assert proc.returncode == 0, f"stderr: {proc.stderr!r}"
    _encoding, count = proc.stdout.split()
    assert int(count) == 1, f"expected exactly the one U+FFFD to be counted, got {count}"


def test_missing_source_file_fails_loudly(tmp_path: Path) -> None:
    proc = run_script(str(tmp_path / "absent.orig"), str(tmp_path / "out"))
    assert proc.returncode == 1
    assert proc.stderr != ""


def test_wrong_argument_count_fails_with_usage(tmp_path: Path) -> None:
    proc = run_script(str(tmp_path / "only-one"))
    assert proc.returncode == 1
    assert "usage" in proc.stderr
