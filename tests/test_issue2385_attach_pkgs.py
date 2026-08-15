"""Issue #2385: attach-pkgs must not publish a Release with no .pkg."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / ".github" / "workflows" / "release.yml"
_ARTIFACT = re.compile(r"uses:\s+actions/(?P<kind>upload|download)-artifact@v(?P<major>\d+)")


def _attach_job(text: str) -> str:
    match = re.search(r"^  attach-pkgs:\n", text, re.MULTILINE)
    assert match is not None, "attach-pkgs job missing"
    start = match.start()
    nxt = re.search(r"^  [A-Za-z0-9_-]+:\n", text[match.end() :], re.MULTILINE)
    end = match.end() + nxt.start() if nxt else len(text)
    return text[start:end]


def test_attach_pkgs_download_artifact_major_matches_upload() -> None:
    text = RELEASE.read_text(encoding="utf-8")
    uploads = {m.group("major") for m in _ARTIFACT.finditer(text) if m.group("kind") == "upload"}
    downloads = {m.group("major") for m in _ARTIFACT.finditer(text) if m.group("kind") == "download"}
    assert uploads, "release.yml must use upload-artifact"
    assert downloads, "release.yml must use download-artifact"
    assert uploads == downloads, (sorted(uploads), sorted(downloads))


def test_attach_pkgs_download_does_not_continue_on_error() -> None:
    job = _attach_job(RELEASE.read_text(encoding="utf-8"))
    download = job.split("- name: Download")[1].split("- name:")[0]
    assert "continue-on-error:" not in download, download


def test_attach_pkgs_empty_pkgs_fails_closed() -> None:
    job = _attach_job(RELEASE.read_text(encoding="utf-8"))
    empty = re.search(r'if \[ -z "\$PKGS" \]; then(?P<body>.*?)\n\s*fi', job, re.DOTALL)
    assert empty is not None, job
    assert "exit 0" not in empty.group("body"), empty.group("body")
    assert "exit 1" in empty.group("body"), empty.group("body")
