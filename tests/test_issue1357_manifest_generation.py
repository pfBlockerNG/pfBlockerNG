"""Issue #1357: a DNSBL manifest generation fails as one unit."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import pfb_unbound


def test_one_missing_raw_aborts_two_feed_manifest_and_opens_ledger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    status_path = tmp_path / "pfb_py_status.json"
    manifest_path = tmp_path / "pfb_py_sources.json"
    (tmp_path / "present.raw").write_text("present.example\n", encoding="utf-8")
    manifest_path.write_text(
        json.dumps(
            {
                "version": 1,
                "config": {},
                "feeds": [
                    {
                        "raw": "present.raw",
                        "feed": "Present",
                        "group": "Test",
                        "log_flag": "1",
                    },
                    {
                        "raw": "missing.raw",
                        "feed": "Missing",
                        "group": "Test",
                        "log_flag": "1",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setitem(pfb_unbound.pfb, "pfb_py_status", str(status_path))

    result = pfb_unbound.dnsbl_build_from_manifest(str(manifest_path))

    assert result is None, "one missing generation member must reject the whole manifest"
    entries = json.loads(status_path.read_text(encoding="utf-8"))
    assert len(entries) == 1
    assert entries[0]["facility"] == "dnsbl"
    assert entries[0]["item"] == str(manifest_path)
    assert entries[0]["stage"] == "parse"


@pytest.mark.parametrize("present_keys", [(), ("feeds",), ("config",)])
def test_missing_required_manifest_root_rejects_generation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, present_keys: tuple[str, ...]
) -> None:
    manifest: dict[str, object] = {"version": 1}
    if "feeds" in present_keys:
        manifest["feeds"] = []
    if "config" in present_keys:
        manifest["config"] = {}
    manifest_path = tmp_path / "pfb_py_sources.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    status_path = tmp_path / "pfb_py_status.json"
    monkeypatch.setitem(pfb_unbound.pfb, "pfb_py_status", str(status_path))

    assert pfb_unbound.dnsbl_build_from_manifest(str(manifest_path)) is None
    entries = json.loads(status_path.read_text(encoding="utf-8"))
    assert len(entries) == 1
    assert entries[0]["item"] == str(manifest_path)
    assert entries[0]["stage"] == "parse"
