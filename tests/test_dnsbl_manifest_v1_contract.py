from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import pfb_unbound

CORPUS = Path(__file__).parent / "fixtures" / "dnsbl_corpus"
FIXTURE = CORPUS / "manifest-v1.json"


def _stage_fixture(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    with FIXTURE.open(encoding="utf-8") as handle:
        manifest = json.load(handle)
    for row in manifest["feeds"]:
        relative = Path(row["raw"])
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(CORPUS / relative, destination)
    shutil.copyfile(CORPUS / "pfb_py_top1m.txt", tmp_path / "pfb_py_top1m.txt")
    path = tmp_path / "pfb_py_sources.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path, manifest


def _write_manifest(path: Path, manifest: dict[str, Any]) -> None:
    path.write_text(json.dumps(manifest), encoding="utf-8")


def _ledger_path(path: Path) -> Path:
    ledger = path.parent / "status.json"
    pfb_unbound.pfb["pfb_py_status"] = str(ledger)
    return ledger


def _assert_rejected_before_build(
    path: Path,
    monkeypatch: pytest.MonkeyPatch,
    expected_field: str,
    ledger: Path,
) -> None:
    def fail_build(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("manifest contract reached build()")

    monkeypatch.setattr(pfb_unbound, "build", fail_build)
    assert pfb_unbound.dnsbl_build_from_manifest(str(path)) is None
    entries = json.loads(ledger.read_text(encoding="utf-8"))
    assert entries and expected_field in entries[-1]["message"]


def test_fixture_manifest_v1_builds_and_config_affects_result(tmp_path: Path) -> None:
    path, _ = _stage_fixture(tmp_path)

    result = pfb_unbound.dnsbl_build_from_manifest(str(path))

    assert result is not None
    assert result.zone_db["zip"]["index"] >= 0
    assert result.white_db["popularcdn.com"]["important"] is True
    assert result.white_db["adblock.com"]["wildcard"] is False
    assert result.white_db["wildwhite.org"]["wildcard"] is True
    assert result.white_db["allowme.example"]["band"] == pfb_unbound.PRIO_FEED_ALLOW
    observed_groups = {entry["group"] for entry in result.feed_group_index_db.values()}
    assert "\ufffd" in observed_groups
    assert observed_groups >= {
        "grp_custom",
        "grp_permit",
    }


def test_in_base_absolute_raw_path_is_preserved(tmp_path: Path) -> None:
    path, manifest = _stage_fixture(tmp_path)
    manifest["feeds"] = [dict(manifest["feeds"][0])]
    manifest["feeds"][0]["raw"] = str(tmp_path / "raw" / "plain_hosts.raw")
    _write_manifest(path, manifest)

    result = pfb_unbound.dnsbl_build_from_manifest(str(path))

    assert result is not None
    assert result.counts > 0


def test_empty_feeds_are_valid(tmp_path: Path) -> None:
    path, manifest = _stage_fixture(tmp_path)
    manifest["feeds"] = []
    manifest["config"] = {}
    _write_manifest(path, manifest)

    result = pfb_unbound.dnsbl_build_from_manifest(str(path))

    assert result is not None
    assert result.data_db == {}
    assert result.zone_db == {}


def test_empty_group_and_log_flag_are_valid(tmp_path: Path) -> None:
    path, manifest = _stage_fixture(tmp_path)
    manifest["feeds"] = [dict(manifest["feeds"][0])]
    manifest["feeds"][0]["group"] = ""
    manifest["feeds"][0]["log_flag"] = ""
    _write_manifest(path, manifest)

    result = pfb_unbound.dnsbl_build_from_manifest(str(path))

    assert result is not None
    assert {entry["group"] for entry in result.feed_group_index_db.values()} >= {""}
    assert result.data_db["plainhost1.example"]["log"] == ""


@pytest.mark.parametrize(
    ("mutate", "field"),
    [
        (lambda m: m.pop("version"), "version"),
        (lambda m: m.__setitem__("version", 2), "version"),
        (lambda m: m.__setitem__("version", "1"), "version"),
        (lambda m: m.__setitem__("version", True), "version"),
        (lambda m: m.__setitem__("version", None), "version"),
        (lambda m: m.pop("config"), "config"),
        (lambda m: m.__setitem__("config", []), "config"),
        (lambda m: m["config"].__setitem__("tld_wildcard_blacklist", "zip"), "config.tld_wildcard_blacklist"),
        (
            lambda m: m["config"].__setitem__("user_whitelist", ["ok.example", 1]),
            "config.user_whitelist",
        ),
        (lambda m: m["config"].__setitem__("top1m_enabled", 1), "config.top1m_enabled"),
        (lambda m: m["config"].__setitem__("regex_cap", "on"), "config.regex_cap"),
        (lambda m: m.pop("feeds"), "feeds"),
        (lambda m: m.__setitem__("feeds", {}), "feeds"),
        (lambda m: m["feeds"].__setitem__(0, "row"), "feeds[0]"),
        (lambda m: m["feeds"][0].pop("raw"), "feeds[0].raw"),
        (lambda m: m["feeds"][0].__setitem__("raw", ""), "feeds[0].raw"),
        (lambda m: m["feeds"][0].pop("feed"), "feeds[0].feed"),
        (lambda m: m["feeds"][0].__setitem__("feed", 1), "feeds[0].feed"),
        (lambda m: m["feeds"][0].__setitem__("feed", ""), "feeds[0].feed"),
        (lambda m: m["feeds"][0].pop("group"), "feeds[0].group"),
        (lambda m: m["feeds"][0].pop("log_flag"), "feeds[0].log_flag"),
        (lambda m: m["feeds"][0].__setitem__("log_flag", False), "feeds[0].log_flag"),
        (lambda m: m["feeds"][0].__setitem__("provenance", "other"), "feeds[0].provenance"),
        (lambda m: m["feeds"][0].__setitem__("provenance", []), "feeds[0].provenance"),
        (lambda m: m["feeds"][0].__setitem__("mode", "other"), "feeds[0].mode"),
        (lambda m: m["feeds"][0].__setitem__("mode", {}), "feeds[0].mode"),
    ],
)
def test_invalid_v1_shape_is_rejected_before_build(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutate: Callable[[dict[str, Any]], Any],
    field: str,
) -> None:
    path, manifest = _stage_fixture(tmp_path)
    mutate(manifest)
    _write_manifest(path, manifest)
    ledger = _ledger_path(path)

    _assert_rejected_before_build(path, monkeypatch, field, ledger)


def test_known_shapes_are_checked_before_raw_io(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path, manifest = _stage_fixture(tmp_path)
    manifest["feeds"][0]["raw"] = "missing.raw"
    manifest["feeds"][0]["log_flag"] = 1
    _write_manifest(path, manifest)
    ledger = _ledger_path(path)

    def fail_path_check(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("raw I/O started before contract validation")

    monkeypatch.setattr(pfb_unbound, "_dnsbl_path_within_base", fail_path_check)
    _assert_rejected_before_build(path, monkeypatch, "feeds[0].log_flag", ledger)


def test_unknown_additive_root_config_and_feed_keys_are_accepted(tmp_path: Path) -> None:
    path, manifest = _stage_fixture(tmp_path)
    manifest["future_root"] = {"enabled": True}
    manifest["config"]["future_config"] = {"value": 7}
    manifest["feeds"][0]["future_feed"] = ["kept additive"]
    _write_manifest(path, manifest)

    result = pfb_unbound.dnsbl_build_from_manifest(str(path))

    assert result is not None


def test_non_object_root_is_rejected_before_build(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "pfb_py_sources.json"
    path.write_text("[]", encoding="utf-8")
    ledger = _ledger_path(path)
    _assert_rejected_before_build(path, monkeypatch, "root", ledger)
