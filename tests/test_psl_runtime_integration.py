"""Issue #1541 Step 2: runtime PSL authority, classification, and snapshots."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import pfb_unbound as P

PSL = """// ===BEGIN ICANN DOMAINS===
com
io
*.ck
!www.ck
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
github.io
// ===END PRIVATE DOMAINS===
"""


def _manifest(path: Path) -> Path:
    raw = path / "feed.raw"
    raw.write_text("evil.example.com\n", encoding="utf-8")
    manifest = path / "pfb_py_sources.json"
    manifest.write_text(
        json.dumps(
            {
                "version": 1,
                "feeds": [{"raw": raw.name, "feed": "feed", "group": "group", "log_flag": "1"}],
                "config": {"tld_wildcard_blacklist": [], "tld_wildcard_exclusion": []},
            }
        ),
        encoding="utf-8",
    )
    return manifest


def test_psl_classifier_uses_arbitrary_depth_and_private_policy() -> None:
    rules = P.parse_psl_rules(PSL)

    assert P.tld_wildcard_classify("com", rules, set()) == (P.DNSBL_CLASS_DATA, "com")
    assert P.tld_wildcard_classify("example.com", rules, set()) == (P.DNSBL_CLASS_ZONE, "example.com")
    assert P.tld_wildcard_classify("a.b.example.com", rules, set()) == (P.DNSBL_CLASS_DATA, "a.b.example.com")
    assert P.tld_wildcard_classify("example.github.io", rules, set()) == (P.DNSBL_CLASS_ZONE, "example.github.io")
    assert P.tld_wildcard_classify("example.github.io", rules, set(), include_private=False) == (
        P.DNSBL_CLASS_DATA,
        "example.github.io",
    )
    assert P.tld_wildcard_classify("a.b.example.github.io", rules, set()) == (
        P.DNSBL_CLASS_DATA,
        "a.b.example.github.io",
    )
    assert P.tld_wildcard_classify("foo.ck", rules, set()) == (P.DNSBL_CLASS_DATA, "foo.ck")
    assert P.tld_wildcard_classify("www.ck", rules, set()) == (P.DNSBL_CLASS_ZONE, "www.ck")


@pytest.mark.parametrize("bad", ["", "not-a-psl", "xn--bad", "a..com", "a$[b].com"])
def test_psl_authority_loader_rejects_invalid_files(tmp_path: Path, bad: str) -> None:
    authority = tmp_path / "dnsbl_psl"
    authority.write_bytes(bad.encode("utf-8"))
    with pytest.raises(ValueError):
        P._load_psl_authority(str(authority), enabled=True)


def test_psl_authority_loader_off_is_exact_only_without_open(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    authority = tmp_path / "missing"
    monkeypatch.setattr(P, "open", lambda *_args, **_kwargs: pytest.fail("authority opened while OFF"), raising=False)
    assert P._load_psl_authority(str(authority), enabled=False) == P.PslRules()


def test_build_carries_psl_rules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    authority = tmp_path / "dnsbl_psl"
    authority.write_text(PSL, encoding="utf-8")
    manifest = _manifest(tmp_path)
    monkeypatch.setitem(P.pfb, "pfb_py_psl", str(authority))
    monkeypatch.setitem(P.pfb, "python_tld_wildcard", True)
    result = P.dnsbl_build_from_manifest(str(manifest))
    assert result is not None
    assert result.psl_rules.private_exact == ("github.io",)


def test_reload_failure_retains_psl_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    old = P.Snapshot({}, {}, {}, {}, {}, {}, {}, psl_rules=P.parse_psl_rules(PSL))
    monkeypatch.setattr(P, "_snapshot", old)
    assert P.rebuild_and_swap(lambda: None, emit_counts=False) is False
    assert P._snapshot is old
    assert P._snapshot.psl_rules == old.psl_rules
