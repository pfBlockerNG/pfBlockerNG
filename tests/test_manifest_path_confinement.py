"""Manifest path confinement: a feed ``raw`` path that resolves OUTSIDE the
manifest's base directory is skipped and logged, never opened.

The manifest is published next to its raw feeds, so every referenced ``raw`` file
must resolve under the manifest directory. A row whose resolved real path escapes
that directory (``..`` traversal, an absolute path elsewhere, or a symlink pointing
out) is refused (``_dnsbl_file_line_reader``): in-base content is read; out-of-base
content is skipped with a stderr log line.

issue #1255: ``_dnsbl_config_from_manifest`` no longer reads ``tld_master`` from the
manifest at all (HSTS parity -- a shipped static file gated by ``python_tld_wildcard``
instead), so its confinement coverage retired with that mechanism; see
``TestTldWildcardOracleGating`` for the replacement contract.

Scenario: confine manifest file references under base_dir
  Background: a base dir holding an in-base file, and an out-of-base file alongside
  Given a line_reader bound to base_dir
  When it is asked for an in-base path  Then it yields the file's lines
  When it is asked for an out-of-base path  Then it yields nothing and logs a refusal
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

import pfb_unbound


class TestFeedPathConfinement:
    def test_in_base_feed_is_read(self, tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
        # Given a feed file inside the manifest base dir.
        base = tmp_path / "base"
        base.mkdir()
        (base / "feed.txt").write_text("good.example\nblock.example\n", encoding="utf-8")
        reader = pfb_unbound._dnsbl_file_line_reader(str(base))

        # When the reader is asked for the in-base feed (by relative name).
        lines = list(reader("feed.txt"))

        # Then its lines are yielded and nothing is refused.
        assert lines == ["good.example", "block.example"]
        assert "Refusing DNSBL feed" not in capsys.readouterr().err

    def test_out_of_base_feed_is_skipped_and_logged(self, tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
        # Given a real file OUTSIDE the manifest base dir (a sibling of base).
        base = tmp_path / "base"
        base.mkdir()
        outside = tmp_path / "secret.txt"
        outside.write_text("escaped.example\n", encoding="utf-8")
        reader = pfb_unbound._dnsbl_file_line_reader(str(base))

        # Before-state: the in-base equivalent of the same name WOULD be read.
        (base / "secret.txt").write_text("inbase.example\n", encoding="utf-8")
        assert list(reader("secret.txt")) == ["inbase.example"]
        capsys.readouterr()  # drain the in-base (clean) run

        # When the reader is asked for a traversal path escaping base_dir.
        escaped = list(reader(os.path.join("..", "secret.txt")))

        # Then nothing is yielded (the outside file is never opened) and it is logged.
        assert escaped == []
        assert "Refusing DNSBL feed outside base dir" in capsys.readouterr().err


class TestManifestGenerationFailClosed:
    @pytest.mark.parametrize(
        "raw_kind",
        ["missing", "directory", "traversal", "absolute", "symlink_escape", "missing_key", "wrong_type"],
    )
    def test_invalid_raw_member_rejects_whole_manifest_and_opens_ledger(
        self,
        tmp_path: Path,
        raw_kind: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        base = tmp_path / "base"
        base.mkdir()
        outside = tmp_path / "outside.raw"
        outside.write_text("outside.example\n", encoding="utf-8")
        raw: object = "missing.raw"
        if raw_kind == "directory":
            (base / "directory.raw").mkdir()
            raw = "directory.raw"
        elif raw_kind == "traversal":
            raw = "../outside.raw"
        elif raw_kind == "absolute":
            raw = str(outside)
        elif raw_kind == "symlink_escape":
            os.symlink(outside, base / "link.raw")
            raw = "link.raw"
        elif raw_kind == "wrong_type":
            raw = ["feed.raw"]

        row: dict[str, object] = {"raw": raw, "feed": "Bad", "group": "Test", "log_flag": "1"}
        if raw_kind == "missing_key":
            row.pop("raw")
        manifest_path = base / "pfb_py_sources.json"
        manifest_path.write_text(json.dumps({"version": 1, "config": {}, "feeds": [row]}), encoding="utf-8")
        status_path = base / "pfb_py_status.json"
        monkeypatch.setitem(pfb_unbound.pfb, "pfb_py_status", str(status_path))

        result = pfb_unbound.dnsbl_build_from_manifest(str(manifest_path))

        assert result is None, f"{raw_kind} raw reference unexpectedly produced a partial build"
        entries = json.loads(status_path.read_text(encoding="utf-8"))
        assert len(entries) == 1
        assert entries[0]["item"] == str(manifest_path)
        assert entries[0]["stage"] == "parse"

    def test_absolute_out_of_base_feed_is_skipped(self, tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
        # An absolute path pointing outside base_dir is refused too.
        base = tmp_path / "base"
        base.mkdir()
        outside = tmp_path / "abs.txt"
        outside.write_text("escaped.example\n", encoding="utf-8")
        reader = pfb_unbound._dnsbl_file_line_reader(str(base))

        assert list(reader(str(outside))) == []
        assert "Refusing DNSBL feed outside base dir" in capsys.readouterr().err


class TestPathWithinBaseHelper:
    """The containment helper ``_dnsbl_path_within_base`` itself: in-base -> True,
    out-of-base -> False, and the root-base edge case (``base_dir`` resolving to ``/``)
    where a child must still be accepted (the old ``startswith(real_base + os.sep)`` form
    built ``//`` and falsely rejected every child of ``/``).
    """

    def test_root_base_accepts_child(self) -> None:
        # Given base_dir resolving to "/", a child path is contained (True), not rejected.
        assert pfb_unbound._dnsbl_path_within_base("/var/unbound/x/y", "/") is True

    def test_out_of_base_is_rejected(self) -> None:
        # A path outside the base dir is not contained (containment still enforced).
        assert pfb_unbound._dnsbl_path_within_base("/etc/passwd", "/var/unbound/pfb") is False


class TestTldWildcardOracleGating:
    """The parsed PSL authority is sourced from the SHIPPED ``dnsbl_psl`` file
    gated by ``pfb["python_tld_wildcard"]`` -- HSTS parity
    -- never from the manifest. A manifest carrying a stale/malicious
    ``config.tld_master`` key (an old install, or a crafted manifest) is ignored
    entirely; the flag is the sole gate.
    """

    def setup_method(self) -> None:
        pfb_unbound.pfb["python_tld_wildcard"] = False
        pfb_unbound.pfb["tld_allow"] = False
        pfb_unbound.pfb["pfb_py_psl"] = ""

    def test_oracle_not_loaded_when_flag_off_even_if_file_exists(self, tmp_path: Any) -> None:
        oracle = tmp_path / "dnsbl_psl"
        oracle.write_text(
            "// ===BEGIN ICANN DOMAINS===\ncom\nnet\n// ===END ICANN DOMAINS===\n"
            "// ===BEGIN PRIVATE DOMAINS===\n// ===END PRIVATE DOMAINS===\n",
            encoding="utf-8",
        )
        pfb_unbound.pfb["python_tld_wildcard"] = False
        pfb_unbound.pfb["pfb_py_psl"] = str(oracle)

        config = pfb_unbound._dnsbl_config_from_manifest({"config": {}}, str(tmp_path))

        assert config["psl_rules"] == pfb_unbound.PslRules(), (
            "OFF must never load the oracle, even though the file exists"
        )

    def test_oracle_loaded_when_flag_on_and_file_present(self, tmp_path: Any) -> None:
        oracle = tmp_path / "dnsbl_psl"
        oracle.write_text(
            "// ===BEGIN ICANN DOMAINS===\ncom\nnet\n// ===END ICANN DOMAINS===\n"
            "// ===BEGIN PRIVATE DOMAINS===\n// ===END PRIVATE DOMAINS===\n",
            encoding="utf-8",
        )
        pfb_unbound.pfb["python_tld_wildcard"] = True
        pfb_unbound.pfb["pfb_py_psl"] = str(oracle)

        config = pfb_unbound._dnsbl_config_from_manifest({"config": {}}, str(tmp_path))

        assert config["psl_rules"].icann_exact == ("com", "net")

    def test_oracle_load_fails_closed_when_flag_on_but_file_missing(self, tmp_path: Any) -> None:
        # Fail-closed: ON but no authority staged -> ValueError, never a silent
        # empty authority that would disable PSL policy without a signal.
        pfb_unbound.pfb["python_tld_wildcard"] = True
        pfb_unbound.pfb["pfb_py_psl"] = str(tmp_path / "does_not_exist")

        with pytest.raises(ValueError, match="PSL authority"):
            pfb_unbound._dnsbl_config_from_manifest({"config": {}}, str(tmp_path))

    @pytest.mark.parametrize("flag_on", [False, True])
    def test_manifest_tld_master_key_is_ignored_regardless_of_flag(self, tmp_path: Any, flag_on: bool) -> None:
        # A manifest embedding tld_master (stale pre-#1255 shape, or crafted) must
        # never feed the oracle -- the flag + shipped file are the sole source, for
        # BOTH flag states. ON ships a REAL oracle file alongside the poisoned
        # manifest key, so a regression that merged/fell back to the manifest value
        # would surface as extra/wrong entries, not just an empty-vs-empty match.
        pfb_unbound.pfb["python_tld_wildcard"] = flag_on
        expected: tuple[str, ...] = ()
        if flag_on:
            oracle = tmp_path / "dnsbl_psl"
            oracle.write_text(
                "// ===BEGIN ICANN DOMAINS===\ncom\nnet\n// ===END ICANN DOMAINS===\n"
                "// ===BEGIN PRIVATE DOMAINS===\n// ===END PRIVATE DOMAINS===\n",
                encoding="utf-8",
            )
            pfb_unbound.pfb["pfb_py_psl"] = str(oracle)
            expected = ("com", "net")
        manifest = {"config": {"tld_master": "/etc/passwd"}}

        config = pfb_unbound._dnsbl_config_from_manifest(manifest, str(tmp_path))

        assert config["psl_rules"].icann_exact == expected, (
            f"expected {expected!r} (only the shipped oracle, never the poisoned "
            f"manifest 'tld_master' key), got {config['psl_rules']!r}"
        )
