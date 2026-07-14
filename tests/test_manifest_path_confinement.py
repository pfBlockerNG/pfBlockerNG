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

import os
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
    """issue #1255: the public-suffix oracle (``tld_wildcard_master`` suffix lines
    fed to ``_dnsbl_load_tld_wildcard_master``) is sourced from a SHIPPED file
    (``pfb["pfb_py_tld"]``) gated by ``pfb["python_tld_wildcard"]`` -- HSTS parity
    -- never from the manifest. A manifest carrying a stale/malicious
    ``config.tld_master`` key (an old install, or a crafted manifest) is ignored
    entirely; the flag is the sole gate.
    """

    def setup_method(self) -> None:
        pfb_unbound.pfb["python_tld_wildcard"] = False
        pfb_unbound.pfb["pfb_py_tld"] = ""

    def test_oracle_not_loaded_when_flag_off_even_if_file_exists(self, tmp_path: Any) -> None:
        oracle = tmp_path / "pfb_py_tld.txt"
        oracle.write_text("com\nnet\n", encoding="utf-8")
        pfb_unbound.pfb["python_tld_wildcard"] = False
        pfb_unbound.pfb["pfb_py_tld"] = str(oracle)

        config = pfb_unbound._dnsbl_config_from_manifest({"config": {}}, str(tmp_path))

        assert config["tld_wildcard_master"] == [], "OFF must never load the oracle, even though the file exists"

    def test_oracle_loaded_when_flag_on_and_file_present(self, tmp_path: Any) -> None:
        oracle = tmp_path / "pfb_py_tld.txt"
        oracle.write_text("com\nnet\n", encoding="utf-8")
        pfb_unbound.pfb["python_tld_wildcard"] = True
        pfb_unbound.pfb["pfb_py_tld"] = str(oracle)

        config = pfb_unbound._dnsbl_config_from_manifest({"config": {}}, str(tmp_path))

        assert config["tld_wildcard_master"] == ["com", "net"]

    def test_oracle_empty_when_flag_on_but_file_missing(self, tmp_path: Any) -> None:
        # Fail-safe: ON but no oracle staged yet -> empty, never a raise/crash.
        pfb_unbound.pfb["python_tld_wildcard"] = True
        pfb_unbound.pfb["pfb_py_tld"] = str(tmp_path / "does_not_exist.txt")

        config = pfb_unbound._dnsbl_config_from_manifest({"config": {}}, str(tmp_path))

        assert config["tld_wildcard_master"] == []

    def test_manifest_tld_master_key_is_ignored_regardless_of_flag(self, tmp_path: Any) -> None:
        # A manifest embedding tld_master (stale pre-#1255 shape, or crafted) must
        # never feed the oracle -- the flag + shipped file are the sole source.
        pfb_unbound.pfb["python_tld_wildcard"] = False
        manifest = {"config": {"tld_master": "/etc/passwd"}}

        config = pfb_unbound._dnsbl_config_from_manifest(manifest, str(tmp_path))

        assert config["tld_wildcard_master"] == []
