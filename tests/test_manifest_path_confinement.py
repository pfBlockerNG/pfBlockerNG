"""Manifest path confinement: a feed ``raw`` / ``tld_master`` path that resolves
OUTSIDE the manifest's base directory is skipped and logged, never opened.

The manifest is published next to its raw feeds, so every referenced file must
resolve under the manifest directory. A row whose resolved real path escapes that
directory (``..`` traversal, an absolute path elsewhere, or a symlink pointing out)
is refused. Both branches are pinned for each sink (``_dnsbl_file_line_reader`` for
feed ``raw`` paths, ``_dnsbl_config_from_manifest`` for ``tld_master``):
in-base content is read; out-of-base content is skipped with a stderr log line.

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


class TestTldMasterPathConfinement:
    def test_in_base_tld_master_is_read(self, tmp_path: Any) -> None:
        # Given a tld_master file inside the base dir, referenced by name.
        base = tmp_path / "base"
        base.mkdir()
        (base / "tlds.txt").write_text("com\nnet\n", encoding="utf-8")
        manifest = {"config": {"tld_master": "tlds.txt"}}

        # When the config is shaped from the manifest.
        config = pfb_unbound._dnsbl_config_from_manifest(manifest, str(base))

        # Then the in-base suffix lines are loaded.
        assert config["tld_master"] == ["com", "net"]

    def test_out_of_base_tld_master_is_skipped_and_logged(
        self, tmp_path: Any, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Given a tld_master file OUTSIDE the base dir, reached via traversal.
        base = tmp_path / "base"
        base.mkdir()
        (tmp_path / "tlds.txt").write_text("evil\n", encoding="utf-8")

        # Before-state: an in-base tld_master of the same name IS loaded.
        (base / "tlds.txt").write_text("com\n", encoding="utf-8")
        inbase = pfb_unbound._dnsbl_config_from_manifest({"config": {"tld_master": "tlds.txt"}}, str(base))
        assert inbase["tld_master"] == ["com"]
        capsys.readouterr()

        # When the manifest points tld_master at an escaping path.
        manifest = {"config": {"tld_master": os.path.join("..", "tlds.txt")}}
        config = pfb_unbound._dnsbl_config_from_manifest(manifest, str(base))

        # Then no suffix lines are loaded and the refusal is logged.
        assert config["tld_master"] == []
        assert "Refusing tld_master outside base dir" in capsys.readouterr().err
