"""Regression coverage for charset-normalizer identity synchronization."""

from __future__ import annotations

from pathlib import Path

from tests.test_build_dep_pkg_portable import _write_port, bdp
from tests.test_tagged_release_handoff import ROW, _dependency_identity


def test_issue_2867_charset_normalizer_identity_matches_builder_and_tagged_handoff(
    tmp_path: Path,
) -> None:
    port_dir = _write_port(tmp_path)
    facts = bdp.read_port(port_dir)
    distfile = f"{facts.distname}.tar.gz"
    sha256, size = bdp.read_distinfo(port_dir, distfile)
    expected = {
        "port_version": "3.4.7",
        "distfile": "charset_normalizer-3.4.7.tar.gz",
        "distfile_sha256": "ae89db9e5f98a11a4bf50407d4363e7b09b31e55bc117b4f7d80aab97ba009e5",
        "distfile_size": 144_271,
        "portname": "charset-normalizer",
        "package_name": "py311-charset-normalizer",
        "package_version": "3.4.7",
    }
    builder = {
        "port_version": facts.portversion,
        "distfile": distfile,
        "distfile_sha256": sha256,
        "distfile_size": size,
        "portname": facts.portname,
        "package_name": f"{ROW['py_flavor']}-{facts.portname}",
        "package_version": facts.portversion,
    }
    tagged = _dependency_identity(ROW)

    assert expected == builder == {field: tagged[field] for field in expected}
