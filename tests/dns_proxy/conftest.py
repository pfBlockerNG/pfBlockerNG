"""Fixtures for the pfb-dns end-to-end tests: a module directory shaped like /var/unbound, and a test certificate.

Run: python3 -m pytest tests/dns_proxy
"""

from __future__ import annotations

from pathlib import Path

import pytest
from dot_helpers import make_certificate
from frontend_constants import GP_BYPASS_INI, SAFESEARCH_CSV, write_module_dir
from hang_guard import hang_guard  # noqa: F401  (autouse: every test here gets the alarm)


@pytest.fixture
def module_dir(tmp_path: Path) -> Path:
    """A module dir shaped like /var/unbound: shipped code (symlinked, byte-identical), ini, manifest, raw feed."""
    write_module_dir(tmp_path)
    return tmp_path


@pytest.fixture
def safesearch_csv(module_dir: Path) -> None:
    """Drops pfb_py_ss.txt into the module dir, where the decider reads it at boot."""
    (module_dir / "pfb_py_ss.txt").write_text(SAFESEARCH_CSV, encoding="utf-8")


@pytest.fixture
def bypass_list(module_dir: Path) -> None:
    """Adds [GP_Bypass_List] (BYPASSED_CLIENT) to pfb_unbound.ini, which the decider reads at boot."""
    ini = module_dir / "pfb_unbound.ini"
    ini.write_text(ini.read_text(encoding="utf-8") + GP_BYPASS_INI, encoding="utf-8")


@pytest.fixture
def forwarding_ini(module_dir: Path) -> None:
    """Sets `forwarding = true` in [MAIN] (the Resolver forwards): the only mode in which upstream blocks are seen."""
    ini = module_dir / "pfb_unbound.ini"
    ini.write_text(ini.read_text(encoding="utf-8").replace("[MAIN]\n", "[MAIN]\nforwarding = true\n", 1), "utf-8")


@pytest.fixture(scope="module")
def certificate(tmp_path_factory: pytest.TempPathFactory) -> tuple[bytes, bytes]:
    """A self-signed localhost certificate as (certificate PEM, private key PEM), made once per test module."""
    return make_certificate(tmp_path_factory.mktemp("dot-cert"))
