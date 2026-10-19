"""Fixtures: put the shipped DNS decider on sys.path and boot the REAL shipped pfb_unbound.py through the shim.

Run: python3 -m pytest tests/dns_proxy
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from frontend_constants import GP_BYPASS_INI, PROTO_DIR, SAFESEARCH_CSV, Booted, LogFeed, write_module_dir
from hang_guard import hang_guard  # noqa: F401  (autouse: every test here gets the alarm)

if TYPE_CHECKING:
    from frontend_helpers import ManualClock

sys.path.insert(0, str(PROTO_DIR))


@pytest.fixture
def module_dir(tmp_path: Path) -> Path:
    """A module dir shaped like /var/unbound: shipped code (symlinked, byte-identical), ini, manifest, raw feed."""
    write_module_dir(tmp_path)
    return tmp_path


@pytest.fixture
def booted(module_dir: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Booted]:
    import pfb_dns_proxy

    monkeypatch.chdir(module_dir)
    # init_standard() replaces sys.stderr with a file logger; register monkeypatch's auto-restore.
    monkeypatch.setattr(sys, "stderr", sys.stderr)
    module = pfb_dns_proxy.boot(str(module_dir))
    log = LogFeed()
    monkeypatch.setattr(module, "pfb_log", lambda name, line: log.append((name, line)))
    try:
        yield Booted(module, log)
    finally:
        pfb_dns_proxy.shutdown(module)


@pytest.fixture
def safesearch_csv(module_dir: Path) -> None:
    """Drops pfb_py_ss.txt into the module dir; init_standard() reads it, so it must exist before `booted`."""
    (module_dir / "pfb_py_ss.txt").write_text(SAFESEARCH_CSV, encoding="utf-8")


@pytest.fixture
def ss_booted(safesearch_csv: None, booted: Booted) -> Booted:
    """`booted` with the SafeSearch CNAME redirects of SAFESEARCH_CSV loaded."""
    return booted


@pytest.fixture
def bypass_list(module_dir: Path) -> None:
    """Adds [GP_Bypass_List] (BYPASSED_CLIENT) to pfb_unbound.ini; init_standard() reads it, so it precedes `booted`."""
    ini = module_dir / "pfb_unbound.ini"
    ini.write_text(ini.read_text(encoding="utf-8") + GP_BYPASS_INI, encoding="utf-8")


@pytest.fixture
def gp_booted(bypass_list: None, booted: Booted) -> Booted:
    """`booted` with BYPASSED_CLIENT on the Group Policy bypass list."""
    return booted


@pytest.fixture
def forwarding_ini(module_dir: Path) -> None:
    """Sets `forwarding = true` in [MAIN] (the Resolver forwards): init_standard() reads it, so it precedes `booted`."""
    ini = module_dir / "pfb_unbound.ini"
    ini.write_text(ini.read_text(encoding="utf-8").replace("[MAIN]\n", "[MAIN]\nforwarding = true\n", 1), "utf-8")


@pytest.fixture
def fwd_booted(forwarding_ini: None, booted: Booted) -> Booted:
    """`booted` with the Resolver in forwarding mode, the only mode in which upstream blocks are detected."""
    return booted


@pytest.fixture(scope="module")
def certificate(tmp_path_factory: pytest.TempPathFactory) -> tuple[bytes, bytes]:
    """A self-signed localhost certificate as (certificate PEM, private key PEM), made once per test module."""
    from dot_helpers import make_certificate  # imported late: it needs the proxy dir that this module puts on sys.path

    return make_certificate(tmp_path_factory.mktemp("dot-cert"))


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> ManualClock:
    """The proxy's clock, frozen: a ManualClock that only moves when a test advances it."""
    import frontend_helpers  # imported late: it needs the proxy dir that this module puts on sys.path
    import pfb_dns_proxy

    frozen = frontend_helpers.ManualClock()
    monkeypatch.setattr(pfb_dns_proxy, "monotonic", frozen, raising=False)  # a proxy without a clock has none to set
    return frozen
