from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

import pytest

from tests.smoke.ui.test_render_smoke import (
    _PKG_CONF_PATH,
    _PRODUCT_LABEL_PATH,
    pkg_conf_ca_block_seeded,
)

if TYPE_CHECKING:
    from tests.smoke.conftest import SmokeVM

_ROOT = Path(__file__).resolve().parents[1]
_HOOK = _ROOT / "scripts" / "rc.d" / "pfblockerng_repo_generate.sh"


def test_boot_hook_does_not_replace_concurrent_pkgconf_rewrite(tmp_path: Path) -> None:
    product_label = tmp_path / "product_label"
    product_label.write_text("pfSense Plus\n")
    version = tmp_path / "version"
    version.write_text("2.8.1\n")
    config = tmp_path / "config.xml"
    config.write_text(
        "<pfsense>\n<installedpackages>\n<pfblockerng>\n<config>\n"
        "<pfb_pkg_ca_consent>on</pfb_pkg_ca_consent>\n"
        "</config>\n</pfblockerng>\n</installedpackages>\n</pfsense>\n"
    )
    ca_dir = tmp_path / "certs"
    ca_dir.mkdir()
    (ca_dir / "hash.0").write_text("")
    ca_file = tmp_path / "netgate-ca.pem"
    ca_file.write_text("test CA bundle\n")
    pkg_conf = tmp_path / "pkg.conf"
    pkg_conf.write_bytes(f"PKG_ENV {{\n\tSSL_CA_CERT_FILE={ca_file}\n}}\n".encode() + b"# padding\n" * 5_000_000)
    newer = tmp_path / "pkg.conf.newer"
    newer_content = b"NEWER_REWRITE_SURVIVED\n"
    pkg_dirty = tmp_path / "pkg.dirty"
    newer.write_bytes(newer_content)

    env = {
        **os.environ,
        "PFB_STABLE_CONF": str(tmp_path / "missing-stable.conf"),
        "PFB_TESTING_CONF": str(tmp_path / "missing-testing.conf"),
        "PFB_EDGE_CONF": str(tmp_path / "missing-edge.conf"),
        "PFB_NIGHTLY_CONF": str(tmp_path / "missing-nightly.conf"),
        "PFB_PRODUCT_LABEL": str(product_label),
        "PFB_VERSION_FILE": str(version),
        "PFB_CONFIG_XML": str(config),
        "PFB_PKG_CONF": str(pkg_conf),
        "PFB_SSL_CA_CERT_PATH": str(ca_dir),
        "PFB_PKG_DIRTY": str(pkg_dirty),
    }
    process = subprocess.Popen(
        ["sh", str(_HOOK), "onestart"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    staged = Path(f"{pkg_conf}.tmp")
    writer_seen = False
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and process.poll() is None:
            if staged.is_file():
                with staged.open("rb") as handle:
                    if b"SSL_CA_CERT_PATH=" in handle.read(4096):
                        os.replace(newer, pkg_conf)
                        writer_seen = True
                        break
            time.sleep(0.005)
        stdout, stderr = process.communicate(timeout=15)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)

    assert writer_seen, "the competing writer never observed a completed transformed temp file"
    assert process.returncode == 0, f"hook failed: stdout={stdout!r} stderr={stderr!r}"
    actual = pkg_conf.read_bytes()
    if actual != newer_content:
        pytest.fail(f"concurrent rewrite was lost: final_size={len(actual)} prefix={actual[:80]!r}")


class _FakeVM:
    def __init__(self) -> None:
        self.files = {
            _PKG_CONF_PATH: "ABI=FreeBSD:15:amd64\n",
            _PRODUCT_LABEL_PATH: "pfSense Community Edition\n",
        }

    def ssh(self, command: str, path: str) -> SimpleNamespace:
        assert command == "cat"
        return SimpleNamespace(returncode=0, stdout=self.files[path], stderr="")


def test_plus_simulation_restores_both_files_when_second_seed_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    vm = _FakeVM()
    original = dict(vm.files)
    calls = 0

    def failing_write(_vm: _FakeVM, path: str, content: str, *, timeout: float = 30.0) -> None:
        del timeout
        nonlocal calls
        calls += 1
        _vm.files[path] = content
        if calls == 2:
            raise RuntimeError("injected pkg.conf seed failure")

    monkeypatch.setattr("tests.smoke.ui.test_render_smoke._overwrite_vm_file", failing_write)
    with (
        pytest.raises(RuntimeError, match="injected pkg.conf seed failure"),
        pkg_conf_ca_block_seeded(cast("SmokeVM", vm)),
    ):
        pass

    assert vm.files == original


def test_plus_simulation_restores_label_when_pkgconf_restore_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    vm = _FakeVM()
    original = dict(vm.files)
    calls = 0

    def failing_write(_vm: _FakeVM, path: str, content: str, *, timeout: float = 30.0) -> None:
        del timeout
        nonlocal calls
        calls += 1
        _vm.files[path] = content
        if calls == 3:
            raise RuntimeError("injected pkg.conf restore failure")

    monkeypatch.setattr("tests.smoke.ui.test_render_smoke._overwrite_vm_file", failing_write)
    with (
        pytest.raises(RuntimeError, match="injected pkg.conf restore failure"),
        pkg_conf_ca_block_seeded(cast("SmokeVM", vm)),
    ):
        pass

    assert vm.files == original
