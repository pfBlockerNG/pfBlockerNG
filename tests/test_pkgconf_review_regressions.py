from __future__ import annotations

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
