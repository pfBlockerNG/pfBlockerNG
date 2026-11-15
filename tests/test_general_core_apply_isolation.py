"""General-save markers must activate the existing UI snapshot/restore fixture (H2)."""

from __future__ import annotations

import subprocess
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from xml.etree import ElementTree

import pytest

from tests.smoke import helpers
from tests.smoke.ui import conftest as ui_fixtures
from tests.smoke.ui import test_general_core_apply as general


class _ConfigBoundary:
    def __init__(self, config: str) -> None:
        self.config = config
        self.snapshots: dict[str, str] = {}
        self.restores: list[str] = []

    def ssh(self, *args: str, timeout: float = 30.0) -> subprocess.CompletedProcess[str]:
        if args == (f"cp /conf/config.xml {ui_fixtures.UI_CONFIG_SNAPSHOT}",):
            self.snapshots[ui_fixtures.UI_CONFIG_SNAPSHOT] = self.config
            return subprocess.CompletedProcess(args, 0, "", "")
        if args == ("cat", "/conf/config.xml"):
            return subprocess.CompletedProcess(args, 0, self.config, "")
        raise AssertionError(f"unmodelled config transport: {args!r}")

    def restore(self, vm: Any, *, snapshot_path: str) -> None:
        assert vm is self
        self.restores.append(snapshot_path)
        self.config = self.snapshots[snapshot_path]


def _exercise_actual_isolation(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
    enabled: str | None,
    keep: str | None,
    early_failure: bool,
    *,
    force_mutating: bool = False,
) -> None:
    fields = "".join(
        f"<{key}>{value}</{key}>" for key, value in (("enable_cb", enabled), ("pfb_keep", keep)) if value is not None
    )
    original = (
        f"<pfsense><installedpackages><pfblockerng><config>{fields}</config>"
        "</pfblockerng></installedpackages></pfsense>"
    )
    vm = _ConfigBoundary(original)
    module = pytest.Module.from_parent(request.session, path=Path(general.__file__))
    assert module.obj is general
    node = pytest.Function.from_parent(
        module,
        name="test_general_save_uses_core_apply_without_an_inline_feed_pass",
        callobj=general.test_general_save_uses_core_apply_without_an_inline_feed_pass,
    )
    assert node.get_closest_marker("ui_render") is not None
    if force_mutating:
        node.add_marker(pytest.mark.ui_e2e)
    baseline: dict[str, str] | None = None
    requested: list[str] = []

    def getfixturevalue(name: str) -> Any:
        nonlocal baseline
        requested.append(name)
        if name == "_ui_config_baseline":
            baseline = getattr(ui_fixtures._ui_config_baseline, "__wrapped__")(None, vm)
            return baseline
        assert name == "smoke_vm", name
        return vm

    monkeypatch.setattr(helpers, "restore_pfb_config_baseline", vm.restore)
    fixture = getattr(ui_fixtures._ui_pfb_isolation, "__wrapped__")(
        SimpleNamespace(node=node, getfixturevalue=getfixturevalue)
    )
    next(fixture)
    body_outcome = (
        pytest.raises(AssertionError, match="early General-save body failure") if early_failure else nullcontext()
    )
    with body_outcome:
        try:
            config = ElementTree.fromstring(vm.config)
            settings = config.find("./installedpackages/pfblockerng/config")
            assert settings is not None
            for key, value in (("pfb_keep", "" if keep == "on" else "on"), ("enable_cb", "")):
                field = settings.find(key)
                if field is None:
                    field = ElementTree.SubElement(settings, key)
                field.text = value
            vm.config = ElementTree.tostring(config, encoding="unicode")
            assert vm.config != original
            if early_failure:
                raise AssertionError("early General-save body failure")
        finally:
            with pytest.raises(StopIteration):
                next(fixture)

    assert vm.config == original, "General-save module markers bypassed config restoration"
    assert requested == ["_ui_config_baseline", "smoke_vm"]
    assert vm.snapshots == {ui_fixtures.UI_CONFIG_SNAPSHOT: original}
    assert vm.restores == [ui_fixtures.UI_CONFIG_SNAPSHOT]
    assert baseline == {"digest": helpers.pfb_config_digest(vm)}  # type: ignore[arg-type]
    restored = ElementTree.fromstring(vm.config).find("./installedpackages/pfblockerng/config")
    assert restored is not None
    for key, expected_value in (("enable_cb", enabled), ("pfb_keep", keep)):
        field = restored.find(key)
        assert (field is not None) == (expected_value is not None), f"{key} presence changed"
        if field is not None:
            assert (field.text or "") == expected_value, f"{key} state changed"


@pytest.mark.parametrize("enabled", [None, "", "on"], ids=["enabled-absent", "disabled", "enabled"])
@pytest.mark.parametrize("keep", [None, "on"], ids=["keep-absent", "keep-on"])
@pytest.mark.parametrize("early_failure", [False, True], ids=["normal-return", "early-failure"])
def test_general_module_markers_restore_config(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
    enabled: str | None,
    keep: str | None,
    early_failure: bool,
) -> None:
    _exercise_actual_isolation(request, monkeypatch, enabled, keep, early_failure)


def test_existing_mutating_marker_restores_config_control(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> None:
    _exercise_actual_isolation(request, monkeypatch, "on", None, True, force_mutating=True)
