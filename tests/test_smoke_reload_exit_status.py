"""Hermetic contract tests for ``tests.smoke.helpers.reload`` CLI status handling."""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from tests.smoke import helpers


@dataclass
class _FakeResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


@dataclass
class _FakeVM:
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""
    commands: list[tuple[str, ...]] = field(default_factory=list)

    def ssh(self, *remote: str, timeout: float = 60.0) -> _FakeResult:
        self.commands.append(remote)
        if remote and remote[0] == helpers.PHP_BIN:
            return _FakeResult(self.returncode, self.stdout, self.stderr)
        raise AssertionError(f"reload performed unexpected guest I/O: {remote!r}")


def _reload(vm: _FakeVM, scope: str = "update", **kwargs: object) -> None:
    helpers.reload(vm, scope, wait_unbound=False, **kwargs)  # type: ignore[arg-type]


def test_clean_exit_is_accepted_without_pass_marker_log_scraping() -> None:
    vm = _FakeVM(returncode=0)

    _reload(vm)

    assert vm.commands == [
        (helpers.PHP_BIN, helpers.PFB_CLI, "pfb_trigger", "scope=both", "force=false", "trigger=cron")
    ]


@pytest.mark.parametrize(
    ("scope", "stderr", "expected_command"),
    [
        (
            "update",
            "pfBlockerNG feed pass deferred: dispatcher lock is held\n",
            (helpers.PHP_BIN, helpers.PFB_CLI, "pfb_trigger", "scope=both", "force=false", "trigger=cron"),
        ),
        (
            "cron",
            "pfBlockerNG feed pass deferred: feed-pass lock is held\n",
            (helpers.PHP_BIN, helpers.PFB_CLI, "cron"),
        ),
    ],
)
def test_lock_deferral_fails_immediately_with_precise_stderr_reason(
    scope: str, stderr: str, expected_command: tuple[str, ...]
) -> None:
    vm = _FakeVM(returncode=75, stderr=stderr)

    with pytest.raises(RuntimeError) as excinfo:
        helpers.reload(vm, scope)  # type: ignore[arg-type]

    assert str(excinfo.value) == f"reload({scope}) deferred (rc=75): {stderr.strip()}"
    assert vm.commands == [expected_command]


def test_lock_deferral_does_not_wait_for_swap_or_resolver(monkeypatch: pytest.MonkeyPatch) -> None:
    counted_markers: list[str | tuple[str, ...]] = []
    monkeypatch.setattr(
        helpers,
        "count_log_marker",
        lambda _vm, _path, marker: counted_markers.append(marker) or 0,
    )
    monkeypatch.setattr(
        helpers,
        "wait_zero_downtime_swap",
        lambda *_args, **_kwargs: pytest.fail("rc=75 must fail before the zero-downtime swap wait"),
    )
    monkeypatch.setattr(
        helpers,
        "wait_unbound_ready",
        lambda *_args, **_kwargs: pytest.fail("rc=75 must fail before the resolver readiness wait"),
    )
    vm = _FakeVM(returncode=75, stderr="pfBlockerNG feed pass deferred: feed-pass lock is held\n")

    with pytest.raises(RuntimeError, match=r"^reload\(update\) deferred \(rc=75\): .*feed-pass lock is held$"):
        helpers.reload(vm, "update", data_path=True, timeout=30.0)  # type: ignore[arg-type]

    assert counted_markers == [helpers.SWAP_LOG_MARKER]


def test_real_failure_preserves_generic_diagnostic() -> None:
    vm = _FakeVM(returncode=1, stdout="fatal output", stderr="real failure\n")

    with pytest.raises(RuntimeError) as excinfo:
        _reload(vm, "updateip")

    assert str(excinfo.value) == "reload(updateip) failed: rc=1 stdout='fatal output' stderr='real failure\\n'"
    assert vm.commands == [(helpers.PHP_BIN, helpers.PFB_CLI, "pfb_trigger", "scope=ip", "force=true", "trigger=force")]


@pytest.mark.parametrize(
    ("scope", "expected"),
    [
        ("update", ("scope=both", "force=false", "trigger=cron")),
        ("updateip", ("scope=ip", "force=true", "trigger=force")),
        ("updatednsbl", ("scope=dnsbl", "force=true", "trigger=force")),
    ],
)
def test_trigger_shape_is_unchanged(scope: str, expected: tuple[str, ...]) -> None:
    vm = _FakeVM(returncode=0)

    _reload(vm, scope)

    assert vm.commands == [(helpers.PHP_BIN, helpers.PFB_CLI, "pfb_trigger", *expected)]
