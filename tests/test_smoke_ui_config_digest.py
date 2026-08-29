"""Off-box pins for the UI tier's per-test config-change probe + restore (issue #810).

``tests/smoke/ui/conftest.py``'s ``_ui_pfb_isolation`` autouse fixture pays
``helpers.restore_pfb_config_baseline``'s real cost (a config.xml byte restore +
services_unbound_configure + clearip/cleardnsbl + apply_filter_sync, ~15-30s) ONLY when a
mutating UI test actually left config dirty -- detected via a cheap ``pfb_config_digest``
probe (one ``cat /conf/config.xml`` over ssh, no ``pfSsh.php`` spin-up). This module pins
the digest logic off-VM: ``strip_config_revision``'s "strip only the FIRST <revision> block"
contract (the volatile write_config-rewritten block must never make a real change read as
clean; any LATER <revision>-shaped content -- e.g. a hostile package key literally named
"revision" -- must stay live so a change inside it still reads as dirty) and
``pfb_config_digest``'s never-fold-a-failed-read-into-a-digest contract (the same #909
lesson as ``guest_file_contains``); it also pins ``restore_pfb_config_baseline``'s sequence
(cp the snapshot + drop the config cache, THEN services_unbound_configure, THEN
clearip/cleardnsbl gated on package presence, THEN apply_filter_sync) -- the RESTORE-to-
session-baseline mechanism that replaced ``reset_pfb_baseline``'s wipe-to-empty after the
latter deleted the DNSBL VIP and broke every later DNSBL/SafeSearch save in ui-tests.yml
run 28900064099. ``tests.smoke.helpers`` is import-safe off-VM (precedent:
``test_smoke_unblock_egress.py``).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from tests._workflow_steps import extract_job
from tests.smoke import helpers

_REPO_ROOT = Path(__file__).resolve().parents[1]


@dataclass
class _FakeResult:
    """Stand-in for ``subprocess.CompletedProcess[str]`` (the shape ``SmokeVM.ssh`` returns)."""

    returncode: int
    stdout: str = ""
    stderr: str = ""


@dataclass
class _FakeVM:
    """Fake ``vm.ssh(*remote, timeout=...)`` -- records calls, replays scripted result(s).

    ``results`` (a list) supports the restore sequence's MULTIPLE distinct ``vm.ssh``
    calls (the cp step, then clearip/cleardnsbl) -- each call pops the next entry.
    When empty (the (a)-(j) tests' shape), every call replays the single ``result``
    instead, unchanged from before this extension.
    """

    result: _FakeResult
    calls: list[tuple[str, ...]] = field(default_factory=list)
    results: list[_FakeResult] = field(default_factory=list)

    def ssh(self, *remote: str, timeout: float = 60.0) -> _FakeResult:
        self.calls.append(remote)
        if self.results:
            return self.results.pop(0)
        return self.result


# --------------------------------------------------------------------------- #
# strip_config_revision
# --------------------------------------------------------------------------- #


def test_revision_only_diff_reads_equal() -> None:
    """(a) Two configs differing ONLY inside the first <revision> block strip to identical
    text -- the self-restoring-test clean path (a write_config with no real change)."""
    saved_at_t1 = (
        "<pfsense>\n<revision><time>1700000000</time><description>saved</description></revision>\n"
        "<system><hostname>pfsense</hostname></system>\n</pfsense>\n"
    )
    saved_at_t2 = (
        "<pfsense>\n<revision><time>1700000123</time><description>saved again</description></revision>\n"
        "<system><hostname>pfsense</hostname></system>\n</pfsense>\n"
    )
    stripped_t1 = helpers.strip_config_revision(saved_at_t1)
    stripped_t2 = helpers.strip_config_revision(saved_at_t2)
    assert stripped_t1 == stripped_t2, f"expected equal after strip, got {stripped_t1!r} != {stripped_t2!r}"


def test_real_value_diff_reads_different() -> None:
    """(b) A change OUTSIDE <revision> (a real config edit) must still differ after stripping --
    the dirty path a mutating UI test is supposed to trip."""
    before = (
        "<pfsense>\n<revision><time>1</time></revision>\n"
        "<installedpackages><pfblockerng><enable_cb>on</enable_cb></pfblockerng></installedpackages>\n"
        "</pfsense>\n"
    )
    after = before.replace("<enable_cb>on</enable_cb>", "<enable_cb></enable_cb>")
    stripped_before = helpers.strip_config_revision(before)
    stripped_after = helpers.strip_config_revision(after)
    assert stripped_before != stripped_after, "a real config edit must not collapse to the same stripped text"


def test_no_revision_block_is_a_no_op() -> None:
    """(c) A body with no <revision> element at all strips to itself, unraised."""
    text = "<pfsense>\n<system><hostname>pfsense</hostname></system>\n</pfsense>\n"
    result = helpers.strip_config_revision(text)
    assert result == text, f"expected no-op, got {result!r}"


def test_second_revision_shaped_block_is_preserved() -> None:
    """(d) Only the FIRST <revision> block is stripped -- a SECOND <revision>-shaped block
    (hostile: e.g. a package key literally named "revision") survives, so a change buried
    in IT still reads as dirty (fail-safe-to-dirty, never fail-safe-to-clean)."""
    template = "<pfsense><revision><time>1</time></revision><installedpackages>{inner}</installedpackages></pfsense>"
    before = template.format(inner="<revision><time>1</time></revision>")
    after = template.format(inner="<revision><time>2</time></revision>")
    stripped_before = helpers.strip_config_revision(before)
    stripped_after = helpers.strip_config_revision(after)
    assert stripped_before != stripped_after, "a change inside the SECOND <revision>-shaped block must survive"
    # Only the first (real, volatile) <revision> block was removed -- the second remains once.
    assert stripped_before.count("<revision>") == 1, f"expected exactly one <revision> left, got {stripped_before!r}"
    assert stripped_after.count("<revision>") == 1, f"expected exactly one <revision> left, got {stripped_after!r}"


def test_empty_string_is_a_no_op() -> None:
    """(e) Empty input strips to empty -- no crash on the degenerate case."""
    result = helpers.strip_config_revision("")
    assert result == "", f"expected empty, got {result!r}"


def test_multiline_nested_revision_fully_stripped() -> None:
    """(f) A realistic multi-line <revision> with nested <time>/<description> children is
    stripped in FULL -- pins the DOTALL flag (a naive non-DOTALL regex would stop at the
    first newline and leave the tail of the block behind)."""
    text = (
        "before"
        "<revision>\n"
        "\t<time>1700000000</time>\n"
        "\t<description>Made unknown change - not sure why this happened.</description>\n"
        "\t<username>admin@10.0.0.1</username>\n"
        "</revision>"
        "after"
    )
    result = helpers.strip_config_revision(text)
    assert result == "beforeafter", f"expected the whole nested block gone, got {result!r}"


def test_crlf_line_endings_still_stripped_deterministically() -> None:
    """(g) CRLF-terminated config text (a real pfSense-generated file can carry ``\\r\\n``)
    still strips the <revision> block, and the resulting digest is deterministic."""
    crlf_before = (
        "<pfsense>\r\n<revision><time>1</time>\r\n<description>x</description></revision>\r\n"
        "<system><hostname>pfsense</hostname></system>\r\n</pfsense>\r\n"
    )
    crlf_after = (
        "<pfsense>\r\n<revision><time>2</time>\r\n<description>y</description></revision>\r\n"
        "<system><hostname>pfsense</hostname></system>\r\n</pfsense>\r\n"
    )
    stripped_before = helpers.strip_config_revision(crlf_before)
    stripped_after = helpers.strip_config_revision(crlf_after)
    assert stripped_before == stripped_after, (
        f"CRLF revision-only diff must still collapse to equal, got {stripped_before!r} != {stripped_after!r}"
    )
    digest_before = hashlib.md5(stripped_before.encode("utf-8")).hexdigest()
    digest_after = hashlib.md5(stripped_after.encode("utf-8")).hexdigest()
    assert digest_before == digest_after, "deterministic digest expected once <revision> content is stripped"


# --------------------------------------------------------------------------- #
# pfb_config_digest
# --------------------------------------------------------------------------- #


def test_digest_raises_on_nonzero_returncode() -> None:
    """(h) A failed guest read (ssh transport fault, permission error, ...) raises -- it must
    NEVER fold into a digest value that could spuriously compare equal to another failure."""
    vm = _FakeVM(result=_FakeResult(returncode=1, stderr="cat: /conf/config.xml: Permission denied"))
    with pytest.raises(RuntimeError, match=r"rc=1.*Permission denied"):
        helpers.pfb_config_digest(vm)  # type: ignore[arg-type]


def test_digest_raises_on_empty_stdout() -> None:
    """(i) rc 0 with EMPTY stdout is a truncated/absent read, not a valid (empty) config --
    must raise, never quietly digest the empty string."""
    vm = _FakeVM(result=_FakeResult(returncode=0, stdout=""))
    with pytest.raises(RuntimeError, match=r"pfb_config_digest"):
        helpers.pfb_config_digest(vm)  # type: ignore[arg-type]


def test_digest_happy_path_matches_independent_md5() -> None:
    """(j) The happy path returns exactly the md5 hexdigest of the stripped config text,
    computed independently here (not by re-calling the function under test)."""
    text = (
        "<pfsense>\n<revision><time>1700000000</time></revision>\n"
        "<system><hostname>pfsense</hostname></system>\n</pfsense>\n"
    )
    vm = _FakeVM(result=_FakeResult(returncode=0, stdout=text))
    expected = hashlib.md5(helpers.strip_config_revision(text).encode("utf-8")).hexdigest()
    actual = helpers.pfb_config_digest(vm)  # type: ignore[arg-type]
    assert actual == expected, f"expected {expected}, got {actual}"


# --------------------------------------------------------------------------- #
# restore_pfb_config_baseline (issue #810 follow-up: RESTORE-to-session-baseline,
# not reset_pfb_baseline's wipe-to-empty -- see helpers.restore_pfb_config_baseline's
# docstring for why the wipe broke the UI tier, ui-tests.yml run 28900064099).
# --------------------------------------------------------------------------- #

_SNAPSHOT_PATH = "/root/pfb_ui_config_baseline.xml"


def test_restore_cp_failure_raises_before_php_eval(monkeypatch: pytest.MonkeyPatch) -> None:
    """(k) A failed guest-side ``cp`` (bad snapshot path, disk full, ...) raises RuntimeError
    BEFORE ``php_eval`` runs -- a broken restore must surface immediately, never limp forward
    into a resolver reconfigure against a config.xml that was never actually replaced."""
    php_eval_calls: list[str] = []

    def fake_php_eval(vm: object, snippet: str, *, timeout: float = 60.0) -> _FakeResult:
        php_eval_calls.append(snippet)
        return _FakeResult(returncode=0, stdout="OK")

    monkeypatch.setattr(helpers, "php_eval", fake_php_eval)

    vm = _FakeVM(result=_FakeResult(returncode=1, stderr="cp: cannot stat 'snapshot': No such file"))
    with pytest.raises(RuntimeError, match=r"rc=1.*No such file"):
        helpers.restore_pfb_config_baseline(vm, snapshot_path=_SNAPSHOT_PATH)  # type: ignore[arg-type]
    assert php_eval_calls == [], f"php_eval must not run when the cp step failed, got calls={php_eval_calls!r}"


def test_restore_happy_path_with_pkg_installed_runs_steps_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    """(l) Happy path, package installed: cp, THEN services_unbound_configure (php_eval), THEN
    clearip/cleardnsbl, THEN a blocking apply_filter_sync -- the exact sequence
    reset_pfb_baseline uses for its own derived-state teardown, adapted to a byte restore."""
    trace: list[str] = []
    vm = _FakeVM(
        result=_FakeResult(returncode=0),
        results=[_FakeResult(returncode=0), _FakeResult(returncode=0), _FakeResult(returncode=0)],
    )
    real_ssh = vm.ssh

    def traced_ssh(*remote: str, timeout: float = 60.0) -> _FakeResult:
        trace.append(f"ssh:{remote}")
        return real_ssh(*remote, timeout=timeout)

    vm.ssh = traced_ssh  # type: ignore[method-assign]

    def fake_php_eval(v: object, snippet: str, *, timeout: float = 60.0) -> _FakeResult:
        assert v is vm, "php_eval must be called with the same vm"
        trace.append(f"php_eval:{snippet}")
        return _FakeResult(returncode=0, stdout="OK")

    def fake_pkg_installed(v: object, *, timeout: float = 30.0) -> bool:
        assert v is vm, "pkg_installed must be called with the same vm"
        trace.append("pkg_installed")
        return True

    def fake_apply_filter_sync(v: object, *, timeout: float = 60.0) -> None:
        assert v is vm, "apply_filter_sync must be called with the same vm"
        trace.append("apply_filter_sync")

    monkeypatch.setattr(helpers, "php_eval", fake_php_eval)
    monkeypatch.setattr(helpers, "pkg_installed", fake_pkg_installed)
    monkeypatch.setattr(helpers, "apply_filter_sync", fake_apply_filter_sync)

    helpers.restore_pfb_config_baseline(vm, snapshot_path=_SNAPSHOT_PATH)  # type: ignore[arg-type]

    assert len(trace) == 6, f"expected exactly 6 recorded steps, got trace={trace!r}"
    cp_call = trace[0]
    assert cp_call.startswith("ssh:"), f"first step must be the cp ssh call, got {cp_call!r}"
    assert _SNAPSHOT_PATH in cp_call, f"cp step must reference the snapshot path, got {cp_call!r}"
    assert "/conf/config.xml" in cp_call, f"cp step must target /conf/config.xml, got {cp_call!r}"
    assert "rm -f /tmp/config.cache" in cp_call, f"cp step must drop the config cache, got {cp_call!r}"

    php_eval_idx = next(i for i, e in enumerate(trace) if e.startswith("php_eval:"))
    assert "services_unbound_configure" in trace[php_eval_idx], (
        f"expected services_unbound_configure in the php_eval snippet, got {trace[php_eval_idx]!r}"
    )

    pkg_installed_idx = trace.index("pkg_installed")
    clearip_idx = next(i for i, e in enumerate(trace) if e.startswith("ssh:") and "clearip" in e)
    cleardnsbl_idx = next(i for i, e in enumerate(trace) if e.startswith("ssh:") and "cleardnsbl" in e)
    apply_filter_sync_idx = trace.index("apply_filter_sync")

    assert 0 < php_eval_idx < pkg_installed_idx < clearip_idx < cleardnsbl_idx < apply_filter_sync_idx, (
        f"expected cp < php_eval < pkg_installed < clearip < cleardnsbl < apply_filter_sync, got trace={trace!r}"
    )


def test_restore_skips_clearip_cleardnsbl_when_pkg_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    """(m) Package NOT installed (a prior test uninstalled it): NO clearip/cleardnsbl ssh calls
    are made (PFB_CLI no longer exists to shell out to), but apply_filter_sync still runs -- the
    same guard/rationale reset_pfb_baseline uses for its own derived-state clear."""
    apply_filter_sync_calls: list[object] = []

    def fake_php_eval(vm: object, snippet: str, *, timeout: float = 60.0) -> _FakeResult:
        return _FakeResult(returncode=0, stdout="OK")

    def fake_pkg_installed(vm: object, *, timeout: float = 30.0) -> bool:
        return False

    def fake_apply_filter_sync(vm: object, *, timeout: float = 60.0) -> None:
        apply_filter_sync_calls.append(vm)

    monkeypatch.setattr(helpers, "php_eval", fake_php_eval)
    monkeypatch.setattr(helpers, "pkg_installed", fake_pkg_installed)
    monkeypatch.setattr(helpers, "apply_filter_sync", fake_apply_filter_sync)

    vm = _FakeVM(result=_FakeResult(returncode=0))
    helpers.restore_pfb_config_baseline(vm, snapshot_path=_SNAPSHOT_PATH)  # type: ignore[arg-type]

    clear_calls = [c for c in vm.calls if "clearip" in c or "cleardnsbl" in c]
    assert clear_calls == [], f"expected no clearip/cleardnsbl ssh calls when pkg not installed, got {clear_calls!r}"
    assert len(apply_filter_sync_calls) == 1, (
        f"expected apply_filter_sync to still run once, got {len(apply_filter_sync_calls)} calls"
    )


@pytest.mark.parametrize(
    "eval_result",
    [
        _FakeResult(returncode=1, stdout="OK", stderr="pfSsh.php: syntax error"),
        _FakeResult(returncode=0, stdout="no sentinel here"),
    ],
    ids=["nonzero-rc", "rc-zero-missing-OK-sentinel"],
)
def test_restore_php_eval_failure_raises_and_skips_apply_filter_sync(
    monkeypatch: pytest.MonkeyPatch, eval_result: _FakeResult
) -> None:
    """(n) A failed services_unbound_configure eval -- either a non-zero pfSsh.php exit OR an
    'OK' sentinel missing from stdout -- raises RuntimeError and never reaches
    apply_filter_sync (a resolver reconfigure that did not actually succeed must not be
    followed by a filter sync as if it had)."""
    apply_filter_sync_calls: list[object] = []

    def fake_php_eval(vm: object, snippet: str, *, timeout: float = 60.0) -> _FakeResult:
        return eval_result

    def fake_apply_filter_sync(vm: object, *, timeout: float = 60.0) -> None:
        apply_filter_sync_calls.append(vm)

    monkeypatch.setattr(helpers, "php_eval", fake_php_eval)
    monkeypatch.setattr(helpers, "apply_filter_sync", fake_apply_filter_sync)

    vm = _FakeVM(result=_FakeResult(returncode=0))
    with pytest.raises(RuntimeError, match=r"restore_pfb_config_baseline"):
        helpers.restore_pfb_config_baseline(vm, snapshot_path=_SNAPSHOT_PATH)  # type: ignore[arg-type]
    assert apply_filter_sync_calls == [], (
        f"apply_filter_sync must not run after a failed php_eval, got calls={apply_filter_sync_calls!r}"
    )


# --------------------------------------------------------------------------- #
# ui-tests.yml `ui` job budget (issue #1689: two sampled cancellations at
# 30m18s/30m19s on the functional/plus-26.03 live-VM leg; identical commit
# passed on rerun in 20m04s). Pins the budget high enough to cover the
# observed leg, matching smoke-single.yml's live-VM precedent (45).
# --------------------------------------------------------------------------- #


def test_ui_job_budget_covers_live_vm_leg() -> None:
    """The `ui` job's ``timeout-minutes`` must be >= 45 -- the live-VM budget
    smoke-single.yml already uses -- so a slow-but-healthy leg (setup alone ran
    ~23 of the observed 20m04s pass) isn't cancelled mid-run."""
    workflow = (_REPO_ROOT / ".github/workflows/ui-tests.yml").read_text(encoding="utf-8")
    ui_job = extract_job(workflow, "ui")
    match = re.search(r"^\s*timeout-minutes:\s*(\S+)\s*$", ui_job, re.MULTILINE)
    assert match, f"expected a timeout-minutes key under the `ui` job, found none in:\n{ui_job[:200]}"

    raw = match.group(1)
    assert re.fullmatch(r"-?\d+", raw), f"expected an int timeout-minutes value, got {raw!r} (YAML wiring bug)"
    budget = int(raw)

    assert budget >= 45, (
        f"expected the `ui` job's timeout-minutes >= 45 (smoke-single.yml's live-VM budget), got {budget}"
    )
