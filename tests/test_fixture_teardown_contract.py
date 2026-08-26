"""Pin the failure-diagnostics contracts of the smoke suite's dump machinery.

Issue #774: ``tests/smoke/test_smoke_tick.py``'s ``mfs_var`` fixture captures
failure-time diagnostics in its own teardown, BEFORE its revert reboot wipes the MFS
/var — instead of leaving it to the autouse ``_dump_vm_on_failure``. That design is
only correct if two pytest behaviours hold:

1. A fixture requested by the test finalizes BEFORE an autouse fixture of the same scope
   (reverse setup order — autouse sets up first), so the autouse dump runs post-reboot,
   too late.
2. The ``pytest_runtest_makereport`` hookwrapper's stashed ``_rep_call`` is already
   readable inside fixture teardowns, so the requested fixture can see the failure.

Issue #777: a fixture that raises during ARRANGE means the test never reaches its call
phase, so ``_rep_call`` is never stashed — the failure signal is then the SETUP report.
``_failure_report`` in ``tests/smoke/conftest.py`` owns that call-then-setup fallback;
its branches are pinned here against the real function, and the pytest contract it
relies on (``_rep_setup`` stashed + readable at autouse teardown when arrange fails) is
pinned by its own pytester case.

If any contract changes in a future pytest, this test goes red and flags that the
smoke failure diagnostics are silently broken again.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from tests.smoke.conftest import _failure_report

pytest_plugins = ["pytester"]

_CONFTEST = """
import pytest


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    setattr(item, f"_rep_{rep.when}", rep)
"""

_TESTFILE = """
import pytest


@pytest.fixture(autouse=True)
def dump_on_failure(request):
    yield
    rep = getattr(request.node, "_rep_call", None)
    print(f"AUTOUSE-TEARDOWN failed={getattr(rep, 'failed', None)}")


@pytest.fixture
def mfs_like(request):
    yield
    rep = getattr(request.node, "_rep_call", None)
    print(f"MFS-TEARDOWN failed={getattr(rep, 'failed', None)}")


def test_fails(mfs_like):
    raise AssertionError("deliberate failure to exercise the teardown path")
"""


def test_requested_fixture_finalizes_first_and_sees_the_failure_report(pytester: pytest.Pytester) -> None:
    """mfs_var-style teardown runs before the autouse dump and can read the failed report."""
    pytester.makeconftest(_CONFTEST)
    pytester.makepyfile(_TESTFILE)

    result = pytester.runpytest("-s", "-q")

    # fnmatch_lines asserts the lines occur IN THIS ORDER (with full-output diagnostics
    # on mismatch): the requested fixture (mfs_var-style) finalizes before the autouse
    # dump, and both saw failed=True — the two contracts under pin. Wildcards keep the
    # match robust against pytest's progress-marker interleaving under -s.
    result.stdout.fnmatch_lines(
        [
            "*MFS-TEARDOWN failed=True*",
            "*AUTOUSE-TEARDOWN failed=True*",
        ]
    )


_SETUP_FAIL_TESTFILE = """
import pytest


@pytest.fixture(autouse=True)
def dump_on_failure(request):
    yield
    rep_call = getattr(request.node, "_rep_call", None)
    rep_setup = getattr(request.node, "_rep_setup", None)
    print(
        f"AUTOUSE-TEARDOWN call_absent={rep_call is None} "
        f"setup_failed={getattr(rep_setup, 'failed', None)}"
    )


@pytest.fixture
def arrange_fails():
    raise RuntimeError("deliberate arrange failure")
    yield


def test_never_reaches_call(arrange_fails):
    pass
"""


def test_arrange_failure_stashes_a_readable_setup_report(pytester: pytest.Pytester) -> None:
    """Fixture raises during arrange: no call report, but _rep_setup.failed is readable (issue #777)."""
    pytester.makeconftest(_CONFTEST)
    pytester.makepyfile(_SETUP_FAIL_TESTFILE)

    result = pytester.runpytest("-s", "-q")

    result.stdout.fnmatch_lines(["*AUTOUSE-TEARDOWN call_absent=True setup_failed=True*"])


def _node(**reps: Any) -> Any:
    """A minimal stand-in for a pytest node carrying stashed phase reports."""
    return SimpleNamespace(**reps)


def _rep(*, failed: bool = False, skipped: bool = False) -> Any:
    return SimpleNamespace(failed=failed, skipped=skipped)


def test_failure_report_call_failure_wins() -> None:
    """A failed call phase is the failure signal (the pre-#777 behaviour, preserved)."""
    rep = _rep(failed=True)
    assert _failure_report(_node(_rep_call=rep)) is rep


def test_failure_report_passed_call_is_no_failure() -> None:
    """A passed call phase means no dump — even if setup was somehow also stashed."""
    assert _failure_report(_node(_rep_call=_rep(failed=False), _rep_setup=_rep(failed=True))) is None


def test_failure_report_arrange_failure_falls_back_to_setup() -> None:
    """No call report + failed setup = a fixture arrange failure ⇒ dump (issue #777)."""
    rep = _rep(failed=True)
    assert _failure_report(_node(_rep_setup=rep)) is rep


def test_failure_report_arrange_skip_is_no_failure() -> None:
    """A setup SKIP (e.g. SMOKE_PKG unset) must not trigger a dump — failed is False."""
    assert _failure_report(_node(_rep_setup=_rep(skipped=True))) is None


def test_failure_report_no_reports_is_no_failure() -> None:
    """No stashed reports at all (nothing ran) ⇒ no dump."""
    assert _failure_report(_node()) is None
