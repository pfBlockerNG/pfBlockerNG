"""Pin the pytest contracts the mfs_var pre-reboot failure dump relies on (issue #774).

``tests/smoke/test_smoke_tick.py``'s ``mfs_var`` fixture captures failure-time
diagnostics in its own teardown, BEFORE its revert reboot wipes the MFS /var — instead
of leaving it to the autouse ``_dump_vm_on_failure``. That design is only correct if two
pytest behaviours hold:

1. A fixture requested by the test finalizes BEFORE an autouse fixture of the same scope
   (reverse setup order — autouse sets up first), so the autouse dump runs post-reboot,
   too late.
2. The ``pytest_runtest_makereport`` hookwrapper's stashed ``_rep_call`` is already
   readable inside fixture teardowns, so the requested fixture can see the failure.

If either contract changes in a future pytest, this test goes red and flags that the
tick failure diagnostics are silently broken again.
"""

from __future__ import annotations

import pytest

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
