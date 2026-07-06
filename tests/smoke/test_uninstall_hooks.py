"""ADR-12: the pre/post update hooks must fire during a real uninstall (``pkg delete``).

The pre-deinstall runs a full DISABLE pass so external consumers can reconfigure to the OFF
state, and #684 publishes ``PFB_PRE_UNINSTALL=1`` to those hooks. But nothing in the suite
asserts a hook actually RUNS during that pass: ``HookLifecycleCtxTest`` only unit-tests the
context helper's return value, ``test_smoke_hooks`` tests the normal cron/force update pass,
and ``test_pkg_op_teardown`` tests the teardown DECISION (owned objects removed) — the object
sweep lives in the pre-deinstall's own code AFTER the sync call, so it can pass while the
hooks inside the sync never fire.

This pins the missing behaviour end-to-end: install a ``pre`` and a ``post`` env-dump hook,
``pkg delete`` the package, and assert BOTH fired with ``PFB_PRE_UNINSTALL=1``.
"""

from __future__ import annotations

import pytest

from . import helpers as h

_PKG_NAME = "pfSense-pkg-pfBlockerNG-devel"


@pytest.mark.smoke
def test_uninstall_hooks_fire_with_pre_uninstall_context(smoke_vm) -> None:
    vm = smoke_vm

    # Fresh install so the pre-deinstall below is a genuine `pkg delete` teardown.
    h.deploy(vm)

    token = "uninst"
    # Given a pre + post hook are configured (env-dump to distinct /tmp markers)...
    h.set_update_hooks(vm, [h.env_dump_hook(token, "pre"), h.env_dump_hook(token, "post")])
    h.clear_hook_markers(vm, token)
    pre_marker = h.hook_marker_path(token, "pre")
    post_marker = h.hook_marker_path(token, "post")
    assert not h.hook_marker_exists(vm, pre_marker), "pre marker present before uninstall (stale state?)"
    assert not h.hook_marker_exists(vm, post_marker), "post marker present before uninstall (stale state?)"

    # When the package is genuinely removed (pkg delete -> pre-deinstall -> teardown disable pass)...
    res = vm.ssh("/bin/sh", "-c", f'env ASSUME_ALWAYS_YES=yes pkg delete -y "{_PKG_NAME}"', timeout=300)

    pre_env = h.read_hook_env(vm, pre_marker)
    post_env = h.read_hook_env(vm, post_marker)

    # Diagnostics: whether teardown even ran ("Removing pfBlockerNG" vs "Keeping pfBlockerNG
    # active"), and whether the runner logged its "[ pfB Hook ]" markers — pinpoints the break.
    log_lines = vm.ssh(
        "/usr/bin/grep", "-iE", "pfB Hook|Removing pfBlockerNG|Keeping pfBlockerNG active", h.PFB_LOG
    ).stdout
    diag = (
        f"\npkg delete rc={res.returncode}\nstdout:\n{res.stdout}\nstderr:\n{res.stderr}\n"
        f"pfB log (hook/teardown lines):\n{log_lines}\n{h.deinstall_debug(vm)}\n"
    )

    # Then both fire points ran, each carrying the uninstall lifecycle context.
    assert pre_env is not None, f"PRE uninstall hook did NOT fire (no marker).{diag}"
    assert post_env is not None, f"POST uninstall hook did NOT fire (no marker).{diag}"
    assert pre_env.get("PFB_PRE_UNINSTALL") == "1", f"pre hook missing PFB_PRE_UNINSTALL=1: {pre_env}{diag}"
    assert post_env.get("PFB_PRE_UNINSTALL") == "1", f"post hook missing PFB_PRE_UNINSTALL=1: {post_env}{diag}"
    assert pre_env.get("PFB_WHEN") == "pre", f"pre PFB_WHEN wrong: {pre_env}"
    assert post_env.get("PFB_WHEN") == "post", f"post PFB_WHEN wrong: {post_env}"
