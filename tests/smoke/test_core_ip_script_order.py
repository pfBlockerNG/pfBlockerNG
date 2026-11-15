"""#3977: native IPv4/IPv6 cross-group list-script ordering acceptance."""

from __future__ import annotations

import json
import shlex

import pytest

from . import helpers as h
from .conftest import SmokeVM
from .test_core_feedphase_repairs import (
    _install_list_script,
    _restored_case,
    _write_guest,
)
from .test_core_update import DB, _assert_feed_disposition, _run_update, await_idle
from .test_core_update import core_vm as core_vm

pytestmark = pytest.mark.smoke


def _set_ip_group_scripts(vm: SmokeVM, root: str, scripts: dict[str, tuple[str, str]]) -> None:
    rows = ",".join(
        f"{h._php_str(alias)}=>array({h._php_str(pre)},{h._php_str(post)})" for alias, (pre, post) in scripts.items()
    )
    result = h.php_eval(
        vm,
        "$wanted=array(" + rows + ");"
        f"$groups=config_get_path({h._php_str(root)},array());"
        "foreach($groups as &$group){$name=(string)($group['aliasname']??'');"
        "if(isset($wanted[$name])){$group['script_pre']=$wanted[$name][0];"
        "$group['script_post']=$wanted[$name][1];}}unset($group);"
        f"config_set_path({h._php_str(root)},$groups);"
        "write_config('pfBlockerNG smoke: native IP list scripts');echo 'OK';",
    )
    assert result.returncode == 0 and "OK" in result.stdout, f"script config failed: {result}"
    h.tell_core_the_settings_changed(vm)


@pytest.mark.timeout(1200)
@pytest.mark.parametrize(
    ("family", "phase_family", "suffix", "first", "previous", "current"),
    (
        ("v4", "ipv4", "_v4", "198.51.100.200", "198.51.100.201", "198.51.100.202"),
        ("v6", "ipv6", "_v6", "2001:db8::200", "2001:db8::201", "2001:db8::202"),
    ),
    ids=("ipv4", "ipv6"),
)
def test_native_ip_two_feed_scripts_preserve_cross_group_side_effect_order(
    core_vm: SmokeVM,
    family: str,
    phase_family: str,
    suffix: str,
    first: str,
    previous: str,
    current: str,
) -> None:
    """Feed 2 must parse the local source generated synchronously by feed 1 post."""
    vm = core_vm
    with _restored_case(vm) as (token, owned, status_aliases):
        await_idle(vm)
        h1, h2 = f"ipone{token}", f"iptwo{token}"
        a1, a2 = f"ipfirst{token}", f"ipsecond{token}"
        source1 = h.write_local_feed(vm, f"{h1}-{family}.source", first + "\n")
        owned.append(source1)
        source2 = h.write_local_feed(vm, f"{h2}-{family}.source", previous + "\n")
        owned.append(source2)
        trace = f"{DB}/repair-ip-script-{token}-{family}.trace"
        owned.append(trace)
        _write_guest(vm, trace, "")

        qtrace = shlex.quote(trace)
        qsource2 = shlex.quote(source2)
        pre_name = f"ip_pre_repair_{token}_{family}.sh"
        post_name = f"ip_post_repair_{token}_{family}.sh"
        _install_list_script(
            vm,
            owned,
            pre_name,
            f'#!/bin/sh\nset -eu\n[ "$#" -eq 2 ] && [ -f "$1" ] && [ "$2" = {suffix} ] || exit 91\n'
            f"if /usr/bin/grep -q '^pre1$' {qtrace}; then n=2; else n=1; fi\n"
            f"printf 'pre%s\\n' \"$n\" >> {qtrace}\n",
        )
        _install_list_script(
            vm,
            owned,
            post_name,
            f'#!/bin/sh\nset -eu\n[ "$#" -eq 2 ] && [ -f "$1" ] && [ "$2" = {suffix} ] || exit 92\n'
            f'case "$1" in *{h1}{suffix}.orig) n=1;; *{h2}{suffix}.orig) n=2;; *) exit 93;; esac\n'
            f"printf 'post%s\\n' \"$n\" >> {qtrace}\n"
            f"[ \"$n\" -ne 1 ] || printf '%s\\n' {shlex.quote(current)} > {qsource2}\n",
        )

        first_case = h.IpCase(aliasname=a1, header=h1, feed_url=source1, family=family)
        second_case = h.IpCase(aliasname=a2, header=h2, feed_url=source2, family=family)
        status_aliases.extend(((phase_family, a1), (phase_family, a2)))
        h.inject_ip_lists(vm, [first_case, second_case])
        root = h.CFG_IP_V4_LISTS if family == "v4" else h.CFG_IP_V6_LISTS
        _set_ip_group_scripts(vm, root, {a1: (pre_name, post_name), a2: (pre_name, post_name)})

        update, log = _run_update(vm, "manual", "ip")
        assert update["result"] == "success", update
        assert vm.ssh("cat", trace).stdout == "pre1\npost1\npre2\npost2\n"
        for header in (h1, h2):
            _assert_feed_disposition(log, f"{phase_family}:{header}{suffix}", "changed")

        action = f"{DB}/deny/{h2}{suffix}.txt"
        result = vm.ssh("cat", action)
        assert result.returncode == 0, f"cannot read feed 2 action {action}: {result.stderr}"
        assert result.stdout == current + "\n", (
            f"feed 2 action did not use feed 1's generated source: {json.dumps(result.stdout)}"
        )
        members = h.pfctl_table_members(vm, second_case.alias)
        assert h.member_present(members, current), f"current member missing from {second_case.alias}: {members}"
        assert not h.member_present(members, previous), f"previous member survived in {second_case.alias}: {members}"
