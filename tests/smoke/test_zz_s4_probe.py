"""THROWAWAY live probe for #3455 S4 (never merged): what do pkg add, the legacy sender and the logs really do?"""

# ruff: noqa
from __future__ import annotations

import json
import os
import subprocess
import traceback
from pathlib import Path

import pytest

from . import ha_policy as hp
from . import helpers as h
from .ha_pair import SECONDARY_SYNC_IP, HaPair

pytestmark = pytest.mark.smoke

INC = "/usr/local/pkg/pfblockerng/pfblockerng.inc"
EXTRA = "/usr/local/pkg/pfblockerng/pfblockerng_extra.inc"


def show(tag, vm, cmd, timeout=120):
    r = vm.ssh(cmd, timeout=timeout)
    print(
        f"PROBE[{tag}] rc={r.returncode}\n--stdout--\n{r.stdout[-6000:]}\n--stderr--\n{r.stderr[-1500:]}\n", flush=True
    )
    return r


def ident(tag, vm):
    show(
        f"ident:{tag}",
        vm,
        "pkg query '%n-%v %t' -x pfBlockerNG; sha256 -q " + INC + "; "
        f'printf \'scope_migrate=%s receive_policy=%s\\n\' "$(grep -c pfb_sync_scope_migrate {EXTRA})" "$(grep -c pfb_sync_receive_policy {INC})"',
    )


def step(tag, fn):
    print(f"PROBE[{tag}] BEGIN", flush=True)
    try:
        out = fn()
        print(f"PROBE[{tag}] OK {out!r}"[:6000], flush=True)
        return out
    except BaseException as exc:  # noqa: BLE001
        print(
            f"PROBE[{tag}] FAILED {type(exc).__name__}: {str(exc)[:3000]}\n{traceback.format_exc()[-3000:]}", flush=True
        )
        return None


def force_add(vm, pkg, flag):
    key = vm.ssh_key_path
    remote = f"/tmp/{Path(pkg).name}"
    scp = subprocess.run(
        [
            "scp",
            "-i",
            key,
            "-P",
            str(vm.ssh_port),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            str(pkg),
            f"{vm.ssh_target}:{remote}",
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    print(f"PROBE[scp] rc={scp.returncode} {scp.stderr[-300:]}", flush=True)
    abi = os.environ.get("SMOKE_ABI", "")
    pre = f"pkg -o ABI='{abi}' add" if abi else "pkg add"
    show(f"pkg-add{flag}", vm, f"env ASSUME_ALWAYS_YES=yes {pre} {flag} {remote}", timeout=600)
    show(
        "unbound",
        vm,
        "for i in 1 2 3 4 5 6 7 8 9 10; do /usr/local/sbin/unbound-control -c /var/unbound/unbound.conf status >/dev/null 2>&1 && break; sleep 3; done; /usr/local/sbin/unbound-control -c /var/unbound/unbound.conf status | head -2",
    )
    show("cron", vm, "touch /var/db/pfblockerng/.pfb_cron_disable; ls -la /var/db/pfblockerng/.pfb_cron_disable")


def revisions(vm, n=6):
    show(
        "revisions",
        vm,
        "for f in $(ls -t /conf/backup/config-*.xml | head -"
        + str(n)
        + "); do printf '%s ' $f; grep -o '<description>[^<]*</description>' $f | head -1; done; "
        "grep -o '<revision>.*</revision>' /conf/config.xml | head -2; grep -A4 '<revision>' /conf/config.xml | head -8",
    )


@pytest.mark.timeout(3300)  # throwaway probe: several package switches and two sends
def test_probe(ha_pair: HaPair, prev_pkg: Path) -> None:
    a, b = ha_pair.primary, ha_pair.secondary
    branch = os.environ["SMOKE_PKG"]
    print(f"PROBE prev={prev_pkg} branch={branch}", flush=True)
    for t, vm in (("A", a), ("B", b)):
        ident(f"{t}0", vm)
    step(
        "logs-b0",
        lambda: show(
            "nginx-logs",
            b,
            "ls -la /var/log/nginx* /var/log/ 2>&1 | head -60; ls -la /var/etc/nginx* ; grep -n 'access_log\\|error_log\\|log_format' /var/etc/nginx-webConfigurator.conf",
        ),
    )
    step("baseline", lambda: hp.arrange_baseline(ha_pair))
    snap_b0 = step("snapshot-b0", lambda: hp.read_sections(b, ["pfblockernglistsv4", "pfblockerngipsettings"]))

    # --- 1. same-version redeploy via the harness's own deploy
    step("deploy-prev-plain-B", lambda: h.deploy(b, str(prev_pkg)))
    ident("B-after-plain-deploy-prev", b)
    show("sections-b", b, f"grep -c pfblockerng {hp.CONFIG}")

    # --- 2. forced add
    step("force-add-prev-B", lambda: force_add(b, prev_pkg, "-f"))
    ident("B-after-pkg-add-f-prev", b)
    show("sections-b2", b, f"grep -c pfblockerng {hp.CONFIG}")
    step("sections-b-after", lambda: json.dumps(hp.read_sections(b, ["pfblockernglistsv4"]))[:300])
    step("keep", lambda: hp.read_leaves(b, [hp.GEN + "/pfb_keep", hp.SYNC + "/syncscope", hp.SYNC + "/syncinterfaces"]))

    # --- 3. A to prev too, legacy sender
    step("force-add-prev-A", lambda: force_add(a, prev_pkg, "-f"))
    ident("A-after-pkg-add-f-prev", a)
    legacy = {
        "varsynconchanges": "manual",
        "varsynctimeout": "150",
        "syncinterfaces": "on",
        "row": [
            {
                "varsyncprotocol": "https",
                "varsyncipaddress": SECONDARY_SYNC_IP,
                "varsyncport": "443",
                "varsyncusername": "pfbhasync",
                "varsyncpassword": ha_pair.sync_password,
                "varsyncdestinenable": "on",
            }
        ],
    }
    step(
        "legacy-config-A",
        lambda: hp.set_leaves(a, {hp.SYNC: legacy}, "probe legacy sync", secret_values=[ha_pair.sync_password]),
    )
    step(
        "p-sync-sections",
        lambda: hp.php_json(a, hp.emit("array(pfblockerng_sync_sections(TRUE), pfblockerng_sync_sections(FALSE))")),
    )
    show("sysclear", a, ": > /var/log/system.log 2>/dev/null; echo cleared")
    revisions(b, 3)
    step("legacy-send", lambda: h.reload(a, "update", wait_unbound=False))
    show("A-pfb-log", a, "tail -n 40 /var/log/pfblockerng/pfblockerng.log")
    show(
        "A-system-log", a, "grep -i 'xmlrpc\\|sync' /var/log/system.log | tail -n 20; ls /var/db/pfblockerng | head -40"
    )
    revisions(b, 4)
    show("B-system-log", b, "grep -i 'xmlrpc\\|sync\\|merged' /var/log/system.log | tail -n 20")
    show("B-nginx", b, "ls -la /var/log/nginx* 2>&1 | head; tail -n 10 /var/log/nginx/*.log 2>&1 | tail -n 30")
    step("b-revision-cfg", lambda: hp.read_leaves(b, ["revision"]))
    step("b-lists-after", lambda: json.dumps(hp.read_sections(b, ["pfblockernglistsv4"]))[:600])

    # --- 4. upgrade A and B to branch (force add)
    def all_secs(vm):
        names = hp.php_json(
            vm,
            hp.emit(
                "array_values(array_filter(array_keys(config_get_path('installedpackages', array())), function ($n) { return strpos((string) $n, 'pfblockerng') === 0; }))"
            ),
        )
        return hp.read_sections(vm, names)

    def flat(tree, prefix=""):
        out = {}
        if isinstance(tree, dict) and tree:
            for k, v in tree.items():
                out.update(flat(v, f"{prefix}/{k}"))
        elif isinstance(tree, list) and tree:
            for i, v in enumerate(tree):
                out.update(flat(v, f"{prefix}/{i}"))
        else:
            out[prefix] = tree
        return out

    a_pre = step("a-all-pre-upgrade", lambda: {k: flat(v, k) for k, v in all_secs(a).items()})
    b_pre = step("b-all-pre-upgrade", lambda: {k: flat(v, k) for k, v in all_secs(b).items()})
    for t, vm in (("A", a), ("B", b)):
        step(f"force-add-branch-{t}", lambda vm=vm: force_add(vm, branch, "-f"))
        ident(f"{t}-after-pkg-add-f-branch", vm)
    step(
        "migrated-A",
        lambda: hp.read_leaves(
            a,
            [hp.SYNC + "/syncscope", hp.SYNC + "/syncinterfaces", hp.SYNC + "/varsynconchanges", hp.GEN + "/pfb_keep"],
        ),
    )

    def delta(pre, vm, tag):
        post = {k: flat(v, k) for k, v in all_secs(vm).items()}
        flatpre = {p: v for sec in pre.values() for p, v in sec.items()}
        flatpost = {p: v for sec in post.values() for p, v in sec.items()}
        d = hp.diff_leaves(flatpre, flatpost)
        print(f"PROBE[delta-{tag}] sections pre={sorted(pre)} post={sorted(post)}", flush=True)
        return json.dumps(d)[:5000]

    step("a-upgrade-delta", lambda: delta(a_pre, a, "A"))
    step("b-upgrade-delta", lambda: delta(b_pre, b, "B"))
    step("sync2", lambda: h.reload(a, "update", wait_unbound=False))
    show("A-send-record", a, f"cat {hp.SEND_FILE}")
    show("B-recv-record", b, f"cat {hp.RECEIVE_FILE} 2>&1")
    revisions(b, 4)

    # --- 5. new (policy) -> B on prev
    step("force-add-prev-B2", lambda: force_add(b, prev_pkg, "-f"))
    ident("B-prev-again", b)
    step("cfg-policy", lambda: hp.configure_sender(ha_pair, "manual", scope="policy"))
    step("whitelist-A", lambda: hp.set_leaves(a, {hp.DNSBL + "/whitelist": "cGZiaC1wcm9iZS5jb20K"}, "probe whitelist"))
    before_b = step(
        "b-before", lambda: hp.read_sections(b, ["pfblockerng", "pfblockerngdnsblsettings", "pfblockernglistsv4"])
    )
    revisions(b, 3)
    step("policy-send", lambda: h.reload(a, "update", wait_unbound=False))
    show("A-send-record2", a, f"cat {hp.SEND_FILE}")
    show(
        "A-pfb-log2",
        a,
        "tail -n 25 /var/log/pfblockerng/pfblockerng.log; grep -i 'xmlrpc\\|sync' /var/log/system.log | tail -n 10",
    )
    revisions(b, 4)
    after_b = step(
        "b-after", lambda: hp.read_sections(b, ["pfblockerng", "pfblockerngdnsblsettings", "pfblockernglistsv4"])
    )
    print(f"PROBE b sections identical after policy send: {before_b == after_b}", flush=True)
    show("B-nginx2", b, "ls -la /var/log/nginx* 2>&1 | head; tail -n 10 /var/log/nginx/*.log 2>&1 | tail -n 30")
    show("B-system-log2", b, "grep -i 'xmlrpc\\|sync\\|merged' /var/log/system.log | tail -n 20")

    # --- 6. automatic transport new -> prev
    step("cfg-auto", lambda: hp.configure_sender(ha_pair, "automatic", scope="policy"))
    show(
        "A-fsync",
        a,
        "/etc/rc.filter_synchronize 2>&1 | tail -n 5; grep -i 'xmlrpc\\|sync' /var/log/system.log | tail -n 15",
        timeout=400,
    )
    revisions(b, 4)
    after_b2 = step(
        "b-after-auto", lambda: hp.read_sections(b, ["pfblockerng", "pfblockerngdnsblsettings", "pfblockernglistsv4"])
    )
    print(f"PROBE b sections identical after auto send: {before_b == after_b2}", flush=True)

    # --- restore
    for t, vm in (("B", b), ("A", a)):
        step(f"restore-branch-{t}", lambda vm=vm: force_add(vm, branch, "-f"))
        ident(f"{t}-restored", vm)
    pytest.fail("probe done (deliberate: surfaces the captured output)")
