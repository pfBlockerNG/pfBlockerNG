"""Issue #3454: two-node pfSense HA smoke topology — hermetic contract of the harness.

The live proof is ``tests/smoke/test_ha_topology.py`` (two real guests). Everything here runs
off-box: the guests are in-process fakes behind the ``SmokeVM.ssh`` / ``helpers.php_eval`` /
``helpers.apply_filter_sync`` seams, so lane ports, the peer MAC, the boot env, secret handling
and the restore guarantees are pinned without a VM.
"""

from __future__ import annotations

import importlib
import io
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, cast

import pytest

import tests.smoke as smoke_pkg
from tests.smoke import conftest as smoke_conftest

BASELINE = "/root/pfb-smoke-ha-baseline.xml"

# Lane-0 value of every port the HA pair adds; each moves by one stride (10) per lane.
LANE0_NEW_PORTS = {
    "DEFAULT_PEER_SSH_PORT": 2227,
    "DEFAULT_PEER_WEB_PORT": 8085,
    "DEFAULT_PEER_LAN_SOCKET_PORT": 12345,
    "DEFAULT_SYNC_PORT": 12343,
    "DEFAULT_PEER_SYNC_PORT": 12344,
}
LANE_SERIES = (
    "DEFAULT_SSH_PORT",
    "DEFAULT_WEB_PORT",
    "DEFAULT_DNS_PORT",
    "DEFAULT_CLIENT_SSH_PORT",
    "DEFAULT_LAN_SOCKET_PORT",
)
LANE_ENV_DEFAULTS = (
    ("SMOKE_SSH_HOSTPORT", "2222"),
    ("SMOKE_WEB_HOSTPORT", "8080"),
    ("SMOKE_CLIENT_SSH_HOSTPORT", "2223"),
    ("SMOKE_LAN_SOCKET_PORT", "12340"),
)


@pytest.fixture
def ha() -> ModuleType:
    return importlib.import_module("tests.smoke.ha_pair")


def _conftest_at_lane(monkeypatch: pytest.MonkeyPatch, lane: int) -> ModuleType:
    """Fresh ``tests.smoke.conftest`` import at ``lane``; env and sys.modules restored at teardown."""
    for key, default in LANE_ENV_DEFAULTS:
        monkeypatch.setenv(key, default)  # conftest writes these back at import; setenv records the originals
    monkeypatch.setenv("SMOKE_LANE", str(lane))
    monkeypatch.setitem(sys.modules, "tests.smoke.conftest", smoke_conftest)
    monkeypatch.setattr(smoke_pkg, "conftest", smoke_conftest)  # the import rebinds the package attribute too
    sys.modules.pop("tests.smoke.conftest")
    return importlib.import_module("tests.smoke.conftest")


# --------------------------------------------------------------------------- #
# Lane ports
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("lane", [0, 1])
def test_peer_and_sync_ports_sit_inside_the_lane_block(monkeypatch: pytest.MonkeyPatch, lane: int) -> None:
    for key in ("SMOKE_SYNC_PORT", "SMOKE_SYNC_PEER_PORT"):
        monkeypatch.delenv(key, raising=False)

    mod = _conftest_at_lane(monkeypatch, lane)

    for name, lane0 in LANE0_NEW_PORTS.items():
        assert getattr(mod, name) == lane0 + 10 * lane, f"{name} at lane {lane}: expected {lane0 + 10 * lane}"
    for key in ("SMOKE_SYNC_PORT", "SMOKE_SYNC_PEER_PORT"):
        assert key not in os.environ, f"{key} must not be written at import: one-node boots stay unchanged"


def test_peer_and_sync_ports_never_collide_with_any_lane_series(monkeypatch: pytest.MonkeyPatch) -> None:
    ports: list[int] = []
    for lane in range(33):
        mod = _conftest_at_lane(monkeypatch, lane)
        ports += [getattr(mod, name) for name in (*LANE_SERIES, *LANE0_NEW_PORTS)]

    duplicates = sorted({p for p in ports if ports.count(p) > 1})
    assert not duplicates, f"ports shared between lanes/series: {duplicates}"


# --------------------------------------------------------------------------- #
# Sync env: only sessions that collect an ha_pair test boot the UDP link
# --------------------------------------------------------------------------- #


def _item(*fixturenames: str) -> Any:
    return SimpleNamespace(fixturenames=list(fixturenames))


def test_one_node_sessions_get_no_sync_env() -> None:
    items = [_item("smoke_vm"), _item("smoke_vm", "client_vm", "lan_interface")]

    assert smoke_conftest._ha_sync_env(items) == {}
    assert not smoke_conftest._needs_ha_pair(["smoke_vm", "client_vm"])


def test_a_session_collecting_ha_pair_gets_the_lane_sync_ports() -> None:
    items = [_item("smoke_vm"), _item("smoke_vm", "peer_vm", "ha_pair")]

    assert smoke_conftest._needs_ha_pair(["smoke_vm", "peer_vm", "ha_pair"])
    assert smoke_conftest._ha_sync_env(items) == {
        "SMOKE_SYNC_PORT": str(smoke_conftest.DEFAULT_SYNC_PORT),
        "SMOKE_SYNC_PEER_PORT": str(smoke_conftest.DEFAULT_PEER_SYNC_PORT),
    }


# --------------------------------------------------------------------------- #
# Peer MAC: identical hardware profile except the sync NIC
# --------------------------------------------------------------------------- #


def test_ce_default_macs_are_pinned_to_boot_vm_sh() -> None:
    script = Path(smoke_conftest.BOOT_VM_SH).read_text()
    block = re.search(r'DEFAULT_CE_MAC="\$\(printf .*?\)"', script, re.DOTALL)

    assert block, "boot_vm.sh no longer defines DEFAULT_CE_MAC the way the harness pins it"
    assert tuple(re.findall(r"[0-9A-F]{2}(?::[0-9A-F]{2}){5}", block.group(0))) == smoke_conftest._CE_DEFAULT_MACS


def test_peer_mac_replaces_only_the_sync_nic(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SMOKE_VM_MAC", raising=False)

    macs = smoke_conftest._peer_vm_mac().split("\n")

    expected = list(smoke_conftest._CE_DEFAULT_MACS)
    expected[3] = smoke_conftest.PEER_SYNC_MAC
    assert macs == expected
    assert smoke_conftest.PEER_SYNC_MAC not in smoke_conftest._CE_DEFAULT_MACS, (
        "the two sync-link ends would share a MAC"
    )


def test_peer_mac_honours_a_custom_mac_list(monkeypatch: pytest.MonkeyPatch) -> None:
    custom = [f"AA:BB:CC:00:00:0{i}" for i in range(8)]
    monkeypatch.setenv("SMOKE_VM_MAC", "\n".join(custom))

    macs = smoke_conftest._peer_vm_mac().split("\n")

    assert macs == [*custom[:3], smoke_conftest.PEER_SYNC_MAC, *custom[4:]]


def test_peer_mac_refuses_a_list_without_a_sync_nic(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SMOKE_VM_MAC", "AA:BB:CC:00:00:00\nAA:BB:CC:00:00:01\nAA:BB:CC:00:00:02")

    with pytest.raises(RuntimeError, match="SMOKE_VM_MAC"):
        smoke_conftest._peer_vm_mac()


def test_peer_boot_env_gives_node_b_its_own_ports_and_the_mirror_image_of_node_as_sync_link(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SMOKE_VM_MAC", raising=False)
    expected = {
        "SMOKE_SSH_HOSTPORT": str(smoke_conftest.DEFAULT_PEER_SSH_PORT),
        "SMOKE_WEB_HOSTPORT": str(smoke_conftest.DEFAULT_PEER_WEB_PORT),
        "SMOKE_LAN_SOCKET_PORT": str(smoke_conftest.DEFAULT_PEER_LAN_SOCKET_PORT),
        "SMOKE_SYNC_PORT": str(smoke_conftest.DEFAULT_PEER_SYNC_PORT),
        "SMOKE_SYNC_PEER_PORT": str(smoke_conftest.DEFAULT_SYNC_PORT),
        "SMOKE_VM_MAC": smoke_conftest._peer_vm_mac(),
    }

    env = smoke_conftest._peer_boot_env()

    assert env == expected
    node_a = smoke_conftest._ha_sync_env([_item("ha_pair")])
    assert (env["SMOKE_SYNC_PORT"], env["SMOKE_SYNC_PEER_PORT"]) == (
        node_a["SMOKE_SYNC_PEER_PORT"],
        node_a["SMOKE_SYNC_PORT"],
    ), f"the two ends of the sync link must mirror each other: A={node_a} B={env}"


# --------------------------------------------------------------------------- #
# boot_and_probe: extra_env reaches the qemu wrapper, and only when asked
# --------------------------------------------------------------------------- #


def _booted_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, **kwargs: Any) -> dict[str, str]:
    """Run boot_and_probe against fakes and return the env boot_vm.sh would have been spawned with."""
    live_helpers = importlib.import_module("tests.smoke.helpers")
    captured: dict[str, str] = {}

    class FakeProcess:
        pid = 1234

        def poll(self) -> None:
            return None

    def fake_popen(*args: Any, **popen_kwargs: Any) -> FakeProcess:
        captured.update(popen_kwargs["env"])
        return FakeProcess()

    def fake_run(argv: list[str], **run_kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 0, "boot-to-ready: 1 second\n", "")

    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setattr(smoke_conftest.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(smoke_conftest.subprocess, "run", fake_run)
    monkeypatch.setattr(live_helpers, "wait_boot_complete", lambda vm: None)
    monkeypatch.setattr(live_helpers, "_write_cron_disable_flag", lambda vm: None)
    monkeypatch.setattr(smoke_conftest, "_log_guest_identity", lambda vm: None)

    handle = smoke_conftest.boot_and_probe(Path("base.qcow2"), "key", log_path=tmp_path / "vm.log", **kwargs)
    handle.log_file.close()
    return captured


def test_boot_and_probe_without_extra_env_adds_no_sync_keys(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for key in ("SMOKE_SYNC_PORT", "SMOKE_SYNC_PEER_PORT"):
        monkeypatch.delenv(key, raising=False)

    env = _booted_env(monkeypatch, tmp_path)

    assert not [k for k in env if k.startswith("SMOKE_SYNC_")], f"unexpected sync keys in boot env: {sorted(env)}"
    assert "QMP_SOCK" in env, f"boot env lost QMP_SOCK: {sorted(env)}"


def test_boot_and_probe_passes_extra_env_through_to_the_boot_script(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    extra = {"SMOKE_SYNC_PORT": "12343", "SMOKE_SYNC_PEER_PORT": "12344"}

    env = _booted_env(monkeypatch, tmp_path, extra_env=extra)

    assert {k: env.get(k) for k in extra} == extra
    assert "QMP_SOCK" in env, f"boot env lost QMP_SOCK: {sorted(env)}"


def test_boot_and_probe_extra_env_wins_over_the_inherited_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SMOKE_SSH_HOSTPORT", "2222")

    env = _booted_env(monkeypatch, tmp_path, extra_env={"SMOKE_SSH_HOSTPORT": "9"})

    assert env["SMOKE_SSH_HOSTPORT"] == "9", f"expected extra_env to override the inherited 2222, got {env!r}"


# --------------------------------------------------------------------------- #
# In-process guests for the ha_pair module
# --------------------------------------------------------------------------- #


class FakeNode(smoke_conftest.SmokeVM):
    """A guest that records what the harness sent it and answers from a tiny state machine."""

    def __init__(
        self,
        name: str,
        *,
        baseline: bool = False,
        fail_php: str | None = None,
        fatal_php: str | None = None,
        interrupt_php: str | None = None,
        fail_ssh: str | None = None,
        interrupt_snapshot: bool = False,
        busy: list[str] | None = None,
        verify: dict[str, Any] | None = None,
        ifconfig: str = "",
        xmlrpc_out: str = "",
    ) -> None:
        super().__init__(ssh_key_path="key")
        self.name = name
        self.files: set[str] = {BASELINE} if baseline else set()
        self.fail_php = fail_php
        self.fatal_php = fatal_php
        self.interrupt_php = interrupt_php
        self.fail_ssh = fail_ssh
        self.interrupt_snapshot = interrupt_snapshot
        self.busy = busy or []
        self.verify = verify or {"protocol": "http", "opt2": False}
        self.ifconfig = ifconfig
        self.xmlrpc_out = xmlrpc_out
        self.ssh_calls: list[str] = []
        self.snippets: list[str] = []

    @property
    def baseline(self) -> bool:
        return BASELINE in self.files

    def ssh(self, *remote: str, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
        cmd = remote[0] if len(remote) == 1 else shlex.join(remote)
        self.ssh_calls.append(cmd)
        if self.fail_ssh and self.fail_ssh in cmd:
            return subprocess.CompletedProcess(remote, 1, "", f"{self.fail_ssh}: I/O error")
        if "echo present" in cmd:
            return subprocess.CompletedProcess(remote, 0, "present\n" if self.baseline else "absent\n", "")
        # Shell chain semantics: `a && b` skips b after a failure, `a ; b` runs it regardless.
        steps = re.split(r"\s*(&&|;)\s*", cmd)
        result = self._run(steps[0])
        for i in range(1, len(steps), 2):
            if steps[i] == ";" or result.returncode == 0:
                result = self._run(steps[i + 1])
        return subprocess.CompletedProcess(remote, result.returncode, result.stdout, result.stderr)

    def _run(self, step: str) -> subprocess.CompletedProcess[str]:
        """One simple guest command: only the file operations the harness depends on have effects."""
        argv = shlex.split(step)
        ok = subprocess.CompletedProcess(argv, 0, "", "")
        if argv[:2] == ["cp", "-p"]:
            src, dst = argv[2:4]
            if src != "/conf/config.xml" and src not in self.files:
                return subprocess.CompletedProcess(argv, 1, "", f"{src}: No such file or directory")
            self.files.add(dst)
            if self.interrupt_snapshot and src == "/conf/config.xml":
                # The link drops mid-copy: the destination exists, truncated.
                return subprocess.CompletedProcess(argv, 255, "", "connection lost")
        elif argv[:1] == ["mv"]:
            src, dst = argv[1:3]
            if src not in self.files:
                return subprocess.CompletedProcess(argv, 1, "", f"{src}: No such file or directory")
            self.files.discard(src)
            self.files.add(dst)
        elif argv[:2] == ["rm", "-f"]:
            self.files.difference_update(argv[2:])
        elif argv[:1] == ["ifconfig"]:
            return subprocess.CompletedProcess(argv, 0, self.ifconfig, "")
        return ok

    def php(self, snippet: str) -> subprocess.CompletedProcess[str]:
        self.snippets.append(snippet)
        if self.interrupt_php and self.interrupt_php in snippet:
            raise KeyboardInterrupt
        if self.fatal_php and self.fatal_php in snippet:
            return subprocess.CompletedProcess(
                [], 0, "PHP Fatal error:  Uncaught Error: Call to undefined function", ""
            )
        if self.fail_php and self.fail_php in snippet:
            # Worst case: the shell echoes the whole program (secrets included) into its error output.
            return subprocess.CompletedProcess([], 1, f"PHP Fatal error in:\n{snippet}", "boom")
        if "<<<HABUSY>>>" in snippet:
            out = f"banner <<<HABUSY>>>{json.dumps(self.busy)}<<<END>>>"
        elif "<<<HARESTORE>>>" in snippet:
            out = f"<<<HARESTORE>>>{json.dumps(self.verify)}<<<END>>>"
        elif "<<<HAXMLRPC>>>" in snippet:
            out = self.xmlrpc_out
        else:
            out = "OK"
        return subprocess.CompletedProcess([], 0, out, "")


@pytest.fixture
def seams(ha: ModuleType, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Route the pfSsh and filter-reload seams to the fakes; returns the nodes that reloaded their filter."""
    reloaded: list[str] = []
    monkeypatch.setattr(ha.helpers, "php_eval", lambda vm, snippet, **kw: vm.php(snippet))
    monkeypatch.setattr(ha.helpers, "apply_filter_sync", lambda vm, **kw: reloaded.append(vm.name))
    return reloaded


@pytest.fixture
def tokens(ha: ModuleType, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Deterministic, recognisable generated secrets; returns the ones issued so far."""
    issued: list[str] = []

    def fake_token_urlsafe(nbytes: int = 32) -> str:
        issued.append(f"NEEDLE{len(issued)}x9f")
        return issued[-1]

    monkeypatch.setattr(ha.secrets, "token_urlsafe", fake_token_urlsafe)
    return issued


# --------------------------------------------------------------------------- #
# Setup failures: stage/node labelled, secret-free, and the pair is put back
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("failing_node", "marker", "stage"),
    [
        ("secondary", "bcrypt-hash", "users"),
        ("primary", "config_set_path('interfaces/opt2'", "sync-interface"),
        ("primary", "config_set_path('hasync'", "hasync"),
    ],
)
def test_setup_failure_names_node_and_stage_leaks_no_secret_and_restores_both_nodes(
    ha: ModuleType, seams: list[str], tokens: list[str], failing_node: str, marker: str, stage: str
) -> None:
    nodes = {
        "primary": FakeNode("primary", fail_php=marker if failing_node == "primary" else None),
        "secondary": FakeNode("secondary", fail_php=marker if failing_node == "secondary" else None),
    }

    with pytest.raises(ha.HaSetupError) as caught:
        with ha.ha_pair_session(nodes["primary"], nodes["secondary"]):
            pytest.fail("the session must not yield after a setup failure")

    text = str(caught.value)
    assert f"node={failing_node} stage={stage}" in text, f"expected node={failing_node} stage={stage} in: {text}"
    assert len(tokens) == 3, f"expected 3 generated secrets (sync, nopriv, carp), got {tokens}"
    failing_snippet = next(s for s in nodes[failing_node].snippets if marker in s)
    assert any(t in failing_snippet for t in tokens), "the failing program must have carried a secret (non-vacuous)"
    for token in tokens:
        assert token not in text, f"generated secret leaked into the setup error: {text}"
        assert not [c for n in nodes.values() for c in n.ssh_calls if token in c], "secret travelled in an ssh argv"
    for name, node in nodes.items():
        assert any("echo present" in c for c in node.ssh_calls), f"restore was not attempted on {name}"
        assert not node.baseline, f"{name} still holds its baseline: it was not restored"


def test_secondary_is_restored_before_primary_on_exit(ha: ModuleType, seams: list[str], tokens: list[str]) -> None:
    a, b = FakeNode("primary"), FakeNode("secondary")

    with ha.ha_pair_session(a, b) as pair:
        assert (pair.primary, pair.secondary) == (a, b)
        assert a.baseline and b.baseline, "both nodes must be snapshotted before the pair is yielded"
        assert not any(t in repr(pair) for t in tokens), "the pair's repr must not print its secrets"

    assert not a.baseline and not b.baseline, f"baselines left behind: primary={a.baseline} secondary={b.baseline}"
    assert seams == ["primary", "secondary", "secondary", "primary"]


def test_node_that_already_holds_a_baseline_is_refused_not_overwritten(ha: ModuleType, seams: list[str]) -> None:
    node = FakeNode("primary", baseline=True)

    with pytest.raises(ha.HaSetupError, match=r"node=primary stage=snapshot"):
        ha.configure_node(node, "primary", sync_ip=ha.PRIMARY_SYNC_IP, advskew="0", carp_password="carp")

    assert "cp -p /conf/config.xml" not in " ".join(node.ssh_calls), "a leftover baseline must never be overwritten"


def test_node_whose_sync_nic_is_already_assigned_is_refused_untouched(ha: ModuleType, seams: list[str]) -> None:
    node = FakeNode("secondary", busy=["opt2"])

    with pytest.raises(ha.HaSetupError, match=r"node=secondary stage=sync-interface"):
        ha.configure_node(node, "secondary", sync_ip=ha.SECONDARY_SYNC_IP, advskew="100", carp_password="carp")

    assert not [s for s in node.snippets if "config_set_path('interfaces/opt2'" in s], "interfaces were mutated"


def test_secondary_users_are_hand_built_and_only_the_ha_user_holds_the_privilege(
    ha: ModuleType, seams: list[str]
) -> None:
    node = FakeNode("secondary")

    ha.configure_secondary_users(node, "sync-pw", "nopriv-pw")

    (snippet,) = node.snippets
    assert "local_user_set" not in snippet, "local_user_set_password() stores the hash under the wrong key on CE 2.8"
    assert "PASSWORD_BCRYPT" in snippet and "bcrypt-hash" in snippet, f"users are not hash-written directly: {snippet}"
    assert snippet.count("system-xmlrpc-ha-sync") == 1, "exactly one user may hold the HA sync privilege"
    assert "'sync-pw'" in snippet and "'nopriv-pw'" in snippet, f"passwords not PHP-quoted in: {snippet}"
    assert not [c for c in node.ssh_calls if "sync-pw" in c or "nopriv-pw" in c], "secret travelled in an ssh argv"


# --------------------------------------------------------------------------- #
# restore_node: every step runs, failures are named, baseline-less nodes untouched
# --------------------------------------------------------------------------- #


def test_restore_node_runs_later_steps_after_a_failure_and_names_the_failed_one(
    ha: ModuleType, seams: list[str]
) -> None:
    node = FakeNode("primary", baseline=True, fail_php="interface_bring_down")

    with pytest.raises(RuntimeError) as caught:
        ha.restore_node(node, "primary")

    text = str(caught.value)
    assert "node=primary" in text and "runtime-teardown" in text, f"failed step not named: {text}"
    for succeeded in ("config-restore", "sshguard-flush", "webgui-restart", "filter-reload", "verify"):
        assert succeeded not in text, f"step {succeeded} did not fail but is named: {text}"
    assert not node.baseline, "the baseline copy-back must still run after the teardown step failed"
    assert "pfctl -t sshguard -T flush" in node.ssh_calls, f"sshguard not flushed; ssh calls: {node.ssh_calls}"
    assert "/etc/rc.restart_webgui" in node.ssh_calls, f"webgui not restarted; ssh calls: {node.ssh_calls}"
    assert seams == ["primary"]
    assert any("<<<HARESTORE>>>" in s for s in node.snippets), "the read-back verification must still run"


def test_restore_node_fails_loudly_when_the_read_back_shows_the_ha_config_survived(
    ha: ModuleType, seams: list[str]
) -> None:
    node = FakeNode("secondary", baseline=True, verify={"protocol": "https", "opt2": True})

    with pytest.raises(RuntimeError) as caught:
        ha.restore_node(node, "secondary")

    text = str(caught.value)
    assert "node=secondary" in text and "verify" in text, f"verify failure not reported: {text}"
    assert "runtime-teardown" not in text, f"teardown did not fail but is named: {text}"


def test_restore_node_on_a_node_without_a_baseline_does_nothing(ha: ModuleType, seams: list[str]) -> None:
    node = FakeNode("primary", baseline=False)

    ha.restore_node(node, "primary")

    assert len(node.ssh_calls) == 1 and "echo present" in node.ssh_calls[0], f"unexpected guest calls: {node.ssh_calls}"
    assert node.snippets == []
    assert seams == []


# --------------------------------------------------------------------------- #
# XMLRPC probe + CARP state
# --------------------------------------------------------------------------- #


def test_xmlrpc_call_returns_the_parsed_result_and_redacts_the_password_from_messages(
    ha: ModuleType, seams: list[str]
) -> None:
    password = "p'a\\ss:@w"
    fault = json.dumps({"fault": -1, "msg": f"denied for {password}"})
    node = FakeNode("primary", xmlrpc_out=f"<<<HAXMLRPC>>>{fault}<<<END>>>")

    result = ha.xmlrpc_call(node, user="u", password=password, method="host_firmware_version")

    assert result["fault"] == -1, f"expected fault -1, got {result}"
    assert password not in result["msg"] and "REDACTED" in result["msg"], f"password not redacted: {result}"


def test_xmlrpc_call_quotes_secrets_for_php_and_url_and_targets_the_secondary_over_https(
    ha: ModuleType, seams: list[str]
) -> None:
    password = "p'a\\ss:@w"
    node = FakeNode("primary", xmlrpc_out='<<<HAXMLRPC>>>{"ok": true, "resp": {}}<<<END>>>')

    ha.xmlrpc_call(node, user="u", password=password, method="host_firmware_version")

    (snippet,) = node.snippets
    assert "'p\\'a\\\\ss:@w'" in snippet, "the password must enter PHP as an escaped single-quoted literal"
    assert "rawurlencode(" in snippet, "URL userinfo must be percent-encoded"
    assert "https://" in snippet and f"@{ha.SECONDARY_SYNC_IP}:443/xmlrpc.php" in snippet, f"wrong target in: {snippet}"
    assert not [c for c in node.ssh_calls if password in c], "the password travelled in an ssh argv"


def test_xmlrpc_call_without_a_result_block_is_loud_and_redacted(ha: ModuleType, seams: list[str]) -> None:
    # PHP echoes the URL userinfo percent-encoded; the plain form can appear in other messages.
    node = FakeNode("primary", xmlrpc_out="PHP Fatal error: bad url https://u:h%40nter%3A2@172.30.254.2 (h@nter:2)")

    with pytest.raises(RuntimeError) as caught:
        ha.xmlrpc_call(node, user="u", password="h@nter:2", method="host_firmware_version")

    text = str(caught.value)
    assert "h@nter:2" not in text and "h%40nter%3A2" not in text, f"password leaked into: {text}"
    assert "REDACTED" in text, f"expected REDACTED marker in: {text}"


_IFCONFIG = """vtnet3: flags=8943<UP,BROADCAST,RUNNING,PROMISC,SIMPLEX,MULTICAST> metric 0 mtu 1500
\tether 02:00:00:34:54:02
\tinet 172.30.254.2 netmask 0xffffff00 broadcast 172.30.254.255
\tinet 172.30.254.254 netmask 0xffffffff broadcast 172.30.254.254 vhid 54
\tcarp: BACKUP vhid 55 advbase 1 advskew 100
\tcarp: MASTER vhid 54 advbase 1 advskew 0
"""


def test_carp_state_reads_the_state_of_the_smoke_vhid_only(ha: ModuleType) -> None:
    assert ha.carp_state(FakeNode("primary", ifconfig=_IFCONFIG)) == "MASTER"


def test_carp_state_is_loud_when_the_vhid_is_absent(ha: ModuleType) -> None:
    with pytest.raises(RuntimeError, match="vhid 54"):
        ha.carp_state(FakeNode("primary", ifconfig="vtnet3: flags=8843<UP>\n\tinet 172.30.254.1 netmask 0xffffff00\n"))


def test_wait_carp_state_returns_once_the_state_is_observed(ha: ModuleType) -> None:
    ha.wait_carp_state(FakeNode("primary", ifconfig=_IFCONFIG), "MASTER", timeout=5)


def test_wait_carp_state_timeout_reports_expected_and_actual(ha: ModuleType) -> None:
    with pytest.raises(
        RuntimeError, match=r"stuck/environment: expected CARP BACKUP on secondary, last observed MASTER"
    ):
        ha.wait_carp_state(FakeNode("secondary", ifconfig=_IFCONFIG), "BACKUP", timeout=0, node="secondary")


# --------------------------------------------------------------------------- #
# peer_vm: node B boots only on a CE leg that has a .pkg to deploy
# --------------------------------------------------------------------------- #

_MATRIX_ROWS = (
    {"pfsense_version": "2.8", "variant": "CE", "freebsd_major": "15", "php_version": "8.3", "py_flavor": "py311"},
    {"pfsense_version": "26.03", "variant": "Plus", "freebsd_major": "16", "php_version": "8.5", "py_flavor": "py311"},
)


def _leg(monkeypatch: pytest.MonkeyPatch, version: str, pkg: str | None) -> None:
    """Make this process look like the smoke leg for matrix row ``version``, with or without a built .pkg."""
    monkeypatch.setattr(importlib.import_module("tests.smoke._matrix"), "build_matrix", lambda: _MATRIX_ROWS)
    monkeypatch.setenv("SMOKE_PFSENSE_VERSION", version)
    monkeypatch.delenv("SMOKE_PHP_VERSION", raising=False)
    if pkg is None:
        monkeypatch.delenv("SMOKE_PKG", raising=False)
    else:
        monkeypatch.setenv("SMOKE_PKG", pkg)


def _start_peer_vm(tmp_path_factory: pytest.TempPathFactory) -> Any:
    """Node B's fixture generator for a session that collected an ha_pair test."""
    request = SimpleNamespace(session=SimpleNamespace(items=[_item("smoke_vm", "peer_vm", "ha_pair")]))
    return cast(Any, smoke_conftest.peer_vm).__wrapped__(object(), tmp_path_factory, request)


@pytest.mark.parametrize(
    ("version", "pkg", "reason"),
    [("26.03", "pkg.pkg", "HA pair is CE-only"), ("2.8", None, "SMOKE_PKG not set")],
    ids=["plus-leg", "no-pkg"],
)
def test_peer_vm_skips_before_booting_when_the_pair_cannot_run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path_factory: pytest.TempPathFactory,
    version: str,
    pkg: str | None,
    reason: str,
) -> None:
    _leg(monkeypatch, version, pkg)

    def boot_is_unreachable(*args: Any, **kwargs: Any) -> None:
        pytest.fail("peer_vm reached a boot step on a leg that cannot run the HA pair")

    monkeypatch.setattr(smoke_conftest, "_pfsense_image", boot_is_unreachable)
    monkeypatch.setattr(smoke_conftest, "boot_and_probe", boot_is_unreachable)

    with pytest.raises(pytest.skip.Exception, match=reason):
        next(_start_peer_vm(tmp_path_factory))


def test_peer_vm_on_a_ce_leg_boots_node_b_on_its_own_ports_and_the_mirrored_sync_link(
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> None:
    _leg(monkeypatch, "2.8", "pkg.pkg")
    booted: dict[str, Any] = {}
    handle = SimpleNamespace(vm=object(), process="process", qmp_sock="qmp.sock", log_file=io.StringIO())

    def fake_boot(*args: Any, **kwargs: Any) -> Any:
        booted.update(kwargs)
        return handle

    killed: list[tuple[Any, Any]] = []
    monkeypatch.setattr(smoke_conftest, "_pfsense_image", lambda work: (Path("base.qcow2"), "key"))
    monkeypatch.setattr(smoke_conftest, "boot_and_probe", fake_boot)
    monkeypatch.setattr(smoke_conftest, "_kill", lambda process, qmp_sock: killed.append((process, qmp_sock)))

    fixture = _start_peer_vm(tmp_path_factory)
    node_b = next(fixture)

    assert node_b is handle.vm
    assert booted["ssh_port"] == smoke_conftest.DEFAULT_PEER_SSH_PORT, f"node B booted with {booted}"
    sync = {k: v for k, v in booted["extra_env"].items() if k.startswith("SMOKE_SYNC_")}
    assert sync == {
        "SMOKE_SYNC_PORT": str(smoke_conftest.DEFAULT_PEER_SYNC_PORT),
        "SMOKE_SYNC_PEER_PORT": str(smoke_conftest.DEFAULT_SYNC_PORT),
    }, f"node B's sync link is not the mirror of node A's: {booted['extra_env']}"
    fixture.close()
    assert killed == [("process", "qmp.sock")], "node B's qemu was not reaped at teardown"


# --------------------------------------------------------------------------- #
# ha_pair_session: every way out of setup or the body puts both nodes back
# --------------------------------------------------------------------------- #


def test_an_interrupt_during_setup_restores_both_nodes_secondary_first_and_propagates(
    ha: ModuleType, seams: list[str]
) -> None:
    a, b = FakeNode("primary"), FakeNode("secondary", interrupt_php="bcrypt-hash")

    with pytest.raises(KeyboardInterrupt):
        with ha.ha_pair_session(a, b):
            pytest.fail("the session must not yield after an interrupted setup")

    assert not a.baseline and not b.baseline, f"baselines left behind: primary={a.baseline} secondary={b.baseline}"
    assert seams == ["primary", "secondary", "secondary", "primary"], f"filter reload order was {seams}"


def test_an_interrupt_stays_an_interrupt_even_when_the_restore_also_fails(ha: ModuleType, seams: list[str]) -> None:
    restore_copy = f"cp -p {BASELINE} /conf/config.xml"
    a, b = FakeNode("primary"), FakeNode("secondary", interrupt_php="bcrypt-hash", fail_ssh=restore_copy)

    with pytest.raises(KeyboardInterrupt):
        with ha.ha_pair_session(a, b):
            pytest.fail("the session must not yield after an interrupted setup")

    assert any(restore_copy in c for c in b.ssh_calls) and b.baseline, "the secondary's restore must have failed"
    assert not a.baseline, "the primary must still be restored after the secondary's restore failed"


@pytest.mark.parametrize("error", [RuntimeError("body failed"), KeyboardInterrupt()], ids=["error", "interrupt"])
def test_an_error_in_the_session_body_restores_both_nodes_and_propagates_unchanged(
    ha: ModuleType, seams: list[str], error: BaseException
) -> None:
    a, b = FakeNode("primary"), FakeNode("secondary")

    with pytest.raises(type(error)) as caught:
        with ha.ha_pair_session(a, b):
            raise error

    assert caught.value is error, f"expected the body's own exception, got {caught.value!r}"
    assert not a.baseline and not b.baseline, f"baselines left behind: primary={a.baseline} secondary={b.baseline}"
    assert seams[-2:] == ["secondary", "primary"], f"restore order was {seams[2:]}"


# --------------------------------------------------------------------------- #
# configure_node: refusal precedes the snapshot; the snapshot is all-or-nothing
# --------------------------------------------------------------------------- #


def test_a_pfssh_fatal_with_exit_zero_is_still_a_labelled_setup_failure(ha: ModuleType, seams: list[str]) -> None:
    node = FakeNode("secondary", fatal_php="bcrypt-hash")

    with pytest.raises(ha.HaSetupError, match=r"node=secondary stage=users.*PHP Fatal error"):
        ha.configure_secondary_users(node, "sync-pw", "nopriv-pw")


def test_a_failed_snapshot_is_labelled_and_nothing_is_applied(ha: ModuleType, seams: list[str]) -> None:
    node = FakeNode("primary", fail_ssh="cp -p /conf/config.xml")

    with pytest.raises(ha.HaSetupError, match=r"node=primary stage=snapshot"):
        ha.configure_node(node, "primary", sync_ip=ha.PRIMARY_SYNC_IP, advskew="0", carp_password="carp")

    assert not [s for s in node.snippets if "config_set_path('interfaces/opt2'" in s], "interfaces were mutated"
    assert not node.baseline


def test_an_interrupted_snapshot_never_leaves_a_file_that_passes_for_a_baseline(
    ha: ModuleType, seams: list[str]
) -> None:
    node = FakeNode("secondary", interrupt_snapshot=True)

    with pytest.raises(ha.HaSetupError, match=r"node=secondary stage=snapshot"):
        ha.configure_node(node, "secondary", sync_ip=ha.SECONDARY_SYNC_IP, advskew="100", carp_password="carp")

    assert not node.baseline, (
        "a truncated snapshot under the baseline's own name would later be restored over the config"
    )


def test_a_node_refused_for_its_busy_sync_nic_is_never_snapshotted(ha: ModuleType, seams: list[str]) -> None:
    node = FakeNode("secondary", busy=["opt2"])

    with pytest.raises(ha.HaSetupError, match=r"node=secondary stage=sync-interface"):
        ha.configure_node(node, "secondary", sync_ip=ha.SECONDARY_SYNC_IP, advskew="100", carp_password="carp")

    snapshots = [c for c in node.ssh_calls if c.startswith("cp -p /conf/config.xml")]
    assert not snapshots, f"a refused node must not be snapshotted, got {snapshots}"
    assert not node.baseline


def test_a_refused_secondary_is_left_untouched_by_the_failure_restore(ha: ModuleType, seams: list[str]) -> None:
    a, b = FakeNode("primary"), FakeNode("secondary", busy=["opt2"])

    with pytest.raises(ha.HaSetupError, match=r"node=secondary stage=sync-interface"):
        with ha.ha_pair_session(a, b):
            pytest.fail("the session must not yield after a refused node")

    restores = [c for c in b.ssh_calls if c.startswith(f"cp -p {BASELINE} /conf/config.xml")]
    assert not restores, f"the refused secondary's config.xml was overwritten from a baseline: {restores}"
    assert not [s for s in b.snippets if "interface_bring_down" in s], (
        "the refused secondary's interfaces were torn down"
    )
    assert not a.baseline, "the primary, which WAS configured, must be restored"


# --------------------------------------------------------------------------- #
# conftest.ha_pair: a deploy failure is labelled like every other setup failure
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(("failing", "deployed"), [("primary", []), ("secondary", ["primary"])])
def test_a_deploy_failure_names_the_node_and_the_deploy_stage(
    ha: ModuleType, monkeypatch: pytest.MonkeyPatch, failing: str, deployed: list[str]
) -> None:
    a, b = FakeNode("primary"), FakeNode("secondary")
    deploys: list[str] = []

    def deploy(vm: FakeNode, *args: Any, **kwargs: Any) -> None:
        if vm.name == failing:
            raise RuntimeError("pkg add failed")
        deploys.append(vm.name)

    monkeypatch.setenv("SMOKE_PKG", "pkg.pkg")
    monkeypatch.setattr(importlib.import_module("tests.smoke.helpers"), "deploy", deploy)

    with pytest.raises(ha.HaSetupError, match=rf"node={failing} stage=deploy.*pkg add failed"):
        next(cast(Any, smoke_conftest.ha_pair).__wrapped__(a, b))

    assert deploys == deployed, f"expected deploys {deployed} before the {failing} failure, got {deploys}"


# --------------------------------------------------------------------------- #
# _dump_vm_on_failure: the secondary is dumped whenever its guest exists
# --------------------------------------------------------------------------- #


def _dump_after_failure(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], node: Any) -> list[str]:
    """Finish the autouse failure-dump fixture for ``node``; its dump seam prints ``dump <name>``."""
    monkeypatch.setattr(
        importlib.import_module("tests.smoke.helpers"), "dump_diagnostics", lambda vm: print(f"dump {vm.name}")
    )
    fixture = cast(Any, smoke_conftest._dump_vm_on_failure).__wrapped__(SimpleNamespace(node=node))
    next(fixture)
    with pytest.raises(StopIteration):
        next(fixture)
    return capsys.readouterr().out.splitlines()


_SECONDARY_HEADER = "========== HA NODE secondary diagnostics =========="


def test_a_failed_ha_pair_test_finds_the_secondary_through_the_peer_vm_fixture(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The dump reads node B from peer_vm itself, so it needs no HaPair among the funcargs.
    node = SimpleNamespace(
        funcargs={"smoke_vm": FakeNode("primary"), "peer_vm": FakeNode("secondary")},
        _rep_call=SimpleNamespace(failed=True),
    )

    assert _dump_after_failure(monkeypatch, capsys, node) == ["dump primary", _SECONDARY_HEADER, "dump secondary"]


def test_a_failed_pair_test_dumps_each_guest_once(
    ha: ModuleType, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    a, b = FakeNode("primary"), FakeNode("secondary")
    pair = ha.HaPair(a, b, sync_password="s", nopriv_password="n", carp_password="c")
    node = SimpleNamespace(
        funcargs={"smoke_vm": a, "peer_vm": b, "ha_pair": pair}, _rep_call=SimpleNamespace(failed=True)
    )

    assert _dump_after_failure(monkeypatch, capsys, node) == ["dump primary", _SECONDARY_HEADER, "dump secondary"]


def test_a_failed_one_node_test_dumps_no_secondary(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    node = SimpleNamespace(funcargs={"smoke_vm": FakeNode("primary")}, _rep_call=SimpleNamespace(failed=True))

    assert _dump_after_failure(monkeypatch, capsys, node) == ["dump primary"]
