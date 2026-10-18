"""Issue #3455: hermetic contract of the HA policy-sync smoke helpers (``tests/smoke/ha_policy.py``).

The live proof is ``tests/smoke/test_ha_policy_sync.py`` (two real guests). Everything here runs off-box: the pure
builders, the diff rules the live assertions lean on, the record assertions and the guest plumbing behind fake
``SmokeVM`` / ``helpers.php_eval`` seams. A live assertion built on a wrong helper would pass vacuously, so each
rule the live tests rely on is pinned here with a case that fails when the rule is dropped.
"""

from __future__ import annotations

import importlib
import json
import subprocess
from datetime import datetime, timedelta
from functools import cache
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

BOOTSTRAP = Path(__file__).resolve().parent / "php" / "bootstrap.php"


@cache
def _registry_local_paths() -> frozenset[str]:
    """Every ``sync: local`` key of the shipped registry, as the config path a seed would write (executed PHP)."""
    script = (
        "[, $boot] = $argv; require $boot;"
        "$out = [];"
        "foreach (pfb_cfg_registry() as $key => $entry) {"
        "    if (($entry['sync'] ?? '') === 'local') {"
        "        [$section, $leaf] = explode('/', $key, 2);"
        "        $out[] = PFB_SECTIONS[$section] . '/' . $leaf;"
        "    }"
        "}"
        "echo json_encode($out);"
    )
    result = subprocess.run(
        ["php", "-r", script, "--", str(BOOTSTRAP)], capture_output=True, check=True, text=True, encoding="utf-8"
    )
    return frozenset(json.loads(result.stdout))


@pytest.fixture
def hp() -> ModuleType:
    return importlib.import_module("tests.smoke.ha_policy")


def _done(stdout: str = "", returncode: int = 0, stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def _vm(outputs: dict[str, subprocess.CompletedProcess[str]] | None = None) -> SimpleNamespace:
    """A guest whose ``ssh`` answers the first registered substring found in the command line."""
    calls: list[str] = []

    def ssh(*command: str, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        line = " ".join(command)
        calls.append(line)
        for needle, answer in (outputs or {}).items():
            if needle in line:
                return answer
        return _done()

    return SimpleNamespace(ssh=ssh, calls=calls)


# --------------------------------------------------------------------------- #
# sender_section: what the Sync page stores
# --------------------------------------------------------------------------- #


def test_automatic_sender_stores_the_gate_and_no_targets(hp: ModuleType) -> None:
    section = hp.sender_section("automatic", scope="policy", password="pw", timeout=150)

    assert section == {"syncscope": "policy", "varsynconchanges": "auto", "varsynctimeout": "150"}


def test_manual_sender_stores_one_enabled_https_target_with_the_ha_credentials(hp: ModuleType) -> None:
    section = hp.sender_section("manual", scope="policy", password="s3cret", timeout=5)

    assert section["varsynconchanges"] == "manual"
    assert section["varsynctimeout"] == "5"
    assert section["syncscope"] == "policy"
    assert section["row"] == [
        {
            "varsyncprotocol": "https",
            "varsyncipaddress": "172.30.254.2",
            "varsyncport": "443",
            "varsyncusername": "pfbhasync",
            "varsyncpassword": "s3cret",
            "varsyncdestinenable": "on",
        }
    ]


def test_sender_scope_is_the_stored_leaf_whatever_the_transport(hp: ModuleType) -> None:
    assert hp.sender_section("automatic", scope="lists", password="x", timeout=1)["syncscope"] == "lists"
    assert hp.sender_section("manual", scope="all", password="x", timeout=1)["syncscope"] == "all"


# --------------------------------------------------------------------------- #
# diff_leaves / unexpected_additions: the "B kept its own" rule
# --------------------------------------------------------------------------- #


def test_diff_leaves_separates_changed_removed_and_added(hp: ModuleType) -> None:
    before = {"p/keep": "1", "p/change": "old", "p/gone": "x", "p/blank": ""}
    after = {"p/keep": "1", "p/change": "new", "p/new": "y", "p/blank": ""}

    diff = hp.diff_leaves(before, after)

    assert diff == {"changed": {"p/change": ("old", "new")}, "removed": {"p/gone": "x"}, "added": {"p/new": "y"}}


def test_diff_leaves_tells_a_blank_leaf_from_an_absent_one(hp: ModuleType) -> None:
    assert hp.diff_leaves({"p/x": ""}, {})["removed"] == {"p/x": ""}
    assert hp.diff_leaves({}, {"p/x": ""})["added"] == {"p/x": ""}


ROW = "installedpackages/pfblockernglistsv4/config/3"


def test_a_new_row_may_bring_exactly_the_editor_defaults(hp: ModuleType) -> None:
    added = {f"{ROW}/{leaf}": value for leaf, value in hp.NEW_ROW_DEFAULTS.items()}

    assert hp.unexpected_additions(added, [ROW]) == {}


def test_a_new_blacklist_item_may_bring_empty_credentials(hp: ModuleType) -> None:
    row = "installedpackages/pfblockerngblacklist/item/3"
    added = {f"{row}/username": "", f"{row}/password": ""}

    assert hp.unexpected_additions(added, [row]) == {}


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (f"{ROW}/agateway_in", "WAN_DHCP"),  # a new row carrying a value other than the default: the sender's leaked
        (f"{ROW}/script_pre", "/tmp/PFBHA-A-script_pre.sh"),
        (f"{ROW}/infolists", ""),  # not an editor default of the merge
        ("installedpackages/pfblockernglistsv4/config/4/srcint", ""),  # a default, but under a row that is not new
        ("installedpackages/pfblockerngipsettings/config/0/maxmind_key", ""),  # a settings leaf is never a row default
    ],
)
def test_any_other_addition_is_reported(hp: ModuleType, path: str, value: str) -> None:
    assert hp.unexpected_additions({path: value}, [ROW]) == {path: value}


# --------------------------------------------------------------------------- #
# Seeds: the two nodes must really differ, or "B kept its own" proves nothing
# --------------------------------------------------------------------------- #


def test_every_credential_leaf_is_seeded_with_its_own_sentinel_per_node(hp: ModuleType) -> None:
    a = hp.node_local_leaves("A", vip_uniqid="u")
    b = hp.node_local_leaves("B", vip_uniqid="u")

    assert set(hp.CREDENTIAL_SCALARS) == {"maxmind_account", "maxmind_key", "asn_token", "top1m_token"}
    for name, path in hp.CREDENTIAL_SCALARS.items():
        assert a[path] == f"PFBHA-A-{name}", f"A's {name} sentinel: {a[path]!r}"
        assert b[path] == f"PFBHA-B-{name}", f"B's {name} sentinel: {b[path]!r}"


def test_every_seeded_leaf_both_nodes_hold_differs_between_them(hp: ModuleType) -> None:
    a = hp.node_local_leaves("A", vip_uniqid="u")
    b = hp.node_local_leaves("B", vip_uniqid="u")

    same = [path for path in a if path in b and a[path] == b[path]]

    assert same == [], f"seeded local leaves equal on both nodes (they would prove nothing): {same}"


def test_every_sync_local_registry_key_is_seeded_on_a_node_or_excluded_with_its_reason(hp: ModuleType) -> None:
    registry = _registry_local_paths()
    seeded = (
        set(hp.node_local_leaves("A", vip_uniqid="u"))
        | set(hp.node_local_leaves("B", vip_uniqid="u"))
        | set(hp.GATEWAY_LEAVES)
    )
    excluded = set(hp.UNSEEDED_LOCAL_KEYS)

    missing = sorted(registry - seeded - excluded)
    assert not missing, f"sync:local keys neither seeded nor excluded: {missing}"
    assert not excluded & seeded, f"keys both seeded and excluded: {sorted(excluded & seeded)}"
    assert excluded <= registry, f"exclusions that are not sync:local registry keys: {sorted(excluded - registry)}"
    assert all(reason.strip() for reason in hp.UNSEEDED_LOCAL_KEYS.values()), "an excluded key has no reason"


def test_every_seeded_registry_key_holds_a_value_on_both_nodes_except_the_dnsbl_vip_reference(hp: ModuleType) -> None:
    registry = _registry_local_paths()
    a = set(hp.node_local_leaves("A", vip_uniqid="u")) & registry
    b = set(hp.node_local_leaves("B", vip_uniqid="u")) & registry

    assert a ^ b == {f"{hp.DNSBL}/pfb_dnsvip4"}, f"seeded on one node only: {sorted(a ^ b)}"


def test_the_seeded_numeric_leaves_are_values_the_package_reads_as_given(hp: ModuleType) -> None:
    """A seed the package clamps or ignores proves nothing about "B kept its own": each must read back as seeded."""
    numeric = ("log_max_", "pfb_log_trim_margin_pct", "pfb_alias_delta_batch", "pfb_dnsport", "pfb_py_cache_max")
    for tag in ("A", "B"):
        leaves = hp.node_local_leaves(tag, vip_uniqid="u")
        for path, value in leaves.items():
            if path.rsplit("/", 1)[1].startswith(numeric):
                assert isinstance(value, str) and value.isdigit(), f"{tag} {path}: expected digits, got {value!r}"
        timeout = leaves[f"{hp.GEN}/pfb_reentry_timeout"]
        assert 60 <= int(timeout) <= 7200, (
            f"{tag}'s re-entry timeout {timeout!r} is outside the range the package keeps"
        )


def test_only_node_b_carries_the_dnsbl_vip_reference_with_its_own_uniqid(hp: ModuleType) -> None:
    path = f"{hp.DNSBL}/pfb_dnsvip4"

    assert hp.node_local_leaves("B", vip_uniqid="pfbhaB3455")[path] == "_vippfbhaB3455"
    assert path not in hp.node_local_leaves("A", vip_uniqid="pfbhaB3455")


def test_the_hook_row_is_disabled_so_it_can_never_run(hp: ModuleType) -> None:
    for tag in ("A", "B"):
        (row,) = hp.node_local_leaves(tag, vip_uniqid="u")[f"{hp.GEN}/hooks/row"]
        assert row["enabled"] == "", f"{tag}'s seeded hook would run: {row!r}"


def test_group_local_values_differ_per_node_and_cover_every_row_local_leaf(hp: ModuleType) -> None:
    a, b = hp.group_local_values("A", "WAN_DHCP"), hp.group_local_values("B", "default")

    assert set(a) == set(b) == set(hp.ROW_LOCAL_LEAVES)
    assert [leaf for leaf in a if a[leaf] == b[leaf]] == []


def test_the_baseline_policy_leaves_are_not_local_seeds(hp: ModuleType) -> None:
    locals_ = set(hp.node_local_leaves("A", vip_uniqid="u")) | set(hp.node_local_leaves("B", vip_uniqid="u"))

    assert set(hp.BASELINE_POLICY_LEAVES).isdisjoint(locals_)


def test_seed_node_redacts_the_sentinel_values_it_writes_and_not_their_config_paths(
    hp: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(hp, "write_sections", lambda *_a, **_k: None)
    monkeypatch.setattr(hp, "set_leaves", lambda _vm, _leaves, _message, **kw: calls.append(kw))

    hp.seed_node(object(), "A", "gw")

    (call,) = calls
    redacted = set(call["secret_values"])
    assert set(hp.credential_values("A")) <= redacted, f"a seeded credential would reach a failure text: {redacted}"
    assert not redacted & set(hp.CREDENTIAL_SCALARS.values()), "config paths are not secrets: the values are"


def test_the_baseline_names_every_sync_local_key_it_does_not_seed_and_why(
    hp: ModuleType, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The reasons are printed in the run, so a reader of the log sees what the local-key seeding leaves out."""
    monkeypatch.setattr(hp, "settle", lambda _vm: None)
    monkeypatch.setattr(hp, "gateway_name", lambda _vm: "gw")
    monkeypatch.setattr(hp, "write_feed", lambda *_a: "")
    monkeypatch.setattr(hp, "seed_node", lambda *_a: None)
    monkeypatch.setattr(hp, "php_write", lambda *_a, **_k: None)
    monkeypatch.setattr(hp, "wait_filter_idle", lambda _vm: None)
    monkeypatch.setattr(hp, "assert_dnsbl_vip", lambda *_a: None)
    monkeypatch.setattr(hp, "php_json", lambda *_a, **_k: "/mark")
    monkeypatch.setattr(hp, "set_leaves", lambda *_a, **_k: None)
    for fn in ("inject_ip_lists", "ensure_dnsbl_vip", "set_dnsbl_enabled", "reload"):
        monkeypatch.setattr(hp.h, fn, lambda *_a, **_k: None)
    monkeypatch.setattr(hp.h, "pfb_config_digest", lambda _vm: "d")
    vm = SimpleNamespace(ssh=lambda *_a, **_k: _done())

    hp.arrange_baseline(SimpleNamespace(primary=vm, secondary=vm))

    out = capsys.readouterr().out
    for path, reason in hp.UNSEEDED_LOCAL_KEYS.items():
        assert f"{path}: {reason}" in out, f"the run does not say why {path} is not seeded:\n{out}"


# --------------------------------------------------------------------------- #
# Group and provider rows
# --------------------------------------------------------------------------- #


def test_ip_group_has_the_category_editor_shape(hp: ModuleType) -> None:
    group = hp.ip_group("pfbha_x", "/var/db/pfblockerng/pfbha_x.txt", action="Deny_Both", local={"srcint": "lan"})

    assert group == {
        "aliasname": "pfbha_x",
        "action": "Deny_Both",
        "cron": "EveryDay",
        "srcint": "lan",
        "row": [{"header": "pfbha_x", "url": "/var/db/pfblockerng/pfbha_x.txt", "state": "Enabled", "format": "auto"}],
    }


def test_blacklist_item_keeps_identity_and_credentials_apart(hp: ModuleType) -> None:
    item = hp.blacklist_item("bl_alpha", username="u", password="p")

    assert (item["xml"], item["username"], item["password"]) == ("bl_alpha", "u", "p")
    assert hp.blacklist_item("bl_beta")["username"] == hp.blacklist_item("bl_beta")["password"] == ""


# --------------------------------------------------------------------------- #
# NodeState: local = every stored leaf the package's projection does not list
# --------------------------------------------------------------------------- #


def test_node_state_local_is_the_stored_leaves_outside_the_projection(hp: ModuleType) -> None:
    state = hp.NodeState(
        digest="d",
        projection={"p/policy": "1", "p/blank": ""},
        leaves={"p/policy": "1", "p/blank": "", "p/secret": "PFBHA-A-x", "p/other": ""},
        installedpackages_sha256="s",
        core={},
    )

    assert state.local == {"p/secret": "PFBHA-A-x", "p/other": ""}


# --------------------------------------------------------------------------- #
# Guest plumbing
# --------------------------------------------------------------------------- #


def test_php_json_returns_the_value_between_the_sentinels_whatever_the_banner(
    hp: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = f"pfSsh banner\n{hp._OPEN}{json.dumps({'a': [1, ''], 'b': None})}{hp._CLOSE}\nexit"
    monkeypatch.setattr(hp.h, "php_eval", lambda _vm, _snippet, **_k: _done(out))

    assert hp.php_json(object(), "x") == {"a": [1, ""], "b": None}


def test_php_json_failure_names_rc_and_redacts_every_secret(hp: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        hp.h, "php_eval", lambda _vm, _s, **_k: _done("boom hunter2", returncode=255, stderr="hunter2!")
    )

    with pytest.raises(RuntimeError) as err:
        hp.php_json(object(), "x", secret_values=["hunter2"])

    assert "rc=255" in str(err.value)
    assert "hunter2" not in str(err.value)
    assert "REDACTED" in str(err.value)


def test_php_json_without_a_block_is_an_error_not_an_empty_answer(
    hp: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(hp.h, "php_eval", lambda _vm, _s, **_k: _done("no sentinels here"))

    with pytest.raises(RuntimeError, match="emitted no result"):
        hp.php_json(object(), "x")


def test_php_write_failure_redacts_the_password_it_carried(hp: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hp.h, "php_eval", lambda _vm, _s, **_k: _done("trace pw-9", returncode=1))

    with pytest.raises(RuntimeError) as err:
        hp.php_write(object(), "x", "msg", secret_values=["pw-9"])

    assert "pw-9" not in str(err.value)


def test_set_leaves_sends_none_as_a_delete_and_blank_and_empty_list_as_stored_values(
    hp: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[str] = []

    def record(_vm: object, snippet: str, **_k: Any) -> subprocess.CompletedProcess[str]:
        seen.append(snippet)
        return _done("OK")

    monkeypatch.setattr(hp.h, "php_eval", record)

    hp.set_leaves(object(), {"p/del": None, "p/blank": "", "p/list": [], "p/val": "v"}, "m")

    (snippet,) = seen
    assert '{"p/del": null, "p/blank": "", "p/list": [], "p/val": "v"}' in snippet
    assert "config_del_path($p)" in snippet and "write_config('m', TRUE, TRUE)" in snippet


def test_read_json_file_tells_an_absent_file_from_a_record(hp: ModuleType) -> None:
    record = {"last": {"outcome": "changed"}}

    assert hp.read_json_file(_vm({"cat": _done(json.dumps(record))}), "/x") == record
    assert hp.read_json_file(_vm({"cat": _done("__ABSENT__\n")}), "/x") is None


def test_receive_and_send_state_are_empty_before_a_record_exists(hp: ModuleType) -> None:
    vm = _vm({"cat": _done("__ABSENT__")})

    assert hp.receive_state(vm) == {}
    assert hp.send_state(vm) == {}


def test_clear_sync_state_fails_loudly_when_a_state_file_survives(hp: ModuleType) -> None:
    survivor = _vm({"ls ": _done(f"{hp.RECEIVE_FILE}\n")})

    with pytest.raises(AssertionError, match="survived"):
        hp.clear_sync_state(survivor)
    assert hp.clear_sync_state(_vm()) is None


def test_grep_leaks_feeds_the_needles_on_stdin_and_never_on_a_command_line(
    hp: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        captured.update(argv=argv, input=kwargs["input"])
        return _done("/conf/config.xml\n")

    monkeypatch.setattr(hp.subprocess, "run", run)
    vm = SimpleNamespace(ssh_argv=lambda *a: ["ssh", *a])

    assert hp.grep_leaks(vm, ["PFBHA-A-a", "PFBHA-A-b"], ["/conf/config.xml", "/var/log"]) == ["/conf/config.xml"]
    assert captured["input"] == "PFBHA-A-a\nPFBHA-A-b\n"
    assert not any("PFBHA" in part for part in captured["argv"])


def test_grep_leaks_treats_a_grep_error_as_an_error_not_as_clean(
    hp: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(hp.subprocess, "run", lambda *_a, **_k: _done("", returncode=2, stderr="bad option"))
    vm = SimpleNamespace(ssh_argv=lambda *a: ["ssh", *a])

    with pytest.raises(AssertionError, match="bad option"):
        hp.grep_leaks(vm, ["x"], ["/var/log"])


# --------------------------------------------------------------------------- #
# wait_apply: only an apply record opened for THIS receive may end the wait
# --------------------------------------------------------------------------- #


def test_wait_apply_returns_the_record_once_the_apply_left_waiting(
    hp: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = {"apply": {"opened": 100, "outcome": "applied"}, "last": {"outcome": "changed"}}
    monkeypatch.setattr(hp, "receive_state", lambda _vm: record)

    assert hp.wait_apply(object(), since=100, timeout=1.0) == record


@pytest.mark.parametrize(
    "apply",
    [
        {"opened": 99, "outcome": "applied"},  # a record from an earlier receive is not this one's completion
        {"opened": 100, "outcome": "waiting"},
        {},
    ],
)
def test_wait_apply_does_not_accept_a_stale_or_unsettled_record(
    hp: ModuleType, monkeypatch: pytest.MonkeyPatch, apply: dict[str, Any]
) -> None:
    monkeypatch.setattr(hp, "receive_state", lambda _vm: {"apply": apply})

    with pytest.raises(RuntimeError, match="stuck/environment"):
        hp.wait_apply(object(), since=100, timeout=0.01)


def test_wait_apply_reports_a_failed_apply_instead_of_waiting_for_a_better_one(
    hp: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    failed = {"apply": {"opened": 100, "outcome": "failed", "reason": "apply failed; pending changes kept"}}
    monkeypatch.setattr(hp, "receive_state", lambda _vm: failed)

    assert hp.wait_apply(object(), since=100, timeout=1.0)["apply"]["outcome"] == "failed"


# --------------------------------------------------------------------------- #
# Record assertions
# --------------------------------------------------------------------------- #

DIGEST = "a" * 64


def _sync(hp: ModuleType, **overrides: Any) -> Any:
    fields: dict[str, Any] = {
        "t0_b": 100,
        "send": {
            "time": 101,
            "attempts": [{"target": "172.30.254.2:443", "time": 101, "outcome": "sent", "digest": DIGEST}],
        },
        "receive": {
            "accepted_digest": DIGEST,
            "last": {
                "time": 102,
                "outcome": "changed",
                "incoming_digest": DIGEST,
                "accepted_digest": DIGEST,
                "ignored": [],
                "ignored_count": 0,
            },
            "apply": {"time": 110, "opened": 102, "outcome": "applied"},
        },
        "passes": 1,
    }
    return hp.Sync(**{**fields, **overrides})


def test_assert_sent_accepts_one_sent_attempt_per_manual_target_with_the_digest(hp: ModuleType) -> None:
    hp.assert_sent(_sync(hp), "manual", DIGEST)


def test_assert_sent_accepts_one_handed_attempt_for_the_automatic_transport(hp: ModuleType) -> None:
    send = {"attempts": [{"target": "pfSense HA sync", "time": 1, "outcome": "handed", "digest": DIGEST}]}

    hp.assert_sent(_sync(hp, send=send), "automatic", DIGEST)


@pytest.mark.parametrize(
    ("attempt", "transport", "needle"),
    [
        (
            {"target": "172.30.254.2:443", "outcome": "failed", "error": "timeout", "digest": DIGEST},
            "manual",
            "outcome",
        ),
        ({"target": "172.30.254.2:443", "outcome": "sent", "digest": "b" * 64}, "manual", "digest"),
        ({"target": "pfSense HA sync", "outcome": "handed", "digest": DIGEST}, "manual", "target"),
        ({"target": "172.30.254.2:443", "outcome": "sent", "digest": DIGEST}, "automatic", "target"),
    ],
)
def test_assert_sent_names_expected_and_actual_on_a_wrong_attempt(
    hp: ModuleType, attempt: dict[str, str], transport: str, needle: str
) -> None:
    with pytest.raises(AssertionError, match=needle):
        hp.assert_sent(_sync(hp, send={"attempts": [attempt]}), transport, DIGEST)


def test_assert_sent_rejects_zero_or_two_attempts(hp: ModuleType) -> None:
    one = {"target": "172.30.254.2:443", "outcome": "sent", "digest": DIGEST}

    for attempts in ([], [one, one]):
        with pytest.raises(AssertionError, match="one attempt"):
            hp.assert_sent(_sync(hp, send={"attempts": attempts}), "manual", DIGEST)
    with pytest.raises(AssertionError, match="one attempt"):
        hp.assert_sent(_sync(hp, send={}), "manual", DIGEST)


def test_assert_receive_returns_the_last_record_of_an_honest_sender(hp: ModuleType) -> None:
    assert hp.assert_receive(_sync(hp), "changed", DIGEST)["outcome"] == "changed"


def test_assert_receive_catches_a_wrong_outcome_a_wrong_digest_and_a_stale_record(hp: ModuleType) -> None:
    with pytest.raises(AssertionError, match="expected outcome 'unchanged'"):
        hp.assert_receive(_sync(hp), "unchanged")
    with pytest.raises(AssertionError, match="accepted digest"):
        hp.assert_receive(_sync(hp), "changed", "c" * 64)
    with pytest.raises(AssertionError, match="expected outcome 'changed'"):
        hp.assert_receive(_sync(hp, receive={}), "changed")


def test_assert_receive_catches_a_leaf_the_receiver_ignored(hp: ModuleType) -> None:
    last = {
        "outcome": "changed",
        "incoming_digest": "d" * 64,
        "accepted_digest": DIGEST,
        "ignored": ["p/x"],
        "ignored_count": 1,
    }

    with pytest.raises(AssertionError, match="incoming digest"):
        hp.assert_receive(_sync(hp, receive={"last": last}), "changed")
    ignored_only = {**last, "incoming_digest": DIGEST}
    with pytest.raises(AssertionError, match="ignored paths"):
        hp.assert_receive(_sync(hp, receive={"last": ignored_only}), "changed")


def test_assert_applied_once_needs_an_applied_record_and_exactly_one_pass(hp: ModuleType) -> None:
    hp.assert_applied_once(_sync(hp))

    with pytest.raises(AssertionError, match="2 update passes"):
        hp.assert_applied_once(_sync(hp, passes=2))
    with pytest.raises(AssertionError, match="0 update passes"):
        hp.assert_applied_once(_sync(hp, passes=0))
    failed = {"apply": {"outcome": "failed", "reason": "x"}}
    with pytest.raises(AssertionError, match="expected applied"):
        hp.assert_applied_once(_sync(hp, receive=failed))


# --------------------------------------------------------------------------- #
# sync_once: a stale receive record is never mistaken for this send's
# --------------------------------------------------------------------------- #


def test_sync_once_rejects_a_receive_record_older_than_the_send(
    hp: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    stale = {"last": {"time": 90, "outcome": "changed"}}
    monkeypatch.setattr(hp, "node_time", lambda _vm: 100)
    monkeypatch.setattr(hp, "apply_banners", lambda _vm: 0)
    monkeypatch.setattr(hp, "trigger_send", lambda *_a, **_k: None)
    monkeypatch.setattr(hp, "send_state", lambda _vm: {"attempts": []})
    monkeypatch.setattr(hp, "receive_state", lambda _vm: stale)
    pair = SimpleNamespace(primary=object(), secondary=object())

    with pytest.raises(AssertionError, match="stale"):
        hp.sync_once(pair, "manual")


def test_sync_once_waits_for_the_apply_only_after_a_changed_receive(
    hp: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    waited: list[int] = []
    settled: list[object] = []
    banners = iter([5, 6])
    monkeypatch.setattr(hp, "node_time", lambda _vm: 100)
    monkeypatch.setattr(hp, "apply_banners", lambda _vm: next(banners))
    monkeypatch.setattr(hp, "trigger_send", lambda *_a, **_k: None)
    monkeypatch.setattr(hp, "send_state", lambda _vm: {})
    monkeypatch.setattr(hp, "receive_state", lambda _vm: {"last": {"time": 100, "outcome": "changed"}})

    def wait_apply(_vm: object, *, since: int) -> dict[str, Any]:
        waited.append(since)
        return {"apply": {"outcome": "applied"}}

    monkeypatch.setattr(hp, "wait_apply", wait_apply)
    monkeypatch.setattr(hp, "settle", lambda vm: settled.append(vm))
    pair = SimpleNamespace(primary=object(), secondary=object())

    sync = hp.sync_once(pair, "automatic")

    assert waited == [100] and settled == [pair.secondary]
    assert sync.passes == 1 and sync.receive == {"apply": {"outcome": "applied"}}


def _sync_once_rig(hp: ModuleType, monkeypatch: pytest.MonkeyPatch, outcome: str) -> tuple[SimpleNamespace, list[str]]:
    """``sync_once`` over fakes whose receive record says ``outcome``; ``events``: banner reads and settles in order."""
    events: list[str] = []

    def count(_vm: object) -> int:
        events.append("count")
        return 5

    monkeypatch.setattr(hp, "node_time", lambda _vm: 100)
    monkeypatch.setattr(hp, "apply_banners", count)
    monkeypatch.setattr(hp, "trigger_send", lambda *_a, **_k: None)
    monkeypatch.setattr(hp, "send_state", lambda _vm: {})
    monkeypatch.setattr(hp, "receive_state", lambda _vm: {"last": {"time": 101, "outcome": outcome}})
    monkeypatch.setattr(hp, "wait_apply", lambda *_a, **_k: pytest.fail(f"a {outcome} receive opens no apply"))
    monkeypatch.setattr(hp, "settle", lambda vm: events.append(f"settle {vm.name}"))
    return SimpleNamespace(primary=SimpleNamespace(name="A"), secondary=SimpleNamespace(name="B")), events


@pytest.mark.parametrize("outcome", ["unchanged", "refused"])
def test_sync_once_does_not_wait_for_an_apply_after_a_receive_that_opens_none_but_still_drains_b(
    hp: ModuleType, monkeypatch: pytest.MonkeyPatch, outcome: str
) -> None:
    """The tick spawn is delayed: a "no pass ran" claim read before B is idle could miss a pass that starts late."""
    pair, events = _sync_once_rig(hp, monkeypatch, outcome)

    assert hp.sync_once(pair, "automatic").passes == 0

    assert events == ["count", "settle B", "count"], f"B must be settled between the two banner reads: {events}"


def test_sync_once_without_wait_reads_the_receive_and_settles_nothing(
    hp: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A deferred apply keeps its pending mark, so settling B would wait for it for ever."""
    pair, events = _sync_once_rig(hp, monkeypatch, "changed")

    hp.sync_once(pair, "manual", wait=False)

    assert events == ["count", "count"], f"wait=False must not settle B: {events}"


# --------------------------------------------------------------------------- #
# Core's HA sync: a harness write never raises the event, only the tests that ride it turn it on
# --------------------------------------------------------------------------- #


def _recording_php_eval(hp: ModuleType, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    seen: list[str] = []

    def record(_vm: object, snippet: str, **_k: Any) -> subprocess.CompletedProcess[str]:
        seen.append(snippet)
        return _done("OK")

    monkeypatch.setattr(hp.h, "php_eval", record)
    return seen


def test_a_harness_write_saves_the_file_only_unless_the_filter_sync_event_is_asked_for(
    hp: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = _recording_php_eval(hp, monkeypatch)

    hp.php_write(object(), "x", "m")
    hp.php_write(object(), "x", "m", sync=True)

    quiet, noisy = seen
    assert "write_config('m', TRUE, TRUE);" in quiet, f"default write must be $write_config_only: {quiet!r}"
    assert "write_config('m', TRUE, FALSE);" in noisy, f"sync=True must leave the event on: {noisy!r}"


def test_hasync_section_is_what_ha_pair_stores_on_the_primary(hp: ModuleType) -> None:
    assert hp.hasync_section("pw") == {
        "synchronizetoip": "172.30.254.2",
        "username": "pfbhasync",
        "password": "pw",
        "synchronizerules": "on",
        "synchronizenat": "on",
        "synchronizealiases": "on",
    }


def _stored_by_configure_sender(hp: ModuleType, monkeypatch: pytest.MonkeyPatch, transport: str, **kw: Any) -> Any:
    stored: dict[str, Any] = {}
    monkeypatch.setattr(hp, "set_leaves", lambda vm, leaves, *_a, **_k: stored.update(leaves))
    hp.configure_sender(SimpleNamespace(primary=object(), sync_password="pw"), transport, **kw)
    return stored


def test_the_automatic_sender_turns_core_sync_on_and_the_manual_one_takes_it_off(
    hp: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    auto = _stored_by_configure_sender(hp, monkeypatch, "automatic")
    manual = _stored_by_configure_sender(hp, monkeypatch, "manual")

    assert auto["hasync"] == hp.hasync_section("pw") and auto[hp.SYNC]["varsynconchanges"] == "auto"
    assert manual["hasync"] is None and manual[hp.SYNC]["varsynconchanges"] == "manual"


def test_core_sync_can_be_forced_either_way_whatever_the_transport(
    hp: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    both = _stored_by_configure_sender(hp, monkeypatch, "manual", core_sync=True)
    none = _stored_by_configure_sender(hp, monkeypatch, "automatic", core_sync=False)

    assert both["hasync"] == hp.hasync_section("pw")
    assert none["hasync"] is None


def test_core_ha_on_stores_the_hasync_section_and_saves_the_file_only(
    hp: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = _recording_php_eval(hp, monkeypatch)

    hp.core_ha_on(SimpleNamespace(primary=object(), sync_password="pw"))

    (php,) = seen
    assert '"hasync": {"synchronizetoip": "172.30.254.2"' in php and '"password": "pw"' in php, php
    assert "TRUE, TRUE);" in php, (
        f"a plain write_config() queues core's own rc.filter_synchronize, a second sender: {php!r}"
    )


def _aged(*ages: str) -> SimpleNamespace:
    """A guest whose syslog's last "Syncing firewall" line is ``age`` seconds old at each successive probe."""
    clock = datetime(2026, 10, 18, 12, 0, 0)
    answers = iter(ages)

    def probe(*_a: Any, **_k: Any) -> subprocess.CompletedProcess[str]:
        age = next(answers)
        if age == "none":
            return _done("none\n")
        stamp = clock - timedelta(seconds=int(age))
        return _done(f"{stamp:%b} {stamp.day:>2} {stamp:%H:%M:%S}\n{clock:%Y %b} {clock.day:>2} {clock:%H:%M:%S}\n")

    return SimpleNamespace(ssh=probe)


def test_core_sync_quiet_polls_until_the_last_sync_line_is_as_old_as_the_run_horizon(
    hp: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(hp.h.time, "sleep", lambda _s: None)
    horizon = hp.CORE_SYNC_QUIET

    hp.core_sync_quiet(_aged("0", str(horizon - 1), str(horizon)))

    with pytest.raises(StopIteration):  # one probe too few: the poll must not stop before the horizon
        hp.core_sync_quiet(_aged("0", str(horizon - 1)))


def test_core_sync_quiet_is_immediate_when_the_log_holds_no_sync_line(hp: ModuleType) -> None:
    hp.core_sync_quiet(_aged("none"))


def test_core_sync_quiet_reads_both_syslog_files_for_the_checkreloadstatus_line(hp: ModuleType) -> None:
    vm = _vm({"Syncing firewall": _done("none\n")})

    hp.core_sync_quiet(vm)

    (command,) = vm.calls
    assert "check_reload_status.*Syncing firewall" in command and "system.log.0" in command, command


def test_core_sync_quiet_fails_loudly_when_the_probe_fails(hp: ModuleType) -> None:
    vm = SimpleNamespace(ssh=lambda *_a, **_k: _done("", returncode=1, stderr="date: bad"))

    with pytest.raises(AssertionError, match="date: bad"):
        hp.core_sync_quiet(vm)


@pytest.mark.parametrize(
    ("probe", "age"),
    [
        ("Oct 18 02:41:40\n2026 Oct 18 02:41:47\n", 7),
        ("Oct  8 09:00:00\n2026 Oct  8 09:00:09\n", 9),  # syslog and date(1) both pad a one-digit day with a space
        ("Dec 31 23:59:58\n2027 Jan  1 00:00:05\n", 7),  # a December line read in January is last year's
        ("Feb 29 10:00:00\n2025 Jan 15 10:00:00\n", 27734400),  # a leap day cannot be in a year that has none
        ("none\n", None),
    ],
)
def test_sync_line_age_is_the_distance_to_the_last_line_whatever_the_year_boundary(
    hp: ModuleType, probe: str, age: int | None
) -> None:
    assert hp.sync_line_age(probe) == age


def test_sync_line_age_refuses_a_stamp_that_is_no_date_in_this_year_or_the_one_before(hp: ModuleType) -> None:
    """A leap day read in a year whose predecessor has none either: an error, never a guessed age."""
    with pytest.raises(ValueError, match="Feb 29 10:00:00"):
        hp.sync_line_age("Feb 29 10:00:00\n2026 Mar  5 10:00:00\n")


def _guest_running(tmp_path: Path, *processes: str) -> SimpleNamespace:
    """A guest that runs each command in a real ``/bin/sh``, where ``/bin/pgrep -f PATTERN`` greps ``processes``.

    Like the real pgrep, it also sees the probe's own shell command line: the pattern must not match its own text.
    """
    table = tmp_path / "ps"
    pgrep = tmp_path / "pgrep"
    pgrep.write_text(f'#!/bin/sh\ngrep -Eq -e "$2" {table}\n')
    pgrep.chmod(0o755)

    def ssh(*command: str, **_k: Any) -> subprocess.CompletedProcess[str]:
        line = " ".join(command)
        table.write_text("\n".join([*processes, f"sh -c {line}"]) + "\n")
        done = subprocess.run(
            ["/bin/sh", "-c", line.replace("/bin/pgrep", str(pgrep))], capture_output=True, text=True, check=False
        )
        return _done(done.stdout, done.returncode, done.stderr)

    return SimpleNamespace(ssh=ssh)


TICK = "php /usr/local/www/pfblockerng/pfblockerng.php tick"
SYNC = "/bin/sh /etc/rc.filter_synchronize"


@pytest.mark.parametrize(
    ("running", "signals"),
    [
        ((TICK, SYNC), ["pending", "tick", "sync"]),
        ((TICK,), ["pending", "tick"]),
        ((SYNC,), ["pending", "sync"]),
        (("/usr/sbin/sshd",), ["pending"]),
    ],
)
def test_in_flight_reports_each_signal_from_its_own_process_and_never_from_the_probe_itself(
    hp: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, running: tuple[str, ...], signals: list[str]
) -> None:
    monkeypatch.setattr(hp, "php_json", lambda *_a, **_k: True)

    assert hp.in_flight(_guest_running(tmp_path, *running)) == signals


def test_in_flight_is_empty_when_nothing_is_pending_and_no_process_runs(
    hp: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(hp, "php_json", lambda *_a, **_k: False)

    assert hp.in_flight(_guest_running(tmp_path, "/usr/sbin/sshd")) == []


# --------------------------------------------------------------------------- #
# Rows by identity: B's own values are compared per group / provider, never per list position
# --------------------------------------------------------------------------- #


def test_local_by_identity_keys_each_rows_local_leaves_by_alias_or_xml_whatever_its_position(hp: ModuleType) -> None:
    groups = {
        "config": [{"aliasname": "k2", "srcint": "wan", "action": "Deny_Both"}, {"aliasname": "k1", "srcint": "lan"}]
    }
    items = {"item": [{"xml": "bl_b", "username": "u", "password": "p", "feed": "f"}, {"xml": "bl_a", "username": ""}]}

    assert hp.local_by_identity(groups) == {"k2": {"srcint": "wan"}, "k1": {"srcint": "lan"}}
    assert hp.local_by_identity(items) == {"bl_b": {"username": "u", "password": "p"}, "bl_a": {"username": ""}}
    assert hp.identities(groups) == ["k2", "k1"] and hp.identities(items) == ["bl_b", "bl_a"]


def test_identities_survive_an_index_gap_an_empty_row_and_a_missing_section(hp: ModuleType) -> None:
    gapped = {"config": {"0": {"aliasname": "a"}, "2": {"aliasname": "c"}, "3": ""}}

    assert hp.identities(gapped) == ["a", "c"]
    assert hp.identities(None) == [] and hp.local_by_identity(None) == {}


def test_findings_are_the_recorded_strings_and_empty_before_an_apply(hp: ModuleType) -> None:
    recorded = _vm({"cat": _done(json.dumps({"time": 1, "findings": ["DNSBL disabled: x"]}))})

    assert hp.findings(recorded) == ["DNSBL disabled: x"]
    assert hp.findings(_vm({"cat": _done("__ABSENT__")})) == []


def test_pf_table_is_empty_while_the_table_does_not_exist_and_an_error_otherwise(hp: ModuleType) -> None:
    members = _vm({"pfctl": _done("   198.51.100.4\n\n   198.51.100.5\n")})
    missing = _vm({"pfctl": _done("", returncode=1, stderr="pfctl: Table does not exist.")})
    broken = _vm({"pfctl": _done("", returncode=1, stderr="pfctl: no permission")})

    assert hp.pf_table(members, "g") == ["198.51.100.4", "198.51.100.5"]
    assert "pfB_g_v4" in members.calls[0]
    assert hp.pf_table(missing, "g") == []
    with pytest.raises(AssertionError, match="no permission"):
        hp.pf_table(broken, "g")


def _gated(scope: str) -> dict[str, Any]:
    return {"installedpackages": {"pfblockerngsync": {"config": [{"syncscope": scope}]}}}


def test_policy_payload_is_built_from_the_projection_with_the_gate_leaf(
    hp: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[str] = []

    def php_json(_vm: object, php: str, **_k: Any) -> dict[str, Any]:
        seen.append(php)
        return _gated("policy")

    monkeypatch.setattr(hp, "php_json", php_json)

    assert hp.policy_payload(object()) == _gated("policy")
    (php,) = seen
    assert "pfb_sync_policy_projection($stored)" in php and "/syncscope'" in php and "'policy'" in php


@pytest.mark.parametrize("payload", [_gated("all"), {"installedpackages": {}}])
def test_policy_payload_refuses_a_payload_without_the_policy_gate_leaf(
    hp: ModuleType, monkeypatch: pytest.MonkeyPatch, payload: dict[str, Any]
) -> None:
    """A harness payload without the gate would be refused by B for the wrong reason: the builder must say so."""
    monkeypatch.setattr(hp, "php_json", lambda *_a, **_k: payload)

    with pytest.raises(AssertionError, match="payload gate leaf: expected 'policy'"):
        hp.policy_payload(object())


def test_send_payload_is_one_restore_config_section_call_with_the_ha_credentials(
    hp: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, Any]] = []

    def xmlrpc_call(_pair: object, **kw: Any) -> dict[str, Any]:
        calls.append(kw)
        return {"ok": True, "resp": True}

    monkeypatch.setattr(hp, "xmlrpc_call", xmlrpc_call)
    pair = SimpleNamespace(sync_password="pw")

    assert hp.send_payload(pair, {"installedpackages": {"x": ""}}) == {"ok": True, "resp": True}

    (call,) = calls
    assert (call["user"], call["password"], call["method"]) == ("pfbhasync", "pw", "restore_config_section")
    assert '{"installedpackages": {"x": ""}}' in call["params_php"]


def test_send_payload_can_speak_as_another_user_and_send_a_payload_that_is_no_array(
    hp: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R10 sends with a wrong password, an unprivileged user and a string where the payload array belongs."""
    calls: list[dict[str, Any]] = []

    def xmlrpc_call(_pair: object, **kw: Any) -> dict[str, Any]:
        calls.append(kw)
        return {"ok": True}

    monkeypatch.setattr(hp, "xmlrpc_call", xmlrpc_call)
    pair = SimpleNamespace(sync_password="pw")

    hp.send_payload(pair, {"a": ""}, password="not-pw")
    hp.send_payload(pair, {"a": ""}, user="noprivuser", password="np")
    hp.send_payload(pair, "not-an-array")

    assert [(c["user"], c["password"]) for c in calls] == [
        ("pfbhasync", "not-pw"),
        ("noprivuser", "np"),
        ("pfbhasync", "pw"),
    ]
    assert calls[2]["params_php"] == "json_decode('\"not-an-array\"', TRUE)", calls[2]["params_php"]


def _group_rig(hp: ModuleType, monkeypatch: pytest.MonkeyPatch) -> tuple[SimpleNamespace, Any, dict[str, Any]]:
    """Two named nodes; ``rig`` records the feed files written and the section each node stored."""
    rig: dict[str, Any] = {"feeds": [], "stored": {}}
    a, b = SimpleNamespace(name="A"), SimpleNamespace(name="B")
    tree = {"config": [{"aliasname": "old"}]}
    monkeypatch.setattr(hp, "write_feed", lambda vm, alias, address: rig["feeds"].append((vm.name, alias, address)))
    monkeypatch.setattr(hp, "read_sections", lambda _vm, _names: {"pfblockernglistsv4": json.loads(json.dumps(tree))})
    monkeypatch.setattr(hp, "write_sections", lambda vm, sections, _message: rig["stored"].update({vm.name: sections}))
    return SimpleNamespace(primary=a, secondary=b), hp.Baseline("gw", {}, "/mark"), rig


def test_add_deny_group_adds_one_group_with_the_nodes_own_local_values_and_feeds_both_nodes(
    hp: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    pair, baseline, rig = _group_rig(hp, monkeypatch)

    index = hp.add_deny_group(pair, baseline, "g1", "198.51.100.5", on=pair.secondary, tag="B")

    assert index == 1 and sorted(rig["feeds"]) == [("A", "g1", "198.51.100.5"), ("B", "g1", "198.51.100.5")]
    assert list(rig["stored"]) == ["B"], "the group must be stored on the node it is added to, and only there"
    old, new = rig["stored"]["B"]["pfblockernglistsv4"]["config"]
    assert old == {"aliasname": "old"}
    assert new["aliasname"] == "g1" and new["srcint"] == "wan", f"B's group carries B's local values: {new!r}"
    assert new["agateway_in"] == "gw"


def test_add_deny_group_defaults_to_node_a_and_appends_extra_feed_rows_to_the_group(
    hp: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    pair, baseline, rig = _group_rig(hp, monkeypatch)
    extra = {"header": "g2_key", "url": "https://feeds.invalid/g2.txt", "state": "Disabled", "format": "auto"}

    hp.add_deny_group(pair, baseline, "g2", "198.51.100.6", rows=[extra])

    _old, new = rig["stored"]["A"]["pfblockernglistsv4"]["config"]
    assert new["srcint"] == "lan", f"A's group carries A's local values: {new!r}"
    assert [row["header"] for row in new["row"]] == ["g2", "g2_key"]


def test_add_deny_group_stores_a_ready_made_group_as_given(hp: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    pair, baseline, rig = _group_rig(hp, monkeypatch)
    given = {"aliasname": "g3", "row": [{"header": "g3"}], "marker": "kept"}

    hp.add_deny_group(pair, baseline, "g3", "198.51.100.7", on=pair.primary, group=given)

    assert rig["stored"]["A"]["pfblockernglistsv4"]["config"][1] == given


# --------------------------------------------------------------------------- #
# The baseline: no stale sync, each node still owns its VIP, a failed apply cannot wedge the reset
# --------------------------------------------------------------------------- #


def test_assert_dnsbl_vip_names_what_a_stale_write_undid(hp: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    state = {"uniqids": ["pfbhaB3455"], "ref": "_vippfbhaB3455", "dnsbl": "on"}
    monkeypatch.setattr(hp, "php_json", lambda *_a, **_k: dict(state))
    hp.assert_dnsbl_vip(object(), "secondary", "pfbhaB3455")

    for broken, message in (
        ({"uniqids": []}, "not among its virtual IPs"),
        ({"ref": "_vipother"}, "pfb_dnsvip4"),
        ({"dnsbl": ""}, "pfb_dnsbl"),
    ):
        monkeypatch.setattr(hp, "php_json", lambda *_a, _b=broken, **_k: {**state, **_b})
        with pytest.raises(AssertionError, match=message):
            hp.assert_dnsbl_vip(object(), "secondary", "pfbhaB3455")


def test_reset_pair_clears_the_pending_mark_before_it_waits_and_checks_each_vip(
    hp: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    log: list[str] = []

    def node(name: str) -> SimpleNamespace:
        def ssh(*command: str, **_k: Any) -> subprocess.CompletedProcess[str]:
            log.append(f"{name}:{' '.join(command)}")
            return _done()

        return SimpleNamespace(ssh=ssh, name=name)

    pair = SimpleNamespace(primary=node("A"), secondary=node("B"))
    baseline = hp.Baseline("gw", {"primary": "dA", "secondary": "dB"}, "/mark")
    monkeypatch.setattr(hp, "settle", lambda vm: log.append(f"{vm.name}:settle"))
    monkeypatch.setattr(hp, "clear_sync_state", lambda vm: log.append(f"{vm.name}:clear"))
    monkeypatch.setattr(hp, "clear_sshguard", lambda vm: None)
    monkeypatch.setattr(hp, "in_flight", lambda vm: [])
    monkeypatch.setattr(hp, "assert_dnsbl_vip", lambda vm, name, uniqid: log.append(f"{vm.name}:vip={uniqid}"))
    monkeypatch.setattr(hp.h, "apply_filter_sync", lambda vm: None)
    monkeypatch.setattr(hp.h, "pfb_config_digest", lambda vm: {"A": "dA", "B": "dB"}[vm.name])

    hp.reset_pair(pair, baseline)

    b_steps = [line for line in log if line.startswith("B:")]
    assert (
        b_steps.index("B:rm -f /mark")
        < b_steps.index("B:settle")
        < next(i for i, line in enumerate(b_steps) if "cp -p" in line)
    )
    assert log.index("B:vip=pfbhaB3455") < log.index("A:rm -f /mark"), "B first, as ha_pair restores"
    assert "A:vip=pfbsmokevip" in log


def test_reset_pair_fails_loudly_when_the_restore_does_not_take(
    hp: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    vm = SimpleNamespace(ssh=lambda *_a, **_k: _done(), name="B")
    monkeypatch.setattr(hp, "settle", lambda _vm: None)
    monkeypatch.setattr(hp, "clear_sync_state", lambda _vm: None)
    monkeypatch.setattr(hp, "clear_sshguard", lambda _vm: None)
    monkeypatch.setattr(hp.h, "apply_filter_sync", lambda _vm: None)
    monkeypatch.setattr(hp.h, "pfb_config_digest", lambda _vm: "moved")

    with pytest.raises(AssertionError, match="did not take"):
        hp.reset_pair(
            SimpleNamespace(primary=vm, secondary=vm), hp.Baseline("gw", {"primary": "d", "secondary": "d"}, "/mark")
        )


def _reset_rig(
    hp: ModuleType, monkeypatch: pytest.MonkeyPatch, digests: dict[str, str]
) -> tuple[SimpleNamespace, Any, list[str]]:
    """Two fake nodes for ``reset_pair``; ``digests`` is the config digest each reads after its restore."""
    log: list[str] = []

    def node(name: str) -> SimpleNamespace:
        def ssh(*command: str, **_k: Any) -> subprocess.CompletedProcess[str]:
            log.append(f"{name}:{' '.join(command)}")
            return _done()

        return SimpleNamespace(ssh=ssh, name=name)

    pair = SimpleNamespace(primary=node("A"), secondary=node("B"))
    monkeypatch.setattr(hp, "settle", lambda vm: None)
    monkeypatch.setattr(hp, "clear_sync_state", lambda vm: None)
    monkeypatch.setattr(hp, "clear_sshguard", lambda vm: None)
    monkeypatch.setattr(hp, "in_flight", lambda vm: [])
    monkeypatch.setattr(hp, "assert_dnsbl_vip", lambda vm, name, uniqid: log.append(f"{vm.name}:vip={uniqid}"))
    monkeypatch.setattr(hp.h, "apply_filter_sync", lambda vm: None)
    monkeypatch.setattr(hp.h, "pfb_config_digest", lambda vm: digests[vm.name])
    return pair, hp.Baseline("gw", {"primary": "dA", "secondary": "dB"}, "/mark"), log


def test_reset_pair_still_restores_node_a_when_node_b_does_not_take(
    hp: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    pair, baseline, log = _reset_rig(hp, monkeypatch, {"A": "dA", "B": "moved"})

    with pytest.raises(AssertionError) as err:
        hp.reset_pair(pair, baseline)

    assert any(line.startswith("A:cp -p") for line in log), f"A was never restored after B failed: {log}"
    assert "A:vip=pfbsmokevip" in log, f"A's VIP was never checked after B failed: {log}"
    assert "secondary: baseline restore did not take: config digest moved != baseline dB" in str(err.value)
    assert "primary" not in str(err.value), f"A restored fine, yet the failure names it: {err.value}"


def test_reset_pair_raises_every_failing_node_together(hp: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    pair, baseline, _log = _reset_rig(hp, monkeypatch, {"A": "movedA", "B": "movedB"})

    with pytest.raises(AssertionError) as err:
        hp.reset_pair(pair, baseline)

    text = str(err.value)
    assert "secondary: baseline restore did not take: config digest movedB" in text
    assert "primary: baseline restore did not take: config digest movedA" in text


def test_arrange_baseline_takes_core_sync_off_a_first_and_checks_both_vips_before_it_snapshots(
    hp: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    log: list[str] = []

    def node(name: str) -> SimpleNamespace:
        def ssh(*command: str, **_k: Any) -> subprocess.CompletedProcess[str]:
            log.append(f"{name}:ssh {' '.join(command)}")
            return _done()

        return SimpleNamespace(ssh=ssh, name=name)

    a, b = node("A"), node("B")
    monkeypatch.setattr(hp, "set_leaves", lambda vm, leaves, *_a, **_k: log.append(f"{vm.name}:set {sorted(leaves)}"))
    monkeypatch.setattr(hp, "settle", lambda vm: log.append(f"{vm.name}:settle"))
    monkeypatch.setattr(hp, "gateway_name", lambda _vm: "gw")
    monkeypatch.setattr(hp, "write_feed", lambda *_a: "")
    monkeypatch.setattr(hp, "seed_node", lambda vm, tag, gw: log.append(f"{vm.name}:seed"))
    monkeypatch.setattr(hp, "php_write", lambda vm, *_a, **_k: log.append(f"{vm.name}:vipwrite"))
    monkeypatch.setattr(hp, "wait_filter_idle", lambda vm: None)
    monkeypatch.setattr(hp, "assert_dnsbl_vip", lambda vm, name, uniqid: log.append(f"{vm.name}:vip={uniqid}"))
    monkeypatch.setattr(hp, "php_json", lambda *_a, **_k: "/mark")
    for fn in ("inject_ip_lists", "ensure_dnsbl_vip", "set_dnsbl_enabled", "reload"):
        monkeypatch.setattr(hp.h, fn, lambda vm, *_a, **_k: log.append(f"{vm.name}:h"))
    monkeypatch.setattr(hp.h, "pfb_config_digest", lambda vm: f"digest-{vm.name}")

    baseline = hp.arrange_baseline(SimpleNamespace(primary=a, secondary=b))

    assert log[:2] == ["A:set ['hasync']", "A:settle"], f"core sync must be off before anything else: {log[:4]}"
    first_snapshot = next(i for i, line in enumerate(log) if "cp -p" in line)
    assert log.index("A:vip=pfbsmokevip") < first_snapshot and log.index("B:vip=pfbhaB3455") < first_snapshot
    assert baseline.digests == {"primary": "digest-A", "secondary": "digest-B"} and baseline.marker == "/mark"


# --------------------------------------------------------------------------- #
# Payload surgery and the credential list the R7/R8 greps lean on
# --------------------------------------------------------------------------- #


def test_inject_leaf_sets_a_leaf_in_a_map_and_in_a_list_row_and_creates_missing_maps(hp: ModuleType) -> None:
    payload: dict[str, Any] = {"installedpackages": {"blacklist": {"item": [{"xml": "a"}, {"xml": "b"}]}}}

    hp.inject_leaf(payload, "installedpackages/blacklist/item/1/password", "x")
    hp.inject_leaf(payload, "installedpackages/ipsettings/config/0/inbound_interface", "lan")

    assert payload["installedpackages"]["blacklist"]["item"] == [{"xml": "a"}, {"xml": "b", "password": "x"}]
    assert payload["installedpackages"]["ipsettings"] == {"config": {"0": {"inbound_interface": "lan"}}}


def test_inject_leaf_into_a_list_with_a_non_numeric_segment_is_an_error_not_a_silent_miss(hp: ModuleType) -> None:
    with pytest.raises(ValueError):
        hp.inject_leaf({"a": {"item": [{"xml": "a"}]}}, "a/item/nope/password", "x")


def test_row_key_finds_a_row_by_identity_in_a_list_or_a_map_and_fails_loudly_otherwise(hp: ModuleType) -> None:
    rows = [{"xml": "bl_gamma"}, "", {"xml": "bl_alpha"}]

    assert hp.row_key(rows, "xml", "bl_alpha") == "2"
    assert hp.row_key({"3": {"xml": "bl_alpha"}, "7": {"xml": "bl_beta"}}, "xml", "bl_beta") == "7"
    with pytest.raises(AssertionError, match="no row with xml='bl_none'"):
        hp.row_key(rows, "xml", "bl_none")


def test_credential_values_cover_the_four_scalars_and_each_providers_username_and_password(hp: ModuleType) -> None:
    values = hp.credential_values("A")

    assert len(values) == len(set(values)) == 4 + 2 * len(hp.BLACKLIST_XML)
    assert {"PFBHA-A-maxmind_account", "PFBHA-A-maxmind_key", "PFBHA-A-asn_token", "PFBHA-A-top1m_token"} <= set(values)
    for xml in hp.BLACKLIST_XML:
        assert f"PFBHA-A-{xml}_user" in values and f"PFBHA-A-{xml}_pass" in values
    assert not set(values) & set(hp.credential_values("B")), "A's and B's credentials must never coincide"
