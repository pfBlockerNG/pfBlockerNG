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
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest


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
    assert "config_del_path($p)" in snippet and "write_config('m')" in snippet


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


def test_sync_once_does_not_wait_for_an_apply_after_an_unchanged_receive(
    hp: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    banners = iter([5, 5])
    monkeypatch.setattr(hp, "node_time", lambda _vm: 100)
    monkeypatch.setattr(hp, "apply_banners", lambda _vm: next(banners))
    monkeypatch.setattr(hp, "trigger_send", lambda *_a, **_k: None)
    monkeypatch.setattr(hp, "send_state", lambda _vm: {})
    monkeypatch.setattr(hp, "receive_state", lambda _vm: {"last": {"time": 101, "outcome": "unchanged"}})
    monkeypatch.setattr(hp, "wait_apply", lambda *_a, **_k: pytest.fail("an unchanged receive opens no apply"))
    pair = SimpleNamespace(primary=object(), secondary=object())

    assert hp.sync_once(pair, "automatic").passes == 0
