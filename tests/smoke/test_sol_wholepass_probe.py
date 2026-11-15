"""Temporary #3977 whole-program observations; copy as test_sol_wholepass_probe.py.

This is NOT native scheduled acceptance. Both comparison passes ask Core for
trigger=retry; Core alone selects feeds/Extras. No caller supplies feed IDs.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

import pytest

from . import helpers as h
from .conftest import SmokeVM, _MockFeedServer
from .test_core_update import (
    UPDATE_WATCHDOG,
    _assert_dnsbl_prerequisites,
    _prepare_mock_feeds,
    _run_update,
    _snapshot,
    await_idle,
)
from .test_core_update import core_vm as core_vm
from .test_extras_dispatcher_deferral import _set_registered_toggle
from .test_smoke_feeds import _blacklist_tar_gz

pytestmark = pytest.mark.smoke
DB = "/var/db/pfblockerng"
PROVIDER, TITLE, CATEGORY = "ut1", "UT1", "test-cat"
BLACKLIST = "installedpackages/pfblockerngblacklist"
ROOTS = {"ipv4": h.CFG_IP_V4_LISTS, "ipv6": h.CFG_IP_V6_LISTS, "dnsbl": h.CFG_DNSBL_LISTS}


def _php(vm: SmokeVM, code: str) -> None:
    result = h.php_eval(vm, code + "write_config('temporary whole-pass observation'); echo 'OK';")
    assert result.returncode == 0 and "OK" in result.stdout, (result.stdout, result.stderr)
    h.tell_core_the_settings_changed(vm)


def _clock(vm: SmokeVM) -> str:
    result = vm.ssh("date", "+%s:%Y-%m-%d:%z")
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def _schedule(vm: SmokeVM) -> dict[str, Any]:
    reply = h.core_call(vm, "GetSchedule")
    assert reply["status"] == 200, reply
    body: dict[str, Any] = reply["body"]
    return body


def _actions(vm: SmokeVM, paths: list[str]) -> dict[str, dict[str, str]]:
    return {
        path: {
            "bytesBase64": base64.b64encode(body).decode(),
            "sha256": hashlib.sha256(body).hexdigest(),
            "statInodeMtimeCtimeSize": stat,
            "text": body.decode("ascii"),
        }
        for path, (body, stat) in _snapshot(vm, paths).items()
    }


def _customs(vm: SmokeVM, rows: list[dict[str, str]], generation: int) -> None:
    code = ""
    for row in rows:
        custom = _body(row["kind"], row["cadence"], generation, custom=True)
        code += (
            f"$groups=config_get_path({h._php_str(ROOTS[row['kind']])}, array());"
            f"foreach ($groups as &$group) {{ if ($group['aliasname']==={h._php_str(row['alias'])}) {{"
            f"$group['cron']={h._php_str(row['cadence'])};"
            f"$group['custom']=base64_encode({h._php_str(custom)}); }} }} unset($group);"
            f"config_set_path({h._php_str(ROOTS[row['kind']])}, $groups);"
        )
    _php(vm, code)


def _body(kind: str, cadence: str, generation: int, custom: bool = False) -> str:
    number = generation * 20 + (5 if cadence == "Never" else 1) + (2 if custom else 0)
    if kind == "ipv4":
        return f"198.51.100.{number}\n"
    if kind == "ipv6":
        return f"2001:db8::{number}\n"
    return f"wp-{number}.example.com\n"


@pytest.mark.timeout(4 * UPDATE_WATCHDOG + 600)
def test_sol_wholepass_cadence_observations(core_vm: SmokeVM, mock_feeds: _MockFeedServer, tmp_path: Path) -> None:
    vm = core_vm
    assert vm.host in ("127.0.0.1", "localhost"), "probe requires a disposable smoke guest, never owner firewall"
    destination = Path(os.environ.get("SOL_WHOLEPASS_JSON", str(tmp_path / "wholepass-observations.json")))
    report: dict[str, Any] = {
        "schema": 1,
        "label": os.environ.get("SOL_WHOLEPASS_LABEL", "unlabelled"),
        "acceptance": "observational manual baseline + real Core retry; NOT genuine scheduled acceptance",
        "hypotheses": [
            "custom follows due parent/category follows refreshed Extra",
            "legacy own-ID guards retain existing actions",
        ],
        "operations": [],
        "rows": [],
        "cleanup": "not started",
    }
    rows: list[dict[str, str]] = report["rows"]
    archive_name = f"{PROVIDER}.tar.gz"
    names: list[str] = []
    paths: list[str] = []
    raw_fields = {
        f"{h.CFG_IP_SETTINGS}/maxmind_key": "",
        f"{h.CFG_IP_SETTINGS}/maxmind_account": "",
        f"{h.CFG_IP_SETTINGS}/asn_token": "",
    }
    toggles = (
        ("ip/database_cc", f"{h.CFG_IP_SETTINGS}/database_cc", True),
        ("dnsbl/top1m_enable", f"{h.CFG_DNSBL_SETTINGS}/top1m_enable", False),
    )
    originals = {path: h.config_get_state(vm, path) for path in (*raw_fields, *(t[1] for t in toggles))}
    report["dccConfig"] = {"originalPresence": {path: state[0] for path, state in originals.items()}}
    try:
        await_idle(vm)
        _prepare_mock_feeds(vm, dnsbl=True)
        for path, value in raw_fields.items():
            h.config_set(vm, path, value)
        for key, _path, on in toggles:
            _set_registered_toggle(vm, key, on=on)
        effective = h.php_eval(
            vm,
            "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');"
            "pfb_global();"
            "echo 'DCC_CONFIG_BEGIN'.json_encode(array("
            "'maxmind_key_empty'=>empty($pfb['maxmind_key']),"
            "'maxmind_account_empty'=>empty($pfb['maxmind_account']),"
            "'asn_token_empty'=>empty($pfb['asn_token']),"
            "'database_cc'=>$pfb['cc'],"
            "'top1m_enable'=>$pfb['dnsbl_top1m'] === PfbToggle::On"
            ")).'DCC_CONFIG_END';",
        )
        assert effective.returncode == 0, (effective.stdout, effective.stderr)
        effective_config = json.loads(effective.stdout.split("DCC_CONFIG_BEGIN", 1)[1].split("DCC_CONFIG_END", 1)[0])
        report["dccConfig"]["effective"] = effective_config
        assert effective_config == {
            "maxmind_key_empty": True,
            "maxmind_account_empty": True,
            "asn_token_empty": True,
            "database_cc": True,
            "top1m_enable": False,
        }, "DCC is not eligible for a credential-less, conversion-free clean no-op"
        # Scheduling remains off during baseline; ordinary settings only, never clock/ledger edits.
        h.config_set(vm, f"{h.CFG_GLOBAL}/pfb_scheduled_feed_updates", "")
        h.tell_core_the_settings_changed(vm)
        h.unblock_egress()
        ips: list[h.IpCase] = []
        dns: list[tuple[h.DnsblCase, str]] = []
        for kind in ROOTS:
            for cadence, suffix in (("EveryDay", "due"), ("Never", "never")):
                alias = f"wp{kind}{suffix}"
                name = f"wholepass_{kind}_{suffix}.txt"
                names.append(name)
                url = mock_feeds.register(name, _body(kind, cadence, 1))
                mock_feeds.disable_lastmod(name)
                stem = alias + {"ipv4": "_v4", "ipv6": "_v6", "dnsbl": ""}[kind]
                custom_stem = alias + {"ipv4": "_custom_v4", "ipv6": "_custom_v6", "dnsbl": "_custom"}[kind]
                folder = "dnsbl" if kind == "dnsbl" else "deny"
                row = {
                    "kind": kind,
                    "alias": alias,
                    "cadence": cadence,
                    "mock": name,
                    "id": f"{kind}:{stem}",
                    "action": f"{DB}/{folder}/{stem}.txt",
                    "customAction": f"{DB}/{folder}/{custom_stem}.txt",
                }
                rows.append(row)
                paths.extend((row["action"], row["customAction"]))
                if kind == "dnsbl":
                    dns.append(
                        (
                            h.DnsblCase(
                                aliasname=alias,
                                header=alias,
                                feed_url=url,
                                custom_domains=[_body(kind, cadence, 1, True).strip()],
                            ),
                            "Deny",
                        )
                    )
                else:
                    ips.append(
                        h.IpCase(aliasname=alias, header=alias, feed_url=url, family="v4" if kind == "ipv4" else "v6")
                    )
        h.inject_dnsbl_lists(vm, dns)
        h.inject_ip_lists(vm, ips)
        _assert_dnsbl_prerequisites(vm)
        _customs(vm, rows, 1)
        archive_url = mock_feeds.register(
            archive_name, _blacklist_tar_gz(PROVIDER, CATEGORY, "wp-category-1.example.com")
        )
        mock_feeds.disable_lastmod(archive_name)
        names.append(archive_name)
        category_action = f"{DB}/dnsbl/{TITLE}_test_cat.txt"
        paths.append(category_action)
        report["category"] = {
            "provider": PROVIDER,
            "title": TITLE,
            "rawCategory": CATEGORY,
            "action": category_action,
            "mock": archive_name,
            "url": archive_url,
        }
        _php(
            vm,
            f"config_set_path({h._php_str(BLACKLIST)}, array('blacklist_enable'=>'Enable',"
            f"'blacklist_freq'=>'Never','blacklist_selected'=>'{PROVIDER}', 'item'=>array(array("
            f"'xml'=>'{PROVIDER}','title'=>'{TITLE}','feed'=>{h._php_str(archive_url)},"
            f"'selected'=>'{CATEGORY}','size'=>'0'))));"
            f"$g=config_get_path({h._php_str(h.CFG_GLOBAL)},array());"
            "$g['pfb_schedule_weekday']='1';$g['pfb_schedule_hour']='0';$g['pfb_schedule_minute']='0';"
            f"config_set_path({h._php_str(h.CFG_GLOBAL)},$g);",
        )
        preparation_started = time.time_ns()
        transfer = vm.ssh(h.PHP_BIN, "-f", h.PFB_CLI, "bls", PROVIDER, timeout=180)
        assert transfer.returncode == 0, f"controlled baseline Blacklist transfer failed: {transfer}"
        assert 200 in mock_feeds.statuses(archive_name), "baseline archive was not fetched through real Extras"
        report["preparation"] = {
            "command": ["php", "-f", h.PFB_CLI, "bls", PROVIDER],
            "hostStartNs": preparation_started,
            "hostEndNs": time.time_ns(),
            "returncode": transfer.returncode,
            "stdout": transfer.stdout,
            "stderr": transfer.stderr,
            "archiveHttp": mock_feeds.statuses(archive_name),
            "meaning": "real standalone Extras setup before measured manual/retry operations",
        }

        report["controlledInputs"] = {
            str(generation): {
                "regular": {
                    r["mock"]: _body(r["kind"], r["cadence"], generation)
                    for r in rows
                    if generation < 3 or r["cadence"] == "Never"
                },
                "custom": {r["alias"]: _body(r["kind"], r["cadence"], generation, True) for r in rows}
                if generation < 3
                else {},
                "archiveDomain": f"wp-category-{generation}.example.com",
                "archiveSha256": hashlib.sha256(
                    _blacklist_tar_gz(PROVIDER, CATEGORY, f"wp-category-{generation}.example.com")
                ).hexdigest(),
            }
            for generation in (1, 2, 3)
        }

        def operation(label: str, trigger: str, *, expect_sync: bool = True) -> dict[str, Any]:
            op: dict[str, Any] = {
                "label": label,
                "request": {
                    "method": "StartUpdate",
                    "params": {"trigger": "manual", "scope": "both", "force": "none"}
                    if trigger == "manual"
                    else {"trigger": "retry"},
                },
                "hostRequestStartNs": time.time_ns(),
                "guestBefore": _clock(vm),
                "scheduleBefore": _schedule(vm),
                "httpBefore": {n: mock_feeds.statuses(n) for n in names},
            }
            report["operations"].append(op)
            update, log = _run_update(vm, trigger)
            op.update(
                update=update,
                log=log,
                hostCompletionNs=time.time_ns(),
                guestAfter=_clock(vm),
                scheduleAfter=_schedule(vm),
                httpAfter={n: mock_feeds.statuses(n) for n in names},
            )
            op["httpDelta"] = {n: op["httpAfter"][n][len(op["httpBefore"][n]) :] for n in names}
            op["httpCounts"] = {
                n: {
                    "before": len(op["httpBefore"][n]),
                    "after": len(op["httpAfter"][n]),
                    "delta": len(op["httpDelta"][n]),
                }
                for n in names
            }
            op["actions"] = _actions(vm, paths)
            # Observations are saved before any assertion about the operation.
            destination.write_text(json.dumps(report, indent=2) + "\n")
            assert update["trigger"] == trigger and update["result"] == "success", update
            assert update["finishedAt"] >= update["startedAt"] > 0, update
            assert (
                int(op["guestBefore"].split(":")[0])
                <= update["startedAt"]
                <= update["finishedAt"]
                <= int(op["guestAfter"].split(":")[0])
            ), op
            if expect_sync:
                assert "UPDATE PROCESS START" in log and "UPDATE PROCESS ENDED" in log, log
            else:
                assert "===[  Aliastables / Rules  ]" not in log, "a no-due retry performed an inline sync"
                assert not any(line.startswith("feed ") for line in log.splitlines()), log
            assert h.core_update_view(vm)["update"] == update, "another Update replaced the observed record"
            return op

        baseline = operation("manual-baseline", "manual")
        assert all(v["text"].strip() for v in baseline["actions"].values()), "empty baseline action"
        assert all(200 in baseline["httpDelta"][n] for n in names if n != archive_name), (
            "baseline did not fetch every controlled regular source"
        )
        # Empty check state is a precondition, not something this probe fabricates.
        initial_checks = baseline["scheduleAfter"]["lastSuccessfulCheck"]
        assert all(r["id"] not in initial_checks for r in rows), initial_checks
        assert "extra:bl" not in initial_checks, "BlacklistExtra already checked: use a fresh guest"
        for row in rows:
            mock_feeds.set_content(row["mock"], _body(row["kind"], row["cadence"], 2))
        _customs(vm, rows, 2)
        mock_feeds.set_content(archive_name, _blacklist_tar_gz(PROVIDER, CATEGORY, "wp-category-2.example.com"))
        h.config_set(vm, f"{BLACKLIST}/blacklist_freq", "EveryDay")
        h.tell_core_the_settings_changed(vm)
        with h.scheduled_updates_on(vm):
            first = operation("retry-due-groups-and-BlacklistExtra", "retry")
            checks = first["scheduleAfter"]["lastSuccessfulCheck"]
            report["selectionEvidence"] = (
                "GetUpdate does not expose feeds/Extras; use HTTP deltas, log and lastSuccessfulCheck, "
                "not invented request fields"
            )
            assert all(r["id"] in checks for r in rows if r["cadence"] == "EveryDay"), checks
            assert "extra:bl" in checks, "due BlacklistExtra did not record a successful check"
            for row in rows:
                if row["cadence"] == "Never":
                    assert not first["httpDelta"][row["mock"]], f"cadence violation: {row}"
                    assert first["actions"][row["action"]] == baseline["actions"][row["action"]], (
                        f"not-due regular rewritten: {row}"
                    )
                else:
                    assert 200 in first["httpDelta"][row["mock"]], f"due source not fetched: {row}"
            assert 200 in first["httpDelta"][archive_name], "due Extra did not fetch controlled archive"
            # Change only unselected regular sources and the archive: no new occurrence is created.
            for row in rows:
                if row["cadence"] == "Never":
                    mock_feeds.set_content(row["mock"], _body(row["kind"], row["cadence"], 3))
            mock_feeds.set_content(archive_name, _blacklist_tar_gz(PROVIDER, CATEGORY, "wp-category-3.example.com"))
            second = operation("retry-without-new-due-occurrence", "retry", expect_sync=False)
            assert baseline["guestBefore"].split(":")[1] == second["guestAfter"].split(":")[1], (
                "crossed midnight: repeat on fresh guest"
            )
            assert second["scheduleAfter"]["lastSuccessfulCheck"] == checks, (
                "a successful check moved without a new due occurrence"
            )
            assert all(not v for v in second["httpDelta"].values()), "unselected source was contacted"
            for row in rows:
                if row["cadence"] == "Never":
                    assert second["actions"][row["action"]] == first["actions"][row["action"]], (
                        f"not-due regular rewritten: {row}"
                    )
            report["secondPassPreserved"] = {p: second["actions"][p] == first["actions"][p] for p in paths}
            report["firstPassChanged"] = {p: first["actions"][p] != baseline["actions"][p] for p in paths}
            report["observationCompleted"] = True
    except BaseException as error:
        report["error"] = f"{type(error).__name__}: {error}"
        try:
            extras_log = vm.ssh("cat", f"{h.PFB_LOGDIR}/extras.log", timeout=30)
            report["failureExtrasLog"] = {
                "returncode": extras_log.returncode,
                "stdout": extras_log.stdout,
                "stderr": extras_log.stderr,
            }
        except Exception as diagnostic_error:
            report["failureExtrasLogError"] = f"{type(diagnostic_error).__name__}: {diagnostic_error}"
        raise
    finally:
        # This record closes BEFORE ordinary cleanup. Cleanup is never a comparison Update.
        report["evidenceClosedHostNs"] = time.time_ns()
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, indent=2) + "\n")
        print(f"SOL_WHOLEPASS_JSON={destination}")
        print("SOL_WHOLEPASS_OBSERVATIONS=" + json.dumps(report, sort_keys=True))
        try:
            h.reset(vm)
            report["cleanup"] = "ordinary h.reset completed after evidence closed"
        finally:
            errors: list[Exception] = []
            for path, state in originals.items():
                try:
                    h.config_restore_state(vm, path, state)
                    assert h.config_get_state(vm, path) == state, f"raw config restore failed: {path}"
                except Exception as error:
                    errors.append(error)
            try:
                h.tell_core_the_settings_changed(vm)
            except Exception as error:
                errors.append(error)
            report["dccConfig"]["restoreErrors"] = [str(error) for error in errors]
            report["dccConfig"]["restored"] = not errors
            destination.write_text(json.dumps(report, indent=2) + "\n")
            if errors:
                raise ExceptionGroup("DCC fixture config restoration failed", errors)
