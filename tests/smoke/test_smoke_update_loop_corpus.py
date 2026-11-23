"""issue #4038 sub-slice 9j-1: the Core Updater's end-to-end corpus, captured from today's PHP Update on a pfSense box.

The corpus (go/pfb_core/update/testdata/e2e/corpus.json, schema in its README.md) defines each case: the feed
groups, the bodies a mock feed server serves, and the Updates to run in order. Each Update runs today's Update program
as Core runs it (``pfb_core_update.sh``: one version 1 request on stdin, the result on fd 3). After each one the
harness records what the Go loop must reproduce (go/pfb_core/update/e2e_replay_test.go):

* the desired sets: every ``pfB_*`` mirror under ``/var/db/aliastables``;
* the DNSBL data: the manifest ``pfb_py_sources.json`` with the lines of each feed's raw file;
* the feed outcomes and the attempted ids: the result lines on fd 3, added up;
* the issues: the open entries of the ADR-61 sync-status ledgers (``pfb_sync_status_read_all()`` and pfB-DNS's own);
* the stage order: the transcript's stage headers in the order they first appear, named as the Go loop names them;
* the settings snapshot the loop would take: the settings adapter's read before the Update, the mock server's address
  written as ``{{FEEDS}}``. It is the replay's input, never compared here.

Every run writes its records to ``helpers.DIAG_DIR / "update_loop_corpus_actual.json"`` so a run can be frozen into the
corpus's ``expect``. A case without a frozen ``expect`` fails.
"""

from __future__ import annotations

import json
import os
import re
import shlex
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from . import helpers as h
from .conftest import SmokeVM, _MockFeedServer, _StubDnsServer

pytestmark = pytest.mark.smoke

CORPUS = Path(__file__).resolve().parents[2] / "go" / "pfb_core" / "update" / "testdata" / "e2e" / "corpus.json"
ACTUAL = "update_loop_corpus_actual.json"
FEEDS_TOKEN = "{{FEEDS}}"
SETTINGS_CMD = "/usr/local/pkg/pfblockerng/pfb_core_settings.sh"
RESULT_FILE = "/tmp/pfb_smoke_e2e_result.jsonl"
CASE_KEYS = {"id", "description", "groups", "serve", "steps", "ordering", "dnsbl_ip", "expect"}
STEP_KEYS = {"request", "serve"}
EXPECT_KEYS = {"exit", "outcomes", "attempted", "sets", "dnsbl", "issues", "stages", "snapshot"}
# Compared by the smoke test; "snapshot" is the replay's input and changes with every package default.
COMPARED = EXPECT_KEYS - {"snapshot"}
KINDS = ("ipv4", "ipv6", "dnsbl")
TRIGGERS = ("scheduled", "retry", "manual", "apply")

# The transcript's stage headers, each named as the Go loop names the stage (go/pfb_core/update/loop.go, stages).
STAGE_MARKERS: tuple[tuple[str, str], ...] = (
    ("dnsbl", "===[  DNSBL Process  ]"),
    ("geoip-sets", "===[  GeoIP Process  ]"),
    ("ip", "===[  IPv4 Process  ]"),
    ("ip", "===[  IPv6 Process  ]"),
    ("apply", "===[  Aliastables / Rules  ]"),
)

_OPEN, _CLOSE = "<<<E2E>>>", "<<<E2E-END>>>"

# Everything the loop's outputs are compared with, read on the box after an Update.
CAPTURE_PHP = r"""
require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');
pfb_global();
global $pfb;
$out = array('sets' => array(), 'dnsbl' => NULL, 'issues' => array());
foreach (glob("{$pfb['aliasdir']}/pfB_*.txt") ?: array() as $f) {
	$t = (string) file_get_contents($f);
	$out['sets'][basename($f, '.txt')] = ($t === '') ? array() : explode("\n", rtrim($t, "\n"));
}
ksort($out['sets'], SORT_STRING);
$m = $pfb['unbound_py_sources'];
if (is_file($m)) {
	$man = json_decode((string) file_get_contents($m), TRUE);
	$feeds = array();
	foreach ($man['feeds'] as $row) {
		$raw = (string) file_get_contents(dirname($m) . "/{$row['raw']}");
		unset($row['raw']);
		$row['rows'] = ($raw === '') ? array() : explode("\n", substr($raw, 0, -1));
		$feeds[] = $row;
	}
	$out['dnsbl'] = array('config' => $man['config'], 'feeds' => $feeds);
}
$ledger = array_merge(pfb_sync_status_flatten(pfb_sync_status_read_all($pfb['dbdir'])),
    pfb_py_sync_status_list_open($pfb['dnsbldir']));
foreach ($ledger as $e) {
	unset($e['first_seen'], $e['last_seen']);
	$out['issues'][] = $e;
}
usort($out['issues'], fn($a, $b) => strcmp(json_encode($a), json_encode($b)));
"""


def corpus() -> dict[str, Any]:
    doc: dict[str, Any] = json.loads(CORPUS.read_text(encoding="utf-8"))
    return doc


def validate(doc: dict[str, Any]) -> list[str]:
    """Strict schema: an unknown or missing key, a duplicate id or header, and a malformed request are errors."""
    errors = []
    if set(doc) != {"schema", "cases"} or doc["schema"] != 1:
        errors.append(f"top level must be exactly schema=1 and cases, got {sorted(doc)}")
    ids: set[str] = set()
    headers: set[str] = set()
    for case in doc.get("cases", []):
        cid = case.get("id", "?")
        if not {"id", "description", "groups", "serve", "steps"} <= set(case) or not set(case) <= CASE_KEYS:
            errors.append(f"{cid}: keys {sorted(case)} do not fit the case schema")
        if cid in ids:
            errors.append(f"duplicate id {cid}")
        ids.add(cid)
        for g in case.get("groups", []):
            if g.get("kind") not in KINDS or not re.fullmatch(r"[A-Za-z0-9_]+", g.get("name", "")):
                errors.append(f"{cid}: group {g!r} has no valid kind and name")
            for f in g.get("feeds", []):
                header = f.get("header", "")
                if not re.fullmatch(r"[A-Za-z0-9_]+", header) or header in headers:
                    errors.append(f"{cid}: feed header {header!r} is invalid or used by another case")
                headers.add(header)
        for i, step in enumerate(case.get("steps", [])):
            if not set(step) <= STEP_KEYS or step.get("request", {}).get("trigger") not in TRIGGERS:
                errors.append(f"{cid}: step {i} is not a request with a known trigger: {step!r}")
        expect = case.get("expect")
        if expect is not None and (
            len(expect) != len(case.get("steps", [])) or any(set(e) != EXPECT_KEYS for e in expect)
        ):
            errors.append(f"{cid}: expect must hold one record of keys {sorted(EXPECT_KEYS)} per step")
    return errors


def stages(transcript: str) -> list[str]:
    """The stages the transcript shows, in the order their headers first appear, each once in a row."""
    found = sorted((transcript.find(marker), name) for name, marker in STAGE_MARKERS if transcript.find(marker) >= 0)
    out: list[str] = []
    for _, name in found:
        if not out or out[-1] != name:
            out.append(name)
    return out


def results(text: str) -> tuple[dict[str, str], list[str]]:
    """The result lines added up, as Core's readResult adds them: outcomes merged, attempted ids in order, each once."""
    outcomes: dict[str, str] = {}
    attempted: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        outcomes.update(row.get("outcomes") or {})
        attempted += [a for a in row.get("attempted") or [] if a not in attempted]
    return outcomes, attempted


def snapshot(reply: dict[str, Any], base: str) -> dict[str, Any]:
    """The settings read as the loop would take it, the mock server's address replaced by FEEDS_TOKEN."""
    text = json.dumps(reply, sort_keys=True).replace(base.rstrip("/"), FEEDS_TOKEN)
    out: dict[str, Any] = json.loads(text)
    return out


def config_php(case: dict[str, Any], base: str) -> str:
    """One write_config() that sets exactly this case's feed groups (every other group of the three lists removed)."""
    lists: dict[str, list[str]] = {k: [] for k in KINDS}
    for g in case["groups"]:
        rows = ", ".join(
            h._php_kv_array({"header": f["header"], "url": base + f["serve"], "state": "Enabled", "format": "auto"})
            for f in g["feeds"]
        )
        if g["kind"] == "dnsbl":
            head = {"aliasname": g["name"], "action": "unbound", "cron": "EveryDay", "order": "primary"}
            head["logging"] = "disabled_log"
        else:
            head = {"aliasname": g["name"], "action": g["action"], "cron": "EveryDay"}
        lists[g["kind"]].append(f"array_merge({h._php_kv_array(head)}, array('row' => array({rows})))")
    roots = {"ipv4": h.CFG_IP_V4_LISTS, "ipv6": h.CFG_IP_V6_LISTS, "dnsbl": h.CFG_DNSBL_LISTS}
    dnsbl = {"pfb_dnsbl": "on", "global_log_mode": "default", "global_log": "disabled_log"}
    if case.get("dnsbl_ip"):
        dnsbl["action"] = case["dnsbl_ip"]
    ipset = {"inbound_interface": h.SMOKE_IP_IFACE, "outbound_interface": h.SMOKE_IP_IFACE}
    return (
        f"$g = config_get_path({h._php_str(h.CFG_GLOBAL)}, array());\n"
        "$g['enable_cb'] = 'on';\n"
        f"config_set_path({h._php_str(h.CFG_GLOBAL)}, $g);\n"
        f"$ip = array_merge(config_get_path({h._php_str(h.CFG_IP_SETTINGS)}, array()), {h._php_kv_array(ipset)});\n"
        f"config_set_path({h._php_str(h.CFG_IP_SETTINGS)}, $ip);\n"
        f"{h._dnsbl_ip_iface_php(case.get('dnsbl_ip'))}"
        f"{h._dnsbl_settings_replace_php(dnsbl) if lists['dnsbl'] else ''}"
        + "".join(f"config_set_path({h._php_str(roots[k])}, array({', '.join(v)}));\n" for k, v in lists.items())
        + "write_config('pfBlockerNG smoke: update loop corpus');\necho 'OK';"
    )


def serve(mock: _MockFeedServer, bodies: dict[str, dict[str, str]]) -> None:
    for name, b in bodies.items():
        mock.register(name, b["text"])
        mock.set_content(name, b["text"], etag=b["etag"])


def _delimited(vm: SmokeVM, php: str, expr: str) -> Any:
    run = h.php_eval(vm, f"{php}\necho {h._php_str(_OPEN)} . json_encode({expr}) . {h._php_str(_CLOSE)};", timeout=300)
    if _OPEN not in run.stdout or _CLOSE not in run.stdout:
        raise AssertionError(f"no delimited reply: rc={run.returncode}\n{run.stdout[-2000:]}\n{run.stderr[-2000:]}")
    return json.loads(run.stdout.split(_OPEN, 1)[1].split(_CLOSE, 1)[0])


def run_step(vm: SmokeVM, step: dict[str, Any], base: str) -> tuple[dict[str, Any], str]:
    """One Update of today's program, and what it left: the record of EXPECT_KEYS, and the whole transcript."""
    read = vm.ssh(f'printf %s \'{{"version":1,"op":"read"}}\' | {SETTINGS_CMD}', timeout=120)
    assert read.returncode == 0, f"the settings adapter failed: {read.stdout[-1000:]}{read.stderr[-1000:]}"
    request = {"version": 1, **step["request"]}
    # No timer decides anything: the program runs to its own end; the timeout only caps a hung session.
    run = vm.ssh(
        f"rm -f {RESULT_FILE}; printf %s {shlex.quote(json.dumps(request))} | {h.CORE_UPDATE_CMD} 3>{RESULT_FILE}",
        timeout=1800,
    )
    result = vm.ssh(f"cat {RESULT_FILE}", timeout=60)
    outcomes, attempted = results(result.stdout if result.returncode == 0 else "")
    left = _delimited(vm, CAPTURE_PHP, "$out")
    record = {
        "exit": run.returncode,
        "outcomes": outcomes,
        "attempted": attempted,
        "sets": left["sets"] or {},  # PHP encodes an empty array as a list
        "dnsbl": left["dnsbl"],
        "issues": left["issues"],
        "stages": stages(run.stdout),
        "snapshot": snapshot(json.loads(read.stdout), base),
    }
    return record, run.stdout + ("\n--- stderr ---\n" + run.stderr if run.stderr else "")


def mismatches(want: list[dict[str, Any]], got: list[dict[str, Any]]) -> list[str]:
    """Every compared key of every step that differs, expected against actual."""
    out = []
    for i, (w, g) in enumerate(zip(want, got, strict=True)):
        for key in sorted(COMPARED):
            if w[key] != g[key]:
                out.append(f"step {i} {key}: expected {json.dumps(w[key])[:600]} actual {json.dumps(g[key])[:600]}")
    return out


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[SmokeVM]:
    """The branch package deployed once, System DNS on the stub, egress open."""
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    h.use_system_dns_upstream(smoke_vm)
    h.unblock_egress()
    try:
        yield smoke_vm
    finally:
        h.collect_host_diagnostics(smoke_vm)


def _record(case_id: str, records: list[dict[str, Any]], transcripts: list[str]) -> None:
    """Add this case's records to the run's actual file, so the run can be frozen."""
    h.DIAG_DIR.mkdir(parents=True, exist_ok=True)
    path = h.DIAG_DIR / ACTUAL
    doc = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"cases": {}}
    doc["cases"][case_id] = {"expect": records, "transcripts": transcripts}
    path.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


def test_corpus_is_well_formed() -> None:
    errors = validate(corpus())
    assert errors == [], "\n".join(errors[:40])


def test_stage_order_is_the_order_the_headers_first_appear() -> None:
    """Scenario: the IPv4 and IPv6 headers between DNSBL and the tables give each stage once, in order."""
    text = (
        "x\n===[  DNSBL Process  ]==\n===[  IPv4 Process  ]==\n===[  IPv6 Process  ]==\n===[  Aliastables / Rules  ]=="
    )
    assert stages(text) == ["dnsbl", "ip", "apply"]
    assert stages("===[  Aliastables / Rules  ]==\n===[  IPv4 Process  ]==") == ["apply", "ip"]
    assert stages("nothing") == []


def test_result_lines_add_up() -> None:
    lines = (
        '{"version":1,"outcomes":{"a":"success"},"attempted":["x"]}\n\n'
        '{"version":1,"outcomes":{"b":"success"},"attempted":["x","y"]}\n'
    )
    assert results(lines) == ({"a": "success", "b": "success"}, ["x", "y"])


# Capturing re-runs today's Update on the box (about 170 s): needed only to re-freeze the corpus, which the Go replay
# checks in every CI run, so it runs on demand (go/pfb_core/update/testdata/e2e/README.md, "Freezing").
CAPTURE_ENV = "PFB_SMOKE_UPDATE_LOOP_CAPTURE"


@pytest.mark.skipif(
    os.environ.get(CAPTURE_ENV) != "1", reason=f"on-demand corpus capture: set {CAPTURE_ENV}=1 to re-freeze"
)
@pytest.mark.parametrize("case", corpus()["cases"], ids=lambda c: c["id"])
def test_case_matches_todays_update(case: dict[str, Any], deployed_vm: SmokeVM, mock_feeds: _MockFeedServer) -> None:
    h.reset_pfb_baseline(deployed_vm)
    # The baseline keeps the ADR-61 ledger: an earlier case's open entry would read as this case's issue.
    cleared = deployed_vm.ssh("rm -f /var/db/pfblockerng/pfb_sync_status.json", timeout=60)
    assert cleared.returncode == 0, cleared.stderr
    # The baseline unsets the feed-host allowlist; the mock server is an internal address the default-ON filter refuses.
    h.set_feed_internal_allowlist(deployed_vm, "192.168.89.0/24")
    h.unblock_egress()
    base = mock_feeds.feed_url("")
    serve(mock_feeds, case["serve"])
    done = h.php_eval(deployed_vm, config_php(case, base), timeout=120)
    assert done.returncode == 0 and "OK" in done.stdout, f"config failed: {done.stdout[-1000:]}{done.stderr[-1000:]}"
    records, transcripts = [], []
    for step in case["steps"]:
        serve(mock_feeds, step.get("serve", {}))
        record, transcript = run_step(deployed_vm, step, base)
        records.append(record)
        transcripts.append(transcript)
    _record(case["id"], records, transcripts)
    assert "expect" in case, f"{case['id']}: no frozen expect (freeze it from {ACTUAL})"
    found = mismatches(case["expect"], records)
    assert found == [], f"{case['id']}: {len(found)} difference(s) against today's Update:\n" + "\n".join(found)
