"""issue #3906: the feed parse parity corpus replayed through the old path on a real pfSense box.

The corpus (go/pfb_core/feedparse/testdata/, schema in its README.md) is what Core's Go package must produce line for
line. The PHPUnit runners replay it off-appliance, where sed's locale data, libc's inet_pton and the pfSense functions
are the host's or test doubles; here the same rows run through the installed package's own functions, with FreeBSD's
sed, iconv and libc, the appliance PHP and the real pfSense includes. Rows marked `appliance` are skipped off-appliance,
so this module is the only old-path run that covers them.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from . import helpers as h
from .conftest import SmokeVM

pytestmark = pytest.mark.smoke

CORPUS = Path(__file__).resolve().parents[2] / "go" / "pfb_core" / "feedparse" / "testdata"
UNITS = ("normalize", "ip", "dnsbl")
OPEN, CLOSE = "<<<FPC>>>", "<<<FPC-END>>>"

# Replays every case through the production functions; results go to result.json beside the corpus copies.
HARNESS = r"""<?php
function fpc_bytes(array $o, string $k): string {
	return array_key_exists($k, $o) ? $o[$k] : (string) hex2bin($o["{$k}_hex"]);
}
function fpc_doc(string $dir, string $unit): array {
	return json_decode((string) file_get_contents("{$dir}/{$unit}.json"), TRUE, 64, JSON_THROW_ON_ERROR);
}
function fpc_normalize(string $dir): array {
	$out = [];
	foreach (fpc_doc($dir, 'normalize')['cases'] as $c) {
		$src = "{$dir}/feed.orig";
		$dst = "{$dir}/feed.norm";
		@unlink($dst);
		file_put_contents($src, fpc_bytes($c, 'input'));
		// NULL: the package's own Python wrapper, the converter production uses.
		$ok = pfb_feed_normalize_generate($src, $dst, $c['converter'] ? NULL : '');
		if ($ok) {
			pfb_ensure_trailing_newline($dst);
		}
		$out[$c['id']] = $ok ? bin2hex((string) file_get_contents($dst)) : 'FAILED';
	}
	return $out;
}
function fpc_ip(string $dir): array {
	$out = [];
	foreach (fpc_doc($dir, 'ip')['cases'] as $c) {
		$k = $c['config'];
		$config = pfb_ip_regex_config() + ['vtype' => $k['vtype'], 'pftype' => $k['pftype'], 'custom' => $k['custom'],
			'cidr_floor_v4' => $k['cidr_floor_v4'], 'cidr_floor_v6' => $k['cidr_floor_v6'],
			'suppression' => $k['suppression'] ? 'on' : 'off'];
		$rows = [];
		foreach ($c['rows'] as $row) {
			$data = '';
			$r = pfb_ip_parse_line_replay(fpc_bytes($row, 'line'), $config, 0, $data, FALSE, 0);
			$entries = $data === '' ? [] : explode("\n", substr($data, 0, -1));
			$rows[] = ['entries' => $entries, 'line' => bin2hex($r['line']),
				'suppressed' => $r['ip_suppressed'], 'parse_fail' => $r['parse_fail'],
				'detailed_parse_fail' => $r['detailed_parse_fail'], 'messages' => array_map('bin2hex', $r['messages'])];
		}
		$out[$c['id']] = $rows;
	}
	return $out;
}
function fpc_dnsbl(string $dir): array {
	global $pfb;
	$out = [];
	$fail_log = "{$dir}/fail.log";
	foreach (fpc_doc($dir, 'dnsbl')['cases'] as $c) {
		$k = $c['config'];
		$pfb['supp'] = $k['suppression'] ? PfbToggle::On : PfbToggle::Off;
		$ctx = ['header' => 'hdr', 'custom' => $k['custom'], 'dnsbl_ip' => $k['dnsbl_ip'], 'lenient' => $k['lenient'],
			'parse_err' => $fail_log];
		$state = pfb_dnsbl_parse_state();
		$lines = [];
		foreach ($c['lines'] as $n => $line) {
			file_put_contents($fail_log, '');
			[$ip4, $ip6, $skipped] = [count($state['ip4']), count($state['ip6']), $state['scheme_skipped']];
			$res = pfb_dnsbl_parse_line(fpc_bytes($line, 'line'), $n + 1, $state, $ctx);
			$lines[] = ['rows' => $res['row'] === NULL ? [] : [json_decode(rtrim($res['row'], "\n"), TRUE)],
				'ip4' => array_slice($state['ip4'], $ip4), 'ip6' => array_slice($state['ip6'], $ip6),
				'fail_log' => bin2hex((string) file_get_contents($fail_log)),
				'scheme_skipped' => $state['scheme_skipped'] - $skipped, 'stop' => $res['stop']];
		}
		$out[$c['id']] = $lines;
	}
	return $out;
}
$fpc = ['normalize' => fpc_normalize($fpc_dir), 'ip' => fpc_ip($fpc_dir), 'dnsbl' => fpc_dnsbl($fpc_dir)];
file_put_contents("{$fpc_dir}/result.json", json_encode($fpc, JSON_THROW_ON_ERROR));
echo 'FPC-DONE';
"""


def _bytes(obj: dict[str, Any], key: str) -> bytes:
    return obj[key].encode() if key in obj else bytes.fromhex(obj[f"{key}_hex"])


def _corpus(unit: str) -> dict[str, Any]:
    doc: dict[str, Any] = json.loads((CORPUS / f"{unit}.json").read_text(encoding="utf-8"))
    return doc


def _put(vm: SmokeVM, path: str, content: bytes) -> None:
    done = subprocess.run(vm.ssh_argv(f"cat > {path}"), input=content, capture_output=True, timeout=120, check=False)
    assert done.returncode == 0, f"upload of {path} failed: {done.stderr!r}"


@pytest.fixture(scope="module")
def results(smoke_vm: SmokeVM) -> Iterator[dict[str, Any]]:
    """The branch package deployed once, every corpus replayed on it once; the results keyed by unit and case id."""
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    made = smoke_vm.ssh("mktemp -d /var/tmp/pfb_fpc.XXXXXX", timeout=30)
    assert made.returncode == 0, made.stderr
    work = made.stdout.strip()
    try:
        for unit in UNITS:
            _put(smoke_vm, f"{work}/{unit}.json", (CORPUS / f"{unit}.json").read_bytes())
        _put(smoke_vm, f"{work}/harness.php", HARNESS.encode())
        run = h.php_eval(
            smoke_vm,
            f"$fpc_dir = '{work}';\nrequire_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\n"
            f"require('{work}/harness.php');",
            timeout=600,
        )
        assert "FPC-DONE" in run.stdout, f"the harness did not finish: rc={run.returncode}\n{run.stdout}\n{run.stderr}"
        got = smoke_vm.ssh(f"cat {work}/result.json", timeout=120)
        assert got.returncode == 0, got.stderr
        yield json.loads(got.stdout)
    finally:
        smoke_vm.ssh(f"rm -rf {work}", timeout=60)


def _report(mismatches: list[str]) -> str:
    return f"{len(mismatches)} case(s) differ from the corpus on the appliance:\n" + "\n".join(mismatches[:40])


def test_normalize_corpus_matches_the_appliance(results: dict[str, Any]) -> None:
    mismatches = []
    for case in _corpus("normalize")["cases"]:
        old = "old_expect" in case or "old_expect_hex" in case
        want = _bytes(case, "old_expect" if old else "expect").hex()
        got = results["normalize"][case["id"]]
        if got != want:
            mismatches.append(f"{case['id']}: expected {want} actual {got}")
    assert mismatches == [], _report(mismatches)


def test_ip_corpus_matches_the_appliance(results: dict[str, Any]) -> None:
    mismatches = []
    for case in _corpus("ip")["cases"]:
        for n, (row, got) in enumerate(zip(case["rows"], results["ip"][case["id"]], strict=True)):
            e = row["expect"]
            messages = [m.encode().hex() for m in e["messages"]] if "messages" in e else e["messages_hex"]
            want = {
                "entries": e["entries"],
                "line": _bytes(e, "line").hex(),
                "suppressed": e["suppressed"],
                "parse_fail": e["parse_fail"],
                "detailed_parse_fail": e["detailed_parse_fail"],
                "messages": messages,
            }
            if got != want:
                mismatches.append(f"{case['id']} row {n} {_bytes(row, 'line')!r}: expected {want} actual {got}")
    assert mismatches == [], _report(mismatches)


def _fail_fields(log: bytes, raw: bytes, lineno: int) -> list[bytes]:
    """The `line` field of each pfb_parse_fail_log() record "{timestamp},hdr,{line},{oline},{lineno}\\n" in log."""
    tail = b"," + raw.rstrip(b"\r\n") + b"," + str(lineno).encode() + b"\n"
    fields = []
    while log:
        head = re.match(rb"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,hdr,", log)
        assert head, f"unexpected parse-failure record: {log!r}"
        rest = log[head.end() :]
        at = rest.find(tail)
        assert at >= 0, f"parse-failure record does not end with the input line: {log!r}"
        fields.append(rest[:at])
        log = rest[at + len(tail) :]
    return fields


def test_dnsbl_corpus_matches_the_appliance(results: dict[str, Any]) -> None:
    mismatches = []
    for case in _corpus("dnsbl")["cases"]:
        for n, (line, got) in enumerate(zip(case["lines"], results["dnsbl"][case["id"]], strict=True)):
            raw = _bytes(line, "line")
            e = dict(line["expect"])
            e["fail"] = [bytes.fromhex(f["hex"]) if isinstance(f, dict) else f.encode() for f in e["fail"]]
            actual = dict(got)
            actual["fail"] = _fail_fields(bytes.fromhex(actual.pop("fail_log")), raw, n + 1)
            if actual != e:
                mismatches.append(f"{case['id']} line {n} {raw!r}: expected {e} actual {actual}")
    assert mismatches == [], _report(mismatches)
