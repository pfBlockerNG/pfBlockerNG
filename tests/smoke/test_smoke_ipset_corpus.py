"""issue #4033: the IP set algebra parity corpus replayed through today's shell and PHP on a real pfSense box.

The corpus (go/pfb_core/ipset/testdata/, schema in its README.md) is what Core's Go package must produce, member for
member. Every expectation is what the appliance's own `pfblockerng.sh` verbs and PHP helpers produce, with the
appliance's real `iprange` and `grepcidr` (the one stubbed input is the GeoIP database lookup, see the README).

The harness copies the INSTALLED script into a scratch tree and rewrites only its data-path constants, then runs the
copy through its real verb dispatch with the argv PHP passes. One harness pass computes every case; each corpus group
is then asserted against its frozen `expect`. The pass always writes its actual results (the corpus shape, keyed by
case id, plus the appliance's package versions) to `helpers.DIAG_DIR / "ipset_corpus_actual.json"`, so a run can be
frozen.
"""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from . import helpers as h
from .conftest import SmokeVM

pytestmark = pytest.mark.smoke

CORPUS = Path(__file__).resolve().parents[2] / "go" / "pfb_core" / "ipset" / "testdata" / "ipset.json"
OPS = (
    "cidr_aggregate",
    "preprocess",
    "recompute",
    "pmax",
    "suppress",
    "remove",
    "closing",
    "canonical",
    "union",
    "dnsblip",
    "matrix",
    "pipeline",
)
CASE_KEYS = {"id", "description", "op", "family", "input", "expect", "digest"}
# Lists compared in order (byte order or sequence is their contract); every other list of strings is a multiset.
ORDERED = {"set", "kept", "counts", "content", "sources"}
VERSION_COMMANDS = {
    "pfsense": "cat /etc/version",
    "freebsd": "uname -r",
    "php": "/usr/local/bin/php -v | head -1",
    "pkg_query": "pkg query '%n-%v' iprange grepcidr",
    "pkg_info": "pkg info iprange grepcidr",
    "iprange": "/usr/local/bin/iprange --version 2>&1 | head -1",
    "grepcidr": "/usr/local/bin/grepcidr -V 2>&1 | head -1",
}

# Replays every case; results go to result.json beside the corpus copy.
HARNESS = r"""<?php
// IP set corpus harness (issue #4033). Runs on the appliance (or, for harness debugging only, on a dev host with
// the PHPUnit doubles). Replays every case of ipset.json through the installed package's own script and PHP
// functions and appends one {"id", "result"} JSON line per case to results.jsonl. Expectations live in the corpus, never here.
//
// Inputs (set by the caller): $ipc_dir (corpus + result dir), $ipc_tools (path overrides, empty on the appliance).
ini_set('memory_limit', '-1');
error_reporting(E_ALL & ~E_DEPRECATED);

const IPC_CAP = 1200;		// hang cap per shell verb, seconds
const IPC_PH = '127.1.7.7';	// default placeholder

// Every path constant of the shell script's init block: [name, original line (after one tab), relative target].
// A target ending in '/' keeps the production trailing slash. The rewrite is verified line by line.
const IPC_PATHS = [
	['pathgeoip',     'pathgeoip="/usr/local/bin/mmdblookup"',                         'bin/mmdblookup'],
	['pathgeoipdat',  'pathgeoipdat="/usr/local/share/GeoIP/GeoLite2-Country.mmdb"',   'bin/GeoLite2-Country.mmdb'],
	['pathasndat',    'pathasndat="/usr/local/share/GeoIP/asn.mmdb"',                  'bin/asn.mmdb'],
	['pathasncsv',    'pathasncsv="/usr/local/share/GeoIP/asn.csv"',                   'bin/asn.csv'],
	['pathasntable',  'pathasntable="/usr/local/www/pfblockerng/pfblockerng_asn.txt"', 'bin/asn_table.txt'],
	['pathpfbphp',    'pathpfbphp=/usr/local/www/pfblockerng/pfblockerng.php',         'bin/no-reentry.php'],
	['aliasarchive',  'aliasarchive="/usr/local/etc/aliastables.tar"',                 'tmp/aliastables.tar'],
	['dnsblarchive',  'dnsblarchive="/usr/local/etc/pfb_dnsbl_cache.tar"',             'tmp/pfb_dnsbl_cache.tar'],
	['pfbsuppression', 'pfbsuppression=/var/db/pfblockerng/pfbsuppression.txt',        'pfbsuppression.txt'],
	['masterfile',    'masterfile=/var/db/pfblockerng/masterfile',                     'masterfile'],
	['mastercat',     'mastercat=/var/db/pfblockerng/mastercat',                       'mastercat'],
	['pfbsnap',       'pfbsnap=/var/db/pfblockerng/snapshot/',                         'snapshot/'],
	['geoiplog',      'geoiplog=/var/log/pfblockerng/geoip.log',                       'log/geoip.log'],
	['errorlog',      'errorlog=/var/log/pfblockerng/error.log',                       'log/error.log'],
	['extraslog',     'extraslog=/var/log/pfblockerng/extras.log',                     'log/extras.log'],
	['etdir',         'etdir=/var/db/pfblockerng/ET',                                  'ET'],
	['pfbdb',         'pfbdb=/var/db/pfblockerng/',                                    ''],
	['pfbdeny',       'pfbdeny=/var/db/pfblockerng/deny/',                             'deny/'],
	['pfborig',       'pfborig=/var/db/pfblockerng/original/',                         'original/'],
	['pfbmatch',      'pfbmatch=/var/db/pfblockerng/match/',                           'match/'],
	['pfbmatchgen',   'pfbmatchgen=/var/db/pfblockerng/match/generated/',              'match/generated/'],
	['pfbpermit',     'pfbpermit=/var/db/pfblockerng/permit/',                         'permit/'],
	['pfbnative',     'pfbnative=/var/db/pfblockerng/native/',                         'native/'],
	['pfsensealias',  'pfsensealias=/var/db/aliastables/',                             'aliastables/'],
	['pfbdomain',     'pfbdomain=/var/db/pfblockerng/dnsbl/',                          'dnsbl/'],
	['pfbdomainorig', 'pfbdomainorig=/var/db/pfblockerng/dnsblorig/',                  'dnsblorig/'],
];

// ---- plumbing ------------------------------------------------------------------------------------------------

function ipc_rm(string $p): void {
	exec('rm -rf ' . escapeshellarg($p));
}

function ipc_put(string $path, string $bytes): void {
	if (!is_dir(dirname($path))) {
		mkdir(dirname($path), 0777, TRUE);
	}
	if (file_put_contents($path, $bytes) !== strlen($bytes)) {
		throw new RuntimeException("write failed: {$path}");
	}
}

function ipc_get(string $path): ?string {
	return is_file($path) ? (string) file_get_contents($path) : NULL;
}

/** File bytes as lines: split at "\n", a final unterminated line counts, "\r" stays in the line. */
function ipc_lines(?string $s): ?array {
	if ($s === NULL) {
		return NULL;
	}
	if ($s === '') {
		return [];
	}
	$a = explode("\n", $s);
	if (end($a) === '') {
		array_pop($a);
	}
	return $a;
}

/** One generated line source (recipes are documented in the corpus README). */
function ipc_gen(array $g): string {
	$out = '';
	$n = $g['count'];
	if ($g['kind'] === 'v4_seq') {
		for ($i = 0; $i < $n; $i++) {
			$out .= long2ip($g['start'] + $i * $g['step']) . $g['suffix'] . "\n";
		}
		return $out;
	}
	if ($g['kind'] === 'v6_seq') {
		$base = inet_pton($g['base']);
		$hi = substr($base, 0, 8);
		$lo = unpack('J', substr($base, 8))[1];
		for ($i = 0; $i < $n; $i++) {
			$out .= inet_ntop($hi . pack('J', $lo + $i * $g['step'])) . $g['suffix'] . "\n";
		}
		return $out;
	}
	throw new RuntimeException('unknown generator ' . $g['kind']);
}

/** A member text object: text | text_hex | parts (strings and {"generate": recipe}). */
function ipc_text(array $o): string {
	if (array_key_exists('text', $o)) {
		return $o['text'];
	}
	if (array_key_exists('text_hex', $o)) {
		return (string) hex2bin($o['text_hex']);
	}
	if (array_key_exists('parts', $o)) {
		$s = '';
		foreach ($o['parts'] as $p) {
			$s .= is_array($p) ? ipc_gen($p['generate']) : $p;
		}
		return $s;
	}
	throw new RuntimeException('member text object has no text, text_hex or parts');
}

/** Digest of a file's lines: count and sha256 of the LC_ALL=C-sorted lines joined with "\n" (no trailing newline). */
function ipc_digest_file(string $path): array {
	$sorted = "{$path}.sorted";
	exec('LC_ALL=C sort ' . escapeshellarg($path) . ' > ' . escapeshellarg($sorted), $o, $rc);
	if ($rc !== 0) {
		throw new RuntimeException("sort failed for digest of {$path}");
	}
	$ctx = hash_init('sha256');
	$fh = fopen($sorted, 'rb');
	$n = 0;
	while (($line = fgets($fh)) !== FALSE) {
		if ($n > 0) {
			hash_update($ctx, "\n");
		}
		hash_update($ctx, rtrim($line, "\n"));
		$n++;
	}
	fclose($fh);
	unlink($sorted);
	return ['count' => $n, 'sha256' => hash_final($ctx)];
}

/** A file as the corpus records a member list: lines, null when absent, or a digest. */
function ipc_out(string $path, bool $digest): array|null {
	if (!is_file($path)) {
		return NULL;
	}
	return $digest ? ipc_digest_file($path) : ipc_lines((string) file_get_contents($path));
}

/** Every regular file of a directory, name => lines (or digest). */
function ipc_dir(string $dir, bool $digest): array|stdClass {
	$out = [];
	foreach (scandir($dir) as $f) {
		if ($f !== '.' && $f !== '..' && is_file("{$dir}/{$f}")) {
			$out[$f] = ipc_out("{$dir}/{$f}", $digest);
		}
	}
	ksort($out, SORT_STRING);
	return $out ?: new stdClass();
}

function ipc_names(string $dir): array {
	$out = [];
	foreach (is_dir($dir) ? scandir($dir) : [] as $f) {
		if ($f !== '.' && $f !== '..') {
			$out[] = $f;
		}
	}
	sort($out, SORT_STRING);
	return $out;
}

// ---- the script copy -----------------------------------------------------------------------------------------

/** The installed script copied with only its path constants rewritten into the scratch world; verified. */
function ipc_script(string $dir, string $world, array $tools): string {
	$srcpath = getenv('IPC_SCRIPT_SRC') ?: '/usr/local/pkg/pfblockerng/pfblockerng.sh';	// the override is for harness debugging off-appliance
	$src = (string) file_get_contents($srcpath);
	if ($src === '') {
		throw new RuntimeException("installed script unreadable: {$srcpath}");
	}
	$lines = explode("\n", $src);
	$want = [];
	foreach (IPC_PATHS as [$name, $orig, $rel]) {
		$want[$name] = ["\t{$orig}", "\t{$name}='{$world}/{$rel}'"];
	}
	foreach ($tools as $name => $path) {	// debug-host overrides only
		$orig = ['pathgrepcidr' => 'pathgrepcidr="/usr/local/bin/grepcidr"', 'pathaggregate' => 'pathaggregate="/usr/local/bin/iprange"',
			'pathpfctl' => 'pathpfctl=/sbin/pfctl', 'pathtimeout' => 'pathtimeout=/usr/bin/timeout'][$name];
		$want[$name] = ["\t{$orig}", "\t{$name}='{$path}'"];
	}
	$sed = [];
	foreach ($want as $name => [$orig, $new]) {
		if (!preg_match("#^\t[a-z0-9]+='[A-Za-z0-9_./-]*'$#", $new)) {
			throw new RuntimeException("unsafe rewrite for {$name}: {$new}");
		}
		$n = count(array_keys($lines, $orig, TRUE));
		if ($n !== 1) {
			throw new RuntimeException("script constant {$name} found {$n} times, expected 1: {$orig}");
		}
		// '#' is the sed delimiter; no path contains one (checked above); BRE specials are escaped by hand.
		$sed[] = '-e ' . escapeshellarg('s#^' . preg_replace('/[.*\[\]^$\\\\#]/', '\\\\$0', $orig) . '$#' . $new . '#');
	}
	$dst = "{$dir}/script/pfblockerng.sh";
	ipc_put($dst, '');
	exec('sed ' . implode(' ', $sed) . ' ' . escapeshellarg($srcpath) . ' > ' . escapeshellarg($dst), $o, $rc);
	if ($rc !== 0) {
		throw new RuntimeException('sed failed rewriting the script');
	}
	$got = explode("\n", (string) file_get_contents($dst));
	foreach ($want as $name => [$orig, $new]) {
		$n = count(array_keys($got, $new, TRUE));
		if ($n !== 1 || in_array($orig, $got, TRUE)) {
			throw new RuntimeException("rewrite of {$name} not applied exactly once: {$new}");
		}
	}
	// No data path of the init block may still point at the live trees.
	$start = $end = NULL;
	foreach ($got as $n => $l) {
		if ($start === NULL && str_starts_with($l, "\tpathgrepcidr=")) {
			$start = $n;
		}
		if ($l === "\tif [ ! -f \"\${mastercat}\" ]; then touch \"\${mastercat}\"; fi") {
			$end = $n;
		}
	}
	if ($start === NULL || $end === NULL || $end < $start) {
		throw new RuntimeException('init block not found in the script');
	}
	foreach (array_slice($got, $start, $end - $start + 1) as $l) {
		if (ltrim($l) !== '' && ltrim($l)[0] !== '#' && !str_contains($l, 'read_xml_tag.sh')
			&& preg_match('#/var/(db|log)/|/usr/local/etc/|/usr/local/share/GeoIP|pfblockerng_asn\.txt#', $l)) {
			throw new RuntimeException("init block still names a live path: {$l}");
		}
	}
	chmod($dst, 0755);
	return $dst;
}

/** A fresh scratch world (the tree the rewritten script works in). */
function ipc_world(string $w, ?array $geo): void {
	ipc_rm($w);
	foreach (['deny', 'original', 'match/generated', 'permit', 'native', 'snapshot', 'db', 'dnsbl', 'dnsblorig', 'aliastables',
		'ET', 'tmp', 'bin', 'log', 'folder'] as $d) {
		mkdir("{$w}/{$d}", 0777, TRUE);
	}
	// The one stubbed input: GeoIP answers from a per-case table, in mmdblookup's output shape.
	ipc_put("{$w}/bin/GeoLite2-Country.mmdb", '');
	if ($geo !== NULL) {
		$tbl = '';
		foreach ($geo as $prefix => $cc) {
			$tbl .= "{$prefix}.1 {$cc}\n";
		}
		ipc_put("{$w}/bin/geo.tbl", $tbl);
		ipc_put("{$w}/bin/mmdblookup", "#!/bin/sh\nip=''\nwhile [ \$# -gt 0 ]; do\n\tcase \"\$1\" in -i) ip=\"\$2\"; shift ;; esac\n\tshift\ndone\n"
			. "cc=\$(awk -v ip=\"\$ip\" '\$1 == ip { print \$2; exit }' {$w}/bin/geo.tbl)\n"
			. "[ -n \"\$cc\" ] && printf '\\n  \"%s\" <utf8_string>\\n\\n' \"\$cc\"\nexit 0\n");
		chmod("{$w}/bin/mmdblookup", 0755);
	}
}

/** Run one verb of the rewritten script; returns [rc, stdout+stderr]. */
function ipc_sh(string $dir, string $w, string $argv, string $ph = IPC_PH): array {
	$out = "{$w}/stdout.txt";
	$cmd = "cd {$w} && env PFB_IP_PLACEHOLDER=" . escapeshellarg($ph) . " PFB_REENTRY_TIMEOUT=60 TMPDIR={$w}/tmp "
		. 'timeout -k 5 ' . IPC_CAP . " /bin/sh {$dir}/script/pfblockerng.sh {$argv} > {$out} 2>&1";
	exec($cmd, $unused, $rc);
	return [$rc, (string) file_get_contents($out)];
}

function ipc_log(string $w): array {
	// the script stamps some lines with `[ <now> ]`; the stamp is the only nondeterministic byte
	return array_map(static fn($l) => preg_replace('/\[ \d{4}-\d\d-\d\d \d\d:\d\d:\d\d \]/', '[ TS ]', $l),
		ipc_lines(ipc_get("{$w}/log/error.log")) ?? []);
}

/** Master rows as the corpus records them: lines, or null when the file is absent. */
function ipc_master(string $w, bool $digest): array|null {
	return ipc_out("{$w}/masterfile", $digest);
}

// ---- the ops -------------------------------------------------------------------------------------------------

function ipc_op_cidr_aggregate(string $dir, string $w, array $c, bool $digest): array {
	ipc_world($w, NULL);
	$in = ipc_text($c['input']['members']);
	ipc_put("{$w}/folder/Feed_v4.txt", $in);
	[$rc, $out] = ipc_sh($dir, $w, "cidr_aggregate Feed_v4 {$w}/folder");
	$after = (string) file_get_contents("{$w}/folder/Feed_v4.txt");
	$stats = preg_match('/^\s+(\d+)\s+(\d+)\s*$/m', $out, $m) ? [(int) $m[1], (int) $m[2]] : NULL;
	return ['rc' => $rc, 'members' => ipc_out("{$w}/folder/Feed_v4.txt", $digest), 'unchanged' => $after === $in,
		'stats' => $stats, 'log' => ipc_log($w)];
}

function ipc_op_preprocess(string $dir, string $w, array $c, bool $digest): array {
	$i = $c['input'];
	ipc_world($w, $i['geo'] ?? NULL);
	ipc_put("{$w}/deny/Feed_v4.txt", ipc_text($i['members']));
	$args = pfb_ip_preprocess_args($i['dup'], $i['agg'], $i['rep']);
	$ran = $args !== '';
	$rc = NULL;
	if ($ran) {
		// exactly pfblockerng_apply.inc:4515
		$token = ($i['drep'] ? PfbToggle::On : PfbToggle::Off)->toStored();
		[$rc, ] = ipc_sh($dir, $w, "{$args} " . escapeshellarg('Feed_v4') . " {$i['max']} " . escapeshellarg($token)
			. " {$i['cc']} {$i['ccwhite']} {$i['ccblack']}");
	}
	$gen = "{$w}/match/generated";
	return ['args' => $args, 'ran' => $ran, 'rc' => $rc, 'members' => ipc_out("{$w}/deny/Feed_v4.txt", $digest),
		'match_rep' => ipc_out("{$gen}/pfB_Match_Rep_Feed_v4.txt", $digest), 'log' => ipc_log($w)];
}

function ipc_op_recompute(string $dir, string $w, array $c, bool $digest): array {
	$i = $c['input'];
	$fam = $c['family'];
	ipc_world($w, $i['geo'] ?? NULL);
	$paths = [];
	foreach ($i['members'] as $m) {
		$snap = "{$w}/snapshot/{$m['name']}.snap";
		if (empty($m['missing'])) {
			ipc_put($snap, ipc_text($m));
		}
		$paths[] = $snap;
	}
	foreach ($i['deny_pre'] ?? [] as $name => $t) {
		ipc_put("{$w}/deny/{$name}.txt", ipc_text($t));
	}
	foreach ($i['match_pre'] ?? [] as $name => $t) {
		ipc_put("{$w}/match/generated/{$name}", ipc_text($t));
	}
	if (isset($i['master'])) {
		ipc_put("{$w}/masterfile", ipc_text($i['master']));
	}
	$list = "{$w}/db/pfb_recompute_{$fam}.members";
	$counts = "{$w}/db/pfb_recompute_{$fam}.counts";
	pfb_ip_recompute_memberlist_write($list, $paths);
	// exactly pfblockerng_apply.inc:4663-4664 (the three country tokens are unquoted there)
	[$rc, $out] = ipc_sh($dir, $w, "recompute {$fam} " . escapeshellarg($list) . ' ' . escapeshellarg($counts)
		. " {$i['dedup']} {$i['repmode']} {$i['max']} {$i['cc']} {$i['ccwhite']} {$i['ccblack']}", $i['ph'] ?? IPC_PH);
	return ['rc' => $rc, 'deny' => ipc_dir("{$w}/deny", $digest), 'master' => ipc_master($w, $digest),
		'mastercat' => ipc_out("{$w}/mastercat", $digest), 'counts' => ipc_out($counts, FALSE),
		'match' => ipc_dir("{$w}/match/generated", $digest),
		'processed' => preg_match('/recompute \[ \w+ \]: (\d+) feed\(s\) processed/', $out, $pm) ? (int) $pm[1] : NULL,
		'log' => ipc_log($w)];
}

function ipc_op_pmax(string $dir, string $w, array $c, bool $digest): array {
	$i = $c['input'];
	ipc_world($w, $i['geo'] ?? NULL);
	foreach ($i['deny'] as $name => $t) {
		ipc_put("{$w}/deny/{$name}.txt", ipc_text($t));
	}
	if (isset($i['master'])) {
		ipc_put("{$w}/masterfile", ipc_text($i['master']));
	}
	[$rc, ] = ipc_sh($dir, $w, "pmax x {$i['max']}", $i['ph'] ?? IPC_PH);	// pfblockerng_apply.inc:4675
	return ['rc' => $rc, 'deny' => ipc_dir("{$w}/deny", $digest), 'master' => ipc_master($w, $digest),
		'mastercat' => ipc_out("{$w}/mastercat", $digest), 'log' => ipc_log($w)];
}

function ipc_op_suppress(string $dir, string $w, array $c, bool $digest): array {
	$i = $c['input'];
	ipc_world($w, NULL);
	if ($c['family'] === 'v4') {
		ipc_put("{$w}/folder/Feed_v4.txt", ipc_text($i['members']));
		if (isset($i['suppression'])) {
			ipc_put("{$w}/pfbsuppression.txt", ipc_text($i['suppression']));
		}
		if (isset($i['master'])) {
			ipc_put("{$w}/masterfile", ipc_text($i['master']));
		}
		// pfblockerng_apply.inc:4820-4824
		[$rc, $out] = ipc_sh($dir, $w, "suppress Feed_v4 {$w}/folder {$i['dedup']}");
		$stats = preg_match('/^Feed_v4\s+(\d+)\s+(\d+)\s+(\d+)\s*$/m', $out, $m) ? [(int) $m[1], (int) $m[2], (int) $m[3]] : NULL;
		return ['rc' => $rc, 'members' => ipc_out("{$w}/folder/Feed_v4.txt", $digest), 'master' => ipc_master($w, $digest),
			'stats' => $stats, 'log' => ipc_log($w)];
	}
	global $pfb;
	$pfb['log'] = "{$w}/log/pfb.log";
	$pfb['errlog'] = "{$w}/log/err.log";
	$pfb['runlog'] = '';
	ipc_put("{$w}/folder/Feed_v6.txt", ipc_text($i['members']));
	if (isset($i['suppression'])) {
		ipc_put("{$w}/supp_v6.txt", ipc_text($i['suppression']));
	}
	ob_start();
	$ok = pfb_suppress_file_v6("{$w}/folder/Feed_v6.txt", "{$w}/supp_v6.txt");
	ob_end_clean();
	$log = [];
	foreach (ipc_lines(ipc_get("{$w}/log/pfb.log")) ?? [] as $l) {
		$log[] = preg_replace('/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d /', '', $l);
	}
	return ['ok' => $ok, 'members' => ipc_out("{$w}/folder/Feed_v6.txt", $digest), 'log' => $log,
		'leftover_tmp' => file_exists("{$w}/folder/Feed_v6.txt.tmp")];
}

function ipc_op_remove(string $dir, string $w, array $c, bool $digest): array {
	$i = $c['input'];
	ipc_world($w, NULL);
	$dirs = ['deny' => 'deny', 'original' => 'original', 'match' => 'match', 'matchgen' => 'match/generated',
		'permit' => 'permit', 'native' => 'native'];
	foreach ($dirs as $key => $rel) {
		foreach ($i[$key] ?? [] as $name => $t) {
			ipc_put("{$w}/{$rel}/{$name}", ipc_text($t));
		}
	}
	if (isset($i['master'])) {
		ipc_put("{$w}/masterfile", ipc_text($i['master']));
		ipc_put("{$w}/mastercat", $i['mastercat'] ?? '');
	}
	[$rc, $out] = ipc_sh($dir, $w, 'remove x x x ' . implode(',', $i['headers']));	// pfblockerng_apply.inc:1994
	$files = [];
	foreach ($dirs as $key => $rel) {
		$files[$key] = array_values(array_filter(ipc_names("{$w}/{$rel}"), static fn($f) => is_file("{$w}/{$rel}/{$f}")));
	}
	preg_match_all('/^(?:The Following List has been REMOVED|Invalid alias|Invalid header).*$/m', $out, $msg);
	return ['rc' => $rc, 'files' => $files, 'master' => ipc_master($w, $digest), 'mastercat' => ipc_out("{$w}/mastercat", $digest),
		'messages' => $msg[0]];
}

/** The sanity block and report sections of `closing`, parsed off stdout (pfctl lines are not part of the corpus). */
function ipc_closing_parse(string $out): array {
	$g = static fn(string $re) => preg_match($re, $out, $m) ? $m[1] : NULL;
	$uniq = static function (string $from, string $to) use ($out): array {
		$a = strpos($out, $from);
		$b = strpos($out, $to, $a === FALSE ? 0 : $a);
		if ($a === FALSE || $b === FALSE) {
			return [];
		}
		return array_values(array_filter(explode("\n", substr($out, $a + strlen($from), $b - $a - strlen($from))), static fn($l) => $l !== ''));
	};
	$tail = strpos($out, 'Deny folder/Masterfile uniq check');
	$s4 = [];
	if ($tail !== FALSE) {
		$rest = substr($out, $tail + strlen('Deny folder/Masterfile uniq check'));
		$cut = strpos($rest, 'Sync check');
		$s4 = array_values(array_filter(explode("\n", $cut === FALSE ? $rest : substr($rest, 0, $cut)), static fn($l) => $l !== ''));
	}
	$empty = [];
	if (preg_match('/Empty Lists w\/[^\n]*\n\n(.*?)(?:\n\n|\z)/s', $out, $m)) {
		$empty = array_values(array_filter(explode("\n", $m[1]), static fn($l) => $l !== '' && !preg_match('/^=+$/', $l)));
	}
	$verdict = preg_match('/Database Sanity check \[\s+(PASSED|FAILED)\s+\]/', $out, $m) ? $m[1] : NULL;
	return ['original' => $g('/\[ Original IP count   \]  \[ ([^\]]*) \]/'), 'final' => $g('/\[ Final IP Count  \]  \[ ([^\]]*) \]/'),
		'verdict' => $verdict, 'masterfile_count' => $g('/Masterfile Count    \[ ([^\]]*) \]/'),
		'deny_count' => $g('/Deny folder Count   \[ ([^\]]*) \]/'),
		'uniq_master' => $uniq("Masterfile/Deny folder uniq check\n", 'Deny folder/Masterfile uniq check'), 'uniq_deny' => $s4,
		'empty_lists' => $empty];
}

function ipc_closing_setup(string $w, array $i): void {
	foreach ($i['deny'] ?? [] as $name => $t) {
		ipc_put("{$w}/deny/{$name}.txt", ipc_text($t));
	}
	foreach ($i['orig'] ?? [] as $name => $t) {
		ipc_put("{$w}/original/{$name}", ipc_text($t));
	}
	if (isset($i['master'])) {
		ipc_put("{$w}/masterfile", ipc_text($i['master']));
		// mastercat is the second column of masterfile (pfblockerng_apply recompute/duplicate derive it with cut)
		exec('cut -d " " -f2 ' . escapeshellarg("{$w}/masterfile") . ' > ' . escapeshellarg("{$w}/mastercat"));
	}
}

function ipc_op_closing(string $dir, string $w, array $c, bool $digest): array {
	$i = $c['input'];
	ipc_world($w, NULL);
	ipc_closing_setup($w, $i);
	[$rc, $out] = ipc_sh($dir, $w, "closing {$i['dedup']}", $i['ph'] ?? IPC_PH);
	return ['rc' => $rc, 'deny' => ipc_dir("{$w}/deny", $digest), 'master' => ipc_master($w, $digest),
		'sanity' => ipc_closing_parse($out), 'log' => ipc_log($w)];
}

function ipc_op_canonical(string $dir, string $w, array $c, bool $digest): array {
	$set = pfb_canonical_alias_set(ipc_text($c['input']['members']));
	if ($digest) {
		$tmp = "{$w}.canonical";
		ipc_put($tmp, $set ? implode("\n", $set) . "\n" : '');
		$set = ipc_digest_file($tmp);
		unlink($tmp);
	}
	return ['set' => $set];
}

const IPC_CLASS_DIR = ['Deny' => 'deny', 'Permit' => 'permit', 'Match' => 'match', 'Native' => 'native'];

/** Class dirs of the PHP helpers, pointed into the scratch world. */
function ipc_pfb_dirs(string $w, string $ph): void {
	global $pfb;
	$pfb['denydir'] = "{$w}/deny";
	$pfb['permitdir'] = "{$w}/permit";
	$pfb['matchdir'] = "{$w}/match";
	$pfb['nativedir'] = "{$w}/native";
	$pfb['dbdir'] = "{$w}";
	$pfb['snapdir'] = "{$w}/snapshot";
	$pfb['origdir'] = "{$w}/original";
	$pfb['ip_ph'] = $ph;
}

/** The Uber union of one class and family: pfb_aggregate_member_list() then the `aggregate` verb (pfblockerng.inc:14707-14726). */
function ipc_union(string $dir, string $w, string $type, string $fam, string $collapsed, bool $digest): array {
	$members = pfb_aggregate_member_list($type, $fam);
	$name = "pfB_{$type}_Aggregated_{$fam}";
	$list = "{$w}/db/{$name}.members";
	$aggout = "{$w}/aliastables/{$name}.txt";
	$consumer = "{$w}/db/{$name}.lst";
	ipc_put($list, $members ? implode("\n", $members) . "\n" : '');
	[$rc, $out] = ipc_sh($dir, $w, 'aggregate ' . escapeshellarg($fam) . ' ' . escapeshellarg($list) . ' ' . escapeshellarg($aggout)
		. ' ' . escapeshellarg($consumer) . ' ' . escapeshellarg($collapsed));
	return ['kept' => array_map('basename', $members), 'rc' => $rc, 'aggregate' => ipc_out($aggout, $digest),
		'consumer' => ipc_out($consumer, $digest),
		'stats' => preg_match('/union (\d+) -> (\d+) CIDRs/', $out, $m) ? [(int) $m[1], (int) $m[2]] : NULL, 'log' => ipc_log($w)];
}

function ipc_op_union(string $dir, string $w, array $c, bool $digest): array {
	$i = $c['input'];
	ipc_world($w, NULL);
	$ph = $i['ph'] ?? IPC_PH;
	ipc_pfb_dirs($w, $ph);
	$d = IPC_CLASS_DIR[$i['type']];
	foreach ($i['members'] as $name => $t) {
		ipc_put("{$w}/{$d}/{$name}", ipc_text($t));
	}
	return ipc_union($dir, $w, $i['type'], $c['family'], $i['collapsed'], $digest);
}

function ipc_op_dnsblip(string $dir, string $w, array $c, bool $digest): array {
	global $pfb;
	$i = $c['input'];
	$fam = $c['family'];
	ipc_world($w, NULL);
	$pfb['log'] = "{$w}/log/pfb.log";
	$pfb['errlog'] = "{$w}/log/err.log";
	$pfb['runlog'] = '';
	$pfb['dnsdir'] = "{$w}/dnsbl";
	$pfb['ip_ph'] = $i['ip_ph'] ?? IPC_PH;
	foreach ($i['ip_files'] as $name => $t) {
		ipc_put("{$w}/dnsbl/{$name}", ipc_text($t));
	}
	// pfblockerng_apply.inc:3209-3266, the v4 and v6 blocks alike
	$dest = "{$w}/DNSBLIP_{$fam}.txt";
	$files = glob("{$pfb['dnsdir']}/*_{$fam}.ip") ?: [];
	ob_start();
	if (!empty($files)) {
		$built = pfb_dnsbl_concat_files($dest, $files);
	} else {
		$ph = $fam === 'v6' ? "::{$pfb['ip_ph']}" : $pfb['ip_ph'];
		$built = (@file_put_contents($dest, "{$ph}\n", LOCK_EX) !== FALSE);
	}
	ob_end_clean();
	$raw = ipc_get($dest);
	return ['built' => $built, 'content' => ipc_out($dest, $digest), 'final_newline' => $raw !== NULL && $raw !== '' && substr($raw, -1) === "\n",
		'sources' => array_map('basename', $files)];
}

function ipc_op_matrix(string $dir, string $w, array $c, bool $digest): array {
	$i = $c['input'];
	if ($i['fn'] === 'recompute_matrix') {
		return pfb_ip_recompute_matrix($i['dedup_on'], $i['rep_trigger'], $i['drep_on'], $i['prep_on']);
	}
	[$invoke, $arg] = pfb_ip_closing_pass_active($i['dup_on'], $i['ran_v4']);
	return ['invoke' => $invoke, 'alias_arg' => $arg];
}

// ---- the pipeline ----------------------------------------------------------------------------------------------

/**
 * Multi-pass scenario. The SEQUENCE is authored from pfblockerng_apply.inc (stage line numbers in the corpus README);
 * every stage is the production verb or function. The lab has no pf tables, so pfb_pfctl_table_count() is empty for
 * every alias and every member file is read (pfblockerng_apply.inc:4806-4810).
 */
function ipc_op_pipeline(string $dir, string $w, array $c, bool $digest): array {
	global $pfb;
	$in = $c['input'];
	$sw = $in['switches'];
	ipc_world($w, $sw['geo'] ?? NULL);
	$ph = $sw['ph'] ?? IPC_PH;
	ipc_pfb_dirs($w, $ph);
	$pfb['log'] = "{$w}/log/pfb.log";
	$pfb['errlog'] = "{$w}/log/err.log";
	$pfb['runlog'] = '';
	if (isset($in['suppression']['v4'])) {
		ipc_put("{$w}/pfbsuppression.txt", ipc_text($in['suppression']['v4']));
	}
	$supp_v6 = "{$w}/supp_v6.txt";
	if (isset($in['suppression']['v6'])) {
		ipc_put($supp_v6, ipc_text($in['suppression']['v6']));
	}
	$feeds = $in['feeds'];
	$existing = array_column($feeds, 'name');
	$cur = [];
	$passes = [];
	foreach ($in['passes'] as $p) {
		$changed = $p['changed'];
		$repcheck = FALSE;
		$supp_update = FALSE;
		// stage 1: per-feed parse output, preprocess, snapshot (pfblockerng_apply.inc:4505-4535)
		foreach ($feeds as $f) {
			if (isset($p['set'][$f['name']])) {
				$cur[$f['name']] = ipc_text($p['set'][$f['name']]);
			}
			if (!in_array($f['name'], $changed, TRUE)) {
				continue;
			}
			$cur[$f['name']] ??= ipc_text($f);
			$txt = "{$w}/deny/{$f['name']}.txt";
			ipc_put($txt, $cur[$f['name']]);
			if (str_ends_with($f['name'], '_v4')) {
				$args = pfb_ip_preprocess_args($sw['dup'], $sw['agg'], $sw['rep']);
				if ($args !== '') {
					$token = ($sw['drep'] ? PfbToggle::On : PfbToggle::Off)->toStored();
					ipc_sh($dir, $w, "{$args} " . escapeshellarg($f['name']) . " {$sw['dmax']} " . escapeshellarg($token)
						. " {$sw['cc']} {$sw['ccwhite']} {$sw['ccblack']}", $ph);
				}
			}
			pfb_ip_recompute_write_snapshot($txt, $f['name'], $pfb['snapdir'], $pfb['origdir']);
			$repcheck = TRUE;
			if (pfb_supp_update_active(TRUE, $sw['supp'])) {
				$supp_update = TRUE;
			}
		}
		// stage 2: recompute per the matrix, then the legacy pMax follow-up (pfblockerng_apply.inc:4603-4675)
		$trigger = $repcheck;
		$m = pfb_ip_recompute_matrix($sw['dup'] && $trigger, $trigger, $sw['drep'], $sw['prep']);
		$ran = ['v4' => FALSE, 'v6' => FALSE];
		foreach (['v4', 'v6'] as $fam) {
			if (!$m["invoke_{$fam}"]) {
				continue;
			}
			$paths = [];
			foreach (pfb_ip_recompute_family_headers($existing, $fam) as $hdr) {
				$paths[] = pfb_ip_recompute_seed_snapshot($hdr, $pfb['snapdir'], $pfb['denydir']);
			}
			$list = "{$w}/db/pfb_recompute_{$fam}.members";
			$counts = "{$w}/db/pfb_recompute_{$fam}.counts";
			pfb_ip_recompute_memberlist_write($list, $paths);
			$mode = ($fam === 'v4') ? $m['repmode'] : 'off';
			$max = ($mode === 'dmax') ? $sw['dmax'] : (($mode === 'pmax') ? $sw['pmax'] : '0');
			ipc_sh($dir, $w, "recompute {$fam} " . escapeshellarg($list) . ' ' . escapeshellarg($counts)
				. " {$m['dedup']} {$mode} {$max} {$sw['cc']} {$sw['ccwhite']} {$sw['ccblack']}", $ph);
			$ran[$fam] = TRUE;
		}
		if ($m['legacy_pmax_followup']) {
			ipc_sh($dir, $w, "pmax x {$sw['pmax']}", $ph);
		}
		// stage 3: per alias suppression, then the canonical set (pfblockerng_apply.inc:4812-4905)
		$groups = [];
		foreach (['_v4', '_v6'] as $vtype) {
			foreach ($feeds as $f) {
				if (str_ends_with($f['name'], $vtype)) {
					$groups["{$f['alias']}{$vtype}"][] = $f['name'];
				}
			}
		}
		$canon = [];
		foreach ($groups as $alias => $names) {
			$vtype = substr($alias, -3);
			$fam = substr($vtype, 1);
			$feed_changed = (bool) array_intersect($names, $changed);
			$alias_ips = '';
			foreach ($names as $name) {
				$file = "{$w}/deny/{$name}.txt";
				if (!file_exists($file)) {
					continue;
				}
				$body = pfb_ip_suppress_body_for_vtype($sw['supp'], $vtype, $supp_update, TRUE, $feed_changed, $ran['v4'], $ran['v6']);
				if ($body && $vtype === '_v4' && pfb_ip_suppress_list_present("{$w}/pfbsuppression.txt")) {
					ipc_sh($dir, $w, 'suppress ' . escapeshellarg($name) . " {$w}/deny " . ($sw['dup'] ? 'on' : 'off'), $ph);
				}
				if ($body && $vtype === '_v6' && pfb_ip_suppress_list_present($supp_v6)) {
					ob_start();
					pfb_suppress_file_v6($file, $supp_v6);
					ob_end_clean();
				}
				$alias_ips .= file_get_contents($file);
			}
			$canon[$alias] = pfb_canonical_alias_set($alias_ips);
		}
		// stage 4: the Uber unions (pfblockerng.inc:14707-14726, called at pfblockerng_apply.inc:4977)
		$agg = [];
		foreach ($in['agg_types'] ?? [] as $type) {
			foreach (['v4', 'v6'] as $fam) {
				$u = ipc_union($dir, $w, $type, $fam, $sw['agg'] ? 'on' : 'off', FALSE);
				$agg["{$type}_{$fam}"] = ['kept' => $u['kept'], 'aggregate' => $u['aggregate'], 'consumer' => $u['consumer']];
			}
		}
		// stage 5: closing (pfblockerng_apply.inc:5530-5538)
		$closing = NULL;
		[$invoke, $arg] = pfb_ip_closing_pass_active($sw['dup'], $ran['v4']);
		if ($repcheck && $invoke) {
			[, $out] = ipc_sh($dir, $w, "closing {$arg}", $ph);
			$closing = ipc_closing_parse($out);
		}
		$passes[] = ['matrix' => $m, 'ran' => $ran, 'canonical' => $canon, 'aggregate' => $agg, 'closing' => $closing,
			'deny_final' => ipc_dir("{$w}/deny", FALSE)];
	}
	return ['passes' => $passes];
}

// ---- main ----------------------------------------------------------------------------------------------------

function ipc_main(string $dir, array $tools): void {
	$doc = json_decode((string) file_get_contents("{$dir}/ipset.json"), TRUE, 512, JSON_THROW_ON_ERROR);
	$w = "{$dir}/world";
	ipc_script($dir, $w, $tools);
	// Nothing the production functions read may point at the live trees, even for an op that never sets them itself.
	global $pfb;
	ipc_pfb_dirs($w, IPC_PH);
	$pfb['dnsdir'] = "{$w}/dnsbl";
	$pfb['log'] = $pfb['errlog'] = $pfb['extraslog'] = "{$dir}/pfb.log";
	$pfb['runlog'] = '';
	$ops = ['cidr_aggregate', 'preprocess', 'recompute', 'pmax', 'suppress', 'remove', 'closing', 'canonical', 'union', 'dnsblip',
		'matrix', 'pipeline'];
	$only = (string) (getenv('IPC_ONLY') ?: '');	// debug-host filter, never set on the appliance
	// One JSON line per case, appended as it finishes: a fatal in a later (heavy) case keeps every earlier result.
	$jsonl = "{$dir}/results.jsonl";
	ipc_put($jsonl, '');
	foreach ($doc['cases'] as $c) {
		if ($only !== '' && !preg_match("#{$only}#", $c['id'])) {
			continue;
		}
		$t0 = microtime(TRUE);
		try {
			if (!in_array($c['op'], $ops, TRUE)) {
				throw new RuntimeException("unknown op {$c['op']}");
			}
			$r = ('ipc_op_' . $c['op'])($dir, $w, $c, !empty($c['digest']));
		} catch (Throwable $e) {
			$r = ['error' => get_class($e) . ': ' . $e->getMessage()];
		}
		$r['_seconds'] = round(microtime(TRUE) - $t0, 2);
		file_put_contents($jsonl, json_encode(['id' => $c['id'], 'result' => $r], JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR) . "\n", FILE_APPEND);
	}
	ipc_rm($w);
	echo 'IPC-DONE';
}
ipc_main($ipc_dir, $ipc_tools);
"""  # noqa: E101, E501  (embedded PHP source, tab-indented like the PHP it mirrors)


def corpus() -> dict[str, Any]:
    doc: dict[str, Any] = json.loads(CORPUS.read_text(encoding="utf-8"))
    return doc


def validate(doc: dict[str, Any]) -> list[str]:
    """Strict schema: an unknown or missing key and a duplicate id are errors, never skips."""
    errors = []
    if set(doc) != {"schema", "cases"} or doc["schema"] != 1:
        errors.append(f"top level must be exactly schema=1 and cases, got {sorted(doc)}")
    seen: set[str] = set()
    for case in doc.get("cases", []):
        cid = case.get("id", "?")
        keys = set(case)
        if not {"id", "description", "op", "family", "input"} <= keys or not keys <= CASE_KEYS:
            errors.append(f"{cid}: keys {sorted(keys)} do not fit the case schema")
        if case.get("op") not in OPS:
            errors.append(f"{cid}: unknown op {case.get('op')!r}")
        if case.get("family") not in ("v4", "v6"):
            errors.append(f"{cid}: family must be v4 or v6")
        if not isinstance(case.get("description"), str) or not case["description"]:
            errors.append(f"{cid}: description must be a non-empty string")
        if "digest" in case and case["digest"] is not True:
            errors.append(f"{cid}: digest is only ever true")
        if cid in seen:
            errors.append(f"duplicate id {cid}")
        seen.add(cid)
    return errors


def _scrub(value: Any) -> Any:
    """The comparable form of a result: bookkeeping keys (leading underscore) removed."""
    if isinstance(value, dict):
        return {k: _scrub(v) for k, v in value.items() if not k.startswith("_")}
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    return value


def diff(want: Any, got: Any, path: str = "") -> list[str]:
    """Differences between a frozen expectation and an actual result, with the comparison rule of the README."""
    if isinstance(want, dict) and isinstance(got, dict):
        out = []
        for key in sorted(set(want) | set(got)):
            if key not in want:
                out.append(f"{path}/{key}: unexpected in actual: {got[key]!r}")
            elif key not in got:
                out.append(f"{path}/{key}: missing in actual (expected {want[key]!r})")
            else:
                out.extend(diff(want[key], got[key], f"{path}/{key}"))
        return out
    if isinstance(want, list) and isinstance(got, list) and all(isinstance(x, str) for x in want + got):
        name = path.rsplit("/", 1)[-1]
        a, b = (want, got) if name in ORDERED else (sorted(want), sorted(got))
        if a == b:
            return []
        extra = [x for x in b if x not in a]
        lost = [x for x in a if x not in b]
        how = "in order" if name in ORDERED else "as a multiset"
        return [
            f"{path}: lists differ {how}: expected {len(want)} rows, actual {len(got)}; "
            f"only in expected {lost[:5]!r}, only in actual {extra[:5]!r}"
        ]
    if want == got:
        return []
    return [f"{path}: expected {want!r} actual {got!r}"]


def mismatches(cases: list[dict[str, Any]], actual: dict[str, Any]) -> list[str]:
    """One entry per case whose frozen expectation differs from, or is missing against, the appliance's result."""
    out = []
    for case in cases:
        cid = case["id"]
        got = actual.get(cid)
        if got is None:
            out.append(f"{cid}: the harness produced no result")
        elif "error" in got:
            out.append(f"{cid}: the harness failed: {got['error']}")
        elif "expect" not in case:
            out.append(f"{cid}: case has no frozen expect (freeze it from ipset_corpus_actual.json)")
        else:
            out.extend(f"{cid}{d}" for d in diff(_scrub(case["expect"]), _scrub(got)))
    return out


def _put(vm: SmokeVM, path: str, content: bytes) -> None:
    done = subprocess.run(vm.ssh_argv(f"cat > {path}"), input=content, capture_output=True, timeout=300, check=False)
    assert done.returncode == 0, f"upload of {path} failed: {done.stderr!r}"


def _versions(vm: SmokeVM) -> dict[str, list[str]]:
    out = {}
    for name, command in VERSION_COMMANDS.items():
        run = vm.ssh(command, timeout=60)
        out[name] = (run.stdout + run.stderr).strip().splitlines()
    return out


@pytest.fixture(scope="module")
def results(smoke_vm: SmokeVM) -> Iterator[dict[str, Any]]:
    """The branch package deployed once, every case replayed on it once; the results keyed by case id."""
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    versions = _versions(smoke_vm)
    made = smoke_vm.ssh("mktemp -d /var/tmp/pfb_isc.XXXXXX", timeout=30)
    assert made.returncode == 0, made.stderr
    work = made.stdout.strip()
    try:
        _put(smoke_vm, f"{work}/ipset.json", CORPUS.read_bytes())
        _put(smoke_vm, f"{work}/harness.php", HARNESS.encode())
        # No timer decides anything here: the harness runs to its own end; the timeout only caps a hung session.
        run = h.php_eval(
            smoke_vm,
            f"$ipc_dir = '{work}';\n$ipc_tools = [];\nrequire_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\n"
            f"require('{work}/harness.php');",
            timeout=10800,
        )
        # Results are appended per case, so a harness that died mid-run still leaves every case it finished.
        got = smoke_vm.ssh(f"cat {work}/results.jsonl", timeout=600)
        assert got.returncode == 0, got.stderr
        actual = {row["id"]: row["result"] for row in map(json.loads, got.stdout.splitlines())}
        h.DIAG_DIR.mkdir(parents=True, exist_ok=True)
        (h.DIAG_DIR / "ipset_corpus_actual.json").write_text(
            json.dumps({"versions": versions, "results": actual}, indent=1, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        assert "IPC-DONE" in run.stdout, (
            f"the harness did not finish: rc={run.returncode}\n{run.stdout[-2000:]}\n{run.stderr[-2000:]}"
        )
        yield actual
    finally:
        smoke_vm.ssh(f"rm -rf {work}", timeout=300)


def test_corpus_is_well_formed() -> None:
    doc = corpus()
    errors = validate(doc)
    assert errors == [], "\n".join(errors[:40])
    assert {c["op"] for c in doc["cases"]} == set(OPS), "every group needs cases"


@pytest.mark.parametrize("op", OPS)
def test_group_matches_the_appliance(op: str, results: dict[str, Any]) -> None:
    cases = [c for c in corpus()["cases"] if c["op"] == op]
    found = mismatches(cases, results)
    assert found == [], (
        f"{len(found)} difference(s) in group {op} ({len(cases)} cases) against the appliance:\n"
        + "\n".join(found[:40])
    )
