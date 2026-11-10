from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

REPROCESS_PROBE = r"""
require 'tests/php/bootstrap.php';
require_once 'src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';
memory_reset_peak_usage();
$before = memory_get_usage();
$reprocess = pfb_top1m_reprocess_needed(getenv('PFB_TOP1M_PROBE_DIR'));
echo json_encode([
    'reprocess' => $reprocess,
    'peak_delta' => memory_get_peak_usage() - $before,
], JSON_THROW_ON_ERROR);
"""

OFFLINE_PUBLICATION_PROBE = r"""
require 'tests/php/bootstrap.php';
$root = getenv('PFB_TOP1M_PROBE_DIR');
$GLOBALS['pfb']['dbdir'] = $root . '/db';
$GLOBALS['pfb']['dnsdir'] = $root . '/dnsbl';
$GLOBALS['pfb']['dnsbl_top1m'] = PfbToggle::On;
$GLOBALS['pfb']['dnsbl_tld_wildcard'] = '';
$GLOBALS['pfb']['dnsblconfig'] = ['tld_wildcard_blacklist' => '', 'tld_wildcard_exclusion' => '', 'whitelist' => ''];
$GLOBALS['pfb']['unbound_py_rawdir'] = $root . '/pfb_py_raw';
$GLOBALS['pfb']['unbound_py_sources'] = $root . '/pfb_py_sources.json';
$GLOBALS['pfb']['unbound_py_top1m'] = $root . '/pfb_py_top1m.txt';
file_put_contents($root . '/dnsbl/fixture.txt',
    pfb_dnsbl_ndjson_emit_row(PfbDnsblRowKind::Domain, 'offline.example') .
    pfb_dnsbl_ndjson_emit_row(PfbDnsblRowKind::Domain, 'www.offline.example') .
    pfb_dnsbl_ndjson_emit_row(PfbDnsblRowKind::Domain, 'deep.offline.example') .
    pfb_dnsbl_ndjson_emit_row(PfbDnsblRowKind::Domain, 'blocked.example'));
$feeds = [pfb_feed_manifest_row('fixture', 'g', '1', 'feed', 'deny', 'on')];
$result = pfb_unbound_python_sources($feeds, ['top1m_atomic' => [
    'chown' => static fn(string $file, string $owner): bool => TRUE,
    'chgrp' => static fn(string $file, string $group): bool => TRUE,
    'chmod' => static fn(string $file, int $mode): bool => TRUE,
]]);
echo json_encode(['published' => is_array($result)], JSON_THROW_ON_ERROR);
"""


def _run_reprocess_probe(tmp_path: Path, *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PFB_TOP1M_PROBE_DIR"] = str(tmp_path)
    return subprocess.run(
        ["php", "-r", REPROCESS_PROBE],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )


def _manifest(tmp_path: Path, *, enabled: bool = True) -> Path:
    raw = tmp_path / "feed.raw"
    raw.write_text("blocked.example\n", encoding="utf-8")
    path = tmp_path / "pfb_py_sources.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "config": {"top1m_enabled": enabled, "user_whitelist": []},
                "feeds": [{"raw": raw.name, "feed": "feed", "group": "g", "log_flag": "1", "top1m": True}],
            }
        ),
        encoding="utf-8",
    )
    return path


@pytest.mark.parametrize("current_baseline", [False, True], ids=["missing-baseline", "current-baseline"])
def test_nonregular_whitelist_never_triggers_reprocessing(tmp_path: Path, current_baseline: bool) -> None:
    (tmp_path / "top-1m.csv").write_text("1,current.example\n", encoding="utf-8")
    if current_baseline:
        (tmp_path / "top-1m.csv.zip.orig").write_text("detector baseline\n", encoding="utf-8")
    whitelist = tmp_path / "pfbalexawhitelist.txt"
    os.mkfifo(whitelist)
    fifo = os.open(whitelist, os.O_RDWR | os.O_NONBLOCK)

    try:
        os.write(fifo, b".legacy.example,,\n")
        proc = _run_reprocess_probe(tmp_path)
    finally:
        os.close(fifo)

    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["reprocess"] is False


def test_current_canonical_whitelist_check_has_bounded_peak_memory(tmp_path: Path) -> None:
    (tmp_path / "top-1m.csv").write_text("1,current.example\n", encoding="utf-8")
    (tmp_path / "top-1m.csv.zip.orig").write_text("detector baseline\n", encoding="utf-8")
    with (tmp_path / "pfbalexawhitelist.txt").open("w", encoding="utf-8") as handle:
        for index in range(200_000):
            handle.write(f"domain-{index:06d}.example\n")

    proc = _run_reprocess_probe(tmp_path)

    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout)
    assert result["reprocess"] is False
    assert result["peak_delta"] < 1024 * 1024


@pytest.mark.parametrize(
    "legacy_wire",
    [
        b".offline.example,,\n,offline.example,,\n,www.offline.example,,\n",
        b'.offline.example 60\n"offline.example 60\n"www.offline.example 60\n',
    ],
    ids=["python-mode", "native-mode"],
)
def test_offline_legacy_publication_filters_only_listed_and_www_entries(tmp_path: Path, legacy_wire: bytes) -> None:
    dbdir = tmp_path / "db"
    dbdir.mkdir()
    (tmp_path / "dnsbl").mkdir()
    source = dbdir / "pfbalexawhitelist.txt"
    source.write_bytes(legacy_wire)
    env = os.environ.copy()
    env["PFB_TOP1M_PROBE_DIR"] = str(tmp_path)

    proc = subprocess.run(
        ["php", "-r", OFFLINE_PUBLICATION_PROBE],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == {"published": True}
    assert not (dbdir / "top-1m.csv.zip.orig").exists()
    assert source.read_bytes() == legacy_wire
    assert (tmp_path / "pfb_py_top1m.txt").read_bytes() == b"offline.example\n"

    manifest = json.loads((tmp_path / "pfb_py_sources.json").read_text(encoding="utf-8"))
    assert manifest["config"]["top1m_enabled"] is True
    assert [feed["top1m"] for feed in manifest["feeds"]] == [True]


@pytest.mark.parametrize(
    "legacy_wire",
    [
        b".legacy.com,,\n,legacy.com,,\n,www.legacy.com,,\n",
        b'.legacy.com 60\n"legacy.com 60\n"www.legacy.com 60\n',
    ],
    ids=["python-mode", "native-mode"],
)
def test_legacy_whitelist_reprocesses_and_republishes_the_top1m_sidecar(tmp_path: Path, legacy_wire: bytes) -> None:
    (tmp_path / "top-1m.csv").write_text("1,LEGACY.COM\n", encoding="utf-8")
    (tmp_path / "top-1m.csv.zip.orig").write_text("detector baseline\n", encoding="utf-8")
    (tmp_path / "pfbalexawhitelist.txt").write_bytes(legacy_wire)
    php = r"""
require 'tests/php/bootstrap.php';
require_once 'src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';
$dbdir = getenv('PFB_TOP1M_PROBE_DIR');
mkdir($dbdir . '/dnsbl');
$GLOBALS['pfb']['dbdir'] = $dbdir;
$GLOBALS['pfb']['dnsdir'] = $dbdir . '/dnsbl';
$GLOBALS['pfb']['dnsbl_top1m'] = PfbToggle::On;
$GLOBALS['pfb']['dnsbl_top1m_inc'] = 'com';
$GLOBALS['pfb']['dnsbl_top1m_cnt'] = '1000';
$GLOBALS['pfb']['dnsblconfig'] = ['tld_wildcard_blacklist' => '', 'tld_wildcard_exclusion' => '', 'whitelist' => ''];
$GLOBALS['pfb']['unbound_py_rawdir'] = $dbdir . '/raw';
$GLOBALS['pfb']['unbound_py_sources'] = $dbdir . '/pfb_py_sources.json';
$GLOBALS['pfb']['unbound_py_top1m'] = $dbdir . '/pfb_py_top1m.txt';
$GLOBALS['pfb']['log'] = $dbdir . '/pfblockerng.log';
$GLOBALS['pfb']['errlog'] = $dbdir . '/pfblockerng_error.log';
$reprocess = pfb_top1m_reprocess_needed($dbdir);
if ($reprocess) {
    pfblockerng_top1m();
    file_put_contents($dbdir . '/dnsbl/fixture.txt',
        pfb_dnsbl_ndjson_emit_row(PfbDnsblRowKind::Domain, 'legacy.com') .
        pfb_dnsbl_ndjson_emit_row(PfbDnsblRowKind::Domain, 'www.legacy.com') .
        pfb_dnsbl_ndjson_emit_row(PfbDnsblRowKind::Domain, 'deep.legacy.com') .
        pfb_dnsbl_ndjson_emit_row(PfbDnsblRowKind::Domain, 'blocked.example'));
    $feeds = [pfb_feed_manifest_row('fixture', 'g', '1', 'feed', 'deny', 'on')];
    $published = pfb_unbound_python_sources($feeds, ['top1m_atomic' => [
        'chown' => static fn(string $file, string $owner): bool => TRUE,
        'chgrp' => static fn(string $file, string $group): bool => TRUE,
        'chmod' => static fn(string $file, int $mode): bool => TRUE,
    ]]);
    if ($published === FALSE) {
        throw new RuntimeException('TOP1M fixed-file publication failed');
    }
}
echo json_encode(['reprocess' => $reprocess], JSON_THROW_ON_ERROR);
"""
    env = os.environ.copy()
    env["PFB_TOP1M_PROBE_DIR"] = str(tmp_path)
    proc = subprocess.run(
        ["php", "-r", php],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == {"reprocess": True}
    assert (tmp_path / "pfbalexawhitelist.txt").read_bytes() == b"legacy.com\n"

    assert (tmp_path / "pfb_py_top1m.txt").read_bytes() == b"legacy.com\n"
    manifest = json.loads((tmp_path / "pfb_py_sources.json").read_text(encoding="utf-8"))
    assert manifest["config"]["top1m_enabled"] is True
    assert [feed["top1m"] for feed in manifest["feeds"]] == [True]
