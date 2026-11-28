from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

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
    implode('', array_map(static fn(string $domain): string =>
        json_encode([PfbDnsblRowKind::Domain, $domain], JSON_THROW_ON_ERROR) . "\n",
        ['offline.example', 'www.offline.example', 'deep.offline.example', 'blocked.example'])));
$feeds = [['header' => 'fixture', 'group' => 'g', 'log' => '1', 'provenance' => 'feed', 'top1m' => TRUE]];
$result = pfb_unbound_python_sources($feeds, ['top1m_atomic' => [
    'chown' => static fn(string $file, string $owner): bool => TRUE,
    'chgrp' => static fn(string $file, string $group): bool => TRUE,
    'chmod' => static fn(string $file, int $mode): bool => TRUE,
]]);
echo json_encode(['published' => is_array($result)], JSON_THROW_ON_ERROR);
"""


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
