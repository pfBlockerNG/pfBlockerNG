"""Issue #3648: an upgraded 3.3 config keeps each DNSBL Group's "TOP1M Whitelist" box in the manifest.

The per-Group checkbox (``filter_top1m``, 3.3's ``filter_alexa``) is the scope of the TOP1M list. The
decider's side of that contract (a ticked Group stops blocking a TOP1M domain, every other Group keeps
blocking it) is pinned by the Go decider tests. This file pins the PHP side: a 3.3 config is migrated and
its Groups are written into the manifest by the production row builder and manifest writer, and only the
Group that had the box ticked carries ``top1m`` in the manifest.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

UPGRADE_PROBE = r"""
require 'tests/php/bootstrap.php';
$root = getenv('PFB_PROBE_DIR');
$GLOBALS['pfb_test_write_config_calls'] = [];
$GLOBALS['pfb_test_file_notices'] = [];
// Two 3.3 DNSBL Groups: the box is stored under its retired 3.3 name.
$GLOBALS['config'] = ['installedpackages' => ['pfblockerngdnsbl' => ['config' => [
    ['aliasname' => 'Phish', 'action' => 'unbound', 'filter_alexa' => 'on'],
    ['aliasname' => 'Ads', 'action' => 'unbound', 'filter_alexa' => ''],
]]]];
pfb_run_migrations();

$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
    'dbdir' => "{$root}/db",
    'dnsdir' => "{$root}/dnsbl",
    'dnsbl_top1m' => PfbToggle::On,
    'dnsbl_tld_wildcard' => '',
    'dnsblconfig' => ['tld_wildcard_blacklist' => '', 'tld_wildcard_exclusion' => '', 'whitelist' => ''],
    'unbound_py_rawdir' => "{$root}/pfb_py_raw",
    'unbound_py_sources' => "{$root}/pfb_py_sources.json",
    'unbound_py_top1m' => "{$root}/pfb_py_top1m.txt",
    'log' => "{$root}/pfblockerng.log",
    'errlog' => "{$root}/pfblockerng_error.log",
]);
file_put_contents("{$root}/db/pfbalexawhitelist.txt", "phish-listed.example\nads-listed.example\n");

// Each Group lists one TOP1M domain; its rows reach the manifest as the DNSBL update loop writes them.
$feeds = [];
foreach (config_get_path('installedpackages/pfblockerngdnsbl/config', []) as $list) {
    $header = "{$list['aliasname']}Feed";
    file_put_contents("{$root}/dnsbl/{$header}.txt",
        pfb_dnsbl_ndjson_emit_row(PfbDnsblRowKind::Domain, strtolower($list['aliasname']) . '-listed.example'));
    $feeds[] = pfb_feed_manifest_row($header, "DNSBL_{$list['aliasname']}", '1', 'feed', 'deny',
        $list['filter_top1m'] ?? NULL);
}
$published = pfb_unbound_python_sources($feeds, ['top1m_atomic' => [
    'chown' => static fn(string $file, string $owner): bool => TRUE,
    'chgrp' => static fn(string $file, string $group): bool => TRUE,
    'chmod' => static fn(string $file, int $mode): bool => TRUE,
]]);
echo json_encode(['published' => is_array($published)], JSON_THROW_ON_ERROR);
"""


def test_an_upgraded_33_config_keeps_each_groups_box(tmp_path: Path) -> None:
    """R7. A 3.3 config stores the box as ``filter_alexa``. After the upgrade migration, the Group that
    had it ticked is marked ``top1m`` in the manifest and the Group that had it cleared is not."""
    (tmp_path / "db").mkdir()
    (tmp_path / "dnsbl").mkdir()
    env = os.environ.copy()
    env["PFB_PROBE_DIR"] = str(tmp_path)
    proc = subprocess.run(
        ["php", "-r", UPGRADE_PROBE],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert proc.returncode == 0, f"PHP probe failed:\nstdout={proc.stdout}\nstderr={proc.stderr}"
    assert json.loads(proc.stdout) == {"published": True}

    manifest = json.loads((tmp_path / "pfb_py_sources.json").read_text(encoding="utf-8"))
    assert manifest["config"]["top1m_enabled"] is True
    assert {feed["group"]: feed.get("top1m") for feed in manifest["feeds"]} == {
        "DNSBL_Phish": True,
        "DNSBL_Ads": None,
    }
