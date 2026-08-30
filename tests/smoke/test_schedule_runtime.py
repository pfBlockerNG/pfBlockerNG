"""Live pfSense checks for the anchored scheduler runtime (#2308)."""

# ruff: noqa: E501 -- embedded PHP remains readable as executable appliance fixtures.

from __future__ import annotations

import json
import os
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM, _StubDnsServer

pytestmark = pytest.mark.smoke


@pytest.fixture(scope="module")
def deployed_vm(smoke_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[SmokeVM]:  # noqa: ARG001
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")
    h.deploy(smoke_vm)
    try:
        yield smoke_vm
    finally:
        h.collect_host_diagnostics(smoke_vm)


def test_schedule_migration_planning_and_cache_regeneration(deployed_vm: SmokeVM) -> None:
    """Fresh/legacy migration, overrides, catch-up, Extras order, and cache rebuild."""
    snippet = r"""
require_once('/usr/local/pkg/pfblockerng/pfblockerng_extra.inc');
$gen = 'installedpackages/pfblockerng/config/0';
$v4 = 'installedpackages/pfblockernglistsv4/config';
$v6 = 'installedpackages/pfblockernglistsv6/config';
$dns = 'installedpackages/pfblockerngdnsbl/config';
$fresh = pfb_schedule_migrate(array($gen => array(), $v4 => array(), $v6 => array(), $dns => array()), static fn (): int => 27);
$legacy = pfb_schedule_migrate(array(
    $gen => array('enable_cb' => 'on', 'pfb_interval' => '4', 'pfb_dailystart' => '2', 'pfb_min' => '30'),
    $v4 => array(array('action' => 'Deny_Inbound', 'cron' => 'Weekly', 'dow' => '3', 'row' => array(array('url' => 'https://example.test/v4', 'state' => 'Enabled')))),
    $v6 => array(array('action' => 'Deny_Inbound', 'cron' => 'EveryDay', 'dow' => '5', 'row' => array(array('url' => 'https://example.test/v6', 'state' => 'Enabled')))),
    $dns => array(array('action' => 'unbound', 'cron' => 'Weekly', 'dow' => '7', 'row' => array(array('url' => 'https://example.test/dns', 'state' => 'Enabled')))),
), static fn (): int => 0);
$default = array('weekday' => 3, 'hour' => 2, 'minute' => 15);
$groups = array(
    'ipv4:hour_v4' => array('cadence' => '01hour', 'enabled' => true, 'has_active_rows' => true, 'override' => null),
    'ipv6:daily_v6' => array('cadence' => 'EveryDay', 'enabled' => true, 'has_active_rows' => true, 'override' => null),
    'dnsbl:weekly' => array('cadence' => 'Weekly', 'enabled' => true, 'has_active_rows' => true, 'override' => array('weekday' => 3, 'hour' => 3, 'minute' => 0)),
);
$now = strtotime('2026-01-07 04:20:00 UTC');
$plan = pfb_schedule_plan($groups, $default, strtotime('2025-12-30 00:00:00 UTC'), $now, new DateTimeZone('UTC'));
foreach ($plan['occurrences'] as $id => $occurrence) {
    $groups[$id]['last_completed_occurrence'] = $occurrence;
}
$second = pfb_schedule_plan($groups, $default, null, $now, new DateTimeZone('UTC'));
$model = pfb_schedule_runtime_model(array(
    'pfb_scheduled_feed_updates' => 'on',
    'pfb_schedule_weekday' => '3',
    'pfb_schedule_hour' => '2',
    'pfb_schedule_minute' => '15',
), array(
    'ipv4' => array(array('action' => 'Deny_Inbound', 'cron' => 'EveryDay', 'schedule_override' => '', 'row' => array(array('header' => 'live', 'url' => 'https://example.test/live', 'state' => 'Enabled')))),
    'ipv6' => array(),
    'dnsbl' => array(),
), array('dcc' => true, 'bl' => array('enabled' => true, 'cadence' => 'EveryDay')));
$tmp = sys_get_temp_dir() . '/pfb_schedule_smoke_' . getmypid() . '_' . uniqid();
mkdir($tmp, 0700, true);
$state = array('schema' => 1, 'items' => array());
$cache_ok = is_array($model) && pfb_schedule_cache_refresh($model, $state, $now, new DateTimeZone('UTC'), $tmp);
$cache = $cache_ok ? pfb_due_ledger_read_cache($tmp, $model['config_hash']) : null;
$extras = is_array($cache) ? pfb_schedule_extra_plan($model, $state, $now, new DateTimeZone('UTC'), $cache) : array('due' => array());
$out = array(
    'fresh' => array(
        'master' => $fresh[$gen]['pfb_scheduled_feed_updates'] ?? null,
        'weekday' => $fresh[$gen]['pfb_schedule_weekday'] ?? null,
        'hour' => $fresh[$gen]['pfb_schedule_hour'] ?? null,
        'minute' => $fresh[$gen]['pfb_schedule_minute'] ?? null,
    ),
    'legacy' => array(
        'master' => $legacy[$gen]['pfb_scheduled_feed_updates'] ?? null,
        'hour' => $legacy[$gen]['pfb_schedule_hour'] ?? null,
        'minute' => $legacy[$gen]['pfb_schedule_minute'] ?? null,
        'retired_general' => array_intersect_key($legacy[$gen], array_flip(array('pfb_interval', 'pfb_min', 'pfb_hour', 'pfb_dailystart'))),
        'v4_override' => $legacy[$v4][0]['schedule_override'] ?? null,
        'v4_weekday' => $legacy[$v4][0]['schedule_weekday'] ?? null,
        'retired_dow' => array_key_exists('dow', $legacy[$v4][0]) || array_key_exists('dow', $legacy[$v6][0]) || array_key_exists('dow', $legacy[$dns][0]),
    ),
    'due' => $plan['due'],
    'second_due' => $second['due'],
    'extras_due' => $extras['due'],
    'cache_ok' => $cache_ok && is_array($cache) && ($cache['_meta']['config_hash'] ?? null) === $model['config_hash'],
);
foreach (glob($tmp . '/*') ?: array() as $path) { @unlink($path); }
@rmdir($tmp);
echo '<<<SCHEDULE>>>' . json_encode($out) . '<<<END>>>';
"""
    result = h.php_eval(deployed_vm, snippet)
    assert result.returncode == 0, result.stderr or result.stdout
    raw = result.stdout.split("<<<SCHEDULE>>>", 1)[1].split("<<<END>>>", 1)[0]
    data = json.loads(raw)

    assert data["fresh"] == {"master": "on", "weekday": "7", "hour": "6", "minute": "45"}
    assert data["legacy"] == {
        "master": "on",
        "hour": "2",
        "minute": "30",
        "retired_general": [],
        "v4_override": "on",
        "v4_weekday": "3",
        "retired_dow": False,
    }
    assert data["due"] == ["ipv4:hour_v4", "ipv6:daily_v6", "dnsbl:weekly"]
    assert data["second_due"] == []
    assert data["extras_due"] == ["extra:dcc", "extra:bl"]
    assert data["cache_ok"] is True


def test_persisted_schedule_runs_once_in_locked_runtime_order(deployed_vm: SmokeVM) -> None:
    """Seed a fresh install, persist migration/runtime inputs, run the real tick, prove once-only ordering."""
    snippet = r"""
require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');
pfb_global();
$paths = array(
    'installedpackages/pfblockerng/config/0',
    'installedpackages/pfblockernglistsv4/config',
    'installedpackages/pfblockernglistsv6/config',
    'installedpackages/pfblockerngdnsbl/config',
    'installedpackages/pfblockerngblacklist',
);
$before = array();
foreach ($paths as $path) { $before[$path] = config_get_path($path, NULL); }
$state_dir = $pfb['schedule_state_dir'] ?? '/usr/local/etc';
$state_path = $state_dir . '/pfb_schedule_state.json';
$cache_path = $pfb['dbdir'] . '/pfb_due_ledger.json';
$state_before = is_file($state_path) ? file_get_contents($state_path) : NULL;
$cache_before = is_file($cache_path) ? file_get_contents($cache_path) : NULL;
$out = array();
try {
    // Cause the virgin-install image instead of inheriting it (issue #2900): the
    // cross-module baseline (conftest.py::_pfb_module_baseline) unsets these very
    // keys, and pfb_schedule_migrate() reads General's operator view for freshness.
    config_set_path($paths[0], array());
    config_set_path($paths[1], array());
    config_set_path($paths[2], array());
    config_set_path($paths[3], array());
    write_config('pfBlockerNG smoke #2308: fresh-install scheduler image');
    pfb_run_migrations();
    $fresh = config_get_path($paths[0], array());
    $out['fresh'] = array(
        'master' => $fresh['pfb_scheduled_feed_updates'] ?? NULL,
        'skipfeed' => $fresh['skipfeed'] ?? NULL,
        'weekday' => $fresh['pfb_schedule_weekday'] ?? NULL,
    );

    config_set_path($paths[0], array(
        'enable_cb' => 'on', 'skipfeed' => '0', 'pfb_interval' => '4',
        'pfb_dailystart' => '2', 'pfb_min' => '30', 'pfb_hour' => '1',
    ));
    config_set_path($paths[1], array(array(
        'action' => 'Deny_Inbound', 'cron' => 'Weekly', 'dow' => '3',
        'row' => array(array('header' => 'legacy', 'url' => '/var/db/pfblockerng/legacy.txt', 'state' => 'Enabled')),
    )));
    config_set_path($paths[2], array());
    config_set_path($paths[3], array());
    write_config('pfBlockerNG smoke #2308: legacy scheduler image');
    pfb_run_migrations();
    $migrated = config_get_path($paths[0], array());
    $migrated_v4 = config_get_path($paths[1], array());
    $out['migration'] = array(
        'master' => $migrated['pfb_scheduled_feed_updates'] ?? NULL,
        'hour' => $migrated['pfb_schedule_hour'] ?? NULL,
        'minute' => $migrated['pfb_schedule_minute'] ?? NULL,
        'retired' => array_intersect_key($migrated, array_flip(array('pfb_interval', 'pfb_min', 'pfb_hour', 'pfb_dailystart'))),
        'override' => $migrated_v4[0]['schedule_override'] ?? NULL,
        'weekday' => $migrated_v4[0]['schedule_weekday'] ?? NULL,
        'dow' => array_key_exists('dow', $migrated_v4[0] ?? array()),
    );

    $anchor = new DateTimeImmutable('-15 minutes');
    $minute = intdiv((int) $anchor->format('i'), 15) * 15;
    config_set_path($paths[0], array(
        'enable_cb' => 'on', 'skipfeed' => '3', 'pfb_scheduled_feed_updates' => 'on',
        'pfb_schedule_weekday' => $anchor->format('N'),
        'pfb_schedule_hour' => $anchor->format('G'),
        'pfb_schedule_minute' => (string) $minute,
        'pfb_quiet_hours' => '',
    ));
    config_set_path($paths[1], array(array(
        'action' => 'Deny_Inbound', 'cron' => '01hour', 'schedule_override' => '',
        'row' => array(array('header' => 'smoke_hour', 'url' => '/var/db/pfblockerng/smoke_hour.txt', 'state' => 'Enabled')),
    )));
    config_set_path($paths[2], array(array(
        'action' => 'Deny_Inbound', 'cron' => 'EveryDay', 'schedule_override' => 'on',
        'schedule_weekday' => $anchor->format('N'), 'schedule_hour' => $anchor->format('G'),
        'schedule_minute' => (string) $minute,
        'row' => array(array('header' => 'smoke_daily', 'url' => '/var/db/pfblockerng/smoke_daily.txt', 'state' => 'Enabled')),
    )));
    config_set_path($paths[3], array(array(
        'action' => 'unbound', 'cron' => 'Weekly', 'schedule_override' => 'on',
        'schedule_weekday' => $anchor->format('N'), 'schedule_hour' => $anchor->format('G'),
        'schedule_minute' => (string) $minute,
        'row' => array(array('header' => 'smoke_weekly', 'url' => '/var/db/pfblockerng/smoke_weekly.txt', 'state' => 'Enabled')),
    )));
    config_set_path($paths[4], array(
        'blacklist_enable' => 'Enable', 'blacklist_selected' => 'smoke', 'blacklist_freq' => 'Weekly',
        'item' => array(array('xml' => 'smoke', 'selected' => 'yes', 'title' => 'Smoke', 'feed' => '/var/db/pfblockerng/smoke_bl.txt')),
    ));
    write_config('pfBlockerNG smoke #2308: persisted runtime schedule');
    pfb_global();
    @unlink($state_path);
    @unlink($cache_path);
    $out['regenerated'] = pfb_schedule_cache_regenerate();
    $fixed_next = time() + 3600;
    pfb_due_ledger_write_entry('ss_refresh', array('last_run' => time(), 'next_due' => $fixed_next, 'jitter' => 0), $pfb['dbdir']);
    pfb_due_ledger_write_entry('apply_reconcile', array('last_run' => time(), 'next_due' => $fixed_next, 'jitter' => 0), $pfb['dbdir']);
    $far_past = time() - (15 * 86400);
    $out['far_past_seeded'] = pfb_due_ledger_update_entry(
        'cron',
        static fn (?array $entry): array => array(
            'last_run' => $entry['last_run'] ?? 0, 'next_due' => $far_past, 'jitter' => 0,
        ),
        $pfb['dbdir']
    );

    $order = array();
    $extra = static function (string $job, string $argument = '', bool &$changed = FALSE) use (&$order): bool {
        $order[] = $job;
        return TRUE;
    };
    $feed = static function () use (&$order, $state_dir): void {
        $order[] = 'feed';
        $state = pfb_schedule_state_read($state_dir);
        foreach (($state['items'] ?? array()) as $id => $item) {
            if (strpos($id, 'extra:') !== 0 && is_int($item['pending_occurrence'] ?? NULL)) {
                pfb_schedule_state_record_outcome($id, PfbScheduleTerminalResult::Success, $state_dir);
            }
        }
    };
    pfblockerng_tick(array(), NULL, NULL, 5.0, NULL, NULL, 5.0, $extra, $feed);
    $state = pfb_schedule_state_read($state_dir);
    $cache = pfb_due_ledger_read_cache($pfb['dbdir'], pfb_schedule_runtime_config()['config_hash']);
    $completed = array();
    foreach (($state['items'] ?? array()) as $id => $item) {
        if (isset($item['last_completed_occurrence']) && !isset($item['pending_occurrence'])) { $completed[] = $id; }
    }
    sort($completed);
    $out['first_order'] = $order;
    $out['completed'] = $completed;
    $out['next_due_future'] = ($cache['cron']['next_due'] ?? 0) > time();
    $order = array();
    pfblockerng_tick(array(), NULL, NULL, 5.0, NULL, NULL, 5.0, $extra, $feed);
    $out['second_order'] = $order;

    $outside_start = date('H:i', time() + 7200);
    $outside_end = date('H:i', time() + 10800);
    $general = config_get_path($paths[0], array());
    $general['pfb_quiet_hours'] = $outside_start . '-' . $outside_end;
    config_set_path($paths[0], $general);
    write_config('pfBlockerNG smoke #2308: closed apply window');
    pfb_due_ledger_set_pending('cron', $pfb['dbdir']);
    $manual_runs = 0;
    $manual = static function () use (&$manual_runs): bool { ++$manual_runs; return TRUE; };
    pfblockerng_tick(array(), NULL, NULL, 5.0, NULL, NULL, 5.0, $extra, $feed, $manual);
    $out['manual_outside'] = $manual_runs;
    $general['pfb_quiet_hours'] = '';
    config_set_path($paths[0], $general);
    write_config('pfBlockerNG smoke #2308: open apply window');
    pfblockerng_tick(array(), NULL, NULL, 5.0, NULL, NULL, 5.0, $extra, $feed, $manual);
    $out['manual_inside'] = $manual_runs;
} finally {
    foreach ($before as $path => $value) {
        if ($value === NULL) { config_del_path($path); } else { config_set_path($path, $value); }
    }
    write_config('pfBlockerNG smoke #2308: restore scheduler config');
    if ($state_before === NULL) { @unlink($state_path); } else { file_put_contents($state_path, $state_before); }
    if ($cache_before === NULL) { @unlink($cache_path); } else { file_put_contents($cache_path, $cache_before); }
}
echo '<<<SCHEDULE_RUNTIME>>>' . json_encode($out) . '<<<END>>>';
"""
    result = h.php_eval(deployed_vm, snippet, timeout=180.0)
    assert result.returncode == 0, result.stderr or result.stdout
    raw = result.stdout.split("<<<SCHEDULE_RUNTIME>>>", 1)[1].split("<<<END>>>", 1)[0]
    data = json.loads(raw)

    assert data["fresh"] == {"master": "on", "skipfeed": "3", "weekday": "7"}
    assert data["migration"] == {
        "master": "on",
        "hour": "2",
        "minute": "30",
        "retired": [],
        "override": "on",
        "weekday": "3",
        "dow": False,
    }
    assert data["regenerated"] is True
    assert data["far_past_seeded"] is True
    assert data["first_order"] == ["dcc", "bl", "feed"]
    assert data["completed"] == [
        "dnsbl:smoke_weekly",
        "extra:bl",
        "extra:dcc",
        "ipv4:smoke_hour_v4",
        "ipv6:smoke_daily_v6",
    ]
    assert data["next_due_future"] is True
    assert data["second_order"] == []
    assert data["manual_outside"] == 0
    assert data["manual_inside"] == 1
