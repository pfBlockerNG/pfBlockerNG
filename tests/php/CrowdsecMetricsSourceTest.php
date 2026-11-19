<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4073 -- the `crowdsec` source of the metrics export (docs/specs/crowdsec-integration.md D6, metrics-export.md).
 *
 * Driven end to end through pfb_metrics_collect() and pfb_metrics_render(), from a status file written as the daemon writes it
 * (go/pfb_crowdsec/status.go):
 *   - while the bouncer should run, runs and its status file is fresh: the D6 families under their exact names and labels, and
 *     source_up{source="crowdsec"} 1;
 *   - a stopped service, or a missing, unreadable, garbled or stale (older than 3 x update_frequency) status file: source_up 0, no
 *     CrowdSec family, every other source intact;
 *   - while the bouncer should not run (each D4 reason): no source at all.
 */
#[CoversFunction('pfb_metrics_collect')]
#[CoversFunction('pfb_metrics_render')]
final class CrowdsecMetricsSourceTest extends TestCase
{
	private const SECTION = 'installedpackages/pfblockerngcrowdsec/config/0';
	private const KEY = 'Zk9-metrics_KEY.0123456789';

	private string $root;
	private mixed $savedConfig;
	private mixed $savedPfb;
	private mixed $savedPids;

	protected function setUp(): void
	{
		global $pfb;

		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$this->savedPfb = $pfb;
		$this->savedPids = $GLOBALS['pfb_test_valid_pids'] ?? NULL;
		$this->root = sys_get_temp_dir() . '/pfb_crowdsec_metrics_' . bin2hex(random_bytes(8));
		mkdir("{$this->root}/db", 0777, TRUE);

		$pfb['dbdir'] = $pfb['dnsbldir'] = "{$this->root}/db";
		$pfb['aliasdir'] = $this->root;
		$pfb['pass_status'] = "{$this->root}/pfb_pass_status.json";
		$pfb['dnsbl'] = PfbToggle::Off;
		$pfb['enable'] = PfbToggle::On;
		$pfb['pfctl'] = "{$this->root}/pfctl";
		file_put_contents($pfb['pfctl'], "#!/bin/sh\nexit 0\n");
		chmod($pfb['pfctl'], 0755);
		$pfb['crowdsec_status'] = "{$this->root}/pfb_crowdsec.json";
		$pfb['crowdsec_pidfile'] = "{$this->root}/pfb_crowdsec.pid";

		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_pf_rules'] = [];
		config_set_path(self::SECTION . '/enable', 'on');
		config_set_path(self::SECTION . '/api_key', self::KEY);
		$GLOBALS['pfb_test_valid_pids'] = [$pfb['crowdsec_pidfile'] => TRUE];
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = $this->savedConfig;
		$GLOBALS['pfb'] = $this->savedPfb;
		$GLOBALS['pfb_test_valid_pids'] = $this->savedPids;
		$GLOBALS['pfb_test_pf_rules'] = [];
		rmdir_recursive($this->root);
	}

	/** The status file as the daemon writes it, $age seconds after its last write, with $changes merged over it. */
	private function statusDoc(int $age = 4, array $changes = []): array
	{
		return array_replace([
			'version' => '0.1.0',
			'start_time' => 1763500000,
			'update_frequency_seconds' => 10,
			'updated_at' => time() - $age,
			'last_pull' => 1763550000,
			'last_error_time' => 1763540000,
			'last_error' => 'Get "http://192.0.2.10:8080/v1/decisions/stream": dial tcp: connection refused',
			'lapi_requests' => 120,
			'lapi_errors' => 3,
			'banned' => [
				'ipv4' => ['total' => 5, 'origins' => ['crowdsec' => 3, 'lists:firehol "x"' => 2]],
				'ipv6' => ['total' => 1, 'origins' => ['cscli' => 1]],
			],
			'dropped' => ['ipv4' => ['packets' => 42, 'bytes' => 2520], 'ipv6' => ['packets' => 0, 'bytes' => 0]],
		], $changes);
	}

	private function writeStatus(string $raw): void
	{
		file_put_contents($GLOBALS['pfb']['crowdsec_status'], $raw);
	}

	/** @return array{0: array<string,mixed>, 1: string} the collected snapshot and its rendering */
	private function collect(): array
	{
		$snapshot = pfb_metrics_collect(static fn (): array => ['status' => 0, 'body' => NULL, 'error' => 'no Core here']);
		return [$snapshot, pfb_metrics_render($snapshot)];
	}

	/** The sources every scrape reports, whatever the bouncer does: proof that the CrowdSec source leaves them intact. */
	private function assertOtherSourcesIntact(array $snapshot, string $prom): void
	{
		foreach (['pfctl' => TRUE, 'pf_rules' => TRUE, 'dnsbl_db' => TRUE, 'resolver_db' => TRUE, 'sync_status' => TRUE, 'pass_status' => TRUE] as $source => $up) {
			$this->assertSame($up, $snapshot['source_up'][$source] ?? NULL, "source {$source}");
		}
		$this->assertStringContainsString("pfblockerng_info{version=", $prom);
		$this->assertStringContainsString('pfblockerng_metrics_source_up{source="pfctl"} 1', $prom);
		$this->assertStringContainsString('pfblockerng_update_last_start_timestamp_seconds 0', $prom);
	}

	private function assertNoCrowdsecFamily(string $prom): void
	{
		foreach (['fw_bouncer_', 'pfblockerng_crowdsec_'] as $prefix) {
			$this->assertStringNotContainsString("\n{$prefix}", "\n{$prom}", "no {$prefix}* family:\n{$prom}");
		}
	}

	public function testARunningBouncerWithAFreshStatusFileExportsTheD6Families(): void
	{
		$this->writeStatus(json_encode($this->statusDoc()));

		[$snapshot, $prom] = $this->collect();

		$this->assertTrue($snapshot['source_up']['crowdsec'] ?? NULL, 'source_up 1 while the bouncer runs');
		$expected = <<<'PROM'
		# HELP fw_bouncer_dropped_packets Packets dropped by the CrowdSec bouncer's rules, per address family.
		# TYPE fw_bouncer_dropped_packets gauge
		fw_bouncer_dropped_packets{ip_type="ipv4"} 42
		fw_bouncer_dropped_packets{ip_type="ipv6"} 0
		# HELP fw_bouncer_dropped_bytes Bytes dropped by the CrowdSec bouncer's rules, per address family.
		# TYPE fw_bouncer_dropped_bytes gauge
		fw_bouncer_dropped_bytes{ip_type="ipv4"} 2520
		fw_bouncer_dropped_bytes{ip_type="ipv6"} 0
		# HELP fw_bouncer_banned_ips Values the CrowdSec bouncer bans, per origin and address family.
		# TYPE fw_bouncer_banned_ips gauge
		fw_bouncer_banned_ips{origin="crowdsec",ip_type="ipv4"} 3
		fw_bouncer_banned_ips{origin="lists:firehol \"x\"",ip_type="ipv4"} 2
		fw_bouncer_banned_ips{origin="cscli",ip_type="ipv6"} 1
		# HELP pfblockerng_crowdsec_lapi_requests_total Requests the CrowdSec bouncer sent to the LAPI since it started.
		# TYPE pfblockerng_crowdsec_lapi_requests_total counter
		pfblockerng_crowdsec_lapi_requests_total 120
		# HELP pfblockerng_crowdsec_lapi_errors_total Failed LAPI requests of the CrowdSec bouncer since it started.
		# TYPE pfblockerng_crowdsec_lapi_errors_total counter
		pfblockerng_crowdsec_lapi_errors_total 3
		# HELP pfblockerng_crowdsec_last_pull_timestamp_seconds Unix time of the CrowdSec bouncer's last successful pull.
		# TYPE pfblockerng_crowdsec_last_pull_timestamp_seconds gauge
		pfblockerng_crowdsec_last_pull_timestamp_seconds 1763550000
		# HELP pfblockerng_crowdsec_last_error_timestamp_seconds Unix time of the CrowdSec bouncer's last error, 0 for none.
		# TYPE pfblockerng_crowdsec_last_error_timestamp_seconds gauge
		pfblockerng_crowdsec_last_error_timestamp_seconds 1763540000

		PROM;
		$this->assertStringContainsString($expected, $prom);
		$this->assertStringContainsString('pfblockerng_metrics_source_up{source="crowdsec"} 1', $prom);
		$this->assertStringNotContainsString(self::KEY, $prom);
		$this->assertOtherSourcesIntact($snapshot, $prom);
	}

	public function testAFileJustInsideThreeUpdateIntervalsIsFreshAndJustOutsideIsStale(): void
	{
		// 3 x 10 s: 25 s old is fresh, 31 s old is stale (a margin either side: the clock may tick between write and read)
		$this->writeStatus(json_encode($this->statusDoc(25)));
		[$snapshot] = $this->collect();
		$this->assertTrue($snapshot['source_up']['crowdsec'] ?? NULL, 'before-state: 25 s old is fresh');

		$this->writeStatus(json_encode($this->statusDoc(31)));
		[$snapshot, $prom] = $this->collect();
		$this->assertFalse($snapshot['source_up']['crowdsec'] ?? NULL, '31 s old, over 3 x 10 s: stale');
		$this->assertStringContainsString('pfblockerng_metrics_source_up{source="crowdsec"} 0', $prom);
		$this->assertNoCrowdsecFamily($prom);
		$this->assertOtherSourcesIntact($snapshot, $prom);
	}

	public function testStalenessFollowsTheDaemonsOwnUpdateFrequency(): void
	{
		$this->writeStatus(json_encode($this->statusDoc(100, ['update_frequency_seconds' => 60])));
		[$snapshot] = $this->collect();
		$this->assertTrue($snapshot['source_up']['crowdsec'] ?? NULL, '100 s old with a 60 s frequency is fresh');
	}

	public function testAStoppedServiceIsDownEvenWithAFreshFile(): void
	{
		$this->writeStatus(json_encode($this->statusDoc()));
		[$snapshot] = $this->collect();
		$this->assertTrue($snapshot['source_up']['crowdsec'] ?? NULL, 'before-state: running');

		$GLOBALS['pfb_test_valid_pids'] = [];
		[$snapshot, $prom] = $this->collect();

		$this->assertFalse($snapshot['source_up']['crowdsec'] ?? NULL, 'stopped: source_up 0');
		$this->assertStringContainsString('pfblockerng_metrics_source_up{source="crowdsec"} 0', $prom);
		$this->assertNoCrowdsecFamily($prom);
		$this->assertOtherSourcesIntact($snapshot, $prom);
	}

	public function testAMissingStatusFileIsDown(): void
	{
		[$snapshot, $prom] = $this->collect();

		$this->assertFalse($snapshot['source_up']['crowdsec'] ?? NULL);
		$this->assertNoCrowdsecFamily($prom);
		$this->assertOtherSourcesIntact($snapshot, $prom);
	}

	public function testAnUnreadableStatusFileIsDown(): void
	{
		// A directory at the path cannot be read as a file, even by root
		mkdir($GLOBALS['pfb']['crowdsec_status']);

		[$snapshot, $prom] = $this->collect();

		$this->assertFalse($snapshot['source_up']['crowdsec'] ?? NULL);
		$this->assertNoCrowdsecFamily($prom);
		$this->assertOtherSourcesIntact($snapshot, $prom);
	}

	/** A healthy status document; "NOW" in updated_at becomes a second ago when written. */
	private static function base(): array
	{
		return [
			'version' => '0.1.0', 'start_time' => 1, 'update_frequency_seconds' => 10, 'updated_at' => 'NOW', 'last_pull' => 2,
			'last_error_time' => 0, 'last_error' => '', 'lapi_requests' => 1, 'lapi_errors' => 0,
			'banned' => ['ipv4' => ['total' => 1, 'origins' => ['crowdsec' => 1]], 'ipv6' => ['total' => 0, 'origins' => []]],
			'dropped' => ['ipv4' => ['packets' => 1, 'bytes' => 60], 'ipv6' => ['packets' => 0, 'bytes' => 0]],
		];
	}

	/** @return iterable<string, array{string}> status file contents the daemon never writes */
	public static function garbled(): iterable
	{
		$ok = self::base();
		$with = static function (callable $edit) use ($ok): string {
			$s = $ok;
			$edit($s);
			return json_encode($s);
		};
		yield 'empty' => [''];
		yield 'not JSON' => ['{"version": "0.1.0",'];
		yield 'NUL bytes' => ["\0\0\0\0"];
		yield 'null' => ['null'];
		yield 'a list' => ['[1,2,3]'];
		yield 'a string' => ['"status"'];
		yield 'an empty object' => ['{}'];
		yield 'no updated_at' => [$with(static function (array &$s): void { unset($s['updated_at']); })];
		yield 'updated_at a string' => [$with(static function (array &$s): void { $s['updated_at'] = '1763550000'; })];
		yield 'lapi_requests negative' => [$with(static function (array &$s): void { $s['lapi_requests'] = -1; })];
		yield 'lapi_errors a float' => [$with(static function (array &$s): void { $s['lapi_errors'] = 1.5; })];
		yield 'lapi_requests beyond 64-bit' => [str_replace('"lapi_requests":1,', '"lapi_requests":184467440737095516150,', $with(static function (array &$s): void {}))];
		yield 'update frequency zero' => [$with(static function (array &$s): void { $s['update_frequency_seconds'] = 0; })];
		yield 'last_error not a string' => [$with(static function (array &$s): void { $s['last_error'] = ['x']; })];
		yield 'banned a list' => [$with(static function (array &$s): void { $s['banned'] = [1, 2]; })];
		yield 'banned without ipv6' => [$with(static function (array &$s): void { unset($s['banned']['ipv6']); })];
		yield 'an origin count a string' => [$with(static function (array &$s): void { $s['banned']['ipv4']['origins']['crowdsec'] = '1'; })];
		yield 'origins a list' => [$with(static function (array &$s): void { $s['banned']['ipv4']['origins'] = [1]; })];
		yield 'dropped bytes missing' => [$with(static function (array &$s): void { unset($s['dropped']['ipv4']['bytes']); })];
		yield 'dropped packets negative' => [$with(static function (array &$s): void { $s['dropped']['ipv6']['packets'] = -5; })];
		yield 'oversized' => [$with(static function (array &$s): void { $s['last_error'] = str_repeat('x', 2 * 1024 * 1024); })];
	}

	#[DataProvider('garbled')]
	public function testAGarbledStatusFileIsDownAndTheOtherSourcesStay(string $raw): void
	{
		$this->writeStatus(str_replace('"NOW"', (string) (time() - 1), $raw));

		[$snapshot, $prom] = $this->collect();

		$this->assertFalse($snapshot['source_up']['crowdsec'] ?? NULL, 'a garbled status file is a source down');
		$this->assertStringContainsString('pfblockerng_metrics_source_up{source="crowdsec"} 0', $prom);
		$this->assertNoCrowdsecFamily($prom);
		$this->assertOtherSourcesIntact($snapshot, $prom);
	}

	public function testTheGarbledFixtureBaseIsItselfAccepted(): void
	{
		// Vacuity guard for the provider above: its base document, unedited, is a healthy source
		$this->writeStatus(str_replace('"NOW"', (string) (time() - 1), json_encode(self::base())));

		[$snapshot, $prom] = $this->collect();

		$this->assertTrue($snapshot['source_up']['crowdsec'] ?? NULL);
		$this->assertStringContainsString('fw_bouncer_banned_ips{origin="crowdsec",ip_type="ipv4"} 1', $prom);
		$this->assertStringContainsString('fw_bouncer_dropped_bytes{ip_type="ipv4"} 60', $prom);
	}

	/** @return iterable<string, array{callable(): void}> each reason the bouncer does not run (D4) */
	public static function offReasons(): iterable
	{
		yield 'pfBlockerNG off' => [static function (): void { $GLOBALS['pfb']['enable'] = PfbToggle::Off; }];
		yield 'CrowdSec off' => [static function (): void { config_set_path(self::SECTION . '/enable', ''); }];
		yield 'no key on this node' => [static function (): void { config_set_path(self::SECTION . '/api_key', ''); }];
	}

	#[DataProvider('offReasons')]
	public function testWhileTheBouncerShouldNotRunTheSourceIsAbsent(callable $turnOff): void
	{
		$this->writeStatus(json_encode($this->statusDoc()));
		[$snapshot] = $this->collect();
		$this->assertArrayHasKey('crowdsec', $snapshot['source_up'], 'before-state: the source is there');

		$turnOff();
		[$snapshot, $prom] = $this->collect();

		$this->assertArrayNotHasKey('crowdsec', $snapshot['source_up'], 'no source while the bouncer should not run');
		$this->assertStringNotContainsString('source="crowdsec"', $prom);
		$this->assertNoCrowdsecFamily($prom);
		$this->assertOtherSourcesIntact($snapshot, $prom);
	}
}
