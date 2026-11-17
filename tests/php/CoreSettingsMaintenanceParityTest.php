<?php

declare(strict_types=1);

require_once __DIR__ . '/ConfigXmlDiskTrait.php';
require_once __DIR__ . '/PfbNoPhpWarningTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3996: Core decides the three timed lanes from its read-only `maintenance` projection, which the settings adapter answers from
 * config.xml and the cron-disable sentinel: tests/core/fixtures/settings_maintenance_parity.json, which go/pfb_core/settings passes too.
 *   - A case is a config.xml (`config`, by section) and whether the sentinel file exists (`cronDisable`); `maintenance`, over the fixture's
 *     defaults, is what the adapter's read answers.
 *   - A refused row is a value Core refuses to read; the adapter's write refuses it too, naming the field, exactly as it does `ingest`.
 *   - The revision covers the five inputs, so a change of any of them reaches Core by the tick's revision check.
 */
#[CoversFunction('pfb_core_maintenance_settings')]
#[CoversFunction('pfb_core_ingest_faults')]
#[CoversFunction('pfb_core_settings_backend')]
#[CoversFunction('pfb_core_settings_request_refusal')]
final class CoreSettingsMaintenanceParityTest extends TestCase
{
	use ConfigXmlDiskTrait;
	use PfbNoPhpWarningTrait;

	private const FIXTURE = __DIR__ . '/../core/fixtures/settings_maintenance_parity.json';
	private const SECTIONS = ['gen' => 'installedpackages/pfblockerng/config/0', 'pfblockerngglobal' => 'installedpackages/pfblockerngglobal'];

	private array $priorConfig;
	private array $priorG;
	private array $priorPfb;
	private string $dir;

	protected function setUp(): void
	{
		$this->priorConfig = $GLOBALS['config'] ?? [];
		$this->priorG = $GLOBALS['g'] ?? [];
		$this->priorPfb = $GLOBALS['pfb'];
		$this->dir = sys_get_temp_dir() . '/pfb_core_maintenance_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->dir, 0700));
		$GLOBALS['config'] = [];
		config_set_path('installedpackages/pfblockerngdnsblsettings/config/0', ['pfb_dnsport' => '8081', 'pfb_dnsport_ssl' => '8443']);
		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '192.0.2.53');
		config_set_path('installedpackages/pfblockerng/config/0/skipfeed', '');
		$GLOBALS['g']['unbound_chroot_path'] = $this->dir;
		$GLOBALS['pfb']['dbdir'] = $this->dir;
		$GLOBALS['pfb']['pending_marker'] = "{$this->dir}/pending";
		$GLOBALS['pfb']['metrics_lock'] = "{$this->dir}/metrics.lock";
		$GLOBALS['pfb']['log'] = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$this->dir}/error.log";
		$GLOBALS['pfb']['runlog'] = '';
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_lock_events'] = [];
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = $this->priorConfig;
		$GLOBALS['g'] = $this->priorG;
		$GLOBALS['pfb'] = $this->priorPfb;
		foreach (['write_config_calls', 'write_config_args', 'write_config_result', 'write_config_hook', 'config_read_hook', 'config_read_calls',
			'config_read_lock_held', 'lock_events', 'lock_held', 'try_lock_fail'] as $global) {
			unset($GLOBALS["pfb_test_{$global}"]);
		}
		rmdir_recursive($this->dir);
	}

	/** @return array<string, mixed> */
	private static function fixture(): array
	{
		return json_decode((string) file_get_contents(self::FIXTURE), TRUE, 512, JSON_THROW_ON_ERROR);
	}

	/** @return array<string, array{0: array<string, mixed>}> */
	public static function cases(): array
	{
		$cases = [];
		foreach (self::fixture()['cases'] as $case) {
			$cases[$case['id']] = [$case];
		}
		return $cases;
	}

	/** @return array<string, array{0: array<string, mixed>}> */
	public static function refused(): array
	{
		$rows = [];
		foreach (self::fixture()['refused'] as $row) {
			$rows[$row['id']] = [$row];
		}
		return $rows;
	}

	/** @param array<string, mixed> $case */
	private function arrange(array $case): void
	{
		foreach ($case['config'] as $section => $keys) {
			foreach ($keys as $key => $value) {
				config_set_path(self::SECTIONS[$section] . "/{$key}", $value);
			}
		}
		$this->sentinel($case['cronDisable'] ?? FALSE);
	}

	private function sentinel(bool $present): void
	{
		$path = pfb_cron_disable_path();
		if ($present) {
			touch($path);
		} else {
			@unlink($path);
		}
	}

	private function backend(array $request): array
	{
		return pfb_core_settings_backend($request, "{$this->dir}/node_exporter", static fn(): array => []);
	}

	/** @return array<string, mixed> the adapter's read */
	private function read(): array
	{
		$reply = $this->backend(['version' => 1, 'op' => 'read']);
		$this->assertArrayHasKey('settings', $reply, 'the read answered ' . json_encode($reply));
		$this->assertArrayHasKey('maintenance', $reply['settings'], 'the read answers the maintenance projection: ' . json_encode($reply));
		return $reply;
	}

	/** @return array<string, mixed> Core's write of the read with $change applied to the projection $name */
	private function writeProjection(string $name, callable $change): array
	{
		$read = $this->read();
		$settings = $read['settings'];
		$settings[$name] = $change($settings[$name]);
		return $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings]);
	}

	public function testTheFixtureHoldsTheFiveFieldsInTheProtocolOrderAndEveryInputClass(): void
	{
		$doc = self::fixture();
		$this->assertSame(1, $doc['schema']);
		$this->assertSame('maintenance', $doc['projection']);
		$this->assertSame(['enabled', 'scheduledWorkDisabled', 'metricsExport', 'clearIpCounters', 'clearDnsblCounters'], array_keys($doc['defaults']));
		$ids = array_column($doc['cases'], 'id');
		$this->assertSame(array_values(array_unique($ids)), $ids, 'a case id appears once');
		foreach (['defaults', 'enable-on', 'metrics-on', 'clear-ip-weekly', 'clear-dnsbl-daily', 'clear-ip-garbage-array', 'sentinel-present', 'sentinel-absent', 'combined'] as $id) {
			$this->assertContains($id, $ids, "the coverage row {$id}");
		}
	}

	/** @param array<string, mixed> $case */
	#[DataProvider('cases')]
	public function testTheAdapterAnswersTheFixturesProjection(array $case): void
	{
		$this->arrange($case);
		pfb_global();

		$reply = $this->read();

		$this->assertSame(array_replace(self::fixture()['defaults'], $case['maintenance']), $reply['settings']['maintenance'], "{$case['id']}: the maintenance projection");
		$this->assertSame([], $GLOBALS['pfb_test_lock_events'], 'a read takes no lock');
		$this->assertNull(pfb_core_settings_request_refusal(['version' => 1, 'op' => 'write', 'expectedRevision' => $reply['revision'], 'settings' => $reply['settings']],
			static fn(): array => []), "{$case['id']}: the adapter's write validation accepts what its read answered");
	}

	/** @param array<string, mixed> $row */
	#[DataProvider('refused')]
	public function testTheAdaptersWriteRefusesAChangedMaintenanceNamingTheFieldAndWritesNothing(array $row): void
	{
		$this->configXmlOnDisk();
		$before = $GLOBALS['config'];

		$reply = $this->writeProjection('maintenance', static fn(array $maintenance): array => array_replace($maintenance, $row['maintenance']));

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, "{$row['id']}: " . json_encode($reply));
		$this->assertContains("maintenance.{$row['field']}", array_column($reply['error']['fieldErrors'] ?? [], 'field'), "{$row['id']}: {$row['description']}");
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], "{$row['id']}: write_config() was called");
		$this->assertSame($before, $GLOBALS['config'], "{$row['id']}: config.xml changed");
		$this->assertFileDoesNotExist("{$this->dir}/pending", "{$row['id']}: pending changes were marked");
	}

	/** A write naming `maintenance` is handled exactly as one naming `ingest`: the same refusal, shaped by the projection's name. */
	public function testAWriteNamingMaintenanceIsRefusedAsOneNamingIngestIs(): void
	{
		$this->configXmlOnDisk();

		$maintenance = $this->writeProjection('maintenance', static fn(array $m): array => ['metricsExport' => !$m['metricsExport']] + $m);
		$ingest = $this->writeProjection('ingest', static fn(array $i): array => ['suppression' => !$i['suppression']] + $i);

		$this->assertSame('invalid_argument', $maintenance['error']['code'] ?? NULL, json_encode($maintenance));
		$this->assertSame(str_replace(['ingest.suppression', 'ingest'], ['maintenance.metricsExport', 'maintenance'], json_encode($ingest)), json_encode($maintenance), 'the two refusals differ only in the projection named');
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
	}

	public function testAWriteThatLeavesMaintenanceAsItWasStoresTheOtherProjections(): void
	{
		$this->configXmlOnDisk();
		$read = $this->read();
		$settings = $read['settings'];
		$settings['dns']['control'] = TRUE;

		$reply = $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings]);

		$this->assertSame('on', $this->onDisk('installedpackages/pfblockerngdnsblsettings/config/0/pfb_control'), 'the dns change reached config.xml');
		$this->assertSame($read['settings']['maintenance'], $this->read()['settings']['maintenance'], 'maintenance is as it was');
		$this->assertSame($this->read()['revision'], $reply['revision'] ?? NULL);
	}

	public function testAWriteWithoutMaintenanceIsMalformed(): void
	{
		$read = $this->read();
		$settings = $read['settings'];
		unset($settings['maintenance']);

		$reply = $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings]);

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertStringContainsString('maintenance', $reply['error']['message'] ?? '', 'the refusal names the projections a write holds');
	}

	/** @return array<string, array{0: mixed}> */
	public static function notAnObject(): array
	{
		return ['a string' => ['x'], 'null' => [NULL], 'an int' => [7], 'a bool' => [FALSE]];
	}

	#[DataProvider('notAnObject')]
	public function testAWriteWhoseMaintenanceIsNotAnObjectIsMalformedNotAFatalError(mixed $maintenance): void
	{
		$this->configXmlOnDisk();

		$reply = $this->writeProjection('maintenance', static fn(array $current): mixed => $maintenance);

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertStringContainsString('maintenance', $reply['error']['message'] ?? '');
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], 'nothing is written');
	}

	/** Each of the five inputs moves the revision, so the tick's check tells Core the moment one changes; an unrelated key does not. */
	public function testTheRevisionMovesOnEachOfTheFiveInputsAndNotOnAnUnrelatedKey(): void
	{
		$reset = function (): void {
			$GLOBALS['config'] = [];
			config_set_path('installedpackages/pfblockerngdnsblsettings/config/0', ['pfb_dnsport' => '8081', 'pfb_dnsport_ssl' => '8443']);
			config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '192.0.2.53');
			config_set_path('installedpackages/pfblockerng/config/0/skipfeed', '');
			$this->sentinel(FALSE);
		};
		$reset();
		$base = $this->read()['revision'];
		$moves = [
			'the master enable' => static function (): void { config_set_path('installedpackages/pfblockerng/config/0/enable_cb', 'on'); },
			'the metrics export' => static function (): void { config_set_path('installedpackages/pfblockerng/config/0/pfb_metrics_export', 'on'); },
			'the IP counters cadence' => static function (): void { config_set_path('installedpackages/pfblockerngglobal/widget-clearip', 'daily'); },
			'the DNSBL counters cadence' => static function (): void { config_set_path('installedpackages/pfblockerngglobal/widget-cleardnsbl', 'weekly'); },
			'the cron-disable sentinel' => function (): void { $this->sentinel(TRUE); },
		];
		$seen = [$base => 'the start'];
		foreach ($moves as $why => $move) {
			$reset();
			$move();
			$revision = $this->read()['revision'];
			$this->assertArrayNotHasKey($revision, $seen, "{$why}: the revision moves, to one no other change gave");
			$seen[$revision] = $why;
		}
		$reset();
		config_set_path('installedpackages/pfblockerngglobal/widget-maxfails', '9');
		$this->assertSame($base, $this->read()['revision'], 'a key the projection does not read leaves the revision alone');
		$reset();
		$this->assertSame($base, $this->read()['revision'], 'the same box gives the same revision');
	}
}
