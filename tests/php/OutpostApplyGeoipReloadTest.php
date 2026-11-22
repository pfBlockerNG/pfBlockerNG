<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/support/ProcessRunner.php';

/**
 * Issue #4213: a GeoIP continent list that changes on an update pass with no rule change reaches its pf table. The
 * continent aliases go through the same ADR-40 content-addressed gate as the IP lists, so the changed table is reloaded
 * from its mirror on the no-rule-change path, and an unchanged one is left alone.
 *
 * The passes run the real update pass in the corpus worker (support/OutpostApplyCorpusWorker.php) over its pfctl,
 * config.xml and ledger doubles; its record holds the pfctl calls and, per table, the kernel set where it differs from its
 * mirror.
 */
#[CoversFunction('sync_package_pfblockerng')]
#[CoversFunction('pfb_apply_objects')]
final class OutpostApplyGeoipReloadTest extends TestCase
{
	private string $work;

	protected function setUp(): void
	{
		$this->work = sys_get_temp_dir() . '/pfb_geoip_reload_' . bin2hex(random_bytes(6));
		mkdir($this->work, 0700, TRUE);
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->work);
	}

	/**
	 * Runs the passes and returns each pass's record with "same" sections resolved to the previous pass's.
	 *
	 * @param list<array<string, mixed>> $steps
	 * @return list<array<string, mixed>>
	 */
	private function passes(array $steps): array
	{
		$scenario = "{$this->work}/scenario.json";
		file_put_contents($scenario, json_encode(['description' => 'issue #4213', 'steps' => $steps], JSON_THROW_ON_ERROR));
		$result  = "{$this->work}/result.json";
		$process = pfb_test_run_process([PHP_BINARY, __DIR__ . '/support/OutpostApplyCorpusWorker.php', $scenario, "{$this->work}/run", $result], 300.0);
		$this->assertSame(0, $process['exit'], "the worker failed: {$process['stderr']}");
		$records = json_decode((string) file_get_contents($result), TRUE, 64, JSON_THROW_ON_ERROR);
		$resolved = [];
		foreach ($records as $i => $record) {
			foreach ($record as $field => $value) {
				if ($value === 'same' && $i > 0) {
					$record[$field] = $resolved[$i - 1][$field];
				}
			}
			$resolved[] = $record;
		}
		return $resolved;
	}

	/** @return list<string> the pfctl calls a pass made that change table pfB_Europe_v4 */
	private static function tableChanges(array $record): array
	{
		return array_values(array_filter(array_column($record['pfctl'], 'call'),
			static fn (string $call): bool => str_starts_with($call, '-t pfB_Europe_v4 ') && !str_ends_with($call, '-T show')));
	}

	public function testAContinentListThatChangesWithNoRuleChangeReachesItsTable(): void
	{
		$records = $this->passes([
			// Given Europe denied for France, published by a first pass that creates its rule
			[
				'pending' => TRUE,
				'config'  => ['installedpackages/pfblockerngeurope/config' => [[
					'action' => 'Deny_Inbound', 'countries4' => 'FR', 'countries6' => '', 'aliaslog' => 'enabled', 'autoproto_in' => '',
					'autoproto_out' => '', 'agateway_in' => 'default', 'agateway_out' => 'default', 'srcint' => '',
				]]],
				'files'   => ['{ccdir}/FR_v4.txt' => ['192.0.2.0/24']],
			],
			// When France gains a network and no rule changes; the filter reload loaded the table from its mirror
			[
				'pending' => TRUE,
				'kernel'  => ['pfB_Europe_v4' => 'mirror'],
				'files'   => ['{ccdir}/FR_v4.txt' => ['192.0.2.0/24', '198.51.100.0/24']],
			],
			// And a later pass finds the data unchanged
			['pending' => TRUE],
		]);

		$this->assertStringContainsString('No changes to Firewall rules, skipping Filter Reload', $records[1]['log'], 'setup: the pass changes no rule');
		$this->assertSame(['192.0.2.0/24', '198.51.100.0/24'], $records[1]['mirrors']['pfB_Europe_v4.txt'], 'setup: the mirror holds the new set');
		$this->assertNotSame([], self::tableChanges($records[1]), 'the changed continent table is never loaded');
		$this->assertArrayNotHasKey('pfB_Europe_v4', $records[1]['kernel'], 'the kernel table differs from its mirror after the pass');
		$this->assertSame([], self::tableChanges($records[2]), 'an unchanged continent table is reloaded anyway');
		$this->assertArrayNotHasKey('pfB_Europe_v4', $records[2]['kernel']);
	}
}
