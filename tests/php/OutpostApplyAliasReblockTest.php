<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/support/ProcessRunner.php';

/**
 * Issue #4213: on a pass with no rule change, a changed alias (an IP list or a GeoIP continent) is applied to its pf table as
 * a delta from its previous set, unless a temporary IP unlock is pending: the unlocked IP is then missing from the kernel
 * table but not from either set, so only a full replace from the mirror blocks it again.
 *
 * The passes run the real update pass in the corpus worker (support/OutpostApplyCorpusWorker.php) over its pfctl,
 * config.xml and ledger doubles; its record holds the pfctl calls and, per table, the kernel set where it differs from its
 * mirror.
 */
#[CoversFunction('sync_package_pfblockerng')]
#[CoversFunction('pfb_apply_objects')]
final class OutpostApplyAliasReblockTest extends TestCase
{
	private const EUROPE = ['installedpackages/pfblockerngeurope/config' => [[
		'action' => 'Deny_Inbound', 'countries4' => 'FR', 'countries6' => '', 'aliaslog' => 'enabled', 'autoproto_in' => '',
		'autoproto_out' => '', 'agateway_in' => 'default', 'agateway_out' => 'default', 'srcint' => '',
	]]];

	private string $work;

	protected function setUp(): void
	{
		$this->work = sys_get_temp_dir() . '/pfb_alias_reblock_' . bin2hex(random_bytes(6));
		mkdir($this->work, 0700, TRUE);
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->work);
	}

	/**
	 * Runs the passes and returns the last pass's record.
	 *
	 * @param list<array<string, mixed>> $steps
	 * @return array<string, mixed>
	 */
	private function lastPass(array $steps): array
	{
		$scenario = "{$this->work}/scenario.json";
		file_put_contents($scenario, json_encode(['description' => 'issue #4213', 'steps' => $steps], JSON_THROW_ON_ERROR));
		$result  = "{$this->work}/result.json";
		$process = pfb_test_run_process([PHP_BINARY, __DIR__ . '/support/OutpostApplyCorpusWorker.php', $scenario, "{$this->work}/run", $result], 300.0);
		$this->assertSame(0, $process['exit'], "the worker failed: {$process['stderr']}");
		$records = json_decode((string) file_get_contents($result), TRUE, 64, JSON_THROW_ON_ERROR);
		$last    = end($records);
		$this->assertStringContainsString('No changes to Firewall rules, skipping Filter Reload', $last['log'], 'setup: the pass changes no rule');
		return $last;
	}

	/** @return list<string> the pfctl calls a pass made that change $table */
	private static function tableChanges(array $record, string $table): array
	{
		return array_values(array_filter(array_column($record['pfctl'], 'call'),
			static fn (string $call): bool => str_starts_with($call, "-t {$table} ") && !str_ends_with($call, '-T show')));
	}

	/**
	 * Europe denied for France (10.2.0.1-50), then a pass where France gains 10.2.0.51 over the given kernel table.
	 *
	 * @param array<string, mixed> $kernel
	 * @param array<string, mixed> $files
	 * @return list<array<string, mixed>>
	 */
	private static function europeGainsANetwork(array $kernel, array $files = []): array
	{
		return [
			['pending' => TRUE, 'config' => self::EUROPE, 'files' => ['{ccdir}/FR_v4.txt' => [['seq' => '10.2.0.%d', 'from' => 1, 'to' => 50]]]],
			['pending' => TRUE, 'kernel' => $kernel, 'files' => ['{ccdir}/FR_v4.txt' => [['seq' => '10.2.0.%d', 'from' => 1, 'to' => 51]]] + $files],
		];
	}

	public function testALowChurnContinentChangeIsAppliedAsADelta(): void
	{
		$record = $this->lastPass(self::europeGainsANetwork(['pfB_Europe_v4' => 'mirror']));

		$changes = self::tableChanges($record, 'pfB_Europe_v4');
		$this->assertNotSame([], $changes, 'setup: the table is changed');
		$this->assertSame([], array_filter($changes, static fn (string $c): bool => str_contains($c, '-T replace')), 'a one-network change replaced the whole table');
		$this->assertArrayNotHasKey('pfB_Europe_v4', $record['kernel']);
	}

	public function testAnUnlockedIpIsBlockedAgainOnAPassThatAlsoChangesTheContinent(): void
	{
		$record = $this->lastPass(self::europeGainsANetwork(
			['pfB_Europe_v4' => [['seq' => '10.2.0.%d', 'from' => 1, 'to' => 4], ['seq' => '10.2.0.%d', 'from' => 6, 'to' => 50]]],
			['ip_unlock' => ['10.2.0.5']]
		));

		$this->assertArrayNotHasKey('pfB_Europe_v4', $record['kernel'], 'the unlocked IP stays out of the kernel table');
	}

	public function testAnUnlockedIpIsBlockedAgainOnAPassThatAlsoChangesItsList(): void
	{
		$list = static fn (int $to): array => ['installedpackages/pfblockernglistsv4/config' => [[
			'aliasname' => 'Abuse', 'action' => 'Deny_Inbound', 'cron' => 'EveryDay', 'aliaslog' => 'enabled', 'autoproto_in' => '',
			'autoproto_out' => '', 'agateway_in' => 'default', 'agateway_out' => 'default', 'srcint' => '', 'whois_convert' => '',
			'custom' => [['seq' => '10.1.0.%d', 'from' => 1, 'to' => $to]], 'row' => [],
		]]];

		$record = $this->lastPass([
			['pending' => TRUE, 'config' => $list(50)],
			['pending' => TRUE, 'config' => $list(51), 'files' => ['{denydir}/Abuse_custom_v4.update' => [], 'ip_unlock' => ['10.1.0.5']],
				'kernel' => ['pfB_Abuse_v4' => [['seq' => '10.1.0.%d', 'from' => 1, 'to' => 4], ['seq' => '10.1.0.%d', 'from' => 6, 'to' => 50]]]],
		]);

		$this->assertArrayNotHasKey('pfB_Abuse_v4', $record['kernel'], 'the unlocked IP stays out of the kernel table');
	}
}
