<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/support/ProcessRunner.php';

/**
 * Corpus A of #4037, first drive: what today's update pass does to pfSense, scenario by scenario
 * (tests/outpost/fixtures/apply/), frozen before the apply is cut out of sync_package_pfblockerng(). A refactor of the
 * pass has no red step; this corpus is its oracle, with every existing suite, and stays green across the cut.
 *
 * Each scenario runs in a child process (support/OutpostApplyCorpusWorker.php) as one or more passes over the PHPUnit
 * doubles. A pass's record is everything a reader of pfSense could observe: the pfctl calls in order with the lines of
 * each -f file, the kernel tables and the mirrors after it, aliases/alias, filter/rule, nat/rule, the write_config()
 * descriptions in order, the service calls, the `post` hook's PFB_* environment, the pending mark and due-ledger flag,
 * the apply record, the ADR-61 ledger, the unlock and IP cache files, the main log, and what the pass returned. Each
 * step's `expect` is that record as today's code wrote it.
 */
#[CoversFunction('sync_package_pfblockerng')]
final class OutpostApplyCorpusTest extends TestCase
{
	private const FIXTURES = __DIR__ . '/../outpost/fixtures/apply';

	/** @var list<string> */
	private array $dirs = [];

	protected function tearDown(): void
	{
		foreach ($this->dirs as $dir) {
			rmdir_recursive($dir);
		}
	}

	/** @return array<string,array{string}> */
	public static function corpus(): array
	{
		$cases = [];
		foreach (glob(self::FIXTURES . '/*.json') ?: [] as $file) {
			$cases[basename($file, '.json')] = [$file];
		}
		return $cases;
	}

	public function testTheCorpusHoldsItsScenarios(): void
	{
		$this->assertGreaterThanOrEqual(18, count(self::corpus()), 'a scenario file went missing from ' . self::FIXTURES);
	}

	#[DataProvider('corpus')]
	public function testThePassDoesWhatTheScenarioRecords(string $file): void
	{
		$sc = json_decode((string) file_get_contents($file), TRUE, 64, JSON_THROW_ON_ERROR);
		$this->assertNotSame('', $sc['description'] ?? '', 'a scenario states what it pins');

		$work = sys_get_temp_dir() . '/pfb_outpost_apply_' . bin2hex(random_bytes(6));
		mkdir($work, 0700, TRUE);
		$this->dirs[] = $work;
		$result  = "{$work}/result.json";
		$process = pfb_test_run_process([PHP_BINARY, __DIR__ . '/support/OutpostApplyCorpusWorker.php', $file, $work, $result], 300.0);
		$this->assertSame(0, $process['exit'], "the worker failed: {$process['stderr']}");
		$this->assertFileExists($result, "the worker reported nothing: {$process['stderr']}");
		$records = json_decode((string) file_get_contents($result), TRUE, 64, JSON_THROW_ON_ERROR);
		$this->assertCount(count($sc['steps']), $records, 'one record per pass');

		foreach ($sc['steps'] as $i => $step) {
			$this->assertSame($step['expect'], $records[$i], "pass {$i} of " . basename($file) . " no longer does what it recorded");
			// ADR-40 end state: a kernel table the pass left equals its mirror, unless the scenario makes pfctl fail.
			if (empty($step['pfctlFail'])) {
				foreach ($records[$i]['kernel'] as $table => $members) {
					if (isset($records[$i]['mirrors']["{$table}.txt"])) {
						$mirror = $records[$i]['mirrors']["{$table}.txt"];
						sort($mirror, SORT_STRING);
						$this->assertSame($mirror, $members, "pass {$i}: kernel table {$table} differs from its mirror");
					}
				}
			}
		}
	}
}
