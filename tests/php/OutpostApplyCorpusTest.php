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
 * descriptions in order, the service calls, the `post` hook's PFB_* environment and whether a change was still pending
 * when it ran, the pending mark and due-ledger flag, the apply record, the ADR-61 ledger, the unlock and IP cache files,
 * the main log, the DNS listener's VIPs and advertisements, the locks left held and the named locks taken in order, the
 * XMLRPC sends, the received payload's absorb, the metrics sentinel, and what the pass returned. Each step's `expect` is
 * that record as the code before the cut wrote it, compacted: a member list longer than 8 lines is its count, digest
 * and ends, a kernel table appears only where it differs from its mirror (NULL: its mirror exists and the table does
 * not), and a section equal to the previous step's reads "same".
 */
#[CoversFunction('sync_package_pfblockerng')]
#[CoversFunction('pfb_apply_enter')]
#[CoversFunction('pfb_apply_objects')]
#[CoversFunction('pfb_apply_settle')]
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
		$this->assertSame(['actions-and-directions', 'aggregate-deny', 'delta-auto-high-churn', 'delta-auto-low-churn',
			'delta-mode-batched', 'dns-config-lock-held', 'dns-listener-vips', 'empty-kernel-forced-replace', 'first-load-rule-change',
			'ip-unlock-reblock', 'kill-states', 'mode-replace-low-churn', 'nat-alias-suffix', 'package-disabled',
			'pfctl-failure-then-recover', 'pfctl-failure', 'received-policy-absorbed', 'refetch-same-set', 'reload-launch-missing', 'reuse-flag-cleared',
			'rule-change-presync-and-kill', 'unchanged'], array_keys(self::corpus()), 'a scenario file went missing from ' . self::FIXTURES);
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

		$kernel = $mirrors = [];
		$log    = '';
		foreach ($sc['steps'] as $i => $step) {
			$this->assertSame($step['expect'], $records[$i], "pass {$i} of " . basename($file) . " no longer does what it recorded");
			// ADR-40 end state: a kernel table the pass left equals its mirror, unless the scenario makes pfctl fail. The record
			// omits a table equal to its sorted mirror, lists one that differs, and holds NULL for a mirror with no table: that
			// is the end state only of a pass that left the tables to the filter reload, which the double does not perform.
			$kernel  = $records[$i]['kernel'] === 'same' ? $kernel : $records[$i]['kernel'];
			$mirrors = $records[$i]['mirrors'] === 'same' ? $mirrors : $records[$i]['mirrors'];
			$log     = $records[$i]['log'] === 'same' ? $log : $records[$i]['log'];
			if (empty($step['pfctlFail'])) {
				foreach ($kernel as $table => $members) {
					if ($members === NULL) {
						$this->assertStringContainsString('Alias tables: skipped (Filter Reload rebuilds them from the alias files)', $log,
							"pass {$i}: kernel table {$table} is absent though its mirror exists and the pass did not leave it to the filter reload");
					} else {
						$this->assertArrayNotHasKey("{$table}.txt", $mirrors, "pass {$i}: kernel table {$table} differs from its mirror");
					}
				}
			}
		}
	}
}
