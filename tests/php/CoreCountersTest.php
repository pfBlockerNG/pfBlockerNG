<?php

declare(strict_types=1);

require_once __DIR__ . '/support/ProcessRunner.php';

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Core runs the counter lane at each local day change with the verbs due as arguments (issue #3996): `core_counters clearip`,
 * `cleardnsbl`, or both in that order. The verb decides nothing: it clears what it is asked, whatever the stored widget cadence, the
 * master switch and the cron-disable sentinel say; Core read those through the `maintenance` projection. Each case runs the real verb in
 * a php process; only pfctl and the SQLite file are the sandbox's. A trigger on the `lastclear` row logs which counter was cleared, in order.
 */
final class CoreCountersTest extends TestCase
{
	private string $dir;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_counters_' . bin2hex(random_bytes(6));
		foreach (['db/pfblockerng', 'log/pfblockerng', 'tmp'] as $sub) {
			$this->assertTrue(mkdir("{$this->dir}/{$sub}", 0755, TRUE));
		}
		file_put_contents("{$this->dir}/pfctl", "#!/bin/sh\nprintf '%s\\n' \"\$*\" >> {$this->dir}/pfctl.log\n");
		chmod("{$this->dir}/pfctl", 0755);
		$db = new SQLite3("{$this->dir}/resolver.sqlite");
		$db->exec('CREATE TABLE lastclear ( row INTEGER, lastipclear TEXT, lastdnsblclear TEXT )');
		$db->exec("INSERT INTO lastclear (row, lastipclear, lastdnsblclear) VALUES (0, 'Unknown', 'Unknown')");
		$db->exec('CREATE TABLE cleared ( n INTEGER PRIMARY KEY AUTOINCREMENT, what TEXT )');
		$db->exec("CREATE TRIGGER ip_cleared AFTER UPDATE OF lastipclear ON lastclear BEGIN INSERT INTO cleared (what) VALUES ('clearip'); END");
		$db->exec("CREATE TRIGGER dnsbl_cleared AFTER UPDATE OF lastdnsblclear ON lastclear BEGIN INSERT INTO cleared (what) VALUES ('cleardnsbl'); END");
		$db->close();
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->dir);
	}

	/**
	 * @param array<string, mixed> $widgets stored widget-<type> values
	 * @param list<string> $args
	 * @return array{stdout: string, stderr: string, exit: int, termsig: int, warnings: array<int, mixed>}
	 */
	private function runVerb(array $widgets, array $args, bool $enabled = TRUE): array
	{
		file_put_contents("{$this->dir}/case.json", json_encode(['enabled' => $enabled, 'widgets' => $widgets, 'args' => $args], JSON_THROW_ON_ERROR));
		$command = [PHP_BINARY, __DIR__ . '/bin/core_counters_entry.php', $this->dir];
		$process = proc_open($command, [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
		$this->assertIsResource($process);
		stream_set_blocking($pipes[1], FALSE);
		stream_set_blocking($pipes[2], FALSE);
		$run = pfb_test_finish_process([$process, $pipes, implode(' ', $command)], 30.0);
		$this->assertFileExists("{$this->dir}/warnings.json", 'the child must publish its warning diagnostics: ' . $run['stdout'] . $run['stderr']);
		$run['warnings'] = json_decode((string) file_get_contents("{$this->dir}/warnings.json"), TRUE, 512, JSON_THROW_ON_ERROR);
		$this->assertSame([], $run['warnings'], 'the verb must raise no PHP warning');
		return $run;
	}

	/** @return array{pfctl: int, order: list<string>} how often pfctl zeroed the counters, and which counters were stamped cleared, in order */
	private function cleared(): array
	{
		$pfctl = is_file("{$this->dir}/pfctl.log") ? file("{$this->dir}/pfctl.log", FILE_IGNORE_NEW_LINES) : [];
		$this->assertSame(array_fill(0, count($pfctl), '-z'), $pfctl, 'pfctl is only ever asked to zero the counters');
		$db = new SQLite3("{$this->dir}/resolver.sqlite");
		$order = [];
		$rows = $db->query('SELECT what FROM cleared ORDER BY n');
		while (($row = $rows->fetchArray(SQLITE3_NUM)) !== FALSE) {
			$order[] = $row[0];
		}
		$db->close();
		return ['pfctl' => count($pfctl), 'order' => $order];
	}

	public static function verbTable(): array
	{
		$nothing = ['pfctl' => 0, 'order' => []];
		return [
			'clearip' => [['clearip'], ['pfctl' => 1, 'order' => ['clearip']]],
			'cleardnsbl' => [['cleardnsbl'], ['pfctl' => 0, 'order' => ['cleardnsbl']]],
			'both in the order Core sends them' => [['clearip', 'cleardnsbl'], ['pfctl' => 1, 'order' => ['clearip', 'cleardnsbl']]],
			'both, the other way round, still clearip first' => [['cleardnsbl', 'clearip'], ['pfctl' => 1, 'order' => ['clearip', 'cleardnsbl']]],
			'clearip twice clears it once' => [['clearip', 'clearip'], ['pfctl' => 1, 'order' => ['clearip']]],
			'both twice clear each once' => [['clearip', 'cleardnsbl', 'cleardnsbl', 'clearip'], ['pfctl' => 1, 'order' => ['clearip', 'cleardnsbl']]],
		];
	}

	public static function storedWidgetValues(): array
	{
		return [
			'never' => ['never'], 'daily' => ['daily'], 'weekly' => ['weekly'], 'garbage' => ['Daily'], 'a number' => [1], 'an array' => [['daily']], 'empty' => [''],
		];
	}

	/**
	 * What is cleared depends on the verbs alone: the stored cadence, `never` and garbage included, never stops a clear Core asked for.
	 *
	 * @param list<string> $args
	 * @param array{pfctl: int, order: list<string>} $expected
	 */
	#[DataProvider('verbTable')]
	public function testTheVerbsCoreSendsDecideWhatIsCleared(array $args, array $expected): void
	{
		foreach (self::storedWidgetValues() as $label => [$stored]) {
			$this->tearDown();
			$this->setUp();
			$this->assertSame(['pfctl' => 0, 'order' => []], $this->cleared(), 'before: nothing has been cleared');

			$run = $this->runVerb(['clearip' => $stored, 'cleardnsbl' => $stored], $args);

			$this->assertSame(0, $run['exit'], "{$label}: " . $run['stdout'] . $run['stderr']);
			$this->assertSame($expected, $this->cleared(), "stored value: {$label}");
		}
	}

	public function testNoStoredWidgetValueAtAllStillClears(): void
	{
		$run = $this->runVerb([], ['clearip', 'cleardnsbl']);

		$this->assertSame(0, $run['exit'], $run['stdout'] . $run['stderr']);
		$this->assertSame(['pfctl' => 1, 'order' => ['clearip', 'cleardnsbl']], $this->cleared());
	}

	public function testTheMasterSwitchOffStillClears(): void
	{
		$run = $this->runVerb(['clearip' => 'never', 'cleardnsbl' => 'never'], ['clearip', 'cleardnsbl'], FALSE);
		$this->assertSame(0, $run['exit'], $run['stdout'] . $run['stderr']);
		$this->assertSame(['pfctl' => 1, 'order' => ['clearip', 'cleardnsbl']], $this->cleared(), 'Core asked: the verb makes no enable decision');
	}

	public function testTheCronDisableSentinelStillClears(): void
	{
		touch("{$this->dir}/db/pfblockerng/.pfb_cron_disable");
		$run = $this->runVerb([], ['clearip', 'cleardnsbl']);
		$this->assertSame(0, $run['exit'], $run['stdout'] . $run['stderr']);
		$this->assertSame(['pfctl' => 1, 'order' => ['clearip', 'cleardnsbl']], $this->cleared(), 'Core asked: the verb makes no sentinel decision');
	}

	public static function invalidArguments(): array
	{
		return [
			'no argument' => [[]],
			'daily' => [['daily']],
			'weekly' => [['weekly']],
			'a valid verb and a cadence' => [['clearip', 'daily']],
			'uppercase' => [['CLEARIP']],
			'the empty string' => [['']],
			'a valid verb then the empty string' => [['clearip', '']],
			'a shell metacharacter payload' => [['clearip;rm -rf /']],
			'a mebibyte argument' => [[str_repeat('x', 1048576)]],
		];
	}

	/** @param list<string> $args */
	#[DataProvider('invalidArguments')]
	public function testAnyInvalidArgumentIsRefusedBeforeAnythingIsCleared(array $args): void
	{
		$run = $this->runVerb(['clearip' => 'daily', 'cleardnsbl' => 'weekly'], $args);

		$this->assertSame(2, $run['exit'], $run['stdout'] . $run['stderr']);
		$this->assertSame('', $run['stdout']);
		$this->assertCount(1, array_filter(explode("\n", $run['stderr'])), 'one diagnostic line: ' . substr($run['stderr'], 0, 300));
		$this->assertLessThan(300, strlen($run['stderr']), 'the diagnostic does not echo the argument');
		$this->assertSame(['pfctl' => 0, 'order' => []], $this->cleared(), 'nothing is cleared when any argument is invalid');
	}
}
