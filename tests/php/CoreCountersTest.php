<?php

declare(strict_types=1);

require_once __DIR__ . '/support/ProcessRunner.php';

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Core runs the counter lane at each local day change (issue #3996): `core_counters daily` every day, `core_counters daily weekly` on
 * Sundays. Each case runs the real verb in a php process; only pfctl and the two SQLite files are the sandbox's. A counter is cleared when
 * its stored widget cadence is one of the arguments, whatever the master switch and the cron-disable sentinel say.
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

	/** @return array{ip: int, dnsbl: int} how often each counter was cleared: pfctl runs, and whether the DNSBL stamp moved (0 or 1) */
	private function cleared(): array
	{
		$pfctl = is_file("{$this->dir}/pfctl.log") ? file("{$this->dir}/pfctl.log", FILE_IGNORE_NEW_LINES) : [];
		$this->assertSame(array_fill(0, count($pfctl), '-z'), $pfctl, 'pfctl is only ever asked to zero the counters');
		$db = new SQLite3("{$this->dir}/resolver.sqlite");
		$row = $db->querySingle('SELECT lastipclear, lastdnsblclear FROM lastclear WHERE row = 0', TRUE);
		$db->close();
		return ['ip' => count($pfctl) + ($row['lastipclear'] !== 'Unknown' ? 100 : 0), 'dnsbl' => $row['lastdnsblclear'] !== 'Unknown' ? 1 : 0];
	}

	public static function cadenceTable(): array
	{
		$ip = ['ip' => 101, 'dnsbl' => 0];
		$dnsbl = ['ip' => 0, 'dnsbl' => 1];
		$both = ['ip' => 101, 'dnsbl' => 1];
		$none = ['ip' => 0, 'dnsbl' => 0];
		return [
			'daily/weekly at the daily change clears only the IP counters' => ['daily', 'weekly', ['daily'], $ip],
			'daily/weekly on Sunday clears both' => ['daily', 'weekly', ['daily', 'weekly'], $both],
			'weekly/weekly at a daily change clears nothing' => ['weekly', 'weekly', ['daily'], $none],
			'weekly/weekly on Sunday clears both' => ['weekly', 'weekly', ['daily', 'weekly'], $both],
			'never/never on Sunday clears nothing' => ['never', 'never', ['daily', 'weekly'], $none],
			'absent/absent clears nothing' => [NULL, NULL, ['daily', 'weekly'], $none],
			'daily/daily at a weekly-only call clears nothing' => ['daily', 'daily', ['weekly'], $none],
			'never/daily clears only the DNSBL counters' => ['never', 'daily', ['daily'], $dnsbl],
			'daily asked twice clears each counter once' => ['daily', 'daily', ['daily', 'daily'], $both],
			'Daily is not a cadence' => ['Daily', 'Weekly', ['daily', 'weekly'], $none],
			'the integer 1 is not a cadence' => [1, 1, ['daily', 'weekly'], $none],
			'the string 1 is not a cadence' => ['1', '1', ['daily', 'weekly'], $none],
			'an array is not a cadence' => [['daily'], ['weekly'], ['daily', 'weekly'], $none],
			'an empty value is not a cadence' => ['', '', ['daily', 'weekly'], $none],
		];
	}

	/** @param array{ip: int, dnsbl: int} $expected */
	#[DataProvider('cadenceTable')]
	public function testEachCounterClearsOnlyWhenItsStoredCadenceIsAmongTheArguments(mixed $clearip, mixed $cleardnsbl, array $args, array $expected): void
	{
		$widgets = array_filter(['clearip' => $clearip, 'cleardnsbl' => $cleardnsbl], static fn (mixed $v): bool => $v !== NULL);
		$this->assertSame(['ip' => 0, 'dnsbl' => 0], $this->cleared(), 'before: nothing has been cleared');

		$run = $this->runVerb($widgets, $args);

		$this->assertSame(0, $run['exit'], $run['stdout'] . $run['stderr']);
		$this->assertSame($expected, $this->cleared(), json_encode([$clearip, $cleardnsbl, $args]));
	}

	public function testTheMasterSwitchOffStillClears(): void
	{
		$run = $this->runVerb(['clearip' => 'daily', 'cleardnsbl' => 'daily'], ['daily'], FALSE);
		$this->assertSame(0, $run['exit'], $run['stdout'] . $run['stderr']);
		$this->assertSame(['ip' => 101, 'dnsbl' => 1], $this->cleared(), 'the cron entries these replace had no master-enable gate');
	}

	public function testTheCronDisableSentinelStillClears(): void
	{
		touch("{$this->dir}/db/pfblockerng/.pfb_cron_disable");
		$run = $this->runVerb(['clearip' => 'daily', 'cleardnsbl' => 'daily'], ['daily']);
		$this->assertSame(0, $run['exit'], $run['stdout'] . $run['stderr']);
		$this->assertSame(['ip' => 101, 'dnsbl' => 1], $this->cleared(), 'the cron entries these replace had no .pfb_cron_disable gate');
	}

	public static function invalidArguments(): array
	{
		return [
			'no argument' => [[]],
			'monthly' => [['monthly']],
			'a valid pair and a third invalid' => [['daily', 'weekly', 'monthly']],
			'uppercase' => [['DAILY']],
			'the empty string' => [['']],
			'a shell metacharacter payload' => [['daily;rm -rf /']],
			'one valid then the empty string' => [['daily', '']],
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
		$this->assertSame(['ip' => 0, 'dnsbl' => 0], $this->cleared(), 'nothing is cleared when any argument is invalid');
	}
}
