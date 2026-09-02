<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #2879 — the core `unbound-control` IPC lane had no client-side wall deadline.
 *
 * `unbound-control` blocks until the resolver answers, so a control socket that accepts
 * and never replies gave every call site in pfblockerng.inc an unbounded maximum, and the
 * per-domain cache flush multiplied that wait by its input cardinality (one call per name
 * plus its 'www.' sibling).
 *
 * The fix routes all six sites through one bounded seam — timeout(1) in its DEFAULT
 * (reaper) mode, SIGTERM then SIGKILL after the package kill grace, because
 * `unbound-control` is a transient request/response helper spawned through chroot(8) whose
 * whole tree must die on expiry — and gives pfb_unbound_py_ccache_flush() a WHOLE-BATCH
 * deadline so no number of names can multiply it.
 *
 * Every behavioural row drives the REAL production function against an `unbound-control`
 * double injected through the existing $pfb['chroot_cmd'] seam, in an isolated PHP process
 * so the row can set the budget constant. Each double self-terminates well inside the
 * salvage cap and records a 'completed …' line when it gets to finish, so a missing
 * deadline reads as a COMPLETED control command in the assertions — a behavioural red,
 * never a hung runner.
 */
#[CoversFunction('pfb_unbound_control_cmd')]
#[CoversFunction('pfb_unbound_control_exec')]
#[CoversFunction('pfb_unbound_py_ccache_flush')]
#[CoversFunction('pfb_reload_unbound')]
#[CoversFunction('pfb_update_unbound')]
#[CoversFunction('pfBlockerNG_clearsqlite')]
final class UnboundControlIpcBoundTest extends TestCase
{
	/** Per-command and whole-batch budget every isolated row runs under. */
	private const BUDGET = 2;

	/** Kill grace every isolated row runs under (shipped default is PFB_HOOK_KILL_GRACE). */
	private const GRACE = 1;

	/** Generous salvage cap: its expiry means "stuck/environment", never behaviour. */
	private const SALVAGE_SECONDS = 90;

	private string $dir = '';

	/** @var list<int> descendant PIDs a double published, reaped in tearDown */
	private array $spawned = [];

	protected function setUp(): void
	{
		$timeout = (string) ($GLOBALS['pfb']['timeout'] ?? '');
		if ($timeout === '' || !is_executable($timeout)) {
			$this->markTestSkipped('no timeout(1) binary available on this host');
		}

		$dir = tempnam(sys_get_temp_dir(), 'pfbctl');
		$this->assertNotFalse($dir);
		$this->assertTrue(unlink($dir) && mkdir($dir, 0700));
		$this->dir = $dir;
	}

	protected function tearDown(): void
	{
		foreach ($this->spawned as $pid) {
			if ($pid > 0 && @posix_kill($pid, 0)) {
				@posix_kill($pid, SIGKILL);
			}
		}
		$this->spawned = [];
		if ($this->dir !== '' && is_dir($this->dir)) {
			rmdir_recursive($this->dir);
		}
		$this->dir = '';
	}

	private function controlLog(): string
	{
		return "{$this->dir}/control.log";
	}

	/**
	 * Write the `unbound-control` double for one scenario and return its path (the
	 * value a row hands to $pfb['chroot_cmd']). argv is the control subcommand and its
	 * arguments; every invocation is recorded, and a scenario that runs to completion
	 * records a second 'completed …' line — the discriminator for "the deadline fired".
	 */
	private function installDouble(string $scenario): string
	{
		$path = "{$this->dir}/unbound-control-double";
		$log = escapeshellarg($this->controlLog());
		$body = match ($scenario) {
			// Healthy resolver: answers immediately.
			'fast' => "\t:\n",
			// Control command that exits non-zero straight away.
			'nonzero' => "\texit 3\n",
			// Control socket that accepts and never replies (self-capped at ~8 s).
			'slow' => "\tsleep 8\n\tprintf 'completed %s\\n' \"\$*\" >> {$log}\n",
			// Answers, but slowly enough that a per-name loop multiplies without a batch bound.
			'crawl' => "\tsleep 0.7\n\tprintf 'completed %s\\n' \"\$*\" >> {$log}\n",
			// Ignores SIGTERM and holds a descendant the expiry must also reap. The wait
			// loop is pure shell (no child to signal), so only SIGKILL ends it.
			'termproof' => "\ttrap '' TERM\n"
				. "\tsleep 30 &\n"
				. "\tprintf 'descendant %s\\n' \"\$!\" >> {$log}\n"
				. "\tend=\$(( \$(date +%s) + 8 ))\n"
				. "\twhile [ \"\$(date +%s)\" -lt \"\$end\" ]; do :; done\n"
				. "\tprintf 'completed %s\\n' \"\$*\" >> {$log}\n",
			// Restart path: the cache dump never replies; a later status would answer.
			'dump_slow' => "\tcase \"\$1\" in\n"
				. "\tdump_cache) printf 'PARTIAL-DUMP\\n'; sleep 8;"
				. " printf 'completed %s\\n' \"\$*\" >> {$log} ;;\n"
				. "\tstatus) printf 'unbound (pid 1) is running...\\n' ;;\n"
				. "\tesac\n",
			// Restart path: the dump succeeds, the later status never replies.
			'status_slow' => "\tcase \"\$1\" in\n"
				. "\tdump_cache) printf 'CACHE-DUMP\\n' ;;\n"
				. "\tstatus) sleep 8; printf 'unbound (pid 1) is running...\\n';"
				. " printf 'completed %s\\n' \"\$*\" >> {$log} ;;\n"
				. "\tesac\n",
		};

		$script = "#!/bin/sh\n"
			. "# unbound-control double for issue #2879's bounded IPC rows.\n"
			. "printf '%s\\n' \"\$*\" >> {$log}\n"
			. "run() {\n{$body}}\n"
			. "run \"\$@\"\n";
		$this->assertNotFalse(file_put_contents($path, $script));
		$this->assertTrue(chmod($path, 0755));

		return $path;
	}

	/**
	 * Run production code in a fresh PHP process so the row owns the budget constants.
	 * The outer timeout is salvage only: default (reaper) mode reaps the whole runner
	 * tree if production regresses to an unbounded wait.
	 *
	 * @param array<string, mixed> $pfb $pfb overrides for the row
	 * @return array{status: int, output: list<string>, log: string, errlog: string, control: list<string>}
	 */
	private function runIsolated(string $body, array $pfb): array
	{
		$runner = "{$this->dir}/runner.php";
		$log = "{$this->dir}/pfblockerng.log";
		$errlog = "{$this->dir}/error.log";
		$timeout = (string) $GLOBALS['pfb']['timeout'];
		$pfb = array_replace([
			'log'     => $log,
			'errlog'  => $errlog,
			'timeout' => $timeout,
			'php'     => PHP_BINARY,
		], $pfb);

		$source = "<?php\n"
			// The budget seam under test, plus the sibling daemon budgets so the
			// restart rows never pay an appliance wait or start a real resolver.
			. "define('PFB_UNBOUND_CONTROL_WAIT', " . self::BUDGET . ");\n"
			. "define('PFB_HOOK_KILL_GRACE', " . self::GRACE . ");\n"
			. "define('PFB_UNBOUND_START_CMD', '/bin/true');\n"
			. "define('PFB_UNBOUND_STOP_WAIT', 1);\n"
			. "define('PFB_UNBOUND_KILL_WAIT', 1);\n"
			. "define('PFB_UNBOUND_START_WAIT', 5);\n"
			. 'require ' . var_export(__DIR__ . '/bootstrap.php', TRUE) . ";\n"
			. '$GLOBALS[\'pfb\'] = array_replace($GLOBALS[\'pfb\'], '
				. var_export($pfb, TRUE) . ");\n"
			. '$GLOBALS[\'g\'][\'varrun_path\'] = ' . var_export($this->dir, TRUE) . ";\n"
			. "{$body}\n";
		$this->assertNotFalse(file_put_contents($runner, $source));

		$output = [];
		$status = 0;
		exec('TMPDIR=' . escapeshellarg($this->dir) . ' ' . escapeshellarg($timeout) .
			' -s TERM -k 5 ' . self::SALVAGE_SECONDS . ' ' . escapeshellarg(PHP_BINARY) .
			' ' . escapeshellarg($runner) . ' 2>&1', $output, $status);
		$this->assertNotSame(124, $status,
			"the isolated runner hit the {$this->salvageLabel()}s salvage cap — stuck run, not a verdict: "
			. implode("\n", $output));

		$control = file_exists($this->controlLog())
			? (file($this->controlLog(), FILE_IGNORE_NEW_LINES) ?: [])
			: [];
		foreach ($control as $line) {
			if (preg_match('/^descendant ([0-9]+)$/D', $line, $m) === 1) {
				$this->spawned[] = (int) $m[1];
			}
		}

		return [
			'status'  => $status,
			'output'  => $output,
			'log'     => (string) @file_get_contents($log),
			'errlog'  => (string) @file_get_contents($errlog),
			'control' => $control,
		];
	}

	private function salvageLabel(): string
	{
		return (string) self::SALVAGE_SECONDS;
	}

	/**
	 * $pfb keys the targeted cache flush needs, wired to this row's double.
	 *
	 * @return array<string, mixed>
	 */
	private function flushPfb(string $scenario): array
	{
		return ['chroot_cmd' => $this->installDouble($scenario)];
	}

	/**
	 * $pfb keys pfb_reload_unbound()'s restart path needs, wired to this row's double.
	 *
	 * @return array<string, mixed>
	 */
	private function reloadPfb(string $scenario): array
	{
		return [
			'chroot_cmd'           => $this->installDouble($scenario),
			'dbdir'                => $this->dir,
			'dnsbldir'             => $this->dir,
			'dnsbl_file'           => "{$this->dir}/pfb_dnsbl",
			'unbound_py_count'     => "{$this->dir}/pfb_py_count",
			'unbound_py_sources'   => "{$this->dir}/pfb_py_sources.json",
			'dnsbl_python_unmount' => FALSE,
			'dnsbl_res_cache'      => PfbToggle::On,
		];
	}

	/**
	 * The restart path's is_process_running('unbound') sequence: up for the cache-dump
	 * gate, down while the resolver is stopped, up again for the post-start status.
	 */
	private function reloadBody(): string
	{
		return "\$GLOBALS['config']['unbound'] = ['python' => 'on', 'python_script' => 'pfb_unbound'];\n"
			. "\$calls = 0;\n"
			. "\$GLOBALS['pfb_test_process_running']['unbound'] = static function () use (&\$calls): bool {\n"
			. "\t\$calls++;\n"
			. "\treturn \$calls === 1 || \$calls >= 4;\n"
			. "};\n"
			. "pfb_reload_unbound('enabled', TRUE, FALSE, FALSE, static fn(): bool => TRUE);\n";
	}

	/**
	 * Scenario: the Alerts allow->block cache flush meets a control socket that accepts
	 * and never replies.
	 *   Given one validated name (so the site issues the name plus its 'www.' sibling)
	 *     and a control double that never answers inside the budget
	 *   When pfb_unbound_py_ccache_flush() runs
	 *   Then the first command is killed at the deadline, the exhausted whole-batch
	 *     budget skips the sibling instead of multiplying the wait, and both facts are
	 *     named in the logs.
	 */
	public function testHungFlushExpiresAndSkipsTheRemainingSibling(): void
	{
		$run = $this->runIsolated(
			"pfb_unbound_py_ccache_flush(array('example.com'));\n",
			$this->flushPfb('slow')
		);

		$this->assertContains('flush example.com', $run['control'],
			'the site must spawn the injected control double through the $pfb[\'chroot_cmd\'] seam');
		$this->assertNotContains('completed flush example.com', $run['control'],
			'a control command that never replies must be killed at the deadline, not waited out');
		$this->assertNotContains('flush www.example.com', $run['control'],
			'an exhausted whole-batch budget must not issue further flush commands');
		$this->assertStringContainsString('TIMED OUT', $run['errlog'],
			'an expired control command must be observable in the error log');
		$this->assertStringContainsString('flush command(s) not run', $run['errlog'],
			'the whole-batch expiry must name the flush commands it skipped');
	}

	/**
	 * Scenario: the same flush against a healthy resolver.
	 *   Given a control double that answers immediately
	 *   When pfb_unbound_py_ccache_flush() runs for one name
	 *   Then both the name and its 'www.' sibling are flushed and nothing is reported
	 *     as expired or failed.
	 */
	public function testHealthyFlushRunsEachNameAndItsWwwSibling(): void
	{
		$run = $this->runIsolated(
			"pfb_unbound_py_ccache_flush(array('example.com'));\n",
			$this->flushPfb('fast')
		);

		$this->assertSame(['flush example.com', 'flush www.example.com'], $run['control'],
			'a healthy flush must still issue exactly the name and its www. sibling');
		$this->assertStringNotContainsString('TIMED OUT', $run['errlog'],
			'a healthy flush must not report an expiry');
		$this->assertStringNotContainsString('FAILED', $run['errlog'],
			'a healthy flush must not report a failure');
	}

	/**
	 * Scenario: many cache-flush names against a resolver that answers slowly.
	 *   Given twelve validated names (24 control commands) and a double that takes
	 *     ~0.7 s per reply — well past the whole-batch budget in total
	 *   When pfb_unbound_py_ccache_flush() runs
	 *   Then the batch stops at its deadline instead of multiplying per name, and the
	 *     skipped remainder is named.
	 */
	public function testManyNamesCannotMultiplyTheBatchBudget(): void
	{
		$names = [];
		for ($i = 1; $i <= 12; $i++) {
			$names[] = "a{$i}.example.com";
		}
		$run = $this->runIsolated(
			'pfb_unbound_py_ccache_flush(' . var_export($names, TRUE) . ");\n",
			$this->flushPfb('crawl')
		);

		$issued = array_values(array_filter($run['control'],
			static fn(string $line): bool => str_starts_with($line, 'flush ')));
		$this->assertNotSame([], $issued,
			'the batch must issue at least its first flush command');
		$this->assertLessThan(count($names) * 2, count($issued),
			'a whole-batch budget must stop the flush loop instead of running one command per name');
		$this->assertStringContainsString('flush command(s) not run', $run['errlog'],
			'the skipped remainder of the batch must be named, not silently dropped');
	}

	/**
	 * Scenario: the control command refuses immediately.
	 *   Given a control double that exits 3 without delay
	 *   When pfb_unbound_py_ccache_flush() runs for one name
	 *   Then the non-zero status is reported as a failure and NOT as an expiry, and a
	 *     fast refusal does not consume the batch budget.
	 */
	public function testNonZeroControlReplyIsNamedAndNotAnExpiry(): void
	{
		$run = $this->runIsolated(
			"pfb_unbound_py_ccache_flush(array('example.com'));\n",
			$this->flushPfb('nonzero')
		);

		$this->assertSame(['flush example.com', 'flush www.example.com'], $run['control'],
			'a fast non-zero reply must not consume the whole-batch budget');
		$this->assertStringContainsString('exit 3', $run['errlog'],
			'a non-zero control status must be reported with its exit code');
		$this->assertStringNotContainsString('TIMED OUT', $run['errlog'],
			'a non-zero exit must never be reported as a timeout');
	}

	/**
	 * Scenario: a transient control child that ignores SIGTERM and holds a descendant.
	 *   Given a double that traps TERM, publishes a `sleep 30` descendant and busy-waits
	 *     past the budget
	 *   When pfb_unbound_py_ccache_flush() runs
	 *   Then the kill grace ends the command anyway and the reaped tree leaves no
	 *     descendant behind.
	 */
	public function testTermIgnoringControlChildIsKilledAndLeavesNoDescendant(): void
	{
		$run = $this->runIsolated(
			"pfb_unbound_py_ccache_flush(array('example.com'));\n",
			$this->flushPfb('termproof')
		);

		$this->assertContains('flush example.com', $run['control'],
			'the site must spawn the injected control double');
		$descendants = [];
		foreach ($run['control'] as $line) {
			if (preg_match('/^descendant ([0-9]+)$/D', $line, $m) === 1) {
				$descendants[] = (int) $m[1];
			}
		}
		$this->assertNotSame([], $descendants,
			'the double must publish the descendant the reaping assertion needs');
		$this->assertNotContains('completed flush example.com', $run['control'],
			'a TERM-ignoring control child must be SIGKILLed after the grace, not waited out');
		foreach ($descendants as $pid) {
			$this->assertFalse(@posix_kill($pid, 0),
				"the expiry must reap the whole transient control tree; PID {$pid} outlived it");
		}
	}

	/**
	 * Scenario: the pre-restart cache dump never replies.
	 *   Given the restart path with resolver-cache handling enabled and a double whose
	 *     dump_cache never answers but whose status would
	 *   When pfb_reload_unbound() runs
	 *   Then the dump is killed at the deadline, its partial output is never loaded back
	 *     into the resolver, and no cache restore is claimed.
	 */
	public function testDumpCacheExpiryNeverFeedsLoadCacheOrClaimsRestore(): void
	{
		$run = $this->runIsolated($this->reloadBody(), $this->reloadPfb('dump_slow'));

		$this->assertContains('dump_cache', $run['control'],
			'the restart path must dump the cache through the injected double');
		$this->assertNotContains('completed dump_cache', $run['control'],
			'a cache dump that never replies must be killed at the deadline');
		$this->assertContains('status', $run['control'],
			'an expired cache dump must not abort the restart status check');
		$this->assertNotContains('load_cache', $run['control'],
			'a partial dump left by an expired dump_cache must never be loaded back');
		$this->assertStringNotContainsString('Resolver cache restored', $run['log'],
			'no cache restore may be claimed when the dump expired');
		$this->assertStringContainsString('TIMED OUT', $run['errlog'],
			'the expired cache dump must be observable in the error log');
	}

	/**
	 * Scenario: the post-restart status never replies.
	 *   Given a double whose dump_cache answers and whose status does not
	 *   When pfb_reload_unbound() runs
	 *   Then the status is killed at the deadline, is not read as a running resolver,
	 *     and the cache is not restored on top of an unconfirmed resolver.
	 */
	public function testStatusExpiryIsNotReadAsARunningResolver(): void
	{
		$run = $this->runIsolated($this->reloadBody(), $this->reloadPfb('status_slow'));

		$this->assertContains('status', $run['control'],
			'the restart path must query status through the injected double');
		$this->assertNotContains('completed status', $run['control'],
			'a status query that never replies must be killed at the deadline');
		$this->assertNotContains('load_cache', $run['control'],
			'an unconfirmed resolver must not have its cache restored');
		$this->assertStringContainsString('Not completed', $run['log'],
			'an expired status must be reported as a not-completed reload');
		$this->assertStringContainsString('TIMED OUT', $run['errlog'],
			'the expired status query must be observable in the error log');
	}

	/**
	 * Scenario: counter clearing meets a nonresponsive control socket.
	 *   Given a DNSBL counter clear and a double whose flush_stats never replies
	 *   When pfBlockerNG_clearsqlite() runs
	 *   Then the statistics flush ends at the deadline, is named, and the counter work
	 *     still completes.
	 */
	public function testStatsFlushExpiryIsNamedDuringCounterClearing(): void
	{
		$pfb = $this->flushPfb('slow');
		$pfb['dbdir'] = $this->dir;
		$pfb['sqlite_timeout'] = 100000;
		$run = $this->runIsolated(
			"\$GLOBALS['pfb_test_process_running']['unbound'] = TRUE;\n"
			. "pfBlockerNG_clearsqlite('cleardnsbl');\n"
			. "file_put_contents(" . var_export("{$this->dir}/returned", TRUE) . ", 'yes');\n",
			$pfb
		);

		$this->assertContains('flush_stats', $run['control'],
			'counter clearing must flush resolver statistics through the injected double');
		$this->assertNotContains('completed flush_stats', $run['control'],
			'a statistics flush that never replies must be killed at the deadline');
		$this->assertStringContainsString('TIMED OUT', $run['errlog'],
			'the expired statistics flush must be observable in the error log');
		$this->assertFileExists("{$this->dir}/returned",
			'an expired statistics flush must not stop the counter-clearing work that follows it');
	}

	/**
	 * Scenario: the opt-in bulk cache flush after a zero-downtime data swap.
	 *   Given the data fast path, the bulk flush enabled, and a double whose flush_zone
	 *     never replies
	 *   When pfb_update_unbound() runs
	 *   Then the full-zone flush ends at the deadline and is named.
	 */
	public function testBulkZoneFlushExpiryIsNamedAfterADataSwap(): void
	{
		$dnsdir = "{$this->dir}/dnsdir";
		$this->assertTrue(mkdir($dnsdir, 0700));
		$pfb = [
			'chroot_cmd'              => $this->installDouble('slow'),
			'dbdir'                   => $this->dir,
			'dnsbldir'                => $this->dir,
			'dnsdir'                  => $dnsdir,
			'dnsbl_file'              => "{$this->dir}/pfb_dnsbl",
			'dnsbl_cache'             => "{$this->dir}/pfb_py_cache.sqlite",
			'unbound_py_count'        => "{$this->dir}/pfb_py_count",
			'unbound_py_sources'      => "{$this->dir}/pfb_py_sources.json",
			'unbound_py_rawdir'       => "{$this->dir}/pfb_py_raw",
			'unbound_py_data'         => "{$this->dir}/pfb_py_data",
			'unbound_py_zone'         => "{$this->dir}/pfb_py_zone",
			'unbound_py_reject_stats' => "{$this->dir}/pfb_py_reject_stats.json",
			'dnsbl_python_unmount'    => FALSE,
			'dnsbl_res_cache'         => PfbToggle::On,
			'dnsbl_cache_flush'       => PfbToggle::On,
			'enable'                  => PfbToggle::On,
			'dnsbl'                   => PfbToggle::On,
			'save'                    => TRUE,
			'dnsbl_tld_wildcard'      => FALSE,
			'domain_update'           => FALSE,
			'reuse_dnsbl'             => '',
			'dnsbl_unlock'            => "{$this->dir}/dnsbl_unlock",
			'keep'                    => PfbToggle::On,
			'install'                 => FALSE,
		];
		$sentinel = "{$this->dir}/pfb_py_reload";
		$applied = "{$this->dir}/pfb_py_reload.applied";
		$this->assertNotFalse(file_put_contents("{$this->dir}/pfb_py_count", "1\n"));
		$this->assertNotFalse(file_put_contents("{$this->dir}/pfb_py_sources.json", '{"feeds":[]}'));
		$this->assertNotFalse(file_put_contents("{$this->dir}/pfb_py_reject_stats.json", '[]'));
		$this->assertNotFalse(file_put_contents("{$this->dir}/unbound.conf", "python-script: pfb_unbound.py\n"));
		$this->assertNotFalse(file_put_contents($sentinel, "1\n"));
		$this->assertNotFalse(file_put_contents($applied, "1\n"));

		$run = $this->runIsolated(
			"\$GLOBALS['config']['unbound'] = ['python' => 'on', 'python_script' => 'pfb_unbound'];\n"
			. "\$GLOBALS['pfb_test_process_running'] = ['unbound' => TRUE];\n"
			. "\$GLOBALS['pfb_test_unbound_py_sentinel_published'] = static function (string \$path, int \$generation): void {\n"
			. "\tif (\$path === " . var_export($sentinel, TRUE) . ") {\n"
			. "\t\tfile_put_contents(" . var_export($applied, TRUE) . ", \"{\$generation}\\n\");\n"
			. "\t}\n"
			. "};\n"
			. "set_error_handler(static function (int \$severity, string \$message): bool {\n"
			. "\treturn \$severity === E_NOTICE && str_contains(\$message, 'tempnam(): file created in the system');\n"
			. "});\n"
			. "pfb_update_unbound('enabled', FALSE, FALSE);\n"
			. "restore_error_handler();\n",
			$pfb
		);

		$this->assertContains('flush_zone +c .', $run['control'],
			'the bulk caller must issue the full-zone flush after a successful data swap');
		$this->assertNotContains('completed flush_zone +c .', $run['control'],
			'a full-zone flush that never replies must be killed at the deadline');
		$this->assertStringContainsString('TIMED OUT', $run['errlog'],
			'the expired full-zone flush must be observable in the error log');
	}

	/**
	 * The shipped wait contract itself: the operator-facing budget, the kill grace, and
	 * timeout(1)'s DEFAULT reaper mode (never --foreground, which would SIGKILL chroot
	 * alone and orphan a blocked unbound-control holding the capture pipe open).
	 */
	public function testShippedControlBudgetAndReaperModeArePinned(): void
	{
		$this->assertTrue(defined('PFB_UNBOUND_CONTROL_WAIT'),
			'the control-IPC budget must be an overridable constant, not a bare literal');
		$this->assertSame(30, PFB_UNBOUND_CONTROL_WAIT,
			'the shipped control-IPC budget must stay the 30 s the sibling resolver waits use');

		$composed = pfb_unbound_control_cmd('CTL status 2>&1');
		$this->assertSame(
			escapeshellarg((string) $GLOBALS['pfb']['timeout']) . ' -s TERM -k ' .
				PFB_HOOK_KILL_GRACE . ' ' . PFB_UNBOUND_CONTROL_WAIT . ' CTL status 2>&1',
			$composed,
			'the seam must wrap the control command in timeout(1) reaper mode with the package kill grace'
		);
		$this->assertStringNotContainsString('--foreground', $composed,
			'a transient control command must die as a whole tree on expiry');
		$this->assertSame(
			escapeshellarg((string) $GLOBALS['pfb']['timeout']) . ' -s TERM -k ' .
				PFB_HOOK_KILL_GRACE . ' 1 CTL flush x 2>&1',
			pfb_unbound_control_cmd('CTL flush x 2>&1', 0),
			'a clipped batch budget must floor at one second, never disable the bound'
		);
	}

	/**
	 * No control call site may bypass the seam: every $pfb['chroot_cmd'] use in the
	 * package is either the definition, the pure flush-command builder, or a call into
	 * the bounded seam. A new raw exec() of the control command turns this red.
	 */
	public function testNoControlSiteBypassesTheBoundedSeam(): void
	{
		$file = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc';
		$lines = file($file, FILE_IGNORE_NEW_LINES);
		$this->assertNotFalse($lines, 'the package source must be readable');

		$offenders = [];
		$sites = 0;
		foreach ($lines as $index => $line) {
			if (!str_contains($line, "\$pfb['chroot_cmd']")) {
				continue;
			}
			if (str_contains($line, "\$pfb['chroot_cmd'] = ")) {
				continue;
			}
			$sites++;
			if (str_contains($line, 'pfb_unbound_control_exec(') ||
			    str_contains($line, 'pfb_unbound_control_cmd(') ||
			    str_contains($line, 'pfb_unbound_py_ccache_flush_cmds(')) {
				continue;
			}
			$offenders[] = ($index + 1) . ': ' . trim($line);
		}

		$this->assertSame([], $offenders,
			'every unbound-control call site must run through the bounded seam, got: ' .
			implode(' | ', $offenders));
		$this->assertGreaterThanOrEqual(6, $sites,
			'the six known control call sites must still be present in the package source');
	}
}
