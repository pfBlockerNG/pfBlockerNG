<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #2878: the synchronous firewall-configuration reload -- the bare
 * mwexec('/etc/rc.filter_configure_sync') boundary inside sync_package_pfblockerng()
 * -- must run under ONE bounded seam: pfb_filter_reload_cmd() composes the bounded
 * command, pfb_filter_reload_exec() runs it, names the expiry, and never lets an
 * expired or never-launched reload read as success. The budget is the ONE operator
 * setting from issue #2851 (pfb_reentry_budget()), normalized at the seam.
 *
 * FROZEN RED: against the unbounded mwexec() boundary this file runs red -- the
 * route pins find no seam and the executed rows fatal on the missing functions --
 * then green UNCHANGED after implementation, driven by deterministic reload doubles
 * and a real timeout(1) from PATH. Nothing here touches the network or the appliance.
 *
 * Mode contract (docs/misc/external-process-waits.md decision table): the reload
 * command runs under timeout(1) in --foreground mode, the ADR-12 hook lane's mode.
 * pfSense's reload starts daemons meant to survive (pflog, dpinger, package service
 * restarts); the default reaper would hold the whole budget on their account and
 * kill them on alarm on EVERY successful apply pass. --foreground exits when the
 * direct child exits, and on a genuine overrun still SIGTERMs the reload root and
 * SIGKILLs it after the shared hook-lane grace, so no reload process outlives its
 * budget. Output is discarded to /dev/null (mwexec's own historical contract) and
 * stdin is /dev/null, so a survivor can neither hold exec()'s capture pipe nor
 * read the parent's stdin.
 */
final class FilterReloadBoundTest extends TestCase
{
	private const APPLY = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';

	/** Wall-clock salvage ceiling (seconds) for the executed rows -- far above the small budgets. */
	private const SALVAGE_CEILING = 20.0;

	/** The named expiry the seam owes every caller when timeout(1) reports 124. */
	private const EXPIRY_LINE = 'Firewall configuration reload TIMED OUT after 2s and was killed';

	private string $tmp;
	/** @var array<string, mixed> */
	private array $originalPfb;
	private bool $hadPfb;

	public static function setUpBeforeClass(): void
	{
		require_once self::APPLY;
	}

	protected function setUp(): void
	{
		$this->tmp = sys_get_temp_dir() . '/pfb_reload_' . getmypid() . '_' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir($this->tmp, 0700, TRUE));
		$this->hadPfb      = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'log'    => "{$this->tmp}/pfblockerng.log",
			'errlog' => "{$this->tmp}/error.log",
		]);
	}

	protected function tearDown(): void
	{
		// A survivor double must never outlive the test -- reap it by its pidfile.
		$pidfile = "{$this->tmp}/survivor.pid";
		if (is_file($pidfile)) {
			$pid = trim((string) file_get_contents($pidfile));
			if ($pid !== '') {
				exec('kill ' . escapeshellarg($pid) . ' 2>/dev/null');
			}
		}
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		foreach (glob("{$this->tmp}/*") ?: [] as $file) {
			@unlink($file);
		}
		@rmdir($this->tmp);
	}

	private function log(string $name): string
	{
		return (string) @file_get_contents("{$this->tmp}/{$name}");
	}

	/**
	 * The `<secs>` word the built command hands timeout(1), read off the `-k 5 ` anchor so
	 * an EMPTY duration is captured as '' rather than silently matching something else.
	 */
	private function durationToken(string $cmd): string
	{
		$this->assertSame(1, preg_match('/ -k 5 ([^ ]*) /', $cmd, $m),
			"the built command carries no '--foreground -s TERM -k 5 <secs>' bound at all: {$cmd}");
		return $m[1];
	}

	/** Real timeout(1) from PATH. A gate whose tool is missing is a failure, never a skip. */
	private function realTimeout(): string
	{
		$out = [];
		$rc  = 0;
		exec('command -v timeout 2>/dev/null', $out, $rc);
		$path = trim((string) ($out[0] ?? ''));
		if ($path === '' || !is_executable($path)) {
			$this->fail('no timeout(1) on PATH: the executed reload rows need a real one');
		}
		return $path;
	}

	/**
	 * Stand-in for /etc/rc.filter_configure_sync (which takes no arguments): the row's
	 * behavior IS the script body, so an executed row never starts a real reload.
	 * `exec sleep` keeps the hang row's root identical to the hung child, so the
	 * foreground kill reaps the whole double with no leftovers.
	 */
	private function fakeReload(string $body = 'exit 0'): string
	{
		$path = "{$this->tmp}/rc.filter_configure_sync";
		file_put_contents($path, "#!/bin/sh\n{$body}\n");
		chmod($path, 0755);
		return $path;
	}

	/** Double that starts a long-lived background "daemon" and hands off successfully. */
	private function survivorReload(): string
	{
		$path = "{$this->tmp}/rc.filter_configure_sync";
		file_put_contents($path, "#!/bin/sh\n"
			. "sleep 30 &\n"
			. "echo \$! > \"\$(dirname \"\$0\")/survivor.pid\"\n"
			. "exit 0\n");
		chmod($path, 0755);
		return $path;
	}

	/** Stand-in for $pfb['timeout']: prints its own argv, one word per line, then exits 0. */
	private function argvEcho(): string
	{
		$path = "{$this->tmp}/argv-echo";
		file_put_contents($path, "#!/bin/sh\n" . 'printf "%s\n" "$@"' . "\n");
		chmod($path, 0755);
		return $path;
	}
	/** Slice a php_strip_whitespace()'d source between two code anchors (comments cannot satisfy it). */
	private function scope(string $source, string $start, string $end): string
	{
		$from = strpos($source, $start);
		if ($from === FALSE) {
			throw new RuntimeException('route-pin scope start not found: ' . $start);
		}
		$to = strpos($source, $end, $from + strlen($start));
		if ($to === FALSE) {
			throw new RuntimeException('route-pin scope end not found: ' . $end);
		}
		return substr($source, $from, $to + strlen($end) - $from);
	}

	/**
	 * sync_package_pfblockerng() runs to the end of the apply pass, so its route-pin
	 * scope is the stripped source from the declaration to end-of-file.
	 */
	private function syncScope(string $source): string
	{
		$from = strpos($source, 'function sync_package_pfblockerng(');
		if ($from === FALSE) {
			throw new RuntimeException('route-pin scope start not found: sync_package_pfblockerng');
		}
		return substr($source, $from);
	}

	// ── Builder: the bound itself ───────────────────────────────────────────────

	public function testCommandStaysInForegroundMode(): void
	{
		// The reload lane's mode is the ADR-12 hook lane's: --foreground. The default
		// reaper would hold the whole budget on every survivor the reload starts
		// (pflog, dpinger, package service restarts) and kill them on alarm.
		$GLOBALS['pfb']['timeout'] = $this->realTimeout();
		$cmd = pfb_filter_reload_cmd();

		$this->assertStringContainsString('--foreground -s TERM -k 5 ', $cmd,
			"the reload must stay in --foreground mode with the shared TERM/kill-grace pair: {$cmd}");
	}

	public function testNullBudgetFallsBackToTheOperatorCeiling(): void
	{
		$GLOBALS['pfb']['timeout'] = $this->argvEcho();
		$cmd = pfb_filter_reload_cmd(NULL);

		$this->assertSame((string) PFB_REENTRY_TIMEOUT, $this->durationToken($cmd),
			"an unspecified budget must land on the issue #2851 operator ceiling: {$cmd}");
	}

	public function testCallerBudgetBecomesTheDuration(): void
	{
		$GLOBALS['pfb']['timeout'] = $this->argvEcho();
		$cmd = pfb_filter_reload_cmd(45);

		$this->assertSame('45', $this->durationToken($cmd),
			"a positive int caller budget must be the duration timeout(1) gets: {$cmd}");
	}

	/** @return array<string, array{0: mixed}> */
	public static function degradedBudgets(): array
	{
		return [
			'empty string'   => [''],
			'non-numeric'    => ['abc'],
			'zero int'       => [0],
			'negative int'   => [-5],
			'decimal string' => ['12.5'],
			'null'           => [NULL],
		];
	}

	#[DataProvider('degradedBudgets')]
	public function testDegradedBudgetStillYieldsAPositiveIntegerDuration(mixed $budget): void
	{
		$GLOBALS['pfb']['timeout'] = $this->argvEcho();
		$cmd = pfb_filter_reload_cmd($budget);
		$secs = $this->durationToken($cmd);

		$this->assertMatchesRegularExpression('/^[0-9]+$/', $secs,
			"issue #2488: no budget may leave timeout(1) an empty or non-numeric duration; got [{$secs}] from: {$cmd}");
		$this->assertGreaterThan(0, (int) $secs,
			"issue #2488: the duration must stay a POSITIVE integer; got [{$secs}] from: {$cmd}");
	}

	public function testCommandDiscardsOutputAndTakesStdinFromDevNull(): void
	{
		$GLOBALS['pfb']['timeout'] = $this->argvEcho();
		$cmd = pfb_filter_reload_cmd();

		$this->assertStringEndsWith('> /dev/null 2>&1 < /dev/null', $cmd,
			"output must stay discarded (mwexec's historical contract) and stdin on /dev/null "
			. "so no survivor can hold exec()'s capture pipe: {$cmd}");
	}

	public function testInjectedBinariesAreEscapedAndLeadTheCommand(): void
	{
		$GLOBALS['pfb']['timeout'] = '/opt/pfb bin/timeout';
		$GLOBALS['pfb']['filter_configure_sync'] = '/opt/pfb bin/rc.filter_configure_sync';
		$cmd = pfb_filter_reload_cmd();

		$this->assertStringStartsWith(escapeshellarg('/opt/pfb bin/timeout') . ' --foreground -s TERM -k 5 ', $cmd,
			"the injected timeout(1) must lead the command, escaped: {$cmd}");
		$this->assertStringContainsString(' ' . escapeshellarg('/opt/pfb bin/rc.filter_configure_sync') . ' > /dev/null', $cmd,
			"the injected reload script must reach timeout(1) as ONE escaped word: {$cmd}");
	}

	public function testAbsentInjectionFallsBackToTheAppliancePaths(): void
	{
		$GLOBALS['pfb'] = [
			'log'    => "{$this->tmp}/pfblockerng.log",
			'errlog' => "{$this->tmp}/error.log",
		];
		$cmd = pfb_filter_reload_cmd();

		$this->assertStringStartsWith(escapeshellarg('/usr/bin/timeout') . ' --foreground -s TERM -k 5 ', $cmd,
			"an uninjected \$pfb['timeout'] must fall back to the appliance path: {$cmd}");
		$this->assertStringContainsString(' ' . escapeshellarg('/etc/rc.filter_configure_sync') . ' > /dev/null', $cmd,
			"an uninjected reload must target the pfSense script, escaped: {$cmd}");
	}

	// ── Executed: real timeout(1), deterministic reload doubles ─────────────────

	public function testHealthyReloadReturnsZeroWithinItsBudget(): void
	{
		$GLOBALS['pfb']['timeout'] = $this->realTimeout();
		$GLOBALS['pfb']['filter_configure_sync'] = $this->fakeReload();

		$started = microtime(TRUE);
		$status  = pfb_filter_reload_exec(10);
		$elapsed = microtime(TRUE) - $started;

		$this->assertLessThan(self::SALVAGE_CEILING, $elapsed,
			sprintf('stuck/environment: a healthy reload took %.1fs', $elapsed));
		$this->assertSame(0, $status, 'a healthy reload must return the child status 0');
		$this->assertSame('', $this->log('pfblockerng.log'),
			'a clean reload must stay silent in the pfBlockerNG log');
	}

	public function testHungReloadIsKilledAtItsBudgetAndTheExpiryIsNamed(): void
	{
		$GLOBALS['pfb']['timeout'] = $this->realTimeout();
		$GLOBALS['pfb']['filter_configure_sync'] = $this->fakeReload('exec sleep 5');

		$started = microtime(TRUE);
		$status  = pfb_filter_reload_exec(2);
		$elapsed = microtime(TRUE) - $started;

		$this->assertLessThan(self::SALVAGE_CEILING, $elapsed,
			sprintf('stuck/environment: a 2s-budgeted reload took %.1fs', $elapsed));
		$this->assertSame(124, $status, "an expired reload must surface timeout(1)'s 124");
		$this->assertStringContainsString(self::EXPIRY_LINE, $this->log('pfblockerng.log'),
			'a swallowed expiry is the defect: the seam must name it in the pfBlockerNG log');
		$this->assertStringContainsString(self::EXPIRY_LINE, $this->log('error.log'),
			'a swallowed expiry is the defect: the seam must name it in the error log');
	}

	public function testReloadWithHeldGrandchildStillReturnsAtItsBudget(): void
	{
		// A stalled reload with a stalled descendant must still return 124 at its budget.
		$GLOBALS['pfb']['timeout'] = $this->realTimeout();
		$GLOBALS['pfb']['filter_configure_sync'] = $this->fakeReload('sleep 3 & sleep 3');

		$started = microtime(TRUE);
		$status  = pfb_filter_reload_exec(2);
		$elapsed = microtime(TRUE) - $started;

		$this->assertLessThan(self::SALVAGE_CEILING, $elapsed,
			sprintf('stuck/environment: a grandchild held the wait for %.1fs against a 2s budget', $elapsed));
		$this->assertSame(124, $status,
			'a reload whose descendant outlives the direct child must still expire at its budget');
	}

	public function testSurvivorOutlivesASuccessfulHandoffWithoutHoldingTheWait(): void
	{
		// Row: "Reload script starts a daemon intended to survive". The parent must
		// return the handoff status as soon as the reload exits -- long before the
		// budget -- and the survivor must still be alive right after.
		$GLOBALS['pfb']['timeout'] = $this->realTimeout();
		$GLOBALS['pfb']['filter_configure_sync'] = $this->survivorReload();

		$started = microtime(TRUE);
		$status  = pfb_filter_reload_exec(15);
		$elapsed = microtime(TRUE) - $started;

		$this->assertSame(0, $status, 'a successful handoff must return the reload status 0');
		$this->assertLessThan(10.0, $elapsed, sprintf(
			'stuck/environment: the parent waited %.1fs for a budget of 15s -- the survivor held the seam',
			$elapsed,
		));

		$pid = trim((string) @file_get_contents("{$this->tmp}/survivor.pid"));
		$this->assertNotSame('', $pid, 'the survivor double must record its pid');
		exec('kill -0 ' . escapeshellarg($pid) . ' 2>/dev/null', $discard, $alive);
		$this->assertSame(0, $alive,
			'the bound mode must not kill a daemon the reload handed off successfully');
	}

	public function testNonZeroReloadExitIsObservableAndNotConflatedWithTimeout(): void
	{
		$GLOBALS['pfb']['timeout'] = $this->realTimeout();
		$GLOBALS['pfb']['filter_configure_sync'] = $this->fakeReload("echo 'reload failed'; exit 7");

		$status = pfb_filter_reload_exec(10);

		$this->assertSame(7, $status, 'a plain non-zero reload status must be returned unchanged');
		$this->assertStringContainsString('Firewall configuration reload exited non-zero [ 7 ]', $this->log('pfblockerng.log'),
			'an existing reload failure must stay observable in the pfBlockerNG log');
		$this->assertStringNotContainsString('TIMED OUT', $this->log('pfblockerng.log'),
			'the 124 branch must discriminate, not fire on every non-zero status');
		$this->assertStringNotContainsString('TIMED OUT', $this->log('error.log'),
			'the 124 branch must discriminate, not fire on every non-zero status');
	}

	public function testLaunchFailureNeverReadsAsSuccess(): void
	{
		$GLOBALS['pfb']['timeout'] = "{$this->tmp}/no-such-timeout";
		$GLOBALS['pfb']['filter_configure_sync'] = $this->fakeReload();

		$status = pfb_filter_reload_exec(10);

		$this->assertSame(127, $status, 'a launcher that never ran must surface the shell status');
		$this->assertStringContainsString('Firewall configuration reload exited non-zero [ 127 ]', $this->log('pfblockerng.log'),
			'a launch failure must stay observable, never silently successful');
		$this->assertStringNotContainsString('TIMED OUT', $this->log('pfblockerng.log'),
			'a launch failure must not be conflated with an expiry');
	}

	// ── Route pins: the one blocking call site ──────────────────────────────────
	//
	// POSITIVE (the site reaches the seam) AND NEGATIVE (no unbounded mwexec boundary
	// survives there) -- the negatives are what a "remove the bound here" mutant has
	// to kill. php_strip_whitespace() keeps comments out of every half.

	public function testSyncPassRoutesTheFilterReloadThroughTheBoundedSeam(): void
	{
		$stripped = php_strip_whitespace(self::APPLY);
		$scope = $this->syncScope($stripped);

		$this->assertSame(1, substr_count($scope, 'pfb_filter_reload_exec('),
			'the sync pass must preserve exactly one bounded reload call');
		$this->assertSame(0, substr_count($stripped, 'mwexec('),
			'no bare mwexec() boundary may survive anywhere in the apply pass');
	}

	public function testTheReloadStaysAheadOfTheFilterDaemonStage(): void
	{
		$stripped = php_strip_whitespace(self::APPLY);
		$scope = $this->syncScope($stripped);

		$reload = strpos($scope, 'pfb_filter_reload_exec(');
		$daemon = strpos($scope, 'Restarting firewall filter daemon');
		$this->assertNotFalse($reload);
		$this->assertNotFalse($daemon);
		$this->assertLessThan($daemon, $reload,
			'the required ordering holds: the reload must precede the filter-daemon management stage');
	}

	public function testAnExpiredOrNeverLaunchedReloadIsNeverReadAsSuccess(): void
	{
		$stripped = php_strip_whitespace(self::APPLY);
		// The pin's scope is the call site's recovery region, never everything after
		// the seam's definition: that wider slice matched the definition's own
		// `=== 124` and the pass's other pfb_mark_pending_changes() calls.
		$scope = $this->scope($this->syncScope($stripped), 'pfb_filter_reload_exec(',
			'Stopping firewall filter daemon');

		$this->assertStringContainsString('pfb_mark_pending_changes();', $scope,
			'the recovery branch must mark the pass pending so the next tick re-applies');
		$this->assertStringContainsString('124', $scope,
			'the expiry status must gate the recovery branch');
	}

	public function testClosingClearDoesNotWipeAnExpiredReloadPendingMark(): void
	{
		$stripped = php_strip_whitespace(self::APPLY);
		$scope = $this->syncScope($stripped);
		$clear = strpos($scope, 'pfb_clear_pending_changes();');
		$this->assertNotFalse($clear, 'the pass still has a closing pending-marker clear');
		$window = substr($scope, max(0, $clear - 250), 350);
		$this->assertStringContainsString('$pfb_filter_reload_unknown', $window,
			'the closing clear must be gated so a 124 pending mark survives the rest of the pass');
	}
}
