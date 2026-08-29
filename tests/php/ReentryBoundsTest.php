<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #2016: every BLOCKING nested pfblockerng.php re-entry runs under timeout(1) at
 * ONE seam -- pfb_reentry_cmd() composes the bounded command, pfb_reentry_exec() runs it,
 * reproduces the child's output and names the expiry. issue #2488 is the degradation class
 * the budget must be immune to: no caller value may turn a capped wait back into an
 * unbounded one by leaving timeout(1) an empty or non-numeric duration.
 *
 * The executed rows use a real timeout(1) from PATH plus a fake interpreter written to the
 * test's tmpdir, so nothing here touches the network, a real php, or the appliance.
 */
final class ReentryBoundsTest extends TestCase
{
	private const APPLY = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';
	private const EXTRA = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_extra.inc';

	/** Wall-clock salvage ceiling (seconds) for the executed rows -- far above the 2s budget. */
	private const SALVAGE_CEILING = 20.0;

	/** The named expiry the seam owes every caller when timeout(1) reports 124. */
	private const EXPIRY_LINE = 'Nested pfblockerng.php [ hang ] TIMED OUT after 2s and was killed';

	private string $tmp;
	/** @var array<string, mixed> */
	private array $originalPfb;
	private bool $hadPfb;

	protected function setUp(): void
	{
		$this->tmp = sys_get_temp_dir() . '/pfb_reentry_' . getmypid() . '_' . bin2hex(random_bytes(4));
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
			"the built command carries no '-s TERM -k 5 <secs>' bound at all: {$cmd}");
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
			$this->fail('no timeout(1) on PATH: the executed re-entry rows need a real one');
		}
		return $path;
	}

	/**
	 * Stand-in for $pfb['php']: ignores $1 (the re-entry script path) and branches on the
	 * verb in $2, so an executed row never starts a real interpreter.
	 */
	private function fakePhp(): string
	{
		$path = "{$this->tmp}/php";
		file_put_contents($path, <<<'SH'
			#!/bin/sh
			shift
			case "$1" in
			healthy) echo 'first child line'; echo 'second child line'; exit 0 ;;
			hang)    sleep 30; exit 0 ;;
			hangkid) sleep 30 & sleep 30; exit 0 ;;
			boom)    echo 'child failed'; exit 7 ;;
			esac
			exit 0
			SH);
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
			throw new RuntimeException("route-pin scope start not found: {$start}");
		}
		$to = strpos($source, $end, $from + strlen($start));
		if ($to === FALSE) {
			throw new RuntimeException("route-pin scope end not found: {$end}");
		}
		return substr($source, $from, $to + strlen($end) - $from);
	}

	// ── Builder: the bound itself ───────────────────────────────────────────────

	public function testSeamConstantsPinTheCeilingAndTheReentryTarget(): void
	{
		$this->assertTrue(defined('PFB_REENTRY_TIMEOUT'),
			'PFB_REENTRY_TIMEOUT (the nested re-entry ceiling) must be defined by pfblockerng.inc');
		$this->assertTrue(defined('PFB_REENTRY_SCRIPT'),
			'PFB_REENTRY_SCRIPT (the single-sourced re-entry target) must be defined by pfblockerng.inc');
		$this->assertSame(1800, PFB_REENTRY_TIMEOUT);
		$this->assertSame('/usr/local/www/pfblockerng/pfblockerng.php', PFB_REENTRY_SCRIPT);
	}

	public function testPositiveIntegerBudgetBecomesTheDuration(): void
	{
		$cmd  = pfb_reentry_cmd('al', ['scheduled'], "{$this->tmp}/out", 45);
		$secs = $this->durationToken($cmd);

		$this->assertSame('45', $secs, "a positive int budget must be the duration timeout(1) gets: {$cmd}");
	}

	public function testNullBudgetFallsBackToTheDefaultCeiling(): void
	{
		$cmd  = pfb_reentry_cmd('al', ['scheduled'], "{$this->tmp}/out", NULL);
		$secs = $this->durationToken($cmd);

		$this->assertSame((string) PFB_REENTRY_TIMEOUT, $secs,
			"an unspecified budget must land on PFB_REENTRY_TIMEOUT: {$cmd}");
	}

	public function testAllDigitStringBudgetIsHonoured(): void
	{
		$cmd  = pfb_reentry_cmd('dc', ['scheduled'], "{$this->tmp}/out", '90');
		$secs = $this->durationToken($cmd);

		$this->assertSame('90', $secs, "an all-digit string budget must be honoured verbatim: {$cmd}");
	}

	/** @return array<string, array{0: mixed}> */
	public static function degradedBudgets(): array
	{
		return [
			'empty string'   => [''],
			'non-numeric'    => ['abc'],
			'trailing space' => ['30 '],
			'leading space'  => [' 30'],
			'zero string'    => ['0'],
			'zero int'       => [0],
			'negative int'   => [-5],
			'decimal string' => ['12.5'],
		];
	}

	#[DataProvider('degradedBudgets')]
	public function testDegradedBudgetStillYieldsAPositiveIntegerDuration(mixed $budget): void
	{
		$cmd  = pfb_reentry_cmd('bls', ['scheduled'], "{$this->tmp}/out", $budget);
		$secs = $this->durationToken($cmd);

		$this->assertMatchesRegularExpression('/^[0-9]+$/', $secs,
			"issue #2488: no budget may leave timeout(1) an empty or non-numeric duration; got [{$secs}] from: {$cmd}");
		$this->assertGreaterThan(0, (int) $secs,
			"issue #2488: the duration must stay a POSITIVE integer; got [{$secs}] from: {$cmd}");
	}

	public function testCommandNeverUsesForegroundMode(): void
	{
		// Default (reaper) mode is mandatory on FreeBSD: a hung download pass must die as
		// a whole tree; --foreground would SIGKILL php alone and orphan a blocked fetch.
		$cmd = pfb_reentry_cmd('dc', ['scheduled'], "{$this->tmp}/out");

		$this->assertStringNotContainsString('--foreground', $cmd,
			"the re-entry must stay in default (reaper) mode: {$cmd}");
	}

	public function testCommandCapturesToTheOutfileAndTakesStdinFromDevNull(): void
	{
		$out = "{$this->tmp}/capture.out";
		$cmd = pfb_reentry_cmd('dc', ['scheduled'], $out);

		$this->assertStringEndsWith('> ' . escapeshellarg($out) . ' 2>&1 < /dev/null', $cmd,
			"output must land on a file and stdin on /dev/null so no descendant can hold exec()'s capture pipe: {$cmd}");
	}

	public function testVerbAndEveryArgumentReachTheChildAsSingleWords(): void
	{
		$GLOBALS['pfb']['timeout'] = $this->argvEcho();
		$GLOBALS['pfb']['php']     = '/nonexistent/php binary';
		$out = "{$this->tmp}/argv.out";

		$discard = [];
		$rc      = 0;
		$cmd     = pfb_reentry_cmd('ve rb', ['a b', "c'd", 'e;f', 'g$(h)'], $out);
		exec($cmd, $discard, $rc);

		$this->assertSame(0, $rc, "the composed command must be runnable by /bin/sh: {$cmd}");
		$this->assertSame([
			'-s', 'TERM', '-k', '5', (string) PFB_REENTRY_TIMEOUT,
			'/nonexistent/php binary', PFB_REENTRY_SCRIPT,
			've rb', 'a b', "c'd", 'e;f', 'g$(h)',
		], file($out, FILE_IGNORE_NEW_LINES) ?: [],
			"every path, the verb and each arg must survive the shell as ONE word: {$cmd}");
	}

	public function testTimeoutAndPhpBinariesAreInjectable(): void
	{
		$GLOBALS['pfb']['timeout'] = '/opt/pfb bin/timeout';
		$GLOBALS['pfb']['php']     = '/opt/pfb bin/php';

		$cmd = pfb_reentry_cmd('asn', [], "{$this->tmp}/out");

		$this->assertStringStartsWith(escapeshellarg('/opt/pfb bin/timeout') . ' -s TERM -k 5 ', $cmd,
			"the injected timeout(1) must lead the command, escaped: {$cmd}");
		$this->assertStringContainsString(
			escapeshellarg('/opt/pfb bin/php') . ' ' . escapeshellarg(PFB_REENTRY_SCRIPT) . ' ' . escapeshellarg('asn'),
			$cmd, "the injected interpreter must run the re-entry target, escaped: {$cmd}");
	}

	public function testAbsentInjectionFallsBackToTheAppliancePaths(): void
	{
		$GLOBALS['pfb'] = [
			'log'    => "{$this->tmp}/pfblockerng.log",
			'errlog' => "{$this->tmp}/error.log",
		];

		$cmd = pfb_reentry_cmd('asn', [], "{$this->tmp}/out");

		$this->assertStringStartsWith(escapeshellarg('/usr/bin/timeout') . ' -s TERM -k 5 ', $cmd,
			"an uninjected \$pfb['timeout'] must fall back to the appliance path: {$cmd}");
		$this->assertStringContainsString(
			escapeshellarg('/usr/local/bin/php') . ' ' . escapeshellarg(PFB_REENTRY_SCRIPT), $cmd,
			"an uninjected \$pfb['php'] must fall back to the appliance path: {$cmd}");
	}

	// ── Executed: real timeout(1), fake interpreter ─────────────────────────────

	public function testHealthyChildReturnsZeroAndReproducesItsOutputLines(): void
	{
		$GLOBALS['pfb']['timeout'] = $this->realTimeout();
		$GLOBALS['pfb']['php']     = $this->fakePhp();

		$lines   = NULL;
		$started = microtime(TRUE);
		$status  = pfb_reentry_exec('healthy', [], NULL, $lines);
		$elapsed = microtime(TRUE) - $started;

		$this->assertLessThan(self::SALVAGE_CEILING, $elapsed,
			sprintf('stuck/environment: a healthy re-entry took %.1fs', $elapsed));
		$this->assertSame(0, $status, 'a healthy re-entry must return the child status 0');
		$this->assertSame(['first child line', 'second child line'], $lines,
			"the file read-back must reproduce exec()'s \$output shape -- no trailing empty element");
	}

	public function testHungChildIsKilledAtItsBudgetAndTheExpiryIsNamed(): void
	{
		$GLOBALS['pfb']['timeout'] = $this->realTimeout();
		$GLOBALS['pfb']['php']     = $this->fakePhp();

		$lines   = NULL;
		$started = microtime(TRUE);
		$status  = pfb_reentry_exec('hang', [], NULL, $lines, 2);
		$elapsed = microtime(TRUE) - $started;

		$this->assertLessThan(self::SALVAGE_CEILING, $elapsed,
			sprintf('stuck/environment: a 2s-budgeted re-entry took %.1fs', $elapsed));
		$this->assertSame(124, $status, "an expired re-entry must surface timeout(1)'s 124");
		$this->assertStringContainsString(self::EXPIRY_LINE, $this->log('pfblockerng.log'),
			'a swallowed expiry is the defect: the seam must name it in the pfBlockerNG log');
		$this->assertStringContainsString(self::EXPIRY_LINE, $this->log('error.log'),
			'a swallowed expiry is the defect: the seam must name it in the error log');
	}

	public function testHungChildAndGrandchildHoldingOutputStillReturnAtTheBudget(): void
	{
		// A stalled child with a stalled descendant must still return 124 at its budget.
		$GLOBALS['pfb']['timeout'] = $this->realTimeout();
		$GLOBALS['pfb']['php']     = $this->fakePhp();

		$lines   = NULL;
		$started = microtime(TRUE);
		$status  = pfb_reentry_exec('hangkid', [], NULL, $lines, 2);
		$elapsed = microtime(TRUE) - $started;

		$this->assertLessThan(self::SALVAGE_CEILING, $elapsed,
			sprintf('stuck/environment: a grandchild held the capture for %.1fs against a 2s budget', $elapsed));
		$this->assertSame(124, $status,
			'a re-entry whose grandchild holds the output must still expire at its budget');
	}

	public function testAppendToReceivesTheChildOutputAndKeepsThePriorContent(): void
	{
		$GLOBALS['pfb']['timeout'] = $this->realTimeout();
		$GLOBALS['pfb']['php']     = $this->fakePhp();
		$dest = "{$this->tmp}/extras.log";
		file_put_contents($dest, "prior content\n");

		$status = pfb_reentry_exec('healthy', [], $dest);

		$this->assertSame(0, $status);
		$this->assertSame("prior content\nfirst child line\nsecond child line\n",
			(string) file_get_contents($dest),
			'$append_to must preserve the old ">> $log" semantics: prior bytes first, child output appended');
	}

	public function testNonZeroChildExitIsReturnedUnchangedAndNamesNoExpiry(): void
	{
		$GLOBALS['pfb']['timeout'] = $this->realTimeout();
		$GLOBALS['pfb']['php']     = $this->fakePhp();

		$lines  = NULL;
		$status = pfb_reentry_exec('boom', [], NULL, $lines);

		$this->assertSame(7, $status, 'a plain non-zero child status must be returned unchanged');
		$this->assertSame(['child failed'], $lines);
		$this->assertStringNotContainsString('TIMED OUT', $this->log('pfblockerng.log'),
			'the 124 branch must discriminate, not fire on every non-zero status');
		$this->assertStringNotContainsString('TIMED OUT', $this->log('error.log'),
			'the 124 branch must discriminate, not fire on every non-zero status');
	}

	// ── Route pins: one per blocking PHP call site ──────────────────────────────
	//
	// Each pin is POSITIVE (the site reaches the seam) AND NEGATIVE (no unbounded
	// composition survives there) -- the negative is what a "remove the bound here"
	// mutant has to kill. php_strip_whitespace() keeps comments out of both halves.

	public function testTop1mFetchRoutesTheAlReentryThroughTheBoundedSeam(): void
	{
		$scope = $this->scope(php_strip_whitespace(self::APPLY),
			'function pfb_top1m_fetch_if_needed(', 'function pfb_top1m_reprocess_needed(');

		$this->assertSame(1, substr_count($scope, "pfb_reentry_exec('al', ['scheduled']);"),
			'the TOP1M refresh must preserve exactly one scheduled child call');
		$this->assertStringNotContainsString('pfblockerng.php', $scope,
			'the TOP1M refresh must compose no re-entry command of its own');
		$this->assertStringNotContainsString('/usr/local/bin/php', $scope,
			'the TOP1M refresh must name no interpreter of its own');
	}

	public function testBlacklistDownloadRoutesTheBlsReentryThroughTheBoundedSeam(): void
	{
		$scope = $this->scope(php_strip_whitespace(self::APPLY),
			'Downloading Blacklist Database(s) [', 'pfb_prune_failed_bl_lists($lists, $pfb_return);');

		$this->assertSame(
			1,
			substr_count($scope, "pfb_reentry_exec('bls', ['scheduled', \$bl_string], NULL, \$pfb_return);"),
			'$pfb_return must stay the output destination of exactly one child call'
		);
		$this->assertStringNotContainsString('pfblockerng.php', $scope,
			'the blacklist download must compose no re-entry command of its own');
		$this->assertStringNotContainsString('/usr/local/bin/php', $scope,
			'the blacklist download must name no interpreter of its own');
	}

	public function testMaxmindDownloadRoutesTheDcReentryThroughTheBoundedSeam(): void
	{
		$scope = $this->scope(php_strip_whitespace(self::APPLY),
			'MaxMind Database downloading and processing ( approx 4MB )',
			'pfb_logger("MaxMind processing failed; update deferred.\n", 2);');

		$this->assertSame(1, substr_count($scope, "\$maxmind_status = pfb_reentry_exec('dc'"), $scope);
		$this->assertStringContainsString('in_array($maxmind_status, [0, 2], TRUE)', $scope,
			'the existing deferral must keep reading the seam status, so 124 defers the pass');
		$this->assertStringNotContainsString('pfblockerng.php', $scope,
			'the MaxMind download must compose no re-entry command of its own');
		$this->assertStringNotContainsString('/usr/local/bin/php', $scope,
			'the MaxMind download must name no interpreter of its own');
	}

	public function testScheduleExtraRunRoutesEveryExtraJobThroughTheBoundedSeam(): void
	{
		$scope = $this->scope(php_strip_whitespace(self::EXTRA),
			'function pfb_schedule_extra_run(', 'function pfb_quiet_hours_in_window(');

		$this->assertSame(1, substr_count($scope, 'pfb_reentry_exec('), $scope);
		$this->assertStringNotContainsString('pfblockerng.php', $scope,
			'pfb_schedule_extra_run() must compose no re-entry command of its own');
		$this->assertStringNotContainsString("\$pfb['php']", $scope,
			'pfb_schedule_extra_run() must name no interpreter of its own');
	}
}
