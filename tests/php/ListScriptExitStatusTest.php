<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1927: the per-feed list pre/post transform scripts' exit status must be
 * honoured — a failed transform is not feed data.
 *
 * pfb_list_script_exec() runs a vetted list script under timeout(1) and returns
 * its exit code; non-zero (124 = timed out) is logged to the pfBlockerNG log AND
 * the error log, naming the stage, the script, and the feed. $tmo_prefix is
 * injectable for off-appliance tests (the appliance default wraps /usr/bin/timeout).
 *
 * The apply-loop call sites gate on that code — a failed pre-script's leftovers
 * are never parsed (the download is restored and the last known-good staged list
 * kept), and a failed post-script's leftovers never feed the empty-feed check.
 * Those sites sit inside the thousands-of-lines sync loop driving real appliance
 * exec, so they are pinned by source inspection (same technique as
 * GunzipTrailingNewlineWiringTest); the behaviour itself is proven on the helper.
 */
#[CoversFunction('pfb_list_script_exec')]
final class ListScriptExitStatusTest extends TestCase
{
	private static string $applySource;

	private string $tmp;
	/** @var array<string, mixed> */
	private array $originalPfb;
	private bool $hadPfb;

	public static function setUpBeforeClass(): void
	{
		$source = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc'
		);
		if ($source === FALSE) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_apply.inc');
		}
		self::$applySource = $source;
	}

	protected function setUp(): void
	{
		$this->tmp = sys_get_temp_dir() . '/pfb_lse_' . getmypid() . '_' . bin2hex(random_bytes(4));
		mkdir($this->tmp, 0755, TRUE);

		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
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
		foreach (glob("{$this->tmp}/*") ?: [] as $f) {
			unlink($f);
		}
		rmdir($this->tmp);
	}

	private function makeScript(string $name, string $body): string
	{
		$path = "{$this->tmp}/{$name}";
		file_put_contents($path, "#!/bin/sh\n{$body}\n");
		chmod($path, 0755);
		return $path;
	}

	private function mainLog(): string
	{
		return (string) @file_get_contents("{$this->tmp}/pfblockerng.log");
	}

	private function errorLog(): string
	{
		return (string) @file_get_contents("{$this->tmp}/error.log");
	}

	public function testZeroExitReturnsZeroAndLogsNoFailure(): void
	{
		$script = $this->makeScript('ip_pre_ok.sh', 'exit 0');

		$ret = pfb_list_script_exec($script, 'ip_pre_ok.sh', 'pre', 'MyFeed_v4', '', '');

		$this->assertSame(0, $ret, 'a successful script must report exit 0 to the caller');
		$this->assertStringNotContainsString('exited non-zero', $this->mainLog(),
			'a zero exit must not log a failure');
		$this->assertStringNotContainsString('TIMED OUT', $this->mainLog(),
			'a zero exit must not log a timeout');
	}

	public function testNonZeroExitIsReturnedAndLoggedNamingStageScriptAndFeed(): void
	{
		$script = $this->makeScript('ip_pre_AWS_fail.sh', 'exit 7');

		$ret = pfb_list_script_exec($script, 'ip_pre_AWS_fail.sh', 'pre', 'MyFeed_v4', '', '');

		$this->assertSame(7, $ret, 'the script exit code must be surfaced, not discarded');
		$log = $this->mainLog();
		$this->assertStringContainsString("pre-script 'ip_pre_AWS_fail.sh'", $log,
			'the failure log line must name the stage and the script');
		$this->assertStringContainsString('MyFeed_v4', $log,
			'the failure log line must name the feed');
		$this->assertStringContainsString('[ 7 ]', $log,
			'the failure log line must carry the exit code');
		$this->assertStringContainsString('exited non-zero', $this->errorLog(),
			'the failure must also surface in the error log');
	}

	public function testExit124IsLoggedAsTimedOut(): void
	{
		// timeout(1) reports an overrun as exit 124 — indistinguishable from the
		// script exiting 124 itself, which is exactly what the helper keys on.
		$script = $this->makeScript('ip_post_slow.sh', 'exit 124');

		$ret = pfb_list_script_exec($script, 'ip_post_slow.sh', 'post', 'SlowFeed_v6', '', '');

		$this->assertSame(124, $ret);
		$log = $this->mainLog();
		$this->assertStringContainsString('TIMED OUT', $log,
			'exit 124 must be reported as a timeout, not a generic non-zero');
		$this->assertStringContainsString("post-script 'ip_post_slow.sh'", $log);
		$this->assertStringContainsString('SlowFeed_v6', $log);
		$this->assertStringContainsString('TIMED OUT', $this->errorLog(),
			'the timeout must also surface in the error log');
	}

	public function testPreScriptCallSiteGatesOnExitStatus(): void
	{
		$prePos = strpos(self::$applySource, 'Executing pre-script:');
		$this->assertNotFalse($prePos, 'vacuity: the pre-script call site must exist');

		$normPos = strpos(self::$applySource, 'pfb_feed_normalize(', $prePos);
		$this->assertNotFalse($normPos, 'vacuity: the normalize step after the pre-script must exist');

		$between = substr(self::$applySource, $prePos, $normPos - $prePos);
		$this->assertStringContainsString('pfb_list_script_exec(', $between,
			'the pre-script must run through the exit-status-honouring runner');
		$this->assertStringContainsString('!== 0', $between,
			'the pre-script exit status must gate the parse — a failed transform is not feed data');
		$this->assertStringContainsString('@rename("{$file_dwn}.orig.pre", "{$file_dwn}.orig")', $between,
			'on failure the saved download must be restored over the failed script\'s leftovers');
		$this->assertStringContainsString('continue;', $between,
			'on failure the row must skip the parse, keeping the last known-good staged list');
	}

	public function testPostScriptCallSiteGatesOnExitStatus(): void
	{
		$postPos = strpos(self::$applySource, 'Executing post-script:');
		$this->assertNotFalse($postPos, 'vacuity: the post-script call site must exist');

		$chkPos = strpos(self::$applySource, 'if (!$custom) {', $postPos);
		$this->assertNotFalse($chkPos, 'vacuity: the empty-feed check after the post-script must exist');

		$between = substr(self::$applySource, $postPos, $chkPos - $postPos);
		$this->assertStringContainsString('pfb_list_script_exec(', $between,
			'the post-script must run through the exit-status-honouring runner');
		$this->assertStringContainsString('!== 0', $between,
			'the post-script exit status must be examined, not discarded');
		$this->assertStringContainsString('@rename("{$file_dwn}.orig.post", "{$file_dwn}.orig")', $between,
			'on failure the saved download must be restored before the empty-feed check reads it');
	}
}
