<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class ListScriptExitStatusTest extends TestCase
{
	private const APPLY = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';

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
		$this->tmp = sys_get_temp_dir() . '/pfb_script_exit_' . getmypid() . '_' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir($this->tmp, 0700, TRUE));
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
		foreach (glob("{$this->tmp}/*") ?: [] as $file) {
			@unlink($file);
		}
		@rmdir($this->tmp);
	}

	private function makeScript(string $name, string $body): string
	{
		$path = "{$this->tmp}/{$name}";
		file_put_contents($path, "#!/bin/sh\n{$body}\n");
		chmod($path, 0755);
		return $path;
	}

	private function log(string $name): string
	{
		return (string) @file_get_contents("{$this->tmp}/{$name}");
	}

	private function applyScope(string $source, string $start, string $end): string
	{
		$from = strrpos($source, $start);
		if ($from === FALSE) {
			throw new RuntimeException("missing apply scope start: {$start}");
		}
		$to = strpos($source, $end, $from + strlen($start));
		if ($to === FALSE) {
			throw new RuntimeException("missing apply scope end: {$end}");
		}
		return substr($source, $from, $to + strlen($end) - $from);
	}

	public function testZeroExitIsReturnedWithoutFailureLog(): void
	{
		$script = $this->makeScript('ok.sh', 'exit 0');

		$this->assertSame(0, pfb_list_script_exec($script, 'ok.sh', 'pre', 'Feed', '', ''));
		$this->assertStringNotContainsString('exited non-zero', $this->log('pfblockerng.log'));
	}

	public function testNonZeroExitIsReturnedAndNamesStageScriptAndFeed(): void
	{
		$script = $this->makeScript('fail.sh', 'exit 7');

		$this->assertSame(7, pfb_list_script_exec($script, 'fail.sh', 'pre', 'Feed', '', ''));
		$log = $this->log('pfblockerng.log');
		$this->assertStringContainsString("pre-script 'fail.sh'", $log);
		$this->assertStringContainsString('Feed', $log);
		$this->assertStringContainsString('[ 7 ]', $log);
		$this->assertStringContainsString('exited non-zero', $this->log('error.log'));
	}

	public function testExit124IsReportedAsTimeout(): void
	{
		$script = $this->makeScript('slow.sh', 'exit 124');

		$this->assertSame(124, pfb_list_script_exec($script, 'slow.sh', 'post', 'Feed', '', ''));
		$this->assertStringContainsString('TIMED OUT', $this->log('pfblockerng.log'));
		$this->assertStringContainsString('TIMED OUT', $this->log('error.log'));
	}

	/**
	 * #993: sync_package_pfblockerng() is a top-level appliance orchestration path that
	 * downloads feeds and mutates firewall/service state, so it has no safe off-appliance
	 * driver. php_strip_whitespace() makes these route pins independent of comments. The pre-script runs in Core's
	 * feed phase since #3977 (go/pfb_core/feedparse TestPreScriptCorpus); the post-script stays here.
	 */
	public function testEachFeedFamilyDispatchesItsPostScriptOnce(): void
	{
		$source     = php_strip_whitespace(self::APPLY);
		$dnsbl_post = $this->applyScope($source, 'if ($pfb_row_script_post && is_file("{$pfb_row_script_post}")) {', 'if ($feed_result[\'dnsblRows\'] > 0) {');
		$ip_post    = $this->applyScope($source, 'if ($pfb_script_post && is_file("{$pfb_script_post}")) {', 'if ($has_data && !pfb_core_feed_artifact_copy(');

		$this->assertSame(1, substr_count($dnsbl_post, 'pfb_list_script_exec($pfb_row_script_post, $list[\'script_post\'], \'post\''), 'DNSBL post-script dispatch must stay in its loop');
		$this->assertSame(1, substr_count($ip_post, 'pfb_list_script_exec($pfb_script_post, $list[\'script_post\'], \'post\''), 'IP post-script dispatch must stay in its loop');
		$this->assertSame(2, substr_count($source, 'pfb_list_script_exec('), 'only the two post-script sites run a list script');
	}
}
