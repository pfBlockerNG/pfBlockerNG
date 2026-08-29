<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1925: pfb_list_pre_script_run() stages a COPY of the normalized feed
 * for the per-feed pre-script — the script rewrites the copy in place; the
 * normalized source ('.norm', and by extension '.orig') is never touched.
 *
 * Honours the #1927 exit-status contract via pfb_list_script_exec(): a copy
 * failure, a non-zero exit, or the script deleting its staged input all
 * return 'ok' FALSE (with the staged file removed where it exists), leaving
 * the caller to keep its last known-good staged list.
 */
#[CoversFunction('pfb_list_pre_script_run')]
final class ListPreScriptStageTest extends TestCase
{
	private string $tmp;
	/** @var array<string, mixed> */
	private array $originalPfb;
	private bool $hadPfb;

	protected function setUp(): void
	{
		$this->tmp = sys_get_temp_dir() . '/pfb_lpss_' . getmypid() . '_' . bin2hex(random_bytes(4));
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
		// A test may leave a 0555 dir behind (copy-failure case) -- restore write
		// perms so the house cleanup helper can remove it.
		foreach (glob("{$this->tmp}/*", GLOB_ONLYDIR) ?: [] as $d) {
			@chmod($d, 0755);
		}
		rmdir_recursive($this->tmp);
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

	public function testSuccessfulRewriteStagesTheCopyAndLeavesTheSourceUntouched(): void
	{
		$norm = "{$this->tmp}/feed.norm";
		file_put_contents($norm, "original\n");
		$staged = "{$this->tmp}/feed.pre";
		$script = $this->makeScript('ip_pre_rewrite.sh', 'printf \'transformed\\n\' > "$1"');

		$result = pfb_list_pre_script_run($norm, $staged, $script, 'ip_pre_rewrite.sh', 'MyFeed_v4',
		    escapeshellarg($staged), '');

		$this->assertTrue($result['ok'], 'a rewriting script must be honoured');
		$this->assertSame($staged, $result['path']);
		$this->assertSame("transformed\n", file_get_contents($staged),
			'the staged copy must carry the script\'s rewrite');
		$this->assertSame("original\n", file_get_contents($norm),
			'the normalized source must stay byte-identical -- the script only ever sees the copy');
		$this->assertNotSame(file_get_contents($norm), file_get_contents($staged),
			'the script must have seen the normalized copy, not produced the source verbatim');
	}

	public function testIdentityScriptStagesContentByteIdenticalToTheNormalizedSource(): void
	{
		$norm = "{$this->tmp}/feed.norm";
		file_put_contents($norm, "1.2.3.4\n5.6.7.8\n");
		$staged = "{$this->tmp}/feed.pre";
		$script = $this->makeScript('ip_pre_noop.sh', 'exit 0');

		$result = pfb_list_pre_script_run($norm, $staged, $script, 'ip_pre_noop.sh', 'MyFeed_v4',
		    escapeshellarg($staged), '');

		$this->assertTrue($result['ok']);
		$this->assertSame($staged, $result['path']);
		$this->assertSame(file_get_contents($norm), file_get_contents($staged),
			'a no-op script must leave the staged copy identical to the normalized source it received');
	}

	public function testNonZeroExitFailsRemovesTheStagedCopyAndLogs(): void
	{
		$norm = "{$this->tmp}/feed.norm";
		file_put_contents($norm, "1.2.3.4\n");
		$staged = "{$this->tmp}/feed.pre";
		$script = $this->makeScript('ip_pre_fail.sh', 'exit 7');

		$result = pfb_list_pre_script_run($norm, $staged, $script, 'ip_pre_fail.sh', 'MyFeed_v4',
		    escapeshellarg($staged), '');

		$this->assertFalse($result['ok'], 'a non-zero exit must fail the stage');
		$this->assertFileDoesNotExist($staged, 'the staged copy must be removed on failure');
		$log = $this->mainLog();
		$this->assertStringContainsString("ip_pre_fail.sh", $log, 'the failure must name the script');
		$this->assertStringContainsString('MyFeed_v4', $log, 'the failure must name the feed');
	}

	public function testScriptDeletingItsStagedInputFailsAndLogs(): void
	{
		$norm = "{$this->tmp}/feed.norm";
		file_put_contents($norm, "1.2.3.4\n");
		$staged = "{$this->tmp}/feed.pre";
		$script = $this->makeScript('ip_pre_delete.sh', 'rm -f "$1"');

		$result = pfb_list_pre_script_run($norm, $staged, $script, 'ip_pre_delete.sh', 'MyFeed_v4',
		    escapeshellarg($staged), '');

		$this->assertFalse($result['ok'], 'a script that deletes its input must not be treated as success');
		$this->assertFileDoesNotExist($staged);
		$log = $this->mainLog();
		$this->assertStringContainsString('ip_pre_delete.sh', $log, 'the failure must name the script');
		$this->assertStringContainsString('MyFeed_v4', $log, 'the failure must name the feed');
	}

	public function testCopyFailureFailsAndKeepsTheNormalizedPath(): void
	{
		if (function_exists('posix_getuid') && posix_getuid() === 0) {
			$this->markTestSkipped('root bypasses directory permissions; cannot simulate an unwritable staging dir');
		}

		$norm = "{$this->tmp}/feed.norm";
		file_put_contents($norm, "1.2.3.4\n");
		$deniedDir = "{$this->tmp}/denied";
		mkdir($deniedDir, 0755, TRUE);
		chmod($deniedDir, 0555);
		$staged = "{$deniedDir}/feed.pre";
		$script = $this->makeScript('ip_pre_unreached.sh', 'exit 0');

		$result = pfb_list_pre_script_run($norm, $staged, $script, 'ip_pre_unreached.sh', 'MyFeed_v4',
		    escapeshellarg($staged), '');

		$this->assertFalse($result['ok'], 'a copy failure must fail the stage');
		$this->assertSame($norm, $result['path'],
			'on copy failure the caller keeps the normalized path -- there is no staged copy');
		$log = $this->mainLog();
		$this->assertStringContainsString('ip_pre_unreached.sh', $log,
			'the copy failure must be logged, naming the script');
		$this->assertStringContainsString('MyFeed_v4', $log, 'the copy failure must be logged, naming the feed');
	}
}
