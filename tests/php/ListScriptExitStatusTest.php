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

	public function testSuccessfulPreScriptUsesStagedCopyAndLeavesNormalizedInput(): void
	{
		$norm   = "{$this->tmp}/feed.norm";
		$staged = "{$this->tmp}/feed.pre";
		$script = $this->makeScript('rewrite.sh', 'printf changed > "$1"');
		file_put_contents($norm, 'original');

		$result = pfb_list_pre_script_run($norm, $staged, $script, 'rewrite.sh', 'Feed', escapeshellarg($staged), '');

		$this->assertTrue($result['ok']);
		$this->assertSame($staged, $result['path']);
		$this->assertSame('original', file_get_contents($norm));
		$this->assertSame('changed', file_get_contents($staged));
	}

	public function testFailedPreScriptDiscardsStagedOutputAndKeepsNormalizedInput(): void
	{
		$norm   = "{$this->tmp}/feed.norm";
		$staged = "{$this->tmp}/feed.pre";
		$script = $this->makeScript('fail-rewrite.sh', 'printf bad > "$1"; exit 7');
		file_put_contents($norm, 'original');

		$result = pfb_list_pre_script_run($norm, $staged, $script, 'fail-rewrite.sh', 'Feed', escapeshellarg($staged), '');

		$this->assertFalse($result['ok']);
		$this->assertSame($norm, $result['path']);
		$this->assertFileDoesNotExist($staged);
		$this->assertSame('original', file_get_contents($norm));
	}

	public function testPreScriptWithMissingInputFailsWithoutProducingData(): void
	{
		$staged = "{$this->tmp}/feed.pre";
		$script = $this->makeScript('unused.sh', 'exit 0');

		$result = pfb_list_pre_script_run("{$this->tmp}/missing.norm", $staged, $script, 'unused.sh', 'Feed', escapeshellarg($staged), '');

		$this->assertFalse($result['ok']);
		$this->assertFileDoesNotExist($staged);
	}

	public function testDnsblSuccessfulPreScriptConsumesBeforeCleanup(): void
	{
		$staged = "{$this->tmp}/feed.pre";
		file_put_contents($staged, 'dnsbl-data');
		$events = [];

		$result = pfb_dnsbl_script_consume_staged($staged, $staged, function (string $path) use (&$events): string {
			$events[] = 'consume:' . file_get_contents($path);
			return 'parsed';
		});

		$this->assertSame('parsed', $result);
		$this->assertSame(['consume:dnsbl-data'], $events);
		$this->assertFileDoesNotExist($staged);
	}

	public function testIpSuccessfulPreScriptConsumesBeforeCleanup(): void
	{
		$staged = "{$this->tmp}/feed.pre";
		file_put_contents($staged, 'ip-data');
		$events = [];

		$result = pfb_ip_script_consume_staged($staged, $staged, function (string $path) use (&$events): string {
			$events[] = 'consume:' . file_get_contents($path);
			return 'probed';
		});

		$this->assertSame('probed', $result);
		$this->assertSame(['consume:ip-data'], $events);
		$this->assertFileDoesNotExist($staged);
	}

	public function testCustomIpFeedSkipsProbeButStillRemovesTheStagedCopy(): void
	{
		$staged = "{$this->tmp}/custom.pre";
		file_put_contents($staged, 'custom-data');
		$probes = 0;

		$result = pfb_ip_script_probe_staged(TRUE, $staged, $staged, static function () use (&$probes): string {
			$probes++;
			return 'unexpected';
		});

		$this->assertNull($result);
		$this->assertSame(0, $probes);
		$this->assertFileDoesNotExist($staged);
	}

	public function testDnsblKnownPrePathIsRemovedWithoutAnActiveStagedCopy(): void
	{
		$norm  = "{$this->tmp}/feed.norm";
		$known = "{$this->tmp}/feed.pre";
		file_put_contents($known, 'stale-dnsbl-data');

		$result = pfb_dnsbl_script_consume_staged(
			$norm,
			NULL,
			static fn(string $path): string => $path,
			$known
		);

		$this->assertSame($norm, $result);
		$this->assertFileDoesNotExist($known,
			'a processed DNSBL row must remove a stale known .pre path even without a pre-script stage');
	}

	public function testIpKnownPrePathIsRemovedWithoutAnActiveStagedCopy(): void
	{
		$norm  = "{$this->tmp}/feed.norm";
		$known = "{$this->tmp}/feed.pre";
		file_put_contents($known, 'stale-ip-data');

		$result = pfb_ip_script_probe_staged(
			FALSE,
			$norm,
			NULL,
			static fn(string $path): string => $path,
			$known
		);

		$this->assertSame($norm, $result);
		$this->assertFileDoesNotExist($known,
			'a processed IP row must remove a stale known .pre path even without a pre-script stage');
	}

	/**
	 * #993: sync_package_pfblockerng() is a top-level appliance orchestration path that
	 * downloads feeds and mutates firewall/service state, so it has no safe off-appliance
	 * driver. php_strip_whitespace() makes these six route pins independent of comments.
	 */
	public function testEachFeedFamilyDispatchesEveryScriptStageOnce(): void
	{
		$source      = php_strip_whitespace(self::APPLY);
		$dnsbl_pre   = $this->applyScope($source, 'if ($pfb_row_script_pre && is_file("{$pfb_row_script_pre}")) {', 'pfb_dnsbl_script_failure_continue($alias,');
		$dnsbl_loop  = 'if (($dhandle = @fopen("{$pfbfolder}/{$header}.bk", \'w\')) !== FALSE) {';
		$dnsbl_end   = 'if (!empty($domain_data)) {';
		$dnsbl_stage = $this->applyScope($source, $dnsbl_loop, $dnsbl_end);
		$dnsbl_post  = $this->applyScope($source, 'if ($pfb_row_script_post && is_file("{$pfb_row_script_post}")) {', 'if (isset($csvline)) {');
		$ip_pre      = $this->applyScope($source, 'if ($pfb_script_pre && is_file("{$pfb_script_pre}")) {', 'pfb_ip_script_failure_continue($alias,');
		$ip_stage    = $this->applyScope($source, '$file_chk = pfb_ip_script_probe_staged(', 'if (!$custom && $file_chk == 0) {');
		$ip_post     = $this->applyScope($source, 'if ($pfb_script_post && is_file("{$pfb_script_post}")) {', '$file_chk = pfb_ip_script_probe_staged(');

		$this->assertSame(1, substr_count($dnsbl_pre, 'pfb_list_pre_script_run($pfb_norm[\'path\']'), 'DNSBL pre-script dispatch must stay in its loop');
		$dnsbl_cleanup = 'pfb_list_script_cleanup_staged($pfb_parse_path, $pfb_staged_path, "{$file_dwn}.pre");';
		$this->assertSame(1, substr_count($dnsbl_stage, $dnsbl_cleanup), 'DNSBL staged input cleanup must stay in its loop');
		$this->assertStringContainsString('"{$file_dwn}.pre"', $dnsbl_stage, 'DNSBL staged seam must receive its known cleanup path');
		$this->assertSame(1, substr_count($dnsbl_post, 'pfb_list_script_exec($pfb_row_script_post, $list[\'script_post\'], \'post\''), 'DNSBL post-script dispatch must stay in its loop');
		$this->assertSame(1, substr_count($ip_pre, 'pfb_list_pre_script_run($pfb_norm[\'path\']'), 'IP pre-script dispatch must stay in its loop');
		$this->assertSame(1, substr_count($ip_stage, 'pfb_ip_script_probe_staged('), 'IP staged input must be probed once');
		$this->assertStringContainsString('"{$file_dwn}.pre"', $ip_stage, 'IP staged seam must receive its known cleanup path');
		$this->assertSame(1, substr_count($ip_post, 'pfb_list_script_exec($pfb_script_post, $list[\'script_post\'], \'post\''), 'IP post-script dispatch must stay in its loop');

		$removed = 0;
		$mutant = str_replace($dnsbl_cleanup, '', $source, $removed);
		$this->assertSame(1, $removed, 'mutation fixture must remove the DNSBL cleanup call once');
		$endPos = strpos($mutant, $dnsbl_end);
		$this->assertNotFalse($endPos, 'mutation fixture must retain the DNSBL loop end anchor');
		$mutant = substr_replace($mutant, $dnsbl_cleanup, $endPos + strlen($dnsbl_end), 0);
		$mutantScope = $this->applyScope($mutant, $dnsbl_loop, $dnsbl_end);
		$this->assertSame(0, substr_count($mutantScope, $dnsbl_cleanup), 'DNSBL cleanup relocated outside its loop must fail the route pin');
	}
}
