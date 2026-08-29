<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Script failures are observable through the retry marker and sync-status
 * ledger. PRODUCTION COMMENTS AND DOCBLOCKS MUST NEVER BE LOAD-BEARING FOR A
 * TEST. If a mechanism makes them so, the mechanism is wrong.
 */
final class ListScriptFailureLedgerWiringTest extends TestCase
{
	private const APPLY = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';

	private string $dir;

	public static function setUpBeforeClass(): void
	{
		require_once self::APPLY;
	}

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_script_state_' . getmypid() . '_' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir($this->dir, 0700, TRUE));
	}

	protected function tearDown(): void
	{
		foreach (glob("{$this->dir}/*") ?: [] as $file) {
			@unlink($file);
		}
		@rmdir($this->dir);
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

	public function testIpFailureRecordsRetryMarkerAndLedgerRow(): void
	{
		$state  = ['failed' => FALSE];
		$marker = "{$this->dir}/pfB_Example_v4.update";
		pfb_list_script_failure_record('ip', 'pfB_Example_v4', 'Pre-script FAIL', $this->dir, $marker, $state);

		$this->assertTrue($state['failed']);
		$this->assertFileExists($marker);
		$open = pfb_sync_status_list_open($this->dir, 'ip');
		$this->assertCount(1, $open);
		$this->assertSame('pfB_Example_v4', $open[0]['item']);
		$this->assertSame('script', $open[0]['stage']);
	}

	public function testDnsblFailureRecordsRetryMarkerAndLedgerRow(): void
	{
		$state  = ['failed' => FALSE];
		$marker = "{$this->dir}/DNSBL_Example.update";
		pfb_list_script_failure_record('dnsbl', 'DNSBL_Example', 'Pre-script FAIL', $this->dir, $marker, $state);

		$this->assertTrue($state['failed']);
		$this->assertFileExists($marker);
		$open = pfb_sync_status_list_open($this->dir, 'dnsbl');
		$this->assertCount(1, $open);
		$this->assertSame('DNSBL_Example', $open[0]['item']);
		$this->assertSame('script', $open[0]['stage']);
	}

	public function testMarkerWriteDoesNotTruncateExistingData(): void
	{
		$marker = "{$this->dir}/pfB_Example_v4.update";
		file_put_contents($marker, 'keep-this-marker');
		$state = ['failed' => FALSE];

		pfb_list_script_failure_record('ip', 'pfB_Example_v4', 'msg', $this->dir, $marker, $state);

		$this->assertSame('keep-this-marker', file_get_contents($marker));
	}

	public function testLedgerStillOpensWhenMarkerParentIsMissing(): void
	{
		$marker = "{$this->dir}/missing/pfB_Example_v4.update";
		$state  = ['failed' => FALSE];

		pfb_list_script_failure_record('ip', 'pfB_Example_v4', 'msg', $this->dir, $marker, $state);

		$this->assertTrue($state['failed']);
		$this->assertFileDoesNotExist($marker);
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'ip'));
	}

	public function testIndependentAliasStatesCloseOnlySuccessfulSibling(): void
	{
		$failed = ['failed' => TRUE];
		$ok     = ['failed' => FALSE];
		pfb_sync_status_open('ip', 'pfB_Failed_v4', 'script', 'failure', $this->dir);
		pfb_sync_status_open('ip', 'pfB_Ok_v4', 'script', 'success', $this->dir);

		pfb_list_script_failure_close('ip', 'pfB_Failed_v4', $this->dir, $failed);
		pfb_list_script_failure_close('ip', 'pfB_Ok_v4', $this->dir, $ok);

		$open = pfb_sync_status_list_open($this->dir, 'ip');
		$this->assertCount(1, $open);
		$this->assertSame('pfB_Failed_v4', $open[0]['item']);
	}

	public function testFailureStateIsIndependentAcrossFacilities(): void
	{
		$ipState    = ['failed' => TRUE];
		$dnsblState = ['failed' => FALSE];
		pfb_sync_status_open('ip', 'pfB_Failed_v4', 'script', 'failure', $this->dir);
		pfb_sync_status_open('dnsbl', 'DNSBL_Ok', 'script', 'success', $this->dir);

		pfb_list_script_failure_close('ip', 'pfB_Failed_v4', $this->dir, $ipState);
		pfb_list_script_failure_close('dnsbl', 'DNSBL_Ok', $this->dir, $dnsblState);

		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'ip'));
		$this->assertSame([], pfb_sync_status_list_open($this->dir, 'dnsbl'));
	}

	public function testDnsblFailureRecordsBeforeManifestAndContinuesWithCurrentStagedTxt(): void
	{
		$state  = ['failed' => FALSE];
		$marker = "{$this->dir}/DNSBL_Example.update";
		$txt    = "{$this->dir}/feed.txt";
		file_put_contents($txt, "known-good\n");
		$events = [];

		$result = pfb_dnsbl_script_failure_continue(
			'DNSBL_Example', 'Pre-script FAIL', $this->dir, $marker, $state, TRUE, $txt,
			function () use (&$events, $marker, $txt): void {
				$events[] = file_exists($marker) ? 'marker' : 'marker-missing';
				$events[] = count(pfb_sync_status_list_open(dirname($marker), 'dnsbl')) > 0
					? 'ledger' : 'ledger-missing';
				$events[] = 'manifest:' . file_get_contents($txt);
			}
		);

		$this->assertTrue($result);
		$this->assertSame(['marker', 'ledger', "manifest:known-good\n"], $events);
		$this->assertSame("known-good\n", file_get_contents($txt));
	}

	public function testDnsblFailureSkipsManifestWhenGenerationOrStagedTxtIsMissing(): void
	{
		$state  = ['failed' => FALSE];
		$marker = "{$this->dir}/DNSBL_Example.update";
		$events = [];

		$this->assertTrue(pfb_dnsbl_script_failure_continue(
			'DNSBL_Example', 'Pre-script FAIL', $this->dir, $marker, $state, FALSE,
			"{$this->dir}/missing.txt", static function () use (&$events): void { $events[] = 'manifest'; }
		));
		$this->assertSame([], $events);

		$state  = ['failed' => FALSE];
		$marker = "{$this->dir}/DNSBL_Example_2.update";
		$this->assertTrue(pfb_dnsbl_script_failure_continue(
			'DNSBL_Example_2', 'Pre-script FAIL', $this->dir, $marker, $state, TRUE,
			"{$this->dir}/missing.txt", static function () use (&$events): void { $events[] = 'manifest'; }
		));
		$this->assertSame([], $events);
	}

	public function testIpFailureLeavesPriorStagedTxtBytesUntouched(): void
	{
		$state  = ['failed' => FALSE];
		$marker = "{$this->dir}/pfB_Example_v4.update";
		$txt    = "{$this->dir}/pfB_Example_v4.txt";
		file_put_contents($txt, "192.0.2.1\n");

		$this->assertTrue(pfb_ip_script_failure_continue(
			'pfB_Example_v4', 'Pre-script FAIL', $this->dir, $marker, $state, TRUE, $txt,
			static function (): void {}
		));
		$this->assertSame("192.0.2.1\n", file_get_contents($txt));
	}

	/**
	 * #993: the apply monolith owns feed download and appliance side effects, so its loop
	 * cannot be driven safely off-appliance. Pin each live failure binding in a route scope;
	 * php_strip_whitespace() removes comments/docblocks from the source under test.
	 */
	public function testEachFamilyBindsFailureContinueAndCloseOnce(): void
	{
		$source       = php_strip_whitespace(self::APPLY);
		$dnsbl_cont   = $this->applyScope($source, 'if ($pfb_row_script_pre && is_file("{$pfb_row_script_pre}")) {', "pfb_download_ledger_close_if_clean('dnsbl',");
		$dnsbl_close  = $this->applyScope($source, "pfb_download_ledger_close_if_clean('dnsbl',", "if (\$pfb['aliasupdate']) {");
		$ip_cont      = $this->applyScope($source, 'if ($pfb_script_pre && is_file("{$pfb_script_pre}")) {', "pfb_download_ledger_close_if_clean('ip',");
		$ip_close     = $this->applyScope($source, "pfb_download_ledger_close_if_clean('ip',", 'unlink_if_exists("{$pfb[\'dbdir\']}/geoip.update");');

		$this->assertSame(1, substr_count($dnsbl_cont, 'pfb_dnsbl_script_failure_continue($alias,'), 'DNSBL failure continue must stay in its loop');
		$this->assertSame(1, substr_count($dnsbl_close, 'pfb_dnsbl_script_failure_close($alias,'), 'DNSBL failure close must stay at alias-pass end');
		$this->assertSame(1, substr_count($ip_cont, 'pfb_ip_script_failure_continue($alias,'), 'IP failure continue must stay in its loop');
		$this->assertSame(1, substr_count($ip_close, 'pfb_ip_script_failure_close($alias,'), 'IP failure close must stay at alias-pass end');

		foreach ([
			['if ($pfb_row_script_pre && is_file("{$pfb_row_script_pre}")) {', "pfb_download_ledger_close_if_clean('dnsbl',", 'pfb_dnsbl_script_failure_continue($alias,'],
			["pfb_download_ledger_close_if_clean('dnsbl',", "if (\$pfb['aliasupdate']) {", 'pfb_dnsbl_script_failure_close($alias,'],
			['if ($pfb_script_pre && is_file("{$pfb_script_pre}")) {', "pfb_download_ledger_close_if_clean('ip',", 'pfb_ip_script_failure_continue($alias,'],
			["pfb_download_ledger_close_if_clean('ip',", 'unlink_if_exists("{$pfb[\'dbdir\']}/geoip.update");', 'pfb_ip_script_failure_close($alias,'],
		] as [$start, $end, $needle]) {
			$removed = 0;
			$mutant = str_replace($needle, '', $source, $removed);
			$this->assertSame(1, $removed, "mutation fixture must remove {$needle} once");
			$endPos = strpos($mutant, $end);
			$this->assertNotFalse($endPos, "mutation fixture must retain {$end}");
			$mutant = substr_replace($mutant, $needle, $endPos + strlen($end), 0);
			$mutantScope = $this->applyScope($mutant, $start, $end);
			$this->assertSame(0, substr_count($mutantScope, $needle), "a {$needle} relocation after its loop boundary must fail the scope pin");
		}
	}

	/**
	 * issue #2059 in-suite reproduction: a per-feed POST-process script that
	 * exits non-zero must be visible in the ADR-61 ledger after the alias pass
	 * closes, in BOTH loops. Drives the REAL pfb_list_script_exec() against a
	 * genuinely failing script and feeds its real exit status to the recorder,
	 * so the fault is produced the way the appliance produces it -- not injected.
	 */
	#[DataProvider('postScriptFacilities')]
	public function testFailingPostScriptStaysVisibleAfterTheAliasPassCloses(string $facility, string $alias): void
	{
		$script = $this->postScript('fail_post.sh', 'exit 3');
		$state = ['failed' => FALSE];
		$this->assertSame([], pfb_sync_status_list_open($this->dir, $facility), 'before: the ledger has no open entry');

		// The loop's own sequence: run the post-script, hand its status over.
		$status = pfb_list_script_exec($script, 'fail_post.sh', 'post', 'foo_feed', '', '');
		$this->assertNotSame(0, $status, 'the fixture must genuinely fail -- a zero exit proves nothing');
		pfb_list_post_script_failure_record($status, $facility, $alias,
			"[ {$alias} - foo_feed ] Post-script FAIL - feed updated, side effects incomplete",
			$this->dir, $state);
		pfb_list_script_failure_close($facility, $alias, $this->dir, $state);

		$open = pfb_sync_status_list_open($this->dir, $facility);
		$this->assertCount(1, $open, 'a failed post-script must survive the alias-pass close, not read as full success');
		$this->assertSame($alias, $open[0]['item']);
		$this->assertSame('script', $open[0]['stage']);
		$this->assertStringContainsString('Post-script FAIL', $open[0]['message']);
	}

	/**
	 * The other side of the same branch, and the reason
	 * pfb_list_post_script_failure_record() owns the exit-status test (rationale
	 * on that function): a post-script that SUCCEEDS must leave the pass
	 * reading as full success.
	 */
	#[DataProvider('postScriptFacilities')]
	public function testCleanPostScriptRecordsNothingAndLeavesTheAliasPassClean(string $facility, string $alias): void
	{
		$script = $this->postScript('ok_post.sh', 'exit 0');
		$state = ['failed' => FALSE];

		$status = pfb_list_script_exec($script, 'ok_post.sh', 'post', 'foo_feed', '', '');
		$this->assertSame(0, $status, 'the fixture must genuinely succeed');
		pfb_list_post_script_failure_record($status, $facility, $alias,
			'this message must never reach the ledger', $this->dir, $state);

		$this->assertSame([], pfb_sync_status_list_open($this->dir, $facility),
			'a post-script exiting 0 must open no entry');
		$this->assertFalse($state['failed'],
			'a clean post-script must leave the alias-pass state clean, so the paired close still fires');

		pfb_list_script_failure_close($facility, $alias, $this->dir, $state);
		$this->assertSame([], pfb_sync_status_list_open($this->dir, $facility));
	}

	/**
	 * Every non-zero status class the runner can return is a failure: a plain
	 * non-zero exit, timeout(1)'s 124, and -1 for an exec() that never launched
	 * (pfblockerng.inc's #1927 contract -- a script that never ran must never
	 * read as success).
	 */
	#[DataProvider('postScriptStatuses')]
	public function testEveryNonZeroPostScriptStatusOpensAnEntry(int $status): void
	{
		$state = ['failed' => FALSE];

		pfb_list_post_script_failure_record($status, 'ip', 'pfB_Example_v4',
			"status {$status}", $this->dir, $state);

		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'ip'),
			"exit status {$status} must open a ledger entry");
		$this->assertTrue($state['failed']);
	}

	/**
	 * $pfb_script_state accumulates across an alias's rows, so a LATER row's
	 * clean post-script must not undo an earlier row's failure -- the alias
	 * pass closes once, at the end, on the accumulated state.
	 */
	public function testACleanRowDoesNotUndoAnEarlierRowsPostScriptFailure(): void
	{
		$state = ['failed' => FALSE];
		pfb_list_post_script_failure_record(3, 'ip', 'pfB_Example_v4',
			'[ pfB_Example_v4 - row_a ] Post-script FAIL', $this->dir, $state);
		// Before-state: row A genuinely marked the pass.
		$this->assertTrue($state['failed']);
		$this->assertCount(1, pfb_sync_status_list_open($this->dir, 'ip'));

		pfb_list_post_script_failure_record(0, 'ip', 'pfB_Example_v4',
			'row_b succeeded', $this->dir, $state);

		$this->assertTrue($state['failed'],
			"a clean row must leave an earlier row's failure state intact");
		pfb_list_script_failure_close('ip', 'pfB_Example_v4', $this->dir, $state);

		$open = pfb_sync_status_list_open($this->dir, 'ip');
		$this->assertCount(1, $open, "row A's entry must survive the alias-pass close");
		$this->assertStringContainsString('row_a', $open[0]['message'],
			"the surviving entry must still be row A's, not row B's message");
	}

	/** @return array<string, array{0: string, 1: string}> */
	public static function postScriptFacilities(): array
	{
		return [
			'IP loop'    => ['ip', 'pfB_Example_v4'],
			'DNSBL loop' => ['dnsbl', 'DNSBL_Example'],
		];
	}

	/** @return array<string, array{0: int}> */
	public static function postScriptStatuses(): array
	{
		return [
			'plain non-zero'      => [3],
			'timeout(1) killed'   => [124],
			'exec never launched' => [-1],
		];
	}

	private function postScript(string $name, string $body): string
	{
		$path = "{$this->dir}/{$name}";
		file_put_contents($path, "#!/bin/sh\n{$body}\n");
		$this->assertTrue(chmod($path, 0755));
		return $path;
	}

	/**
	 * issue #2059: both post-script branches must hand their exit status to the
	 * recorder. #993: the apply monolith owns feed download and appliance side
	 * effects, so its loop cannot be driven off-appliance -- pin each live
	 * binding in its own route scope; php_strip_whitespace() removes
	 * comments/docblocks from the source under test.
	 */
	public function testEachFamilyBindsPostScriptFailureRecordOnce(): void
	{
		$source      = php_strip_whitespace(self::APPLY);
		$dnsbl_start = 'if ($pfb_row_script_post && is_file("{$pfb_row_script_post}")) {';
		$dnsbl_end   = 'if (isset($csvline)) {';
		$ip_start    = 'if ($pfb_script_post && is_file("{$pfb_script_post}")) {';
		$ip_end      = '$file_chk = pfb_ip_script_probe_staged(';
		$dnsbl_post  = $this->applyScope($source, $dnsbl_start, $dnsbl_end);
		$ip_post     = $this->applyScope($source, $ip_start, $ip_end);

		$dnsbl_needle = "pfb_list_post_script_failure_record(\$pfb_post_status, 'dnsbl', \$alias,";
		$ip_needle    = "pfb_list_post_script_failure_record(\$pfb_post_status, 'ip', \$alias,";

		$this->assertSame(1, substr_count($dnsbl_post, $dnsbl_needle),
			'the DNSBL post-script branch must pass its own exit status and alias to the recorder');
		$this->assertSame(1, substr_count($ip_post, $ip_needle),
			'the IP post-script branch must pass its own exit status and alias to the recorder');

		// $pfb_script_state is what stops the alias-pass close from wiping the
		// entry the recorder just opened, and 'Post-script FAIL' is the marker an
		// operator reads in the widget -- both are load-bearing arguments.
		foreach (['dnsbl' => $dnsbl_post, 'ip' => $ip_post] as $family => $scope) {
			$this->assertSame(1, substr_count($scope, "\$pfb['dbdir'], \$pfb_script_state);"),
				"the {$family} post-script record must pass the alias-pass state");
			$this->assertSame(1, substr_count($scope, 'Post-script FAIL'),
				"the {$family} post-script record must carry the operator-facing marker");
			// The status must come from THIS branch's own run, not a stale binding.
			$this->assertSame(1, substr_count($scope, '$pfb_post_status = pfb_list_script_exec('),
				"the {$family} post-script branch must bind its status from its own exec");
		}

		// Exactly two call sites -- one post-script branch per loop. A third
		// would double-report; the pre-script sites route through
		// pfb_list_script_failure_continue() instead.
		$this->assertSame(2, substr_count($source, 'pfb_list_post_script_failure_record($pfb_post_status,'),
			'only the two post-script branches may call the post-script recorder');

		foreach ([
			[$dnsbl_start, $dnsbl_end, $dnsbl_needle],
			[$ip_start, $ip_end, $ip_needle],
		] as [$start, $end, $needle]) {
			$removed = 0;
			$mutant = str_replace($needle, '', $source, $removed);
			$this->assertSame(1, $removed, "mutation fixture must remove {$needle} once");
			$endPos = strpos($mutant, $end);
			$this->assertNotFalse($endPos, "mutation fixture must retain {$end}");
			$mutant = substr_replace($mutant, $needle, $endPos + strlen($end), 0);
			$mutantScope = $this->applyScope($mutant, $start, $end);
			$this->assertSame(0, substr_count($mutantScope, $needle),
				"a {$needle} relocation after its post-script branch must fail the scope pin");
		}
	}
}
