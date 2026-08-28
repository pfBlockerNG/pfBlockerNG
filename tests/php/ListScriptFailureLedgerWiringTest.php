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
	 * genuinely failing script, then the real alias-pass close, so the fault is
	 * produced the way the appliance produces it -- not injected.
	 */
	#[DataProvider('postScriptFacilities')]
	public function testFailingPostScriptStaysVisibleAfterTheAliasPassCloses(string $facility, string $alias): void
	{
		$script = "{$this->dir}/fail_post.sh";
		file_put_contents($script, "#!/bin/sh\nexit 3\n");
		$this->assertTrue(chmod($script, 0755));
		$state = ['failed' => FALSE];
		$this->assertSame([], pfb_sync_status_list_open($this->dir, $facility), 'before: the ledger has no open entry');

		// The loop's own sequence: run the post-script, honour its exit status.
		$rc = pfb_list_script_exec($script, 'fail_post.sh', 'post', 'foo_feed', '', '');
		$this->assertNotSame(0, $rc, 'the fixture must genuinely fail -- a zero exit proves nothing');
		pfb_list_script_failure_record($facility, $alias,
			"[ {$alias} - foo_feed ] Post-script FAIL - feed updated, side effects incomplete",
			$this->dir, NULL, $state);
		pfb_list_script_failure_close($facility, $alias, $this->dir, $state);

		$open = pfb_sync_status_list_open($this->dir, $facility);
		$this->assertCount(1, $open, 'a failed post-script must survive the alias-pass close, not read as full success');
		$this->assertSame($alias, $open[0]['item']);
		$this->assertSame('script', $open[0]['stage']);
		$this->assertStringContainsString('Post-script FAIL', $open[0]['message']);
	}

	/** @return array<string, array{0: string, 1: string}> */
	public static function postScriptFacilities(): array
	{
		return [
			'IP loop'    => ['ip', 'pfB_Example_v4'],
			'DNSBL loop' => ['dnsbl', 'DNSBL_Example'],
		];
	}

	/**
	 * issue #2059: both post-script branches must bind the recorder. #993: the
	 * apply monolith owns feed download and appliance side effects, so its loop
	 * cannot be driven off-appliance -- pin each live binding in its own route
	 * scope; php_strip_whitespace() removes comments/docblocks from the source.
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

		$this->assertSame(1, substr_count($dnsbl_post, "pfb_list_script_failure_record('dnsbl', \$alias,"),
			'the DNSBL post-script branch must record against its own alias');
		$this->assertSame(1, substr_count($ip_post, "pfb_list_script_failure_record('ip', \$alias,"),
			'the IP post-script branch must record against its own alias');

		// The trailing arguments are load-bearing: NULL suppresses a retry-marker
		// write both loops would unlink further down the same iteration, and
		// $pfb_script_state is what stops the alias-pass close wiping the entry.
		foreach (['dnsbl' => $dnsbl_post, 'ip' => $ip_post] as $family => $scope) {
			$this->assertSame(1, substr_count($scope, "\$pfb['dbdir'], NULL, \$pfb_script_state);"),
				"the {$family} post-script record must pass no retry marker and the alias-pass state");
		}

		// Exactly two literal-facility call sites -- one post-script branch per
		// loop. A third would double-report; the pre-script sites route through
		// pfb_list_script_failure_continue() instead, which takes $facility.
		$this->assertSame(2, substr_count($source, "pfb_list_script_failure_record('"),
			'only the two post-script branches may call the recorder with a literal facility');

		foreach ([
			[$dnsbl_start, $dnsbl_end, "pfb_list_script_failure_record('dnsbl', \$alias,"],
			[$ip_start, $ip_end, "pfb_list_script_failure_record('ip', \$alias,"],
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
