<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Entry URL-vetting rejection visibility (issue #811). When pfb_filter()
 * rejects a feed URL at an entry gate, the reason-bearing line lands in
 * error.log ONLY (pfb_filter's own logtype-6 call) and the fetch-time gate
 * that WOULD log a header-scoped "[ header ] <reason> -- skipped" line to the
 * main log is statically unreachable (the caller returns before any download).
 * #811's shared helper pfb_log_feed_host_reject() re-runs the SAME guard
 * (pfb_feed_host_allowed) at every entry-reject site -- pfb_download()'s entry
 * branch AND pfb_update_check()'s upstream reject (pfblockerng.php, the site
 * the update flow actually hits; the live #811 fixup) -- landing the line in
 * the MAIN log iff the guard is why vetting failed.
 *
 * pfb_download() as a whole is not off-appliance unit-testable (curl/exec),
 * but its entry early-return path needs neither, so it is exercised directly.
 * pfb_update_check() lives in a www script the harness cannot load -- its call
 * site is covered by the helper-direct tests plus the live smoke test
 * (test_feed_internal_filter_blocks_then_allowlist_exempts).
 *
 * Scenario: an internal-resolving feed host rejected at entry vetting becomes
 * ALSO visible in the main log, header-scoped and reason-bearing -- but only
 * when the guard itself is why entry vetting failed.
 *   Background:
 *     Given the feed-host filter is enabled (default ON) and the allowlist is empty
 *     And the resolver is driven by $GLOBALS['pfb_test_resolve_map']
 */
#[CoversFunction('pfb_log_feed_host_reject')]
#[CoversFunction('pfb_download')]
#[CoversFunction('pfb_feed_host_allowed')]
#[CoversFunction('pfb_feed_filter_enabled')]
final class PfbDownloadEntryVettingSkipLogTest extends TestCase
{
	/** @var string[] temp files to remove in tearDown */
	private array $tmpfiles = [];

	/** @var array<string,mixed> saved $GLOBALS['pfb'] keys (sentinel FALSE = was unset) */
	private array $saved = [];

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_resolve_map'] = [];
		$GLOBALS['pfb_test_configured_ips'] = [];
		foreach (['log', 'errlog', 'pnow', 'runlog', 'runlog_active'] as $k) {
			$this->saved[$k] = array_key_exists($k, $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb'][$k] : false;
		}
		// A stray 'runlog_active' from an earlier test must not mirror our writes
		// into a third file this test never provisions.
		unset($GLOBALS['pfb']['runlog'], $GLOBALS['pfb']['runlog_active']);
	}

	protected function tearDown(): void
	{
		unset($GLOBALS['config'], $GLOBALS['pfb_test_resolve_map'], $GLOBALS['pfb_test_configured_ips']);
		foreach ($this->saved as $k => $prev) {
			if ($prev === false) {
				unset($GLOBALS['pfb'][$k]);
			} else {
				$GLOBALS['pfb'][$k] = $prev;
			}
		}
		foreach ($this->tmpfiles as $f) {
			if (is_file($f)) {
				$this->assertTrue(unlink($f), "failed to remove temp file {$f}");
			}
		}
		$this->tmpfiles = [];
	}

	private function tempFile(string $prefix): string
	{
		$path = tempnam(sys_get_temp_dir(), $prefix);
		$this->assertNotFalse($path, "could not create temp file for {$prefix}");
		$this->tmpfiles[] = $path;
		return $path;
	}

	/**
	 * Entry vetting rejects an internal-resolving feed host -- the guard's OWN
	 * verdict is the reason pfb_filter() failed. The MAIN log now carries
	 * "[ header ] <reason> -- skipped" in addition to the pre-existing bare
	 * "\n Failed" -- proving the new line, not merely that something failed
	 * (pre-#811 code never wrote this line to the main log).
	 */
	public function testInternalHostRejectionLogsHeaderScopedSkipLineToMainLog(): void
	{
		// Given a host that resolves to a non-public, non-allowlisted address.
		$GLOBALS['pfb_test_resolve_map']['internal.entry.vet.'] = [
			['type' => 'A', 'data' => '10.20.30.40'],
		];
		$log = $this->tempFile('pfb_download_entry_log_');
		$GLOBALS['pfb']['log'] = $log;
		$GLOBALS['pfb']['errlog'] = $this->tempFile('pfb_download_entry_errlog_');

		// When pfb_download() is called on that URL (a plain remote format, so
		// entry vetting takes the PFB_FILTER_URL elseif branch).
		$response_meta = null;
		$result = pfb_download(
			'https://internal.entry.vet/list.txt',
			'/tmp/pfb_entry_vet_test',
			FALSE,
			'entryvettest',
			'',
			2,
			'',
			300,
			'',
			'',
			'',
			FALSE,
			$response_meta
		);

		// Then the download is refused ...
		$this->assertFalse($result, 'pfb_download must refuse a URL rejected at entry vetting');

		// ... and the MAIN log carries the header-scoped, reason-bearing skip
		// line (issue #811), alongside the pre-existing bare failure line.
		$logged = (string) file_get_contents($log);
		$this->assertStringContainsString(
			"[ entryvettest ] feed host resolves to a non-permitted address \xe2\x80\x94 skipped",
			$logged,
			"expected the header-scoped skip line in the main log, got <{$logged}>"
		);
		$this->assertStringContainsString(
			'Failed',
			$logged,
			'the pre-existing bare failure line must stay untouched'
		);
	}

	/**
	 * Entry vetting rejects the URL for an UNRELATED reason (a disallowed URL
	 * scheme) while the host itself resolves to a PUBLIC address the guard
	 * would allow: the guard-specific skip line must NOT appear -- proving the
	 * new logging is scoped to the guard's OWN verdict, not "pfb_filter
	 * rejected for any reason".
	 */
	public function testEntryRejectionForOtherReasonWithPublicHostLogsNoSkipLine(): void
	{
		// Given a host that resolves to a public address.
		$GLOBALS['pfb_test_resolve_map']['public.entry.vet.'] = [
			['type' => 'A', 'data' => '203.0.113.20'],
		];
		$log = $this->tempFile('pfb_download_entry_log_');
		$GLOBALS['pfb']['log'] = $log;
		$GLOBALS['pfb']['errlog'] = $this->tempFile('pfb_download_entry_errlog_');

		// When pfb_download() is called with a disallowed scheme (gopher) --
		// pfb_filter() rejects on the scheme check, before ever consulting the
		// feed-host guard for its own verdict.
		$response_meta = null;
		$result = pfb_download(
			'gopher://public.entry.vet/list.txt',
			'/tmp/pfb_entry_vet_test2',
			FALSE,
			'entryvettest2',
			'',
			2,
			'',
			300,
			'',
			'',
			'',
			FALSE,
			$response_meta
		);

		// Then the download is refused ...
		$this->assertFalse($result, 'pfb_download must refuse an invalid-scheme URL');

		// ... but the main log carries NO guard skip line -- the guard itself
		// would have allowed this host, so #811's re-check must not fire.
		$logged = (string) file_get_contents($log);
		$this->assertStringNotContainsString(
			'skipped',
			$logged,
			"expected NO guard skip line for a public host rejected on an unrelated ground, got <{$logged}>"
		);
		$this->assertStringContainsString(
			'Failed',
			$logged,
			'the pre-existing bare failure line must still fire'
		);
	}

	/**
	 * Helper-direct (the #811 live fixup): pfb_log_feed_host_reject() is what
	 * every entry-reject site calls -- including pfb_update_check() in the www
	 * script the harness cannot load. An internal-resolving URL logs the exact
	 * header-scoped, reason-bearing line at the caller's logtype.
	 */
	public function testHelperLogsHeaderScopedSkipLineForInternalHost(): void
	{
		// Given a host that resolves to a non-public, non-allowlisted address.
		$GLOBALS['pfb_test_resolve_map']['internal.helper.vet.'] = [
			['type' => 'A', 'data' => '10.20.30.41'],
		];
		$log = $this->tempFile('pfb_helper_log_');
		$GLOBALS['pfb']['log'] = $log;
		$GLOBALS['pfb']['errlog'] = $this->tempFile('pfb_helper_errlog_');

		// When the helper runs at logtype 1 (pfb_update_check's logtype).
		pfb_log_feed_host_reject('http://internal.helper.vet/list.txt', 'helpervettest', 1);

		// Then the main log carries the exact header-scoped skip line.
		$logged = (string) file_get_contents($log);
		$this->assertStringContainsString(
			"[ helpervettest ] feed host resolves to a non-permitted address \xe2\x80\x94 skipped",
			$logged,
			"expected the header-scoped skip line in the main log, got <{$logged}>"
		);
	}

	/**
	 * Helper-direct negative: a URL whose host the guard ALLOWS (public) logs
	 * nothing -- the helper reports the guard's own verdict, never a blanket
	 * "vetting failed" message.
	 */
	public function testHelperLogsNothingForPublicHost(): void
	{
		// Given a host that resolves to a public address.
		$GLOBALS['pfb_test_resolve_map']['public.helper.vet.'] = [
			['type' => 'A', 'data' => '203.0.113.21'],
		];
		$log = $this->tempFile('pfb_helper_log_');
		$GLOBALS['pfb']['log'] = $log;

		// When the helper runs.
		pfb_log_feed_host_reject('http://public.helper.vet/list.txt', 'helpervettest2', 1);

		// Then nothing is logged.
		$this->assertSame(
			'',
			(string) file_get_contents($log),
			'a guard-allowed host must log no skip line'
		);
	}

	/**
	 * Helper-direct negative: with the feed-host filter toggled OFF the helper
	 * is a no-op even for an internal-resolving host -- the guard is opt-out,
	 * and the skip line must follow the same toggle as the gates it mirrors.
	 */
	public function testHelperLogsNothingWhenFilterDisabled(): void
	{
		// Given an internal-resolving host but the filter toggled OFF.
		$GLOBALS['pfb_test_resolve_map']['internal.helper.off.'] = [
			['type' => 'A', 'data' => '10.20.30.42'],
		];
		config_set_path('installedpackages/pfblockerng/config/0/pfb_feed_internal_filter', 'off');
		$log = $this->tempFile('pfb_helper_log_');
		$GLOBALS['pfb']['log'] = $log;

		// When the helper runs.
		pfb_log_feed_host_reject('http://internal.helper.off/list.txt', 'helpervettest3', 1);

		// Then nothing is logged (filter off => no guard, no line).
		$this->assertSame(
			'',
			(string) file_get_contents($log),
			'the skip line must not fire with the feed-host filter disabled'
		);
	}
}
