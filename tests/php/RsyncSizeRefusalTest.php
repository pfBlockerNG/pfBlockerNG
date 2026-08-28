<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #2667 — the rsync feed path had no size bound at either half of ingest.
 *
 * #2658 capped the fetched body (CURLOPT_MAXFILESIZE_LARGE) and the extracted
 * output (ulimit -f); neither reaches the rsync branch, which writes the fetched
 * body straight to {file}.raw. These tests drive the REAL pfb_download() rsync
 * branch against a local source file with the ceiling lowered through
 * $pfb['rsync_max_bytes'] — the same test seam #2658 used for the cURL ceiling
 * via $pfb['curl_defaults'] — so a handful of kilobytes is "over-large".
 * The source path reaches the branch through $pfb['dbdir'], which PFB_FILTER_URL's
 * local-path arm already honours, and the feed-host filter is switched off
 * through its documented General-settings opt-out (a filesystem path has no
 * host for the resolve+pin guard to vet).
 *
 * Two enforcement halves, one named refusal:
 *  - the kernel half runs rsync under pfb_extract_cmd()'s ulimit -f at TWICE the
 *    ceiling — rsync writes through an atomic temp file and renames only on a
 *    clean exit, so a body over the ceiling must still land whole for the check
 *    below to name it; the backstop bounds what can hit disk even beyond that
 *    (its kill surfaces as rsync's own nonzero exit — probed: openrsync prints
 *    "File too large", GNU rsync's Linux status differs per build, never asserted);
 *  - the size check half names the refusal deterministically on every platform:
 *    a body that lands whole but over the ceiling is refused, removed, and logged
 *    stage=size reason=rsync_too_large.
 */
#[CoversFunction('pfb_download')]
final class RsyncSizeRefusalTest extends TestCase
{
	/** Ceiling used for the refusal tests only — far below the fixture body. */
	private const OVER_CEILING_BYTES = 4 * 1024;

	/** Fixture source size: over OVER_CEILING_BYTES, under every shipped ceiling. */
	private const SOURCE_BYTES = 8 * 1024;

	private string $workdir = '';

	/** @var array<string,mixed> saved $GLOBALS['pfb'] keys (sentinel FALSE = was unset) */
	private array $saved = [];

	/** @var array<string,mixed> saved fixture globals (absent key = was unset) */
	private array $savedGlobals = [];

	protected function setUp(): void
	{
		if (!is_executable('/usr/local/bin/rsync')) {
			$this->markTestSkipped('/usr/local/bin/rsync not available on this host');
		}
		$workdir = tempnam(sys_get_temp_dir(), 'pfbrsz');
		$this->assertNotFalse($workdir);
		$this->assertTrue(unlink($workdir) && mkdir($workdir, 0700));
		$this->workdir = $workdir;

		foreach (['config'] as $g) {
			if (array_key_exists($g, $GLOBALS)) {
				$this->savedGlobals[$g] = $GLOBALS[$g];
			}
		}
		$GLOBALS['config'] = [];
		// Documented opt-out for the resolve+pin guard (General settings
		// 'pfb_feed_internal_filter'); a local rsync source has no host to vet.
		config_set_path('installedpackages/pfblockerng/config/0/pfb_feed_internal_filter', 'off');

		foreach (['log', 'errlog', 'pnow', 'runlog', 'runlog_active', 'dbdir', 'rsync_max_bytes', 'mime_types'] as $k) {
			$this->saved[$k] = array_key_exists($k, $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb'][$k] : FALSE;
		}
		unset($GLOBALS['pfb']['runlog'], $GLOBALS['pfb']['runlog_active']);
		$GLOBALS['pfb']['log']    = "{$workdir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$workdir}/error.log";
		$GLOBALS['pfb']['pnow']   = 'now';
		// PFB_FILTER_URL's local-path arm accepts sources under $pfb['dbdir'].
		$GLOBALS['pfb']['dbdir']  = $workdir;
		// The MIME gate on the ingested body reads $pfb['mime_types']; restore the
		// shipped allow-list (bootstrap snapshot) so this fixture is order-independent.
		$GLOBALS['pfb']['mime_types'] = $GLOBALS['pfb_shipped_mime_types'] ?? [];

		file_put_contents("{$workdir}/source.txt", str_repeat('A', self::SOURCE_BYTES));
	}

	protected function tearDown(): void
	{
		foreach ($this->saved as $k => $prev) {
			if ($prev === FALSE) {
				unset($GLOBALS['pfb'][$k]);
			} else {
				$GLOBALS['pfb'][$k] = $prev;
			}
		}
		foreach ($this->savedGlobals as $g => $prev) {
			$GLOBALS[$g] = $prev;
		}
		$this->savedGlobals = [];
		if ($this->workdir !== '' && is_dir($this->workdir)) {
			foreach ((array) glob("{$this->workdir}/*") as $f) {
				@unlink((string) $f);
			}
			rmdir($this->workdir);
		}
	}

	private function logText(): string
	{
		return (string) @file_get_contents((string) $GLOBALS['pfb']['log']);
	}

	private function fetch(string $header): PfbDownloadResult
	{
		return pfb_download(new PfbDownloadRequest(
			listUrl: "{$this->workdir}/source.txt",
			downloadPath: "{$this->workdir}/feed",
			flex: FALSE,
			header: $header,
			format: 'rsync',
			logType: 1,
			versionType: '',
			timeout: 30,
			type: '',
			username: '',
			password: '',
			sourceInterface: FALSE,
			extraHeaders: array(),
		));
	}

	/**
	 * Scenario: an rsync body over the ceiling is refused and named.
	 *
	 * Given a local rsync source of 8 KiB against a 4 KiB ceiling (the kernel
	 *   backstop at twice the ceiling lets it land whole for the named check)
	 * When pfb_download() fetches it with format 'rsync'
	 * Then the download fails, no body survives on disk, and the log carries the
	 *   distinguishable stage=size reason=rsync_too_large refusal — not just a
	 *   bare exit code.
	 */
	public function test_rsync_body_over_the_ceiling_is_refused_with_a_named_reason(): void
	{
		$GLOBALS['pfb']['rsync_max_bytes'] = self::OVER_CEILING_BYTES;

		$result = $this->fetch('RsyncOversize');

		$this->assertFalse($result->success, 'an over-large rsync body must not download successfully');
		$this->assertFileDoesNotExist("{$this->workdir}/feed.raw",
			'the over-large body must not be left on disk');
		$this->assertStringContainsString('stage=size reason=rsync_too_large', $this->logText(),
			'the refusal must be logged distinguishably, not as a generic rsync failure');
	}

	/**
	 * Scenario: an rsync body under the ceiling is untouched.
	 *
	 * Given the same 8 KiB source with the ceiling above it
	 * When pfb_download() fetches it
	 * Then the transfer succeeds and the whole body is published downstream —
	 *   proving the refusal above is a real branch, not an always-reject path.
	 */
	public function test_rsync_body_under_the_ceiling_still_downloads(): void
	{
		$GLOBALS['pfb']['rsync_max_bytes'] = 1024 * 1024;

		$result = $this->fetch('RsyncUnderCeiling');

		$this->assertTrue($result->success, 'a body under the ceiling must still download');
		$this->assertStringNotContainsString('reason=rsync_too_large', $this->logText());
		// A successful text ingest renames {file}.raw to {file}.orig (finalise may
		// append a trailing newline); the whole body must be in what survives.
		$size = @filesize("{$this->workdir}/feed.orig");
		$this->assertNotFalse($size, 'the published body must survive as feed.orig');
		$this->assertGreaterThanOrEqual(self::SOURCE_BYTES, $size, 'the whole body must arrive intact');
	}

	/**
	 * Scenario: the rsync fetch runs under the kernel write ceiling.
	 *
	 * Given a ceiling so far below the source that even the twice-ceiling kernel
	 *   backstop kills the writer mid-transfer (portable across rsync
	 *   implementations -- probed on openrsync and GNU rsync 3.4.1, both exit
	 *   nonzero once the write hits the limit)
	 * When pfb_download() fetches it
	 * Then the download fails through the rsync-exit gate, before the post-fetch
	 *   size check ever sees a body: the kernel half carries the refusal on its
	 *   own, so no implementation difference can let a body through that the
	 *   ceiling was set to refuse. rsync's own exit code and wording are never
	 *   asserted (implementation-specific); only pfBlockerNG's own log line is.
	 */
	public function test_rsync_fetch_under_a_kernel_tiny_ceiling_never_succeeds(): void
	{
		$GLOBALS['pfb']['rsync_max_bytes'] = 512;

		$result = $this->fetch('RsyncKernelCapped');

		$this->assertFalse($result->success,
			'a writer killed by the file-size ceiling must never read as a successful fetch');
		$log = $this->logText();
		$this->assertStringContainsString('RSYNC Failed', $log,
			'the kernel bound must stop the transfer itself, surfacing as a failed rsync exit');
		$this->assertStringNotContainsString('reason=rsync_too_large', $log,
			'the post-fetch size check must not be what saves this case -- that would leave '
			. 'the kernel bound untested, so a body over the ceiling could land whole on disk');
	}
}
