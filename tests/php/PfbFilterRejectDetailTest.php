<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_filter() FILE_MIME / FILE_MIME_COMPRESSED reject -- the out-param contract
 * (ADR-48 Phase 2, §2 fork resolution option (a)). An opted-in caller (pre-sets
 * $reject_detail = array()) gets the raw mime/retval detail back and pfb_filter()
 * SUPPRESSES its own legacy message -- the caller emits pfb_validate_log() instead,
 * since it has the feed header + true stage in scope and pfb_filter() does not. A
 * caller that does NOT opt in (the plain call every un-migrated site still uses)
 * keeps the exact legacy message unchanged -- no rejection may ever lose its log
 * entry.
 *
 * Fixture: a real on-disk PDF ("%PDF-1.4\n") -- file(1) reliably reports
 * application/pdf for it (verified empirically: a bare PNG/EXE magic alone reads as
 * application/octet-stream on this host's libmagic, which would instead exercise the
 * octet-stream structural-probe recovery branch -- not the plain allow-list reject
 * this test targets). application/pdf is outside the tests' single-entry allow-list
 * (text/plain), so the reject path fires deterministically, without hitting the
 * hostname exceptions (text/x-asm, ipinfo.io octet-stream) either.
 */
#[CoversFunction('pfb_filter')]
final class PfbFilterRejectDetailTest extends TestCase
{
	private string $dir;
	private string $cwd;
	private string $pdfPath;

	/** @var array<string,mixed> saved $GLOBALS['pfb'] keys (sentinel FALSE = was unset) */
	private array $saved = [];

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_reject_detail_' . uniqid('', TRUE);
		mkdir($this->dir);
		$this->cwd     = (string) getcwd();
		$this->pdfPath = $this->dir . '/reject.pdf';
		file_put_contents($this->pdfPath, "%PDF-1.4\n");

		foreach (['log', 'errlog', 'mime_types', 'runlog', 'runlog_active'] as $k) {
			$this->saved[$k] = array_key_exists($k, $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb'][$k] : false;
		}
		// A stray 'runlog_active' from an earlier test must not mirror our writes
		// into a third file this test never provisions.
		unset($GLOBALS['pfb']['runlog'], $GLOBALS['pfb']['runlog_active']);
		// Only text/plain is allow-listed -- application/pdf always fails the gate.
		$GLOBALS['pfb']['mime_types'] = ['text/plain' => 1];
	}

	protected function tearDown(): void
	{
		chdir($this->cwd);
		@unlink($this->pdfPath);
		@rmdir($this->dir);
		foreach ($this->saved as $k => $prev) {
			if ($prev === false) {
				unset($GLOBALS['pfb'][$k]);
			} else {
				$GLOBALS['pfb'][$k] = $prev;
			}
		}
	}

	private function tempLog(): string
	{
		$path = tempnam(sys_get_temp_dir(), 'pfb_reject_detail_log_');
		$this->assertNotFalse($path, 'could not create temp log file');
		return $path;
	}

	// --- PFB_FILTER_FILE_MIME ----------------------------------------------

	/**
	 * Scenario: an un-migrated caller (5-arg call, no out-param)
	 * Given  a PDF whose mime is outside the allow-list
	 * When   FILE_MIME validates it via the plain (non-opted-in) call shape
	 * Then   pfb_filter() rejects it AND still writes its own legacy message
	 *        -- the back-compat regression pin for every caller that never
	 *        migrates to the out-param.
	 */
	public function testNonOptedCallerKeepsLegacyMessage(): void
	{
		$log = $this->tempLog();
		$GLOBALS['pfb']['log'] = $log;
		$this->assertSame('', file_get_contents($log), 'sink must start empty');

		$result = pfb_filter(["'unused'", $this->pdfPath, 'http://feed.example/'], PFB_FILTER_FILE_MIME, 'test');

		$this->assertFalse($result);
		$logged = (string) file_get_contents($log);
		$this->assertStringContainsString(
			'Failed or invalid Mime Type: [application/pdf|0]',
			$logged,
			"expected legacy reject message in <{$logged}>"
		);
		unlink($log);
	}

	/**
	 * Scenario: an opted-in caller (pre-sets $reject_detail = array())
	 * Given  the SAME PDF fixture and allow-list as the non-opted case above
	 * When   FILE_MIME validates it with the out-param bound
	 * Then   pfb_filter() still rejects it, fills the out-param with the raw
	 *        mime/retval detail, and SUPPRESSES its own legacy message -- proving
	 *        the suppression is a real branch (the sibling test above shows the
	 *        SAME reject DOES log when not opted in), not an always-silent path.
	 */
	public function testOptedInCallerSuppressesLegacyMessageAndFillsDetail(): void
	{
		$log = $this->tempLog();
		$GLOBALS['pfb']['log'] = $log;
		$this->assertSame('', file_get_contents($log), 'sink must start empty');

		$detail = array();
		$result = pfb_filter(
			["'unused'", $this->pdfPath, 'http://feed.example/'],
			PFB_FILTER_FILE_MIME,
			'test',
			'',
			FALSE,
			$detail
		);

		$this->assertFalse($result);
		$this->assertSame('application/pdf', $detail['mime_raw'] ?? null, 'mime_raw must carry the raw file(1) output');
		$this->assertSame('application/pdf', $detail['mime'] ?? null, 'mime must carry the (normalised) mime');
		$this->assertSame(0, $detail['retval'] ?? null, 'retval must carry the file(1) exit code');

		$logged = (string) file_get_contents($log);
		$this->assertSame('', $logged, "expected NO legacy message once opted in, got <{$logged}>");
		unlink($log);
	}

	// --- PFB_FILTER_FILE_MIME_COMPRESSED ------------------------------------

	private function skipIfHostLacksDashZSemantics(): void
	{
		$probe = [];
		exec('/usr/bin/file -bZ --mime-type ' . escapeshellarg($this->pdfPath), $probe, $rc);
		if ($rc !== 0 || ($probe[0] ?? '') !== 'application/pdf') {
			$this->markTestSkipped(
				'host file(1) -bZ returned ' . ($probe[0] ?? '(empty)') . ' for the PDF fixture; '
				. 'expected application/pdf -- skipping COMPRESSED wiring test on this host'
			);
		}
	}

	/**
	 * Scenario: an un-migrated caller, FILE_MIME_COMPRESSED
	 * Same back-compat pin as testNonOptedCallerKeepsLegacyMessage, for the
	 * `file -bZ` (compressed) branch.
	 */
	public function testCompressedNonOptedCallerKeepsLegacyMessage(): void
	{
		$this->skipIfHostLacksDashZSemantics();

		$log = $this->tempLog();
		$GLOBALS['pfb']['log'] = $log;
		$this->assertSame('', file_get_contents($log), 'sink must start empty');

		$result = pfb_filter(["'unused'", $this->pdfPath, 'http://feed.example/'], PFB_FILTER_FILE_MIME_COMPRESSED, 'test');

		$this->assertFalse($result);
		$logged = (string) file_get_contents($log);
		$this->assertStringContainsString(
			'Failed or invalid Mime Type Compressed: [application/pdf|0]',
			$logged,
			"expected legacy compressed reject message in <{$logged}>"
		);
		unlink($log);
	}

	/**
	 * Scenario: an opted-in caller, FILE_MIME_COMPRESSED
	 * Same out-param + suppression pin as testOptedInCallerSuppressesLegacyMessageAndFillsDetail,
	 * for the `file -bZ` (compressed) branch.
	 */
	public function testCompressedOptedInCallerSuppressesLegacyMessageAndFillsDetail(): void
	{
		$this->skipIfHostLacksDashZSemantics();

		$log = $this->tempLog();
		$GLOBALS['pfb']['log'] = $log;
		$this->assertSame('', file_get_contents($log), 'sink must start empty');

		$detail = array();
		$result = pfb_filter(
			["'unused'", $this->pdfPath, 'http://feed.example/'],
			PFB_FILTER_FILE_MIME_COMPRESSED,
			'test',
			'',
			FALSE,
			$detail
		);

		$this->assertFalse($result);
		$this->assertSame('application/pdf', $detail['mime_raw'] ?? null, 'mime_raw must carry the raw file(1) -bZ output');
		$this->assertSame('application/pdf', $detail['mime'] ?? null, 'mime must carry the same (no normalisation on this branch)');
		$this->assertSame(0, $detail['retval'] ?? null, 'retval must carry the file(1) exit code');

		$logged = (string) file_get_contents($log);
		$this->assertSame('', $logged, "expected NO legacy compressed message once opted in, got <{$logged}>");
		unlink($log);
	}
}
