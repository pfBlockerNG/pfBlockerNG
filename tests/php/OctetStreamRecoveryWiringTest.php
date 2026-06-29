<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Live wiring test for the octet-stream recovery path in pfb_filter() (ADR-45 Phase 3).
 *
 * Modelled on PfbFileMimeNormaliseWiringTest — uses real file(1) and real decompressor
 * calls on the host.
 *
 * Two branches tested:
 *
 *  1. VALID-octet-stream-archive (the Top1M-shaped live case):
 *     A valid ZIP with 8 junk bytes prepended.  file(1) sees non-ZIP magic at offset 0
 *     and returns application/octet-stream.  bsdtar (libarchive) searches backward from
 *     the end of the file for the EOCD record and applies the SFX-offset correction, so
 *     `tar -tf` exits 0.  pfb_filter() must return 'application/zip' (recovered).
 *     Before Phase 3 the same input returned FALSE — the red baseline.
 *
 *  2. JUNK-octet-stream (random binary blob — not any valid archive):
 *     All structural probes fail.  pfb_filter() must return FALSE.
 *     Pins ADR §7: application/octet-stream is NEVER blanket-accepted; only
 *     positively-identified archives are recovered.
 *
 * Each test is guarded: if the host's file(1) does not return application/octet-stream
 * for the fixture, markTestSkipped (the host magic database classified it differently —
 * not a wiring failure; CI on another host may exercise it).
 */
#[CoversFunction('pfb_filter')]
final class OctetStreamRecoveryWiringTest extends TestCase
{
	private string $dir;
	private string $cwd;
	private string $junkPrefixedZip;
	private string $junkBlob;

	protected function setUp(): void
	{
		$this->dir             = sys_get_temp_dir() . '/pfb_octet_wiring_' . uniqid('', TRUE);
		mkdir($this->dir);
		$this->cwd             = (string) getcwd();
		$this->junkPrefixedZip = $this->dir . '/junk_prefixed.zip';
		$this->junkBlob        = $this->dir . '/junk_blob.bin';

		// Build a valid minimal ZIP (one entry: test.txt → "hello"), then prepend
		// 8 NUL/control bytes so file(1) no longer sees ZIP magic at offset 0.
		// bsdtar (libarchive) uses backward EOCD scanning + SFX-offset correction,
		// so `tar -tf <junk_prefixed.zip>` still exits 0.
		$tmpZip = $this->dir . '/clean.zip';
		$zip    = new ZipArchive();
		$zip->open($tmpZip, ZipArchive::CREATE);
		$zip->addFromString('test.txt', 'hello');
		$zip->close();
		$rawZip = (string) file_get_contents($tmpZip);
		// 8 NUL+low-control bytes: not printable, not any known magic → octet-stream.
		file_put_contents($this->junkPrefixedZip, "\x00\x01\x02\x03\x04\x05\x06\x07" . $rawZip);
		unlink($tmpZip);

		// Structured binary blob with NUL bytes — reliably classified as application/octet-stream
		// by file(1) on both macOS and Linux; not a ZIP/gzip/bzip2/7z.
		file_put_contents($this->junkBlob, str_repeat("\x00\x01\x02\x03", 256));

		// Allow-list: application/zip present; application/octet-stream absent (it is
		// never added to the allow-list — recovery is the only admittance path).
		$GLOBALS['pfb']['mime_types'] = ['application/zip' => 1];
	}

	protected function tearDown(): void
	{
		chdir($this->cwd);
		// junkBlob may already be gone (pfb_filter unlinks on rejection) — suppress.
		@unlink($this->junkPrefixedZip);
		@unlink($this->junkBlob);
		@rmdir($this->dir);
		unset($GLOBALS['pfb']['mime_types']);
	}

	/**
	 * Scenario: valid archive mislabelled as octet-stream is recovered (Top1M-shaped case)
	 * Given  a valid ZIP with junk bytes prepended
	 *        and file(1) reporting application/octet-stream for it
	 *        and an allow-list containing application/zip but not application/octet-stream
	 * When   pfb_filter() runs the FILE_MIME gate
	 * Then   pfb_octet_recover_type() probes each supported type in order (zip first);
	 *        pfb_validate_archive() confirms it is a ZIP via `tar -tf`;
	 *        pfb_filter() returns 'application/zip'.
	 *        Before Phase 3 the same input returned FALSE.
	 */
	public function test_octet_stream_archive_recovered_to_zip(): void
	{
		// Guard: host file(1) must see this as application/octet-stream.
		$probe    = [];
		exec('/usr/bin/file -b --mime-type ' . escapeshellarg($this->junkPrefixedZip), $probe);
		$detected = $probe[0] ?? '';
		if ($detected !== 'application/octet-stream') {
			$this->markTestSkipped(
				'host file(1) returned "' . $detected . '" for the junk-prefixed ZIP fixture; '
				. 'expected "application/octet-stream" — skipping wiring test on this host '
				. '(the host magic database classified it differently)'
			);
		}

		// Recovery adopts application/zip only if the structural probe (tar -tf) can list the
		// junk-prefixed ZIP — which needs bsdtar (the FreeBSD target). On a host whose /usr/bin/tar
		// is GNU tar (cannot read ZIP), the recovery is untestable — skip rather than fail.
		$tarout = [];
		exec('/usr/bin/tar -tf ' . escapeshellarg($this->junkPrefixedZip) . ' >/dev/null 2>&1', $tarout, $tarrv);
		if ($tarrv !== 0) {
			$this->markTestSkipped(
				'/usr/bin/tar on this host cannot read the junk-prefixed ZIP (GNU tar, not bsdtar); '
				. 'octet-stream->zip recovery is untestable here — skipping'
			);
		}

		$result = pfb_filter(
			["'unused'", $this->junkPrefixedZip, 'http://feed.example/top-1m.csv.zip'],
			PFB_FILTER_FILE_MIME,
			'test'
		);

		$this->assertSame('application/zip', $result,
			'Expected "application/zip" after octet-stream recovery via structural probe; '
			. 'got: ' . var_export($result, TRUE) . '. '
			. 'If FALSE: pfb_octet_recover_type() is not wired into pfb_filter(), '
			. 'or tar -tf could not list the junk-prefixed ZIP on this host.'
		);
	}

	/**
	 * Scenario: random binary blob (not a valid archive) is still rejected
	 * Given  a structured binary blob with no archive magic
	 *        and file(1) reporting application/octet-stream for it
	 *        and an allow-list that does not contain application/octet-stream
	 * When   pfb_filter() runs the FILE_MIME gate
	 * Then   all structural probes fail (no valid archive signature found);
	 *        pfb_filter() returns FALSE — octet-stream is NEVER blanket-accepted (ADR §7).
	 */
	public function test_junk_octet_stream_still_rejected(): void
	{
		// Guard: host file(1) must see this as application/octet-stream.
		$probe    = [];
		exec('/usr/bin/file -b --mime-type ' . escapeshellarg($this->junkBlob), $probe);
		$detected = $probe[0] ?? '';
		if ($detected !== 'application/octet-stream') {
			$this->markTestSkipped(
				'host file(1) returned "' . $detected . '" for the junk-blob fixture; '
				. 'expected "application/octet-stream" — skipping wiring test on this host'
			);
		}

		$result = pfb_filter(
			["'unused'", $this->junkBlob, 'http://feed.example/data.bin'],
			PFB_FILTER_FILE_MIME,
			'test'
		);

		// pfb_filter() unlinks the blob on rejection — tearDown uses @unlink.
		$this->assertFalse($result,
			'Expected FALSE (no archive probe passes for junk blob — positive-id only); '
			. 'got: ' . var_export($result, TRUE) . '. '
			. 'If non-false: octet-stream was blanket-accepted — ADR §7 violation.'
		);
	}
}
