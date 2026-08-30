<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Wiring test for pfb_mime_normalise() at L1042 of pfb_filter() — proves the
 * normalise call is actually wired into the PFB_FILTER_FILE_MIME gate.
 *
 * Scenario: EPUB file whose file(1) MIME type is application/epub+zip.
 * The allow-list contains application/zip but NOT application/epub+zip.
 * Without the normalise call at L1042 the raw type fails the allow-list →
 * pfb_filter() returns FALSE. With it, the stripos('zip') catch-all maps
 * epub+zip → application/zip → allow-listed → pfb_filter() returns 'application/zip'.
 *
 * The EPUB fixture is a real zip whose first member is "mimetype" stored
 * uncompressed (the EPUB Open Container spec §3.3 requirement that file(1) uses
 * to identify EPUBs). Embedded as base64 for hermeticity — no shell dependency
 * in the test path itself.
 *
 * Guard: if this host's file(1) cannot detect EPUBs, the test is skipped
 * (markTestSkipped) so CI on boxes with an older magic database does not fail
 * instead of the real wiring.
 */
#[CoversFunction('pfb_filter')]
final class PfbFileMimeNormaliseWiringTest extends TestCase
{
	// Minimal valid EPUB: zip with "mimetype" stored/uncompressed as first member.
	// Generated with: printf 'application/epub+zip' > mimetype;
	//   zip -X -0 -q book.epub mimetype;
	//   zip -X -q book.epub META-INF/container.xml
	// Verified: /usr/bin/file -b --mime-type book.epub == application/epub+zip
	private const EPUB_B64 = 'UEsDBAoAAAAAAPt+21xvYassFAAAABQAAAAIAAAAbWltZXR5cGVhcHBsaWNh'
		. 'dGlvbi9lcHViK3ppcFBLAwQKAAAAAAD7fttckVPT0iEAAAAhAAAAFgAAAE1FVEEtSU5GL2Nv'
		. 'bnRhaW5lci54bWw8P3htbCB2ZXJzaW9uPSIxLjAiPz48Y29udGFpbmVyLz5QSwECHgMKAA'
		. 'AAAAD7fttcb2GrLBQAAAAUAAAACAAAAAAAAAAAAAAApIEAAAAAbWltZXR5cGVQSwECHgMKAAAA'
		. 'AAD7fttckVPT0iEAAAAhAAAAFgAAAAAAAAABAAAApIE6AAAATUVUQS1JTkYvY29udGFpbmVy'
		. 'LnhtbFBLBQYAAAAAAgACAHoAAACPAAAAAAA=';

	private string $dir;
	private string $cwd;
	private string $epubPath;

	/** @var array<string,mixed> saved $GLOBALS['pfb'] keys (sentinel FALSE = was unset) */
	private array $saved = [];

	protected function setUp(): void
	{
		$this->dir      = sys_get_temp_dir() . '/pfb_mime_wiring_' . uniqid('', TRUE);
		mkdir($this->dir);
		$this->cwd      = (string) getcwd();
		$this->epubPath = $this->dir . '/book.epub';

		file_put_contents($this->epubPath, base64_decode(self::EPUB_B64, TRUE));

		$this->saved['mime_types'] = array_key_exists('mime_types', $GLOBALS['pfb'] ?? [])
			? $GLOBALS['pfb']['mime_types']
			: FALSE;

		// Only the wiring test's allow-list: application/zip is present,
		// application/epub+zip is deliberately absent.
		$GLOBALS['pfb']['mime_types'] = ['application/zip' => 1];
	}

	protected function tearDown(): void
	{
		chdir($this->cwd);
		@unlink($this->epubPath);
		@rmdir($this->dir);
		foreach ($this->saved as $k => $prev) {
			if ($prev === FALSE) {
				unset($GLOBALS['pfb'][$k]);
			} else {
				$GLOBALS['pfb'][$k] = $prev;
			}
		}
	}

	/**
	 * Scenario: EPUB whose file(1) type contains "zip"
	 * Given  an EPUB file that file(1) identifies as application/epub+zip
	 *        and an allow-list containing application/zip but not epub+zip
	 * When   pfb_filter() runs the FILE_MIME gate (which calls pfb_mime_normalise
	 *        at L1042 before the allow-list lookup)
	 * Then   the catch-all normalises epub+zip → application/zip, which is
	 *        allow-listed, so pfb_filter() returns 'application/zip'
	 *        — proving the normalise call at L1042 is wired into the gate.
	 *        Without L1042 the raw type fails the allow-list → returns FALSE.
	 */
	public function test_epub_zip_passes_via_normalise_wiring(): void
	{
		// Guard: verify host file(1) can detect this EPUB as application/epub+zip.
		// If not, skip gracefully — the test relies on a live file(1) call.
		$probe = [];
		exec('/usr/bin/file -b --mime-type ' . escapeshellarg($this->epubPath), $probe);
		if (($probe[0] ?? '') !== 'application/epub+zip') {
			$this->markTestSkipped(
				'host file(1) returned ' . ($probe[0] ?? '(empty)') . ' for the EPUB fixture; '
				. 'expected application/epub+zip — skipping wiring test on this host'
			);
		}

		// Given: EPUB on disk, allow-list has application/zip (not epub+zip).
		// The pfb_filter() $input array: [0]=path (legacy unused), [1]=path, [2]=URL.
		$result = pfb_filter(
			["'unused'", $this->epubPath, 'http://feed.example/'],
			PFB_FILTER_FILE_MIME,
			'test'
		);

		// Then: normalise wired at L1042 maps epub+zip → application/zip → allowed.
		$this->assertSame('application/zip', $result,
			'Expected application/zip after epub+zip normalisation; '
			. 'if FALSE, pfb_mime_normalise() is not wired into pfb_filter()'
		);
	}
}
