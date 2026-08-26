<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_text_sanity() UTF-16 handling — issue #946.
 *
 * Before this change, a UTF-16/UTF-32-BOM-prefixed sample is scanned byte-for-byte:
 * every ASCII character of a real feed is interleaved with a NUL byte, so the very
 * first check ('nul_bytes') fires on perfectly legitimate text. pfb_text_sanity()
 * now decodes a BOM-marked sample to UTF-8 (via pfb_utf16_sample_to_utf8()) as its
 * FIRST statement, before the existing UTF-8-BOM strip and the 'nul_bytes' check --
 * so a genuine UTF-16 feed is scanned as text, while BOM-less binary still trips
 * 'nul_bytes' exactly as before (see PfbTextSanityTest.php, left untouched).
 */
#[CoversFunction('pfb_text_sanity')]
final class PfbTextSanityUtf16Test extends TestCase
{
	/**
	 * THE FIX. A UTF-16LE-encoded valid hosts-style feed must be judged sane (NULL),
	 * not 'nul_bytes'.
	 *
	 * RED on today's code: pfb_text_sanity() has no UTF-16 awareness, so the sample's
	 * interleaved \x00 bytes trip the 'nul_bytes' check first -- this assertion fails
	 * (actual 'nul_bytes') until pfb_utf16_sample_to_utf8() is wired in as the first
	 * statement.
	 */
	public function test_utf16le_encoded_valid_feed_is_sane(): void
	{
		$text = "0.0.0.0 ads.example.org\n0.0.0.0 tracker.example.net\n";
		$sample = "\xFF\xFE" . mb_convert_encoding($text, 'UTF-16LE', 'UTF-8');

		$this->assertNull(pfb_text_sanity($sample));
	}

	/** Same fix, opposite byte order. */
	public function test_utf16be_encoded_valid_feed_is_sane(): void
	{
		$text = "0.0.0.0 ads.example.org\n0.0.0.0 tracker.example.net\n";
		$sample = "\xFE\xFF" . mb_convert_encoding($text, 'UTF-16BE', 'UTF-8');

		$this->assertNull(pfb_text_sanity($sample));
	}

	/**
	 * Proves the scan genuinely runs on DECODED text, not merely skips a BOM-marked
	 * sample: a UTF-16LE-encoded HTML error page (no blocklist-shaped line anywhere)
	 * must still be flagged 'html_error_page' -- if the decode were a no-op/bypass,
	 * this sample would instead trip 'nul_bytes' (its interleaved NULs), not the HTML
	 * check downstream of the decode.
	 */
	public function test_utf16le_encoded_html_error_page_is_flagged(): void
	{
		$text = "<!doctype html>\n<html><body><h1>404 Not Found</h1></body></html>\n";
		$sample = "\xFF\xFE" . mb_convert_encoding($text, 'UTF-16LE', 'UTF-8');

		$this->assertSame('html_error_page', pfb_text_sanity($sample));
	}

	/**
	 * Unchanged behaviour: BOM-less binary with interleaved NULs (not a UTF-16/32 BOM)
	 * is still 'nul_bytes' -- pfb_utf16_sample_to_utf8() is a no-op for it.
	 */
	public function test_bom_less_binary_with_nuls_is_still_nul_bytes(): void
	{
		$sample = "garbage\x00\x01\x02binary";

		$this->assertSame('nul_bytes', pfb_text_sanity($sample));
	}

	/**
	 * Unchanged behaviour: a plain UTF-8 sample (no BOM at all) is judged exactly as
	 * before -- pfb_utf16_sample_to_utf8() must be a true no-op on non-BOM-marked text.
	 */
	public function test_plain_utf8_sample_is_unaffected(): void
	{
		$sample = "0.0.0.0 ads.example.org\n0.0.0.0 tracker.example.net\n";

		$this->assertNull(pfb_text_sanity($sample));
	}
}
