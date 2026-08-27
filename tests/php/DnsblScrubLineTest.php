<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Contract for the per-line scrub the DNSBL feed parse loop applies to every
 * row read from the normalized feed file (issue #1797). The scrub owns
 * line-END hygiene only; whole-file concerns (mid-line controls, Unicode
 * whitespace) are the normalize stage's job.
 */
#[CoversFunction('pfb_dnsbl_scrub_line')]
final class DnsblScrubLineTest extends TestCase
{
	public function testPlainRowTrimsAsciiWhitespaceAtBothEnds(): void
	{
		$this->assertSame('example.com', pfb_dnsbl_scrub_line("  example.com \n"));
	}

	public function testTrailingCrlfIsRemoved(): void
	{
		$this->assertSame('example.com', pfb_dnsbl_scrub_line("example.com\r\n"));
	}

	public function testTabSeparatedHostsRowKeepsInteriorTab(): void
	{
		// hosts-format rows use tab as the separator; only the ENDS are trimmed.
		$this->assertSame("127.0.0.1\tads.example.com", pfb_dnsbl_scrub_line("\t127.0.0.1\tads.example.com\t\n"));
	}

	public function testEmptyAndWhitespaceOnlyRowsScrubToEmpty(): void
	{
		$this->assertSame('', pfb_dnsbl_scrub_line(''));
		$this->assertSame('', pfb_dnsbl_scrub_line(" \t\n"));
	}

	public function testInteriorUnicodeTextSurvives(): void
	{
		$this->assertSame('bücher.example', pfb_dnsbl_scrub_line("bücher.example\n"));
	}

	public function testMidLineCrIsRemovedNotJustAtLineEnds(): void
	{
		// issue #1797: a lone CR is a line separator to nothing -- fgets() hands
		// the loop one row containing an embedded CR, and an ends-only trim
		// leaves it inside what is then treated as a single feed entry.
		$this->assertSame('ads.example.comevil', pfb_dnsbl_scrub_line("ads.example.com\revil\n"));
	}

	public function testScrubNeverCreatesInvalidUtf8(): void
	{
		// issue #1797: a byte-wise trim charlist containing "\xC2\xA0" strips
		// those BYTES individually, slicing the final byte off an unrelated
		// multi-byte character (U+0EA0 = E0 BA A0) and CREATING invalid UTF-8.
		$in  = "bad\xE0\xBA\xA0";
		$out = pfb_dnsbl_scrub_line($in);
		$this->assertTrue(mb_check_encoding($out, 'UTF-8'),
			'scrub output must stay valid UTF-8, got bytes: ' . bin2hex($out));
		$this->assertSame($in, $out, 'a well-formed trailing multi-byte character must survive the scrub');
	}

	public function testTrailingNbspIsLineDataAtThisSeam(): void
	{
		// issue #1797: Unicode whitespace hygiene (trailing NBSP and friends)
		// belongs to the whole-file normalize stage; the per-line scrub is
		// ASCII-only so it can never slice a multi-byte sequence.
		$this->assertSame("x\xC2\xA0", pfb_dnsbl_scrub_line("x\xC2\xA0\n"));
	}
}
