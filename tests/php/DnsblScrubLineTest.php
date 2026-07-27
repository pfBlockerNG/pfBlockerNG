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
}
