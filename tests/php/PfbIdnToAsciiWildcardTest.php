<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_idn_to_ascii_wildcard() — the one punycode converter for domain rows that
 * may carry pfBlockerNG's leading-dot wildcard marker (issue #1740).
 *
 * idn_to_ascii() rejects a leading dot outright, so every caller used to carry
 * its own strip/convert/re-prefix dance — or, worse, none at all. The contract:
 * exactly one leading dot is stripped and re-prefixed on success, and a failed
 * conversion is reported as '' rather than idn_to_ascii()'s FALSE.
 */
#[CoversFunction('pfb_idn_to_ascii_wildcard')]
final class PfbIdnToAsciiWildcardTest extends TestCase
{
	public function testBareIdnHostConvertsToPunycode(): void
	{
		$this->assertSame('xn--bcher-kva.de', pfb_idn_to_ascii_wildcard('bücher.de'));
	}

	public function testWildcardIdnHostKeepsItsSingleLeadingDot(): void
	{
		$this->assertSame('.xn--bcher-kva.de', pfb_idn_to_ascii_wildcard('.bücher.de'));
	}

	public function testDoubleLeadingDotIsNotCollapsedToAWildcard(): void
	{
		// Only one dot comes off, so idn_to_ascii() still sees a leading dot and
		// rejects the host — '..bücher.de' must never become '.xn--bcher-kva.de'.
		$this->assertSame('', pfb_idn_to_ascii_wildcard('..bücher.de'));
	}

	public function testAsciiHostPassesThroughUnchanged(): void
	{
		$this->assertSame('example.com', pfb_idn_to_ascii_wildcard('example.com'));
		$this->assertSame('.example.com', pfb_idn_to_ascii_wildcard('.example.com'));
	}

	public function testUnconvertibleHostReportsEmptyString(): void
	{
		// A bare dot has no label to convert; the caller's `=== ''` check is the
		// documented failure signal, so FALSE must never leak out.
		$this->assertSame('', pfb_idn_to_ascii_wildcard('.'));
		$this->assertSame('', pfb_idn_to_ascii_wildcard(''));
	}

	public function testWhitespaceOnlyRemainderReportsEmptyString(): void
	{
		// '.' followed by whitespace leaves no label either — idn_to_ascii()
		// raises on an empty domain, so the remainder is trimmed before the
		// emptiness check rather than handed over as-is.
		$this->assertSame('', pfb_idn_to_ascii_wildcard(".\t  "));
		$this->assertSame('', pfb_idn_to_ascii_wildcard('   '));
	}

	public function testPaddingIsHandedOnUntouchedSoValidationStaysFailClosed(): void
	{
		// The converter must not launder a padded domain: pfb_filter() rejects
		// the space on its charset check, and it can only do that if the space
		// is still there.
		$this->assertSame('.xn--bcher-kva.de ', pfb_idn_to_ascii_wildcard('.bücher.de '));
		$this->assertSame('', pfb_filter('.bücher.de ', PFB_FILTER_DOMAIN, 'test'));
	}

	public function testOverlongLabelIsRejected(): void
	{
		// idn_to_ascii() enforces the 63-char label limit; the wildcard marker
		// must not smuggle an invalid host past it.
		$long = str_repeat('a', 64);
		$this->assertSame('', pfb_idn_to_ascii_wildcard(".{$long}.de"));
	}
}
