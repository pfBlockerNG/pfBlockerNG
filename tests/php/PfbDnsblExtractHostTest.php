<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_dnsbl_extract_host() -- issue #1119 (folded into #1117) extraction of the DNSBL
 * download/parse loop's `if (!$lite)` host-munging branch into a pure, unit-testable
 * helper. Pins the pipeline's load-bearing ORDER (scheme strip -> '/'/'#'/'?' truncation
 * -> ';'-truncation -> trailing-port strip -> IPv6-unbracket LAST -- issue #938) and the
 * FALSE-propagation contract when pfb_dnsbl_scheme_line() rejects a strict-mode URL path.
 */
#[CoversFunction('pfb_dnsbl_extract_host')]
final class PfbDnsblExtractHostTest extends TestCase
{
	private string $parseErr = '';

	protected function setUp(): void
	{
		$this->parseErr = tempnam(sys_get_temp_dir(), 'pfbextracthost');
		@unlink($this->parseErr);
	}

	protected function tearDown(): void
	{
		if ($this->parseErr !== '' && is_file($this->parseErr)) {
			unlink($this->parseErr);
		}
	}

	private function extract(string $line, bool $strict, int &$skipped = 0): string|false
	{
		$skipped = 0;
		return pfb_dnsbl_extract_host($line, $strict, 'hdr', $line, 5, $this->parseErr, $skipped);
	}

	// -- scheme strip -----------------------------------------------------------------

	public function testSchemeStripLenientPermitsAnySchemeShape(): void
	{
		// Lenient (strict=FALSE) strips through the first '://' unconditionally, even a
		// non-RFC-3986 leading-digit scheme.
		$this->assertSame('d.com', $this->extract('http://d.com/path', FALSE));
		$this->assertSame('d.com', $this->extract('123://d.com', FALSE));
	}

	public function testSchemeStripStrictAcceptsRfc3986SchemeWithNoPath(): void
	{
		$this->assertSame('d.com', $this->extract('https://d.com', TRUE));
	}

	public function testSchemeStripStrictRejectsNonRfc3986SchemeAndRecordsSideEffects(): void
	{
		// Given: a leading-digit scheme, invalid under RFC 3986.
		$skipped = 0;
		$result  = $this->extract('123://d.com', TRUE, $skipped);

		// Then: the helper returns FALSE and the by-ref parse-error/skip-counter sinks
		// are updated -- the caller's `continue` depends on this contract.
		$this->assertFalse($result, 'a non-RFC-3986 scheme must be rejected in strict mode');
		$this->assertSame(1, $skipped, 'the per-feed skip counter must be incremented');
		$this->assertStringContainsString(
			'123://d.com',
			(string) file_get_contents($this->parseErr),
			'the rejected line must be recorded in the parse-error log'
		);
	}

	public function testSchemeStripStrictRejectsUrlPathAndRecordsSideEffects(): void
	{
		// A URL path survives past the scheme check itself (valid scheme) but is
		// rejected by pfb_dnsbl_strip_scheme()'s strict path-detection.
		$skipped = 0;
		$result  = $this->extract('http://d.com/path', TRUE, $skipped);

		$this->assertFalse($result, 'a URL path must be rejected in strict mode');
		$this->assertSame(1, $skipped);
		$this->assertStringContainsString('http://d.com/path', (string) file_get_contents($this->parseErr));
	}

	// -- '/', '#', '?' truncation (both modes -- scheme-less lines are strict-invariant) --

	public function testSlashTruncation(): void
	{
		$this->assertSame('d.com', $this->extract('d.com/a/b', FALSE));
		$this->assertSame('d.com', $this->extract('d.com/a/b', TRUE));
	}

	public function testHashTruncation(): void
	{
		$this->assertSame('d.com', $this->extract('d.com#frag', FALSE));
		$this->assertSame('d.com', $this->extract('d.com#frag', TRUE));
	}

	public function testQuestionMarkTruncation(): void
	{
		$this->assertSame('d.com', $this->extract('d.com?q=1', FALSE));
		$this->assertSame('d.com', $this->extract('d.com?q=1', TRUE));
	}

	// -- ';' strstr-only truncation (issue #1237: the parse_url host-pick branch was
	// dropped -- every ';' line now takes the plain strstr-before-';' path) -----------------

	public function testSemicolonWithoutParseUrlHostFallsBackToStrstr(): void
	{
		// parse_url('d.com;jsessionid=x') has no scheme/authority marker, so it never
		// set 'host' even under the old code -- this shape was already strstr-only.
		$this->assertSame('d.com', $this->extract('d.com;jsessionid=x', FALSE));
		$this->assertSame('d.com', $this->extract('d.com;jsessionid=x', TRUE));
	}

	public function testSemicolonParamWithPortLikeSuffixIsTruncatedNotParsed(): void
	{
		// issue #1237: 'host;param:digits' used to hit parse_url()'s isset('host') branch,
		// which mis-parsed the ';param' remainder AS the authority -- e.g.
		// 'd.com;jsessionid=1:80' resolved to 'd.com;jsessionid=1' (still containing ';',
		// so pfb_filter() drops the whole line downstream). Plain strstr-before-';' now
		// yields the clean domain instead.
		$this->assertSame('d.com', $this->extract('d.com;jsessionid=1:80', FALSE));
		$this->assertSame('d.com', $this->extract('d.com;jsessionid=1:80', TRUE));
	}

	public function testSemicolonParamWithPortLikeSuffixShorterLabels(): void
	{
		$this->assertSame('evilhost', $this->extract('evilhost;x:99', FALSE));
		$this->assertSame('evilhost', $this->extract('evilhost;x:99', TRUE));
		$this->assertSame('a', $this->extract('a;b:2', FALSE));
		$this->assertSame('a', $this->extract('a;b:2', TRUE));
	}

	public function testSemicolonSlashCombinationsUnaffectedByTruncationOrder(): void
	{
		// '/' truncation (an earlier pipeline step) already empties or shortens these
		// before the ';' step ever runs -- must stay unchanged by this fix.
		$this->assertSame('', $this->extract('//d.com;jsessionid=x', FALSE));
		$this->assertSame('', $this->extract('//d.com;jsessionid=x', TRUE));
		$this->assertSame('d.com', $this->extract('d.com;jsessionid=1/extra', FALSE));
		$this->assertSame('d.com', $this->extract('d.com;jsessionid=1/extra', TRUE));
	}

	public function testSemicolonEdgeShapesTrailingAndLeading(): void
	{
		$this->assertSame('d.com', $this->extract('d.com;', FALSE));
		$this->assertSame('d.com', $this->extract('d.com;', TRUE));
		// Leading ';' truncates to an empty STRING, never FALSE (FALSE is reserved for
		// the strict scheme-reject contract).
		$this->assertSame('', $this->extract(';x', FALSE));
		$this->assertSame('', $this->extract(';x', TRUE));
	}

	public function testBracketedIpv6WithSemicolonUnaffectedByThisStep(): void
	{
		// parse_url() never sets 'host' for a bracketed-v6-plus-';' shape (only 'path'),
		// so the isset branch was already dead here -- confirms the v6 axis is untouched.
		$this->assertSame('2604:2dc0::', $this->extract('[2604:2dc0::];x', FALSE));
		$this->assertSame('2604:2dc0::', $this->extract('[2604:2dc0::];x', TRUE));
	}

	// -- trailing port (IPv6-safe) -------------------------------------------------------

	public function testTrailingPortIsStripped(): void
	{
		$this->assertSame('d.com', $this->extract('d.com:8080', FALSE));
		$this->assertSame('d.com', $this->extract('d.com:8080', TRUE));
	}

	public function testBareIpv6LiteralTrailingHextetIsNotMangled(): void
	{
		// is_ipaddrv6() gates pfb_strip_trailing_port() -- a bare v6 literal's final
		// hextet must survive, unlike a real ':<port>' suffix.
		$this->assertSame('2604:2dc0::', $this->extract('2604:2dc0::', FALSE));
		$this->assertSame('2604:2dc0::', $this->extract('2604:2dc0::', TRUE));
	}

	// -- IPv6 unbracket (LAST -- issue #938) ---------------------------------------------

	public function testBracketedIpv6IsUnwrappedLast(): void
	{
		$this->assertSame('2604:2dc0::', $this->extract('[2604:2dc0::]', FALSE));
		$this->assertSame('2604:2dc0::', $this->extract('[2604:2dc0::]', TRUE));
	}

	// -- scheme-less bare domain identity -------------------------------------------------

	public function testBareDomainIdentityAcrossHyphenUnderscoreDigitLabels(): void
	{
		foreach (['my-domain.com', 'my_domain-2_test.example.com', '123.example.com'] as $domain) {
			$this->assertSame($domain, $this->extract($domain, FALSE), "{$domain} lenient");
			$this->assertSame($domain, $this->extract($domain, TRUE), "{$domain} strict");
		}
	}

	// -- IDN raw bytes passthrough (no punycode conversion here) --------------------------

	public function testRawUtf8LabelIsPassedThroughUnconverted(): void
	{
		// idn_to_ascii() conversion happens LATER in the download loop, outside this
		// helper -- a raw non-ASCII UTF-8 label must survive byte-for-byte.
		$raw = "\xE4\xBE\x8B\xE3\x81\x88.com";
		$this->assertSame($raw, $this->extract($raw, FALSE));
		$this->assertSame($raw, $this->extract($raw, TRUE));
	}

	// -- empty result after truncation -----------------------------------------------------

	public function testTruncationToEmptyStringReturnsEmptyNotFalse(): void
	{
		// '?foo' truncates entirely at the '?' step -- the real (pinned) result is an
		// empty STRING, not FALSE (FALSE is reserved for the scheme-reject contract).
		$this->assertSame('', $this->extract('?foo', FALSE));
	}

	// -- ordering invariant: scheme -> trunc -> ';' -> port -> unbracket ------------------

	public function testOrderingInvariantSchemeBeforeTruncationBeforePortStrip(): void
	{
		$this->assertSame('d.com', $this->extract('https://d.com:8080/p#f?q', FALSE));
	}

	public function testOrderingInvariantHoldsUnderStrictRejection(): void
	{
		// The same shape, but strict mode: the scheme is valid, yet the '/p' remainder
		// after the port is a URL path -- rejected before any trunc/port/unbracket step
		// runs, proving scheme-check happens FIRST.
		$skipped = 0;
		$result  = $this->extract('https://d.com:8080/p#f', TRUE, $skipped);
		$this->assertFalse($result);
		$this->assertSame(1, $skipped);
	}
}
