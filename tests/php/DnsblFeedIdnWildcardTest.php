<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * The DNSBL feed parser's IDN step in pfblockerng_apply.inc — issue #1740.
 *
 * A feed line carrying a leading dot ('.bücher.de') is punycode-converted
 * before the parser strips the dots, and idn_to_ascii() rejects a leading dot
 * outright: the whole line was recorded as an IDN parse failure and dropped,
 * even though the same line in ASCII form ('.example.com') parses fine. The
 * conversion must preserve the leading dot so the existing trim() reduces the
 * line to its bare domain.
 *
 * The step lives deep inside sync_package_pfblockerng()'s feed loop and is not
 * unit-reachable, so it is eval-extracted verbatim from the REAL source (house
 * precedent: tests/php/CategoryEditPostGuardTest.php).
 */
final class DnsblFeedIdnWildcardTest extends TestCase
{
	private static string $region;

	private string $failLog = '';

	public static function setUpBeforeClass(): void
	{
		$path = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';
		$src = file_get_contents($path);
		if ($src === FALSE) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_apply.inc');
		}
		if (!preg_match(
			'/((?:\t+if \(!empty\(\$line\) && !ctype_print\(\$line\)\) \{).*?\$line = trim\(\$line, \'\.\'\);)/s',
			$src,
			$m
		)) {
			throw new RuntimeException('test bootstrap: DNSBL feed IDN region not found');
		}
		// The region uses `continue` to drop a line; wrap it in a loop of its
		// own so that keeps working inside eval().
		self::$region = "foreach ([0] as \$pfb_test_iter) {\n{$m[1]}\n\$pfb_test_kept = TRUE;\n}\n";
	}

	public function testExtractionStartsAtExecutableCodeNotProductionComment(): void
	{
		$this->assertStringContainsString("if (!empty(\$line) && !ctype_print(\$line))", self::$region);
		$this->assertStringNotContainsString('Convert IDN (Unicode domains)', self::$region);
	}

	protected function setUp(): void
	{
		$this->failLog = tempnam(sys_get_temp_dir(), 'pfb_feed_idn_') ?: '';
		$this->assertNotSame('', $this->failLog, 'could not create the parse-failure log');
	}

	protected function tearDown(): void
	{
		@unlink($this->failLog);
	}

	/**
	 * Run the extracted step over one feed line.
	 *
	 * @return array{0: ?string, 1: string} the surviving line (NULL when the
	 *         step dropped it) and the parse-failure log contents.
	 *
	 * The step is gated on !ctype_print(), which is locale-sensitive; pfSense's
	 * PHP runs under the C locale (high bytes non-printable), so pin that to
	 * make the conversion deterministic on any host.
	 */
	private function convertFeedLine(string $feedLine): array
	{
		$line = $feedLine;
		$oline = $feedLine;
		$header = 'testfeed';
		$dnsbl_lineno = 1;
		$pfb = ['dnsbl_parse_err' => $this->failLog];
		$pfb_test_kept = FALSE;

		$prev = setlocale(LC_CTYPE, '0');
		setlocale(LC_CTYPE, 'C');
		try {
			eval(self::$region);
		} finally {
			setlocale(LC_CTYPE, $prev);
		}

		return [$pfb_test_kept ? $line : NULL, (string) file_get_contents($this->failLog)];
	}

	public function testWildcardIdnFeedLineConvertsToItsBareDomain(): void
	{
		// The parser has no wildcard concept: the dots come off after the
		// conversion, so the line survives as the bare punycode domain.
		[$line, $failLog] = $this->convertFeedLine('.bücher.de');
		$this->assertSame('xn--bcher-kva.de', $line);
		$this->assertSame('', $failLog, 'a convertible IDN line must not be logged as a parse failure');
	}

	public function testBareIdnFeedLineConvertsToPunycode(): void
	{
		[$line, $failLog] = $this->convertFeedLine('bücher.de');
		$this->assertSame('xn--bcher-kva.de', $line);
		$this->assertSame('', $failLog);
	}

	public function testAsciiWildcardFeedLineKeepsItsBareDomain(): void
	{
		// The ASCII twin skips the IDN arm entirely — the behaviour the IDN
		// line is expected to match.
		[$line, $failLog] = $this->convertFeedLine('.example.com');
		$this->assertSame('example.com', $line);
		$this->assertSame('', $failLog);
	}

	public function testUnconvertibleIdnFeedLineStillDropped(): void
	{
		// A lone '.' plus non-ASCII junk has no convertible label; the line is
		// dropped and recorded, as before.
		[$line, $failLog] = $this->convertFeedLine('.。');
		$this->assertNull($line);
		$this->assertStringContainsString('testfeed', $failLog);
	}
}
