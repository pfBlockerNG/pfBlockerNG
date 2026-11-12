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
 * The step is part of the production per-line parser, pfb_dnsbl_parse_line(): the
 * surviving line is the domain of the row it writes.
 */
final class DnsblFeedIdnWildcardTest extends TestCase
{
	private string $failLog = '';

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
	 * Run the production per-line parser over one feed line.
	 *
	 * @return array{0: ?string, 1: string} the surviving line (NULL when the
	 *         parser dropped it) and the parse-failure log contents.
	 *
	 * The step is gated on !ctype_print(), which is locale-sensitive; pfSense's
	 * PHP runs under the C locale (high bytes non-printable), so pin that to
	 * make the conversion deterministic on any host.
	 */
	private function convertFeedLine(string $feedLine): array
	{
		$state = pfb_dnsbl_parse_state();
		$ctx = ['header' => 'testfeed', 'custom' => FALSE, 'dnsbl_ip' => FALSE, 'lenient' => TRUE, 'parse_err' => $this->failLog];

		$prev = setlocale(LC_CTYPE, '0');
		setlocale(LC_CTYPE, 'C');
		try {
			$res = pfb_dnsbl_parse_line($feedLine, 1, $state, $ctx);
		} finally {
			setlocale(LC_CTYPE, $prev);
		}

		$line = $res['row'] === NULL ? NULL : json_decode($res['row'], TRUE, 512, JSON_THROW_ON_ERROR)[1];
		return [$line, (string) file_get_contents($this->failLog)];
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
