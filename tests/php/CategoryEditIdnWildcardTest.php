<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * pfblockerng_category_edit.php's "Validate Custom List" block — issue #1740.
 *
 * A DNSBL/IPv4 customlist row may be a leading-dot wildcard ('.example.com').
 * The 'dnsbl' and whois-converted 'ipv4' arms punycode-convert a non-ASCII row
 * BEFORE handing it to pfb_filter(PFB_FILTER_DOMAIN), so the wildcard marker
 * must survive that conversion: otherwise the row is emptied and the page
 * reports "Invalid Domain name entry" for a row the read path accepts. The
 * 'ipv6' arm hands the raw row straight to pfb_filter() and is the parity
 * oracle — it has always accepted the wildcard IDN row.
 *
 * The page carries top-level execution and cannot be require()d off-appliance,
 * so the validation block is eval-extracted from the REAL source using its
 * executable custom-list condition and following save guard.
 */
final class CategoryEditIdnWildcardTest extends TestCase
{
	private static string $region;

	private array $savedPost = [];

	public static function setUpBeforeClass(): void
	{
		$path = dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_category_edit.php';
		$src = php_strip_whitespace($path);
		if ($src === '') {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_category_edit.php');
		}
		if (!preg_match(
			'/(if \(!empty\(\$_POST\[\x27custom\x27\]\)\) \{.*?\})\s*if \(!\$input_errors\) \{/s',
			$src,
			$m
		)) {
			throw new RuntimeException('test bootstrap: custom-list executable region not found');
		}
		if (strpos($m[1], 'pfb_idn_to_ascii_wildcard') === FALSE) {
			throw new RuntimeException('test bootstrap: IDN conversion disappeared from custom-list region');
		}
		self::$region = $m[1];
	}

	protected function setUp(): void
	{
		$this->savedPost = $_POST;
	}

	protected function tearDown(): void
	{
		$_POST = $this->savedPost;
	}

	/**
	 * Run the extracted block over one customlist row and return $input_errors.
	 *
	 * The IDN arms are gated on !ctype_print(), which is locale-sensitive;
	 * pfSense's PHP runs under the C locale (high bytes non-printable), so pin
	 * that to make the conversion deterministic on any host.
	 */
	private function validateRow(string $gtype, string $row, string $whoisConvert = ''): array
	{
		$_POST = ['custom' => $row, 'whois_convert' => $whoisConvert];
		$input_errors = array();

		$prev = setlocale(LC_CTYPE, '0');
		setlocale(LC_CTYPE, 'C');
		try {
			eval(self::$region);
		} finally {
			setlocale(LC_CTYPE, $prev);
		}

		return $input_errors;
	}

	public function testDnsblWildcardIdnRowAccepted(): void
	{
		// '.bücher.de' is the wildcard form of a valid IDN domain.
		$this->assertSame([], $this->validateRow('dnsbl', '.bücher.de'));
	}

	public function testIpv4WhoisWildcardIdnRowAccepted(): void
	{
		$this->assertSame([], $this->validateRow('ipv4', '.bücher.de', 'on'));
	}

	public function testIpv6WhoisWildcardIdnRowAccepted(): void
	{
		// Parity oracle: this arm never pre-converted, so it already accepted
		// the row; it must keep doing so.
		$this->assertSame([], $this->validateRow('ipv6', '.bücher.de', 'on'));
	}

	public function testDnsblBareIdnRowAccepted(): void
	{
		$this->assertSame([], $this->validateRow('dnsbl', 'bücher.de'));
	}

	public function testDnsblAsciiWildcardRowAccepted(): void
	{
		// The ASCII wildcard row skips the IDN arm entirely — the behaviour the
		// IDN row is expected to match.
		$this->assertSame([], $this->validateRow('dnsbl', '.example.com'));
	}

	public function testDnsblDoubleDotIdnRowRejected(): void
	{
		// '..bücher.de' is not a wildcard row: it must stay rejected, exactly as
		// its ASCII twin is.
		$this->assertSame(
			['Customlist: Invalid Domain name entry: [ ..bücher.de ]'],
			$this->validateRow('dnsbl', '..bücher.de')
		);
		$this->assertSame(
			['Customlist: Invalid Domain name entry: [ ..example.com ]'],
			$this->validateRow('dnsbl', '..example.com')
		);
	}
}
