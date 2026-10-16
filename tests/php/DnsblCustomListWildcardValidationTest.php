<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfblockerng_dnsbl.php's "Validate customlists" block — issue #1741.
 *
 * The Whitelist and No-AAAA lists accept the leading-dot wildcard form
 * ('.example.com'), so the validator strips the marker before handing the row
 * to pfb_filter(). It stripped with trim($value[0], '.'), which takes ALL the
 * leading dots, so an invalid '..example.com' row validated as 'example.com'
 * and was saved — the row the build path then had to defend against. Exactly
 * one leading dot may come off, which is what pfb_filter() already tolerates
 * itself; the trailing-dot tolerance stays.
 *
 * Issue #3508: the Group Policy bypass list ('ip' arm) takes a bare IP or an IPv4/IPv6
 * CIDR, and rejects anything else with the same per-row message shape.
 *
 * The page carries top-level execution and cannot be require()d off-appliance,
 * so the validation block is eval-extracted from the REAL source using its
 * executable custom-type loop and following regex-validation statement.
 */
final class DnsblCustomListWildcardValidationTest extends TestCase
{
	private static string $region;

	private array $savedPost = [];

	public static function setUpBeforeClass(): void
	{
		$path = dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php';
		$src = php_strip_whitespace($path);
		if ($src === '') {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_dnsbl.php');
		}
		if (!preg_match(
			'/(foreach \(array\(\s*\x27pfb_noaaaa_list\x27\s*=>\s*\x27domain\x27.*?\)'
			. ' as \$custom_type => \$custom_format\) \{.*?\})'
			. '\s*\$pfb_regex_python = pfb_python_interpreter\(\)/s',
			$src,
			$m
		)) {
			throw new RuntimeException('test bootstrap: custom-list executable region not found');
		}
		if (strpos($m[1], 'rtrim($value[0], \'.\')') === FALSE) {
			throw new RuntimeException('test bootstrap: custom-list wildcard trim decision disappeared');
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

	/** Run the extracted block over one row of one customlist field. */
	private function validateRow(string $field, string $row): array
	{
		$_POST = [$field => $row];
		$input_errors = array();
		eval(self::$region);

		return $input_errors;
	}

	public function testWhitelistWildcardRowAccepted(): void
	{
		$this->assertSame([], $this->validateRow('whitelist', '.example.com'));
	}

	public function testWhitelistPlainRowAccepted(): void
	{
		$this->assertSame([], $this->validateRow('whitelist', 'example.com'));
	}

	public function testWhitelistTrailingDotRowStillAccepted(): void
	{
		// The trailing-dot (FQDN root) tolerance predates this change.
		$this->assertSame([], $this->validateRow('whitelist', 'example.com.'));
	}

	public function testWhitelistDoubleDotRowRejected(): void
	{
		$this->assertSame(
			['Customlist whitelist: Invalid Domain name entry: [ ..example.com ]'],
			$this->validateRow('whitelist', '..example.com')
		);
	}

	public function testNoAaaaDoubleDotRowRejected(): void
	{
		// The No-AAAA list shares the 'domain' arm and the same wildcard form.
		$this->assertSame(
			['Customlist pfb_noaaaa_list: Invalid Domain name entry: [ ..example.com ]'],
			$this->validateRow('pfb_noaaaa_list', '..example.com')
		);
	}

	public function testNoAaaaWildcardRowAccepted(): void
	{
		$this->assertSame([], $this->validateRow('pfb_noaaaa_list', '.example.com'));
	}

	/** @return array<string, array{string}> */
	public static function groupPolicyAcceptedRows(): array
	{
		return [
			'bare IPv4' => ['192.168.1.5'],
			'bare IPv6' => ['2001:db8::1'],
			'IPv4 CIDR' => ['10.0.0.0/24'],
			'IPv6 CIDR' => ['2001:db8::/64'],
			'IPv4 CIDR with host bits set' => ['10.0.0.1/24'],
			'IPv4 host prefix' => ['10.0.0.5/32'],
			'IPv6 host prefix' => ['2001:db8::1/128'],
			'IPv4 catch-all' => ['0.0.0.0/0'],
			'IPv6 catch-all' => ['::/0'],
			'CIDR followed by an inline comment' => ['10.0.0.0/24 # office'],
		];
	}

	#[DataProvider('groupPolicyAcceptedRows')]
	public function testGroupPolicyBypassAcceptsIpAndCidrRows(string $row): void
	{
		$this->assertSame([], $this->validateRow('pfb_gp_bypass_list', $row));
	}

	/** @return array<string, array{string}> */
	public static function groupPolicyRejectedRows(): array
	{
		return [
			'IPv4 prefix above 32' => ['10.0.0.0/33'],
			'IPv6 prefix above 128' => ['2001:db8::/129'],
			'missing prefix length' => ['10.0.0.0/'],
			'missing network' => ['/24'],
			'hostname' => ['example.com'],
			'trailing text after the CIDR' => ['10.0.0.0/24 extra'],
			'negative prefix length' => ['10.0.0.0/-1'],
		];
	}

	#[DataProvider('groupPolicyRejectedRows')]
	public function testGroupPolicyBypassRejectsMalformedRows(string $row): void
	{
		$this->assertSame(
			["Customlist pfb_gp_bypass_list: Invalid IP or CIDR entry: [ {$row} ]"],
			$this->validateRow('pfb_gp_bypass_list', $row)
		);
	}

	public function testCidrAcceptanceStaysScopedToTheGroupPolicyList(): void
	{
		$this->assertSame(
			['Customlist pfb_noaaaa_list: Invalid Domain name entry: [ 10.0.0.0/24 ]'],
			$this->validateRow('pfb_noaaaa_list', '10.0.0.0/24')
		);
	}
}
