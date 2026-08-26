<?php

declare(strict_types=1);

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
}
