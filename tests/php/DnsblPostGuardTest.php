<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * DNSBL-page customlist array-POST guard (issue #1128).
 *
 * A crafted request submitting an array-valued customlist field
 * ('pfb_regex_list[]=x' etc.) reached strictly-typed string sinks
 * (mb_detect_encoding()/explode(), and base64_encode() further down)
 * before any type check, TypeError-ing the page (HTTP 500). The fix
 * rejects and blanks a non-scalar customlist field up front, mirroring
 * the #1106 category_edit.php idiom (flag + neutralize to '') rather
 * than general.php's flag-only idiom -- these fields are read by
 * unguarded string sinks earlier in the same validation pass, so a bare
 * $input_errors push is not enough to prevent the crash.
 *
 * The page carries top-level execution and cannot be require()d
 * off-appliance, so the region is eval-extracted verbatim from the REAL
 * source, anchored on text stable across both the pre-fix and post-fix
 * code so the same test file proves red on the old code and green on
 * the new.
 */
final class DnsblPostGuardTest extends TestCase
{
	private array $savedPost = [];

	public static function setUpBeforeClass(): void
	{
		$src = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php'
		);
		if ($src === false) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_dnsbl.php');
		}

		// Region: the six-field customlist guard through the 'Validate customlists' loop.
		if (!function_exists('pfb_dnsbl_oracle_customlists')) {
			if (!preg_match(
				'/\'DNSBL Decision cache max entries must be a whole number between 0 and 5000000\.\';'
				. '\n\t\t\}\n\n(.*?)\n\n\t\t\/\/ Validate DNSBL VIP address/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: customlist guard region not found');
			}
			eval(
				'function pfb_dnsbl_oracle_customlists(): array {'
				. ' $input_errors = array();'
				. $m[1]
				. ' return $input_errors; }'
			);
		}
	}

	protected function setUp(): void
	{
		$this->savedPost = $_POST;
		$_POST = [];
	}

	protected function tearDown(): void
	{
		$_POST = $this->savedPost;
	}

	/** field => a value that legitimately validates under that field's own format. */
	public static function customlistFieldProvider(): array
	{
		return [
			'pfb_regex_list'     => ['pfb_regex_list', 'test123'],
			'pfb_noaaaa_list'    => ['pfb_noaaaa_list', 'example.com'],
			'pfb_gp_bypass_list' => ['pfb_gp_bypass_list', '192.0.2.1'],
			'suppression'        => ['suppression', 'example.com'],
			'tldexclusion'       => ['tldexclusion', 'example.com'],
			'tldblacklist'       => ['tldblacklist', 'com'],
		];
	}

	#[DataProvider('customlistFieldProvider')]
	public function testArrayValueIsRejectedWithoutThrowing(string $field, string $validValue): void
	{
		$_POST[$field] = ['x', 'y'];
		try {
			$errors = pfb_dnsbl_oracle_customlists();
		} catch (\TypeError $e) {
			$this->fail("an array {$field} value must not TypeError: " . $e->getMessage());
		}
		$this->assertNotEmpty(
			array_filter($errors, static fn (string $e): bool => str_contains($e, $field)),
			"an array {$field} value must be reported as an input error"
		);
		$this->assertSame('', $_POST[$field], "the guard must blank the array {$field} value to an empty string");
	}

	#[DataProvider('customlistFieldProvider')]
	public function testScalarValueIsUnaffectedByTheGuard(string $field, string $validValue): void
	{
		$_POST[$field] = $validValue;
		$errors = pfb_dnsbl_oracle_customlists();
		$this->assertEmpty(
			array_filter($errors, static fn (string $e): bool => str_contains($e, "Customlist {$field}")),
			"a valid scalar {$field} value must not be flagged by the guard or its format validator"
		);
		$this->assertSame($validValue, $_POST[$field], "a scalar {$field} value must survive the guard unmodified");
	}

	#[DataProvider('customlistFieldProvider')]
	public function testMissingKeyDoesNotWarnOrThrow(string $field, string $validValue): void
	{
		unset($_POST[$field]);
		try {
			$errors = pfb_dnsbl_oracle_customlists();
		} catch (\TypeError $e) {
			$this->fail("a missing {$field} key must not TypeError: " . $e->getMessage());
		}
		$this->assertEmpty(
			array_filter($errors, static fn (string $e): bool => str_contains($e, $field)),
			"a missing {$field} key must not be flagged by the guard"
		);
	}
}
