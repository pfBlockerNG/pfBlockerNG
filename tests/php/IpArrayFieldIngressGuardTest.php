<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #1777: pfblockerng_ip.php's save handler runs `pfb_sanitize_text((string)
 * ($_POST[$field] ?? ''))` over a fixed field list (:123-125) with no upstream
 * guard against an array-valued field ('asn_token[]=x', the shape
 * tests/smoke/ui/test_post_array_scalar_guards.py:92 already covers for the
 * graceful-reject/no-500 contract via pfb_filter()'s own array rejection at
 * :161). The `(string)` cast on an ARRAY raises "Array to string conversion"
 * -- a diagnostic-only regression, not a crash (already covered elsewhere).
 *
 * Fix: copy pfblockerng_category_edit.php's issue #1106 ingress guard (:473-478)
 * IN INTENT -- reject a non-scalar text field with an input error and blank
 * it, BEFORE the sanitize loop -- so no downstream (string) cast ever sees an
 * array. NOT in shape: category_edit has zero multi-selects, so its guard
 * covers every $_POST key unconditionally; this page has three
 * (inbound_interface, outbound_interface, pfb_agg_types -- pfSense's
 * Form_Select(..., TRUE) posts those as arrays for real, browser-driven
 * saves), so an unconditional guard rejects and blanks all three on every
 * save (issue #1777 review, BLOCKING). The guard here excludes those three
 * and covers every other field, so scalar sinks outside the #1723 loops stay
 * protected too. The (string) cast itself must stay: it is load-bearing for
 * genuinely scalar fields (int/bool/null POST values).
 *
 * The ingress+sanitize loops are eval-extracted as a pure function of $_POST
 * (top-level page script, not require()-able off-appliance), bounded by their
 * executable POST-key loop and following select-options assignment.
 */
final class IpArrayFieldIngressGuardTest extends TestCase
{
	private const IP_PHP = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_ip.php';

	public static function setUpBeforeClass(): void
	{
		if (function_exists('pfb_ip_oracle_sanitize_prologue')) {
			return;
		}
		$src = php_strip_whitespace(self::IP_PHP);
		if ($src === '') {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_ip.php');
		}
		if (!preg_match(
			'/(\$pfb_multiselect_fields = array\(.*?\);\s*'
			. 'foreach \(array_keys\(\$_POST\) as \$pfb_post_field\) \{.*?)(?=\$select_options = array\()/s',
			$src,
			$m
		)) {
			throw new RuntimeException('test bootstrap: ip.php ingress guard + sanitize executable region not found');
		}
		if (strpos($m[1], 'pfb_sanitize_text_area') === FALSE) {
			throw new RuntimeException('test bootstrap: IP sanitize executable region is incomplete');
		}
		eval(
			'function pfb_ip_oracle_sanitize_prologue(array $post): array {'
			. ' $_POST = $post; $input_errors = array();'
			. $m[1]
			. ' return [$_POST, $input_errors]; }'
		);
	}

	private function runCapturing(callable $fn): array
	{
		$diagnostics = [];
		set_error_handler(static function (int $errno, string $errstr) use (&$diagnostics): bool {
			$diagnostics[] = $errstr;
			return TRUE;
		});
		try {
			$result = $fn();
		} finally {
			restore_error_handler();
		}
		return [$result, $diagnostics];
	}

	public function testArrayValuedAsnTokenIsRejectedAndBlankedWithNoArrayToStringDiagnostic(): void
	{
		[$result, $diagnostics] = $this->runCapturing(static fn () => pfb_ip_oracle_sanitize_prologue([
			'ip_placeholder'  => '198.51.100.1',
			'asn_token'       => ['crafted'],
			'autorule_suffix' => 'autorule',
			'maxmind_account' => 'acct',
			'maxmind_key'     => 'key',
		]));

		$arrayToString = array_values(array_filter($diagnostics, static fn (string $d): bool => str_contains($d, 'Array to string conversion')));
		$this->assertSame([], $arrayToString, "an array-valued asn_token must emit zero 'Array to string conversion' diagnostics, got:\n" . implode("\n", $arrayToString));

		[$post, $inputErrors] = $result;
		$this->assertSame('', $post['asn_token'], 'an array-valued field must be blanked, never left as an array or stringified "Array"');
		$this->assertNotEmpty($inputErrors, 'an array-valued field must raise an input error');
	}

	public function testScalarFieldsStillSanitizeIdenticallyBeforeAndAfterTheGuard(): void
	{
		[$result, $diagnostics] = $this->runCapturing(static fn () => pfb_ip_oracle_sanitize_prologue([
			'ip_placeholder'  => ' 198.51.100.1 ',
			'asn_token'       => ' mytoken ',
			'autorule_suffix' => 'autorule',
			'maxmind_account' => 'acct',
			'maxmind_key'     => 'key',
		]));

		$this->assertSame([], array_values(array_filter($diagnostics, static fn (string $d): bool => str_contains($d, 'Array to string conversion'))));
		[$post, $inputErrors] = $result;
		$this->assertSame([], $inputErrors, 'a fully scalar submission must raise no input error');
		$this->assertSame('198.51.100.1', $post['ip_placeholder'], 'a scalar field must still sanitize (trim) identically -- the (string) cast must not be weakened');
		$this->assertSame('mytoken', $post['asn_token']);
	}

	public function testMissingFieldsStillDefaultToEmptyStringUnchanged(): void
	{
		[$result, $diagnostics] = $this->runCapturing(static fn () => pfb_ip_oracle_sanitize_prologue([]));

		$this->assertSame([], array_values(array_filter($diagnostics, static fn (string $d): bool => str_contains($d, 'Array to string conversion'))));
		[$post, $inputErrors] = $result;
		$this->assertSame([], $inputErrors, 'an empty POST has nothing non-scalar to reject');
		$this->assertSame('', $post['asn_token'], 'an absent field must still default to \'\' (the pre-existing ?? \'\' behaviour)');
	}

	/**
	 * issue #1777 review (BLOCKING): a realistic browser save POSTs
	 * inbound_interface / outbound_interface / pfb_agg_types as ARRAYS
	 * (Form_Select(..., TRUE) appends '[]' to the POST name). The guard must
	 * leave all three alone -- untouched, still arrays, same members, no
	 * input error -- while an array-valued asn_token (never a legitimate
	 * multi-select on this page) must still be rejected and blanked exactly
	 * as before.
	 */
	public function testMultiSelectArrayFieldsSurviveTheGuardWhileAsnTokenArrayIsStillRejected(): void
	{
		[$result, $diagnostics] = $this->runCapturing(static fn () => pfb_ip_oracle_sanitize_prologue([
			'ip_placeholder'     => '198.51.100.1',
			'asn_token'          => ['crafted'],
			'autorule_suffix'    => 'autorule',
			'maxmind_account'    => 'acct',
			'maxmind_key'        => 'key',
			'inbound_interface'  => ['wan', 'lan'],
			'outbound_interface' => ['wan'],
			'pfb_agg_types'      => ['ipv4', 'ipv6'],
		]));

		$arrayToString = array_values(array_filter($diagnostics, static fn (string $d): bool => str_contains($d, 'Array to string conversion')));
		$this->assertSame([], $arrayToString, "the three multi-selects must never Array-to-string-convert, got:\n" . implode("\n", $arrayToString));

		[$post, $inputErrors] = $result;

		$this->assertSame(['wan', 'lan'], $post['inbound_interface'], 'inbound_interface must survive the guard as an unmodified array');
		$this->assertSame(['wan'], $post['outbound_interface'], 'outbound_interface must survive the guard as an unmodified array');
		$this->assertSame(['ipv4', 'ipv6'], $post['pfb_agg_types'], 'pfb_agg_types must survive the guard as an unmodified array');

		$multiSelectErrors = array_values(array_filter($inputErrors, static fn (string $e): bool =>
			str_contains($e, 'inbound_interface') || str_contains($e, 'outbound_interface') || str_contains($e, 'pfb_agg_types')));
		$this->assertSame([], $multiSelectErrors, "no multi-select field may raise 'Invalid value submitted for field', got:\n" . implode("\n", $multiSelectErrors));

		$this->assertSame('', $post['asn_token'], 'asn_token must still be blanked when array-valued');
		$asnTokenErrors = array_values(array_filter($inputErrors, static fn (string $e): bool => str_contains($e, 'asn_token')));
		$this->assertNotEmpty($asnTokenErrors, 'asn_token must still raise its own input error when array-valued');
	}

	/**
	 * The guard must cover every scalar field on the page, not just the ones the
	 * #1723 sanitize loops name. Scoping it to an allow-list of text fields left
	 * the ADR-40 pair unguarded, and both have a scalar-only sink further down
	 * the same save handler: pfb_alias_delta_mode reaches array_key_exists()
	 * (:277), whose first parameter is int|string -- an array is a fatal
	 * TypeError -- and pfb_alias_delta_batch reaches a (string) cast (:284),
	 * which Array-to-string-converts and then silently resolves to the clamp
	 * floor instead of the intended default. Same class for any scalar field
	 * added to this page later, which is why the guard excludes the three known
	 * multi-selects rather than enumerating the fields it protects.
	 *
	 */
	#[DataProvider('provideUnlistedScalarFields')]
	public function testScalarFieldsOutsideTheSanitizeLoopsAreAlsoRejectedWhenArrayValued(string $field): void
	{
		[$result, $diagnostics] = $this->runCapturing(static fn () => pfb_ip_oracle_sanitize_prologue([
			'ip_placeholder'    => '198.51.100.1',
			'asn_token'         => 'mytoken',
			'inbound_interface' => ['wan'],
			$field              => ['crafted'],
		]));

		$this->assertSame([], array_values(array_filter($diagnostics, static fn (string $d): bool => str_contains($d, 'Array to string conversion'))));

		[$post, $inputErrors] = $result;
		$this->assertSame('', $post[$field], "an array-valued {$field} must be blanked before it reaches its scalar-only sink");
		$this->assertNotEmpty(
			array_values(array_filter($inputErrors, static fn (string $e): bool => str_contains($e, $field))),
			"an array-valued {$field} must raise its own input error"
		);
		$this->assertSame(['wan'], $post['inbound_interface'], 'a legitimate multi-select must still survive alongside the rejection');
	}

	/** @return array<string, array{string}> */
	public static function provideUnlistedScalarFields(): array
	{
		return [
			'ADR-40 apply mode (array_key_exists sink, fatal TypeError)' => ['pfb_alias_delta_mode'],
			'ADR-40 batch size ((string) cast sink)'                     => ['pfb_alias_delta_batch'],
			'single-select locale (never posted as an array by a browser)' => ['maxmind_locale'],
		];
	}
}
