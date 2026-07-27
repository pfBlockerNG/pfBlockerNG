<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1777: pfblockerng_ip.php's save handler runs `pfb_sanitize_text((string)
 * ($_POST[$field] ?? ''))` over a fixed field list (:112-114) with no upstream
 * guard against an array-valued field ('asn_token[]=x', the shape
 * tests/smoke/ui/test_post_array_scalar_guards.py:92 already covers for the
 * graceful-reject/no-500 contract via pfb_filter()'s own array rejection at
 * :161). The `(string)` cast on an ARRAY raises "Array to string conversion"
 * -- a diagnostic-only regression, not a crash (already covered elsewhere).
 *
 * Fix: copy pfblockerng_category_edit.php's issue #1106 ingress guard (:473-478)
 * IN SHAPE -- reject every non-scalar $_POST field with an input error and
 * blank it, BEFORE the sanitize loop -- so no downstream (string) cast ever
 * sees an array. The (string) cast itself must stay: it is load-bearing for
 * genuinely scalar fields (int/bool/null POST values).
 *
 * The ingress+sanitize loops are eval-extracted as a pure function of $_POST
 * (top-level page script, not require()-able off-appliance) -- matching
 * DnsblFreshPconfigTest's convention for this same page family.
 */
final class IpArrayFieldIngressGuardTest extends TestCase
{
	private const IP_PHP = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_ip.php';

	public static function setUpBeforeClass(): void
	{
		if (function_exists('pfb_ip_oracle_sanitize_prologue')) {
			return;
		}
		$src = file_get_contents(self::IP_PHP);
		if ($src === FALSE) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_ip.php');
		}
		// Anchored on the issue #1723 sanitize-loop comment through its closing
		// brace -- non-greedy, so it matches whether or not the #1777 ingress
		// guard has been inserted immediately before it yet.
		if (!preg_match(
			'/(\/\/ issue #1723: sanitize at ingestion -- first step, before any evaluation\.\n'
			. '\t\tforeach \(array\(\'ip_placeholder\', \'asn_token\', \'autorule_suffix\', \'maxmind_account\', \'maxmind_key\'\) as \$pfb_text_field\) \{\n'
			. '.*?\n\t\t\})\n/s',
			$src,
			$m
		)) {
			throw new RuntimeException('test bootstrap: ip.php sanitize prologue not found');
		}
		// The (optional, guard-state-dependent) ingress guard directly precedes
		// the anchor above -- captured separately so the oracle covers it
		// whether or not it exists yet (pre-fix: absent; post-fix: present).
		$guard = '';
		if (preg_match(
			'/(foreach \(\$_POST as \$pfb_post_key => \$pfb_post_value\) \{\n\t\t\tif \(!is_scalar\(\$pfb_post_value\)\) \{\n.*?\n\t\t\t\}\n\t\t\}\n)\n\t\t\/\/ issue #1723/s',
			$src,
			$gm
		)) {
			$guard = $gm[1];
		}
		eval(
			'function pfb_ip_oracle_sanitize_prologue(array $post): array {'
			. ' $_POST = $post; $input_errors = array();'
			. $guard
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
}
