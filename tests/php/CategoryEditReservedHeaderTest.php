<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Category-edit save-time validation must fire regardless of row state
 * (issue #1270): the header \W-format check, the issue-#1104 URL
 * control-char check, and the NEW reserved-header check were all gated on
 * $value != 'Disabled', so a row saved while Disabled skipped validation
 * entirely and its RAW value reached config storage -- where
 * sync_package_pfblockerng()'s periodic sync could later normalise it onto
 * (or find it already equal to) a package-owned reserved name with no check
 * ever having run.
 *
 * Like CategoryEditPostGuardTest, the page carries top-level execution and
 * cannot be require()d off-appliance, so the rowhelper state-loop region is
 * eval-extracted verbatim from the REAL source, anchored on text stable
 * across the pre-fix and post-fix code -- the same test proves red on the
 * old code and green on the new.
 */
final class CategoryEditReservedHeaderTest extends TestCase
{
	private array $savedPost = [];
	private mixed $savedPfb = null;

	public static function setUpBeforeClass(): void
	{
		$continents = $GLOBALS['pfb']['continents'] ?? null;
		if (!is_array($continents) || count($continents) !== 9) {
			throw new RuntimeException('$pfb[continents] must have exactly 9 entries; got: ' . var_export($continents, true));
		}

		$src = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_category_edit.php'
		);
		if ($src === false) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_category_edit.php');
		}

		if (!function_exists('pfb_category_oracle_reserved_header_state_loop')) {
			if (!preg_match(
				'/(\tforeach \(\$_POST as \$key => \$value\) \{\n.*?\n\t\})\n\n\n\t\/\/ Validate Adv\. firewall rule settings/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: state validation loop not found');
			}
			eval(
				'function pfb_category_oracle_reserved_header_state_loop(string $type): array {'
				. ' global $pfb; $input_errors = array(); $line = 1;'
				. $m[1]
				. ' return $input_errors; }'
			);
		}
	}

	protected function setUp(): void
	{
		$this->savedPost = $_POST;
		$this->savedPfb  = $GLOBALS['pfb'] ?? null;
		$_POST = [];
		// Satisfied MaxMind creds so a geoip-format row would never ALSO trip the
		// unrelated credential-notice input error (mirrors CategoryEditPostGuardTest).
		$GLOBALS['pfb']['maxmind_key']     = 'test-key';
		$GLOBALS['pfb']['maxmind_account'] = 'test-account';
	}

	protected function tearDown(): void
	{
		$_POST = $this->savedPost;
		$GLOBALS['pfb'] = $this->savedPfb;
	}

	/** @param array<int, string> $errors */
	private static function hasErrorContaining(array $errors, string $needle): bool
	{
		foreach ($errors as $error) {
			if (str_contains($error, $needle)) {
				return TRUE;
			}
		}
		return FALSE;
	}

	private function makeRow(string $state, string $header, string $url): void
	{
		$_POST = [
			'state-0'  => $state,
			'header-0' => $header,
			'url-0'    => $url,
			'format-0' => 'auto',
		];
	}

	// --- Reserved-header check (issue #1270) -----------------------------

	public function testDisabledRowWithReservedHeaderIsRejected(): void
	{
		$this->makeRow('Disabled', 'DNSBLIP', 'http://192.0.2.1/feed');
		$errors = pfb_category_oracle_reserved_header_state_loop('Test');
		$this->assertTrue(
			self::hasErrorContaining($errors, 'reserved'),
			'expected a reserved-header error; got: ' . implode(' | ', $errors)
		);
	}

	public function testEnabledRowWithReservedHeaderIsRejected(): void
	{
		$this->makeRow('Enabled', 'DNSBLIP', 'http://192.0.2.1/feed');
		$errors = pfb_category_oracle_reserved_header_state_loop('Test');
		$this->assertTrue(
			self::hasErrorContaining($errors, 'reserved'),
			'expected a reserved-header error; got: ' . implode(' | ', $errors)
		);
	}

	// --- \W-format + disallowed-char checks broadened to non-empty-gated -

	public function testDisabledRowWithControlCharUrlIsRejected(): void
	{
		$this->makeRow('Disabled', 'MyBlocklist', "http://192.0.2.1/\x01feed");
		$errors = pfb_category_oracle_reserved_header_state_loop('Test');
		$this->assertTrue(
			self::hasErrorContaining($errors, 'disallowed character'),
			'expected a disallowed-character error; got: ' . implode(' | ', $errors)
		);
	}

	public function testDisabledRowWithPunctuatedHeaderIsRejectedForFormat(): void
	{
		$this->makeRow('Disabled', 'de-dup', 'http://192.0.2.1/feed');
		$errors = pfb_category_oracle_reserved_header_state_loop('Test');
		$this->assertTrue(
			self::hasErrorContaining($errors, 'Header field cannot contain spaces'),
			'expected a \W-format error; got: ' . implode(' | ', $errors)
		);
	}

	// --- Regression guards: unchanged before AND after --------------------

	public function testDisabledRowEmptyHeaderAndUrlHasNoHeaderOrUrlErrors(): void
	{
		$this->makeRow('Disabled', '', '');
		$errors = pfb_category_oracle_reserved_header_state_loop('Test');
		$this->assertFalse(self::hasErrorContaining($errors, 'reserved'), 'draft row: ' . implode(' | ', $errors));
		$this->assertFalse(self::hasErrorContaining($errors, 'Header field cannot contain spaces'), 'draft row: ' . implode(' | ', $errors));
		$this->assertFalse(self::hasErrorContaining($errors, 'disallowed character'), 'draft row: ' . implode(' | ', $errors));
		$this->assertFalse(self::hasErrorContaining($errors, 'must be defined'), 'draft row: ' . implode(' | ', $errors));
	}

	public function testEnabledRowEmptyHeaderStillFlaggedEmpty(): void
	{
		$this->makeRow('Enabled', '', '');
		$errors = pfb_category_oracle_reserved_header_state_loop('Test');
		$this->assertTrue(
			self::hasErrorContaining($errors, 'Header field must be defined'),
			'existing emptiness gating must be unchanged: ' . implode(' | ', $errors)
		);
	}
}
