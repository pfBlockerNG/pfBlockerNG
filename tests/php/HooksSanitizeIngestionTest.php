<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Hooks tab rowhelper text-field sanitize-at-ingestion (issue #1761).
 *
 * pfblockerng_hooks.php's rowhelper validation loop reads
 * hook_description-N / hook_timeout-N raw off $_POST, validates them (the
 * \p{C} control-char regex; PFB_FILTER_NUM), and only THEN -- in the separate
 * `if (!$input_errors)` persist block -- ran them through a bare trim(). So
 * the validators and the persisted value saw different bytes than the
 * #1723 standard requires (sanitize once, at ingestion, before any
 * evaluation): a BOM/control byte the ASCII trim() never touches could
 * survive into config.xml, and a BOM ahead of a numeric timeout tripped
 * PFB_FILTER_NUM even though the digits themselves were fine.
 *
 * The page carries top-level execution and cannot be require()d
 * off-appliance, so each region below is eval-extracted verbatim from the
 * REAL source, anchored on text stable across both the pre-fix and post-fix
 * code (never on the trim() being removed or the sanitize line being added)
 * so the same test file proves red on the old code and green on the new.
 */
final class HooksSanitizeIngestionTest extends TestCase
{
	private array $savedPost = [];

	public static function setUpBeforeClass(): void
	{
		$src = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_hooks.php'
		);
		if ($src === false) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_hooks.php');
		}

		// Region A: the rowhelper validation loop -- from its $rowhelper_exist
		// init through the foreach's closing brace, stopping before the
		// `if (!$input_errors)` persist block.
		if (!function_exists('pfb_hooks_oracle_validate_region')) {
			if (!preg_match(
				'/(\t\t\$rowhelper_exist = array\(\);\n\t\tforeach \(\$_POST as \$key => \$value\) \{\n.*?\n\t\t\})' .
				'\n\n\t\tif \(!\$input_errors\) \{/s',
				$src,
				$regionA
			)) {
				throw new RuntimeException('test bootstrap: rowhelper validation loop region not found');
			}
			eval(
				'function pfb_hooks_oracle_validate_region(array $options_when): array {'
				. ' $input_errors = array();'
				. $regionA[1]
				. ' return array("errors" => $input_errors, "rowhelper_exist" => $rowhelper_exist); }'
			);
		}

		// Region B: the persist block's $hooks-building loop -- from its
		// $hooks init through the foreach's closing brace, stopping before
		// the empty($hooks) branch (which calls config_set_path/write_config/
		// header/exit -- out of scope here; PHPUnit only needs the built array).
		if (!function_exists('pfb_hooks_oracle_persist_region')) {
			if (!preg_match(
				'/(\t\t\t\$hooks = array\(\);\n\t\t\tforeach \(array_keys\(\$rowhelper_exist\) as \$rowid\) \{\n.*?\n\t\t\t\})' .
				'\n\n\t\t\tif \(empty\(\$hooks\)\)/s',
				$src,
				$regionB
			)) {
				throw new RuntimeException('test bootstrap: persist-block hooks region not found');
			}
			eval(
				'function pfb_hooks_oracle_persist_region(array $rowhelper_exist): array {'
				. ' $hooks = array();'
				. $regionB[1]
				. ' return $hooks; }'
			);
		}
	}

	protected function setUp(): void
	{
		$this->savedPost = $_POST;
	}

	protected function tearDown(): void
	{
		$_POST = $this->savedPost;
	}

	private const OPTIONS_WHEN = ['pre' => 'Pre', 'post' => 'Post'];

	/**
	 * Run BOTH regions in the real execution order: validate, then (only if
	 * clean) persist -- mirroring the page's own `if (!$input_errors)` gate.
	 * Returns ['errors' => array, 'hooks' => array, 'post' => $_POST] so a
	 * test can assert on validation outcome, the persisted row(s), AND the
	 * ingestion-sanitized $_POST bytes the validators themselves saw.
	 */
	private function runSave(array $post): array
	{
		$_POST = $post;
		$validated = pfb_hooks_oracle_validate_region(self::OPTIONS_WHEN);
		$hooks = [];
		if (!$validated['errors']) {
			$hooks = pfb_hooks_oracle_persist_region($validated['rowhelper_exist']);
		}
		return ['errors' => $validated['errors'], 'hooks' => $hooks, 'post' => $_POST];
	}

	// --- description: BOM + control char stripped, ASCII-trim-equivalent kept ---

	public function testDescriptionBomAndControlCharStrippedAtIngestion(): void
	{
		// RED today: the page's own \p{C} description validator (broader than
		// pfb_sanitize_text()'s \p{Cc}+BOM strip -- \p{C} also covers Cf, which
		// includes the BOM) runs on the RAW value and rejects it outright, so
		// the row never reaches persist at all. GREEN: sanitize-before-validate
		// means the validator sees the already-clean "ab" and passes, so the
		// row both validates AND persists exactly "ab". Either way the
		// assertion below fails at RED for the reason this change addresses
		// (mirrors the analogous DNSBL description case in
		// tests/smoke/ui/test_sanitize_persist.py).
		$result = $this->runSave([
			'hook_description-0' => "\u{FEFF}a\x01b  ",
		]);
		$this->assertSame([], $result['errors'], 'a BOM+control-char description must not be rejected once sanitized');
		$this->assertSame('ab', $result['hooks'][0]['description'], 'BOM/control char/trailing space must not survive to the persisted description');
	}

	// --- timeout: a leading BOM must not trip PFB_FILTER_NUM ---

	public function testTimeoutBomStrippedSoDigitsValidate(): void
	{
		$result = $this->runSave([
			'hook_timeout-0' => "\u{FEFF}30",
		]);
		$this->assertSame([], $result['errors'], 'a BOM-prefixed numeric timeout must validate once sanitized at ingestion');
		$this->assertSame('30', $result['hooks'][0]['timeout'], 'the sanitized timeout must persist as the plain digit string');
	}

	// --- description: legacy (ISO-8859-1) byte converts to valid UTF-8 ---

	public function testDescriptionLegacyEncodingByteConvertsToUtf8(): void
	{
		// RED today: "caf\xE9" is invalid UTF-8, so preg_match(...,'/u') on the
		// RAW value returns FALSE (not 0); the validator's `!== 0` fail-closed
		// compare treats that as a reject too, so the row never reaches
		// persist. GREEN: sanitize converts the legacy byte to UTF-8 first, so
		// the validator sees valid text and passes.
		$result = $this->runSave([
			'hook_description-0' => "caf\xE9",
		]);
		$this->assertSame([], $result['errors'], 'a legacy-encoded description must not be rejected once sanitized to UTF-8');
		$this->assertSame('café', $result['hooks'][0]['description'], 'an ISO-8859-1 byte must convert to valid UTF-8, not survive as invalid bytes');
	}

	// --- description: an all-Unicode-whitespace value trims to '' ---

	public function testDescriptionAllUnicodeWhitespaceTrimsToEmpty(): void
	{
		$result = $this->runSave([
			'hook_description-0' => "\u{00A0}\u{2003}",
		]);
		$this->assertSame([], $result['errors'], 'an all-Unicode-whitespace description must not be rejected');
		$this->assertSame('', $result['hooks'][0]['description'], 'NBSP/em-space-only content must trim to the empty string');
	}

	// --- description: a Cf (format) char still trips the \p{C} validator ---

	public function testDescriptionCfCharacterStillRejectedByValidator(): void
	{
		// U+200D ZERO WIDTH JOINER -- category Cf, NOT stripped by
		// pfb_sanitize_text() (only \p{Cc}+BOM are stripped there), but still
		// inside \p{C} (the "Other" superset the page's own validator gates
		// on). Pins that the validator stays live post-sanitize.
		$result = $this->runSave([
			'hook_description-0' => "a\u{200D}b",
		]);
		$this->assertNotEmpty($result['errors'], 'a Cf (zero-width-joiner) description must still be rejected by the \\p{C} validator');
	}

	// --- array-valued field: scalar reject fires before sanitize, no TypeError ---

	public function testArrayValuedDescriptionRejectedWithoutTypeError(): void
	{
		try {
			$result = $this->runSave([
				'hook_description-0' => ['x'],
			]);
		} catch (\TypeError $e) {
			$this->fail('an array-valued hook_description-0 must not TypeError the sanitize call: ' . $e->getMessage());
		}
		$this->assertNotEmpty($result['errors'], 'an array-valued hook_description-0 must be rejected as an invalid field');
		$this->assertContains('Invalid hook field value.', $result['errors']);
	}

	// --- timeout: surrounding ASCII whitespace now validates and persists ---

	public function testTimeoutAsciiPaddingStillTrims(): void
	{
		// PFB_FILTER_NUM is `^[0-9]+$` -- no surrounding-space tolerance -- and
		// the OLD code ran it on the raw value (the persist block's trim() ran
		// only AFTER validation already passed/failed). So ' 30 ' was ALWAYS
		// rejected before this change too; it is not a pre-existing trim, it
		// is the same sanitize-before-validate fix as the BOM timeout case
		// above, exercised with plain whitespace instead of a BOM. RED: reject
		// (PFB_FILTER_NUM sees the untrimmed spaces). GREEN: sanitize trims
		// before validation, so it passes and persists '30'.
		$result = $this->runSave([
			'hook_timeout-0' => ' 30 ',
		]);
		$this->assertSame([], $result['errors']);
		$this->assertSame('30', $result['hooks'][0]['timeout']);
	}
}
