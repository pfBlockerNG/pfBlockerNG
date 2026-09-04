<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3194 — the real Python interpreter is the ONLY thing that may block a
 * Regex List save.
 *
 * The CodeMirror/Lezer checker is this package's own approximation of CPython
 * `re` syntax, so a line it cannot parse may be our bug; a user holding a valid
 * Python pattern must still be able to save it. #3192's editor-flag save gate,
 * its hidden `<name>_editor_flags` transport, and the Regex Exceptions holding
 * pen are therefore gone, and the editor's verdict has no path to
 * $input_errors at all.
 *
 * The DNSBL page carries top-level execution and cannot be require()d
 * off-appliance, so the save-path and form rows read the SHIPPED source
 * (DnsblTabLayoutUiTest's / DnsblFreshPconfigTest's pattern). Every absence
 * assertion is paired with a positive control on the same string, so a
 * mis-read or truncated file cannot satisfy it vacuously.
 */
#[CoversFunction('pfb_cfg_registry')]
#[CoversFunction('pfb_dnsbl_regex_validation_errors')]
final class DnsblRegexAdvisoryOnlyTest extends TestCase
{
	private const PAGE     = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php';
	private const CM_REGEX = __DIR__ . '/../../tools/webassets/cm-regex.js';

	private static string $python;
	private static string $timeout;

	public static function setUpBeforeClass(): void
	{
		parent::setUpBeforeClass();
		self::$python  = self::commandPath('python3');
		self::$timeout = self::commandPath('timeout');
	}

	private static function commandPath(string $command): string
	{
		$output = [];
		$status = 1;
		exec('command -v ' . escapeshellarg($command) . ' 2>/dev/null', $output, $status);
		if ($status !== 0 || $output === [] || trim($output[0]) === '') {
			throw new RuntimeException("required test command not found: {$command}");
		}
		return trim($output[0]);
	}

	private static function source(string $path): string
	{
		$src = file_get_contents($path);
		self::assertNotFalse($src, "test fixture unreadable: {$path}");
		return $src;
	}

	// ---- the config key is gone, and gone THROUGH the gateway ------------------

	public function testRegexExceptionsConfigKeyIsAbsentFromTheRegistry(): void
	{
		$registry = pfb_cfg_registry();
		$this->assertArrayHasKey(
			'dnsbl/pfb_regex_list',
			$registry,
			'positive control: the one surviving Regex List key stays registered'
		);
		$this->assertArrayNotHasKey('dnsbl/pfb_regex_exception_list', $registry);
	}

	public function testTheRetiredExceptionKeyIsUnreadableThroughTheGateway(): void
	{
		// ADR-29: an unregistered key throws rather than resolving to a default, so
		// a stale value left in a pre-alpha dev config cannot be read back by
		// accident. This is what makes the removal a gateway removal.
		$this->expectException(InvalidArgumentException::class);
		PfbConfig::read('dnsbl/pfb_regex_exception_list');
	}

	// ---- the editor's verdict has no path to a save gate -----------------------

	public function testTheSavePathHasNoEditorFlagReader(): void
	{
		$page = self::source(self::PAGE);
		$this->assertStringContainsString(
			'pfb_dnsbl_regex_validation_errors(',
			$page,
			'positive control: Python still validates the Regex List on save'
		);
		$this->assertStringNotContainsString(
			'editor_flags',
			$page,
			'no editor-supplied flag may be read on the save path'
		);
		$this->assertStringNotContainsString('pfb_dnsbl_regex_editor_save_errors', $page);
		$this->assertStringNotContainsString('pfb_dnsbl_regex_parse_flagged_lines', $page);
	}

	public function testTheEditorNeverEmitsAnEditorFlagsInput(): void
	{
		$src = self::source(self::CM_REGEX);
		$this->assertStringContainsString(
			'mountTextarea(',
			$src,
			'positive control: the regex textarea is still mounted'
		);
		$this->assertStringNotContainsString('_editor_flags', $src);
		$this->assertStringNotContainsString('flaggedLineNumbers', $src);
		$this->assertStringNotContainsString('getExceptionsView', $src);
	}

	public function testTheRegexExceptionsFieldIsGoneFromTheForm(): void
	{
		$page = self::source(self::PAGE);
		$this->assertStringContainsString(
			"new Form_Textarea(\n\t'pfb_regex_list',\n\t'Regex List'",
			$page,
			'positive control: the Regex List textarea still renders'
		);
		$this->assertStringNotContainsString('pfb_regex_exception_list', $page);
		$this->assertStringNotContainsString('Regex Exceptions', $page);
	}

	// ---- Python remains the gate, both directions ------------------------------

	public function testPythonStillBlocksAPatternItCannotCompile(): void
	{
		$errors = pfb_dnsbl_regex_validation_errors(
			"(unclosed\n",
			self::$python,
			FALSE,
			self::$timeout
		);
		$this->assertNotSame([], $errors, 'a pattern Python rejects must still block the save');
		$this->assertMatchesRegularExpression('/^line 1: /', $errors[0]);
		$this->assertStringContainsString('Python regex compile error', $errors[0]);
	}

	public function testPythonAcceptsAValidPatternSoNothingBlocksTheSave(): void
	{
		// The named-group + inline-flag + escaped-'#' shapes together are the ones a
		// hand-written outer grammar is most likely to mis-parse; Python compiles
		// them, so the save must go through with no diagnostic of any kind.
		$this->assertSame(
			[],
			pfb_dnsbl_regex_validation_errors(
				"(?i)^(?P<sub>[a-z0-9-]+\\.)?ads\\#tag\\.example\\.com$ # ads\n",
				self::$python,
				FALSE,
				self::$timeout
			)
		);
	}
}
