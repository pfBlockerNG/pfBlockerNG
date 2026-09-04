<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3088 — Regex List editor flags, Regex Exceptions holding pen, and
 * auto-return of lines the editor later accepts.
 *
 * There is no known Lezer-flag + Python-accept pattern on current grammars
 * after #3063. Move/PHP is proven with a posted Python-valid line in
 * exceptions, a posted Python-invalid line that must not save, and JS unit
 * coverage that '(' is a red editor flag with the Move action.
 */
#[CoversFunction('pfb_dnsbl_regex_python_reject_suffix')]
#[CoversFunction('pfb_dnsbl_regex_parse_flagged_lines')]
#[CoversFunction('pfb_dnsbl_regex_editor_save_errors')]
#[CoversFunction('pfb_dnsbl_regex_return_accepted_exceptions')]
#[CoversFunction('pfb_dnsbl_regex_resolver_blob')]
#[CoversFunction('pfb_dnsbl_regex_exceptions_upgrade')]
#[CoversFunction('pfb_dnsbl_regex_returned_notice')]
final class DnsblRegexExceptionListTest extends TestCase
{
	private const PYTHON_VALID = '^ads\\.example\\.com$';
	private const PYTHON_VALID_META = '(?i)evil\\.com';
	private const PYTHON_INVALID = '(';
	private const CATASTROPHIC = '(a+)+$';

	private static string $python;
	private static string $timeout;

	public static function setUpBeforeClass(): void
	{
		parent::setUpBeforeClass();
		self::$python = self::commandPath('python3');
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

	/** @return array<int, string> */
	private static function pythonErrors(string $contents, bool $regexCap = FALSE): array
	{
		return pfb_dnsbl_regex_validation_errors(
			$contents,
			self::$python,
			$regexCap,
			self::$timeout
		);
	}

	public function testPythonRejectSuffixSaysItCannotBeExcepted(): void
	{
		$suffix = pfb_dnsbl_regex_python_reject_suffix();
		$this->assertMatchesRegularExpression('/cannot be (moved to|excepted)/i', $suffix);
		$this->assertMatchesRegularExpression('/will never match/i', $suffix);
	}

	public function testRegistryRegistersTheExceptionListSibling(): void
	{
		$registry = pfb_cfg_registry();
		$this->assertArrayHasKey('dnsbl/pfb_regex_exception_list', $registry);
		$this->assertSame('', $registry['dnsbl/pfb_regex_exception_list']['default']);
		$this->assertNull($registry['dnsbl/pfb_regex_exception_list']['read_adapter']);
		$this->assertNull($registry['dnsbl/pfb_regex_exception_list']['write_adapter']);
		$this->assertSame('', PfbConfig::read('dnsbl/pfb_regex_exception_list'));
	}

	public function testParseFlaggedLinesKeepsUniquePositiveIntegers(): void
	{
		$this->assertSame([1, 3], pfb_dnsbl_regex_parse_flagged_lines('1,3,1'));
		$this->assertSame([], pfb_dnsbl_regex_parse_flagged_lines(''));
		$this->assertSame([], pfb_dnsbl_regex_parse_flagged_lines('0,-1,foo'));
		$this->assertSame([2, 4], pfb_dnsbl_regex_parse_flagged_lines(' 2 4 '));
	}

	public function testEditorFlaggedLineRemainingInMainFailsSaveAndNamesTheLine(): void
	{
		$errors = pfb_dnsbl_regex_editor_save_errors(self::PYTHON_VALID . "\n", [1]);
		$this->assertNotSame([], $errors, 'a remaining editor-flagged main-list line must block save');
		$this->assertStringContainsString('1', $errors[0]);
		$this->assertMatchesRegularExpression('/Regex Exceptions/i', $errors[0]);
	}

	public function testEmptyMainAndEmptyExceptionsHaveNoEditorSaveError(): void
	{
		$this->assertSame([], pfb_dnsbl_regex_editor_save_errors('', []));
		$this->assertSame([], pfb_dnsbl_regex_editor_save_errors("\n", []));
	}

	public function testDescriptionOverFifteenDoesNotProduceAnEditorSaveError(): void
	{
		$line = self::PYTHON_VALID . ' # this description is far too long';
		$this->assertSame([], pfb_dnsbl_regex_editor_save_errors($line . "\n", []));
		$this->assertSame([], self::pythonErrors($line . "\n"));
	}

	public function testPythonRejectOnMainFailsValidation(): void
	{
		$errors = self::pythonErrors(self::PYTHON_INVALID . "\n");
		$this->assertNotSame([], $errors);
		$this->assertStringContainsString('line 1:', $errors[0]);
	}

	public function testAutoReturnMovesEditorCleanPythonOkExceptionLines(): void
	{
		$result = pfb_dnsbl_regex_return_accepted_exceptions(
			self::PYTHON_VALID . "\n",
			self::PYTHON_VALID_META . "\n",
			[]
		);
		$this->assertSame(1, $result['returned']);
		$this->assertStringContainsString(self::PYTHON_VALID_META, $result['main']);
		$this->assertSame('', trim($result['exceptions']));
		$this->assertSame(
			'Returned 1 pattern(s) to the Regex List because the editor now accepts them.',
			pfb_dnsbl_regex_returned_notice(1)
		);
	}

	public function testAutoReturnLeavesStillFlaggedExceptionLines(): void
	{
		$result = pfb_dnsbl_regex_return_accepted_exceptions(
			'',
			self::PYTHON_VALID . "\n",
			[1]
		);
		$this->assertSame(0, $result['returned']);
		$this->assertStringContainsString(self::PYTHON_VALID, $result['exceptions']);
		$this->assertSame('', $result['main']);
	}

	public function testUnescapedHashCommentLinesAreNotAutoReturned(): void
	{
		$result = pfb_dnsbl_regex_return_accepted_exceptions(
			'',
			"# just a comment\n",
			[]
		);
		$this->assertSame(0, $result['returned']);
		$this->assertStringContainsString('# just a comment', $result['exceptions']);
	}

	public function testCatastrophicShapeFailsBothLists(): void
	{
		$errors = self::pythonErrors(self::CATASTROPHIC . "\n");
		$this->assertNotSame([], $errors);
		$this->assertStringContainsString('catastrophic-backtracking shape', $errors[0]);
	}

	public function testResolverBlobMergesMainThenExceptions(): void
	{
		$main = base64_encode(self::PYTHON_VALID);
		$exceptions = base64_encode(self::PYTHON_VALID_META);
		$blob = pfb_dnsbl_regex_resolver_blob($main, $exceptions);
		$this->assertNotSame('', $blob);
		$decoded = pfb_b64_text($blob);
		$this->assertSame(self::PYTHON_VALID . "\n" . self::PYTHON_VALID_META, $decoded);
	}

	public function testResolverBlobKeepsMainUnchangedWhenExceptionsAreEmpty(): void
	{
		$main = base64_encode(self::PYTHON_VALID);
		$this->assertSame($main, pfb_dnsbl_regex_resolver_blob($main, ''));
		$this->assertSame($main, pfb_dnsbl_regex_resolver_blob($main, null));
	}

	public function testResolverBlobIsEmptyWhenBothListsAreEmpty(): void
	{
		$this->assertSame('', pfb_dnsbl_regex_resolver_blob('', ''));
	}

	public function testInstallUpgradeReturnsEditorCleanPythonOkLines(): void
	{
		$main = base64_encode(self::PYTHON_VALID);
		$exceptions = base64_encode(self::PYTHON_VALID_META);
		$result = pfb_dnsbl_regex_exceptions_upgrade($main, $exceptions, []);
		$this->assertSame(1, $result['returned']);
		$this->assertFalse($result['python_rejects_remain']);
		$this->assertStringContainsString(self::PYTHON_VALID_META, pfb_b64_text($result['main_b64']));
		$this->assertSame('', trim(pfb_b64_text($result['exception_b64'])));
	}

	public function testInstallUpgradeKeepsPythonRejectsAndReportsThem(): void
	{
		$exceptions = base64_encode(self::PYTHON_INVALID);
		$result = pfb_dnsbl_regex_exceptions_upgrade('', $exceptions, ['line 1: missing ), unterminated subpattern']);
		$this->assertSame(0, $result['returned']);
		$this->assertTrue($result['python_rejects_remain']);
		$this->assertStringContainsString(self::PYTHON_INVALID, pfb_b64_text($result['exception_b64']));
	}

	public function testInstallUpgradeKeepsExceptionsWhenPythonErrorsHaveNoLineNumbers(): void
	{
		$main = base64_encode(self::PYTHON_VALID);
		$exceptions = base64_encode(self::PYTHON_INVALID . "\n" . self::PYTHON_VALID_META);
		$result = pfb_dnsbl_regex_exceptions_upgrade(
			$main,
			$exceptions,
			['Python regex validator: process failed with exit 127: interpreter unavailable']
		);
		$this->assertSame(0, $result['returned']);
		$this->assertTrue($result['python_rejects_remain']);
		$this->assertSame($main, $result['main_b64']);
		$this->assertSame($exceptions, $result['exception_b64']);
	}

	public function testDnsblPageRendersRegexExceptionsTextareaInTheRegexSection(): void
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php');
		$this->assertNotFalse($source);
		$regex = strpos($source, "new Form_Section('Regex List'");
		$noaaaa = strpos($source, "new Form_Section('no-AAAA List'");
		$this->assertNotFalse($regex);
		$this->assertNotFalse($noaaaa);
		$this->assertGreaterThan($regex, $noaaaa);
		$chunk = substr($source, $regex, $noaaaa - $regex);
		$this->assertStringContainsString("new Form_Textarea(\n\t'pfb_regex_exception_list'", $chunk);
		$this->assertStringContainsString("'Regex Exceptions'", $chunk);
	}

	public function testSanitizeLoopAndAsciiCheckCoverTheExceptionField(): void
	{
		$source = php_strip_whitespace(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php'
		);
		$this->assertStringContainsString("'pfb_regex_exception_list'", $source);
		$this->assertMatchesRegularExpression(
			"/foreach\s*\(\s*array\s*\([^)]*pfb_regex_exception_list[^)]*\)\s+as\s+\\\$pfb_text_area_field\s*\)/",
			$source
		);
		$this->assertStringContainsString(
			"mb_detect_encoding(\$_POST['pfb_regex_exception_list']",
			$source
		);
		$this->assertStringContainsString(
			"pfb_dnsbl_regex_validation_errors((string) (\$_POST['pfb_regex_exception_list']",
			$source
		);
		$this->assertStringContainsString(
			"pfb_dnsbl_regex_editor_save_errors( (string) (\$_POST['pfb_regex_list']",
			$source
		);
		$this->assertStringNotContainsString(
			"pfb_dnsbl_regex_editor_save_errors( (string) (\$_POST['pfb_regex_exception_list']",
			$source
		);
	}

	public function testAutoReturnOnSaveRunsOnlyAfterThePersistGate(): void
	{
		$source = php_strip_whitespace(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php'
		);
		$gate = strpos($source, 'if (!$input_errors)');
		$auto = strpos($source, 'pfb_dnsbl_regex_return_accepted_exceptions');
		$this->assertNotFalse($gate, 'expected the persist gate');
		$this->assertNotFalse($auto, 'expected auto-return on save');
		$this->assertGreaterThan(
			$gate,
			$auto,
			'auto-return must run only inside the successful-save branch'
		);
	}

	/** @return array<string, array{string}> */
	public static function pythonRejectProvider(): array
	{
		return [
			'unclosed group' => ['('],
			'trailing backslash' => ['\\'],
			'unclosed class' => ['['],
			'hash leftover group' => ['(#)'],
			'hash leftover class' => ['[#]'],
			'inline comment leftover' => ['(?#comment)'],
		];
	}

	#[DataProvider('pythonRejectProvider')]
	public function testHostilePythonRejectsFailValidationOnEitherList(string $pattern): void
	{
		$this->assertNotSame([], self::pythonErrors($pattern . "\n"), $pattern);
	}
}
