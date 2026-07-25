<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Tests for pfb_dnsbl_regex_validation_errors() (issue #1656).
 *
 * The DNSBL custom-list validator makes one bounded Python re pass over the
 * original form text. Python reports only rejected entries on stderr, retaining
 * source line numbers and the lowercased, inline-comment-stripped pattern.
 */
#[CoversFunction('pfb_dnsbl_regex_validation_errors')]
final class DnsblRegexEntryErrorTest extends TestCase
{
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
	private static function errors(string $contents, bool $regexCap = FALSE, ?string $python = null, ?string $timeout = null): array
	{
		return pfb_dnsbl_regex_validation_errors(
			$contents,
			$python ?? self::$python,
			$regexCap,
			$timeout ?? self::$timeout
		);
	}

	private static function oneError(string $contents, bool $regexCap = FALSE): string
	{
		$errors = self::errors($contents, $regexCap);
		return $errors[0] ?? 'missing validator diagnostic';
	}

	/** @return array<string, array{string}> */
	public static function catastrophicShapeProvider(): array
	{
		return [
			'nested quantifier (a+)+'           => ['(a+)+$'],
			'nested quantifier (\\w+\\.)+'      => ['(\\w+\\.)+bad'],
			'alternation overlap (a|ab)*'       => ['(a|ab)*'],
			// The resolver's alternation guard is deliberately conservative:
			// it drops ANY quantified single-group alternation, disjoint included.
			'disjoint quantified alternation'   => ['(foo|bar)+'],
			'disjoint bounded alternation'      => ['(a|b){3}'],
			'adjacent quantified groups'        => ['(a+)(a+)+'],
			'stacked bounded repeats'           => ['a{1000}{1000}'],
		];
	}

	#[DataProvider('catastrophicShapeProvider')]
	public function testCatastrophicShapeIsRejected(string $pattern): void
	{
		$error = self::oneError($pattern . "\n");
		$this->assertStringContainsString('line 1:', $error);
		$this->assertStringContainsString('catastrophic-backtracking shape', $error);
	}

	public function testThirteenAlternationsExceedBudgetAndAreRejected(): void
	{
		$pattern = 'a|b|c|d|e|f|g|h|i|j|k|l|m|n';
		$error = self::oneError($pattern . "\n");
		$this->assertStringContainsString('line 1:', $error);
		$this->assertStringContainsString('too many quantifiers/alternations', $error);
	}

	public function testTwelveAlternationsAreWithinBudgetAndAccepted(): void
	{
		$pattern = 'a|b|c|d|e|f|g|h|i|j|k|l|m';
		$this->assertSame([], self::errors($pattern . "\n"), '12 alternations are within the resolver budget');
	}

	public function testEscapedQuantifiersDoNotCountTowardTheBudget(): void
	{
		$pattern = 'a\+b\*c\|d\+e\*f\|g\+h\*i\|j\+k\*l\|m\+n';
		$this->assertSame([], self::errors($pattern . "\n"), 'escaped +, * and | are literals, not budget');
	}

	/** @return array<string, array{string, string}> */
	public static function malformedProvider(): array
	{
		return [
			'unterminated group' => ['(unclosed', 'unterminated subpattern'],
			'unterminated class' => ['[a-', 'unterminated character set'],
		];
	}

	#[DataProvider('malformedProvider')]
	public function testMalformedPatternIncludesPatternAndPythonDetail(string $pattern, string $detail): void
	{
		$error = self::oneError($pattern . "\n");
		$this->assertStringContainsString('line 1:', $error);
		$this->assertStringContainsString("'{$pattern}'", $error);
		$this->assertStringContainsString($detail, $error, "{$pattern} must include Python's compile detail");
	}

	public function testOriginalLineNumbersAndFormCommentSemanticsArePreserved(): void
	{
		$contents = "\n# comment-only\n^Ads\\.Example$ # inline comment\n\n(?R) # recursive\n";
		$errors = self::errors($contents);

		$this->assertCount(1, $errors);
		$this->assertStringContainsString('line 5:', $errors[0]);
		$this->assertStringContainsString("'(?r)'", $errors[0]);
		$this->assertStringContainsString('Python', $errors[0]);
	}

	public function testUppercaseNamedGroupIsRejectedAfterResolverLowercases(): void
	{
		$error = self::oneError("(?P<X>A)\n");
		$this->assertStringContainsString('line 1:', $error);
		$this->assertStringContainsString("'(?p<x>a)'", $error);
		$this->assertStringContainsString('unknown extension', $error);
	}

	/** @return array<string, array{string}> */
	public static function pythonOnlyProvider(): array
	{
		return [
			'unicode flag' => ['(?u)\\w+'],
			'unicode scoped flag' => ['(?u:\\w+)'],
		];
	}

	#[DataProvider('pythonOnlyProvider')]
	public function testPythonOnlySyntaxIsAccepted(string $pattern): void
	{
		$this->assertSame([], self::errors($pattern . "\n"), "{$pattern} is valid Python regex syntax");
	}

	/** @return array<string, array{string}> */
	public static function pcreOnlyProvider(): array
	{
		return [
			'recursive subpattern' => ['(?R)'],
			'branch reset group' => ['(?|a|b)'],
			'perl named group' => ['(?<name>a)'],
		];
	}

	#[DataProvider('pcreOnlyProvider')]
	public function testPcreOnlySyntaxIsRejectedByPython(string $pattern): void
	{
		$error = self::oneError($pattern . "\n");
		$this->assertStringContainsString('line 1:', $error);
		$this->assertStringContainsString("'" . strtolower($pattern) . "'", $error);
		$this->assertStringContainsString('Python', $error);
	}

	public function testOverflowIsReportedForItsLineOnly(): void
	{
		$contents = "^before$\na{999999999999999999999999999999999999}\n^after$\n";
		$errors = self::errors($contents);

		$this->assertCount(1, $errors);
		$this->assertStringContainsString('line 2:', $errors[0]);
		$this->assertStringContainsString("'a{999999999999999999999999999999999999}'", $errors[0]);
		$this->assertStringContainsString('repetition number is too large', $errors[0]);
	}

	/** @return array<string, array{string}> */
	public static function controlByteProvider(): array
	{
		return [
			'NUL' => ["^ads\x00$\n"],
			'SOH' => ["^ads\x01$\n"],
		];
	}

	#[DataProvider('controlByteProvider')]
	public function testAsciiControlBytesProduceSafeDiagnostics(string $contents): void
	{
		$errors = self::errors($contents);
		$this->assertCount(1, $errors);
		$this->assertStringContainsString('line 1:', $errors[0]);
		$this->assertStringContainsString('control', strtolower($errors[0]));
		$this->assertStringNotContainsString("\0", $errors[0]);
		$this->assertStringNotContainsString('ValueError', $errors[0]);
	}

	public function testMissingPythonAndTimeoutFailClosed(): void
	{
		$contents = "^ads\\.\n(?u)\\w+\n";
		$missingPython = self::errors($contents, FALSE, '', self::$timeout);
		$missingTimeout = self::errors($contents, FALSE, self::$python, '/path/that/does/not/exist/timeout');

		$this->assertNotSame([], $missingPython);
		$this->assertNotSame([], $missingTimeout);
		$this->assertStringContainsString('Python', implode('\n', $missingPython));
		$this->assertStringContainsString('Python', implode('\n', $missingTimeout));
	}

	public function testBatchUsesOnePythonLaunch(): void
	{
		$dir = sys_get_temp_dir() . '/pfb_regex_wrapper_' . getmypid() . '_' . bin2hex(random_bytes(3));
		mkdir($dir, 0700, TRUE);
		$marker = $dir . '/launches';
		$wrapper = $dir . '/python-wrapper';
		file_put_contents($wrapper, "#!/bin/sh\nprintf '%s\\n' launch >> " . escapeshellarg($marker) .
			"\nexec " . escapeshellarg(self::$python) . ' "$@"' . "\n");
		chmod($wrapper, 0700);
		try {
			$this->assertSame([], self::errors("^one$\n^two$\n(?u)\\w+\n", FALSE, $wrapper));
			$this->assertSame("launch\n", file_get_contents($marker));
		} finally {
			@unlink($wrapper);
			@unlink($marker);
			@rmdir($dir);
		}
	}

	public function testOneHundredBenignLinesAreAcceptedInOneBatch(): void
	{
		$contents = implode("\n", array_fill(0, 100, '^ads\\.example\\.com$')) . "\n";
		$this->assertSame([], self::errors($contents));
	}

	/** @return array<string, array{string}> */
	public static function benignProvider(): array
	{
		return [
			'simple anchor' => ['^ads\\.'],
			'realistic domain pattern' => ['^(.+\\.)?ads?[0-9]*\\.example\\.(com|net|org)$'],
			'unquantified alternation' => ['^(ads|track)\\.example\\.com$'],
			'contains a slash (delimiter)' => ['foo/bar'],
			'bounded repeat, single' => ['[a-z]{2,10}\\.example\\.com'],
		];
	}

	#[DataProvider('benignProvider')]
	public function testBenignPatternIsAccepted(string $pattern): void
	{
		$this->assertSame([], self::errors($pattern . "\n"), "{$pattern} must be accepted");
	}
}
