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
 * source line numbers and the raw, inline-comment-stripped pattern.
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
	private static function errors(string $contents, bool $regexCap = FALSE, ?string $python = null, ?string $timeout = null, ?string $script = null): array
	{
		return pfb_dnsbl_regex_validation_errors(
			$contents,
			$python ?? self::$python,
			$regexCap,
			$timeout ?? self::$timeout,
			$script
		);
	}

	private static function oneError(string $contents, bool $regexCap = FALSE): string
	{
		$errors = self::errors($contents, $regexCap);
		return $errors[0] ?? 'missing validator diagnostic';
	}

	private static function anchoredPattern(int $length): string
	{
		if ($length < 2) {
			throw new InvalidArgumentException('length must be >= 2 to hold both anchors');
		}
		return '^' . str_repeat('a', $length - 2) . '$';
	}

	// issue #1688 red-before proof: the save-time validator has no length-cap concept
	// yet, so an over-length-but-otherwise-safe pattern is silently accepted here even
	// though pfb_unbound.py drops it at load once "Limit long/complex regex" is on.
	public function testOverLengthPatternIsRejectedOnceTheSaveTimeCapExists(): void
	{
		$pattern = self::anchoredPattern(201);
		$error = self::oneError($pattern . "\n", TRUE);
		$this->assertStringContainsString('line 1:', $error);
		$this->assertStringContainsString('200-character length cap', $error);
	}

	public function testOverLengthPatternAloneIsAcceptedWithoutACapConcept(): void
	{
		$pattern = self::anchoredPattern(201);
		$this->assertSame([], self::errors($pattern . "\n"), 'over-length alone is not a rejection reason yet');
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
		$this->assertStringContainsString("'(?R)'", $errors[0]);
		$this->assertStringContainsString('Python', $errors[0]);
	}

	public function testUppercaseNamedGroupIsAcceptedWithoutResolverLowercasing(): void
	{
		$this->assertSame([], self::errors("(?P<X>A)\n"));
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
		$this->assertStringContainsString("'{$pattern}'", $error);
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

	public function testMissingRulesModuleFailsClosed(): void
	{
		// issue #1765: the probe is a shipped script now, not an embedded nowdoc --
		// pin the guard that fires when it is absent. Injected through the same
		// test seam the interpreter and the timeout launcher already use, so the
		// tracked production file is never touched (an interrupted run must not be
		// able to leave the shipped module renamed out of the tree).
		$missing = sys_get_temp_dir() . '/pfb_absent_rules_' . bin2hex(random_bytes(6)) . '.py';
		$this->assertFileDoesNotExist($missing);
		$this->assertSame(
			['Python regex validator: rules module unavailable'],
			self::errors("^ads\\.example\\.com$\n", FALSE, null, null, $missing)
		);
	}

	public function testUnusableRulesModulePathFailsClosedInsteadOfSpawningPython(): void
	{
		// A DIRECTORY is readable, so an is_readable()-only guard would fall through
		// and hand the path to the interpreter, surfacing a generic launcher/exit
		// diagnostic instead of the specific one. The guard must require a FILE.
		$directory = sys_get_temp_dir() . '/pfb_rules_dir_' . bin2hex(random_bytes(6));
		$this->assertTrue(mkdir($directory));
		try {
			$this->assertDirectoryIsReadable($directory);
			$this->assertSame(
				['Python regex validator: rules module unavailable'],
				self::errors("^ads\\.example\\.com$\n", FALSE, null, null, $directory)
			);
		} finally {
			rmdir($directory);
		}
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

	// --- issue #1688: save-time length cap matches the resolver's REGEX_STATIC_LEN_CAP ---

	public function testExactlyTwoHundredCharactersIsAcceptedWhenTheCapIsOn(): void
	{
		$pattern = self::anchoredPattern(200);
		$this->assertSame([], self::errors($pattern . "\n", TRUE), 'the cap compares with >, so exactly 200 is still admissible');
	}

	public function testExactlyTwoHundredOneCharactersIsRejectedWhenTheCapIsOn(): void
	{
		$pattern = self::anchoredPattern(201);
		$error = self::oneError($pattern . "\n", TRUE);
		$this->assertStringContainsString('line 1:', $error);
		$this->assertStringContainsString('200-character length cap', $error);
	}

	/** @return array<string, array{string}> */
	public static function preStrippingLengthProvider(): array
	{
		return [
			'long trailing comment, short pattern' => ['^ads$ # ' . str_repeat('x', 250)],
			'leading whitespace padding' => [str_repeat(' ', 250) . '^ads$'],
		];
	}

	#[DataProvider('preStrippingLengthProvider')]
	public function testLengthIsMeasuredAfterCommentStripAndTrim(string $line): void
	{
		$this->assertGreaterThan(200, strlen($line), 'fixture must be over-length before stripping, to prove parity');
		$this->assertSame(
			[],
			self::errors($line . "\n", TRUE),
			'the resolver measures the stripped/trimmed pattern, not the raw line'
		);
	}

	public function testOverLengthAndCatastrophicShapeReportsTheShapeFirst(): void
	{
		$pattern = '(' . str_repeat('a', 250) . '+)+';
		$this->assertGreaterThan(200, strlen($pattern));
		$error = self::oneError($pattern . "\n", TRUE);
		$this->assertStringContainsString('catastrophic-backtracking shape', $error);
		$this->assertStringNotContainsString('length cap', $error);
	}

	public function testOverLengthAndOverBudgetReportsTheBudgetFirst(): void
	{
		$labels = array_map(static fn (int $i): string => str_repeat(chr(97 + $i), 15), range(0, 13));
		$pattern = implode('|', $labels);
		$this->assertGreaterThan(200, strlen($pattern));
		$error = self::oneError($pattern . "\n", TRUE);
		$this->assertStringContainsString('too many quantifiers/alternations', $error);
		$this->assertStringNotContainsString('length cap', $error);
	}

	public function testOverLengthAndMalformedReportsTheLengthCapFirst(): void
	{
		$pattern = '(unclosed' . str_repeat('a', 200);
		$this->assertGreaterThan(200, strlen($pattern));
		$error = self::oneError($pattern . "\n", TRUE);
		$this->assertStringContainsString('200-character length cap', $error);
		$this->assertStringNotContainsString('compile error', $error);
	}

	public function testOnlyTheOverLengthLineIsReportedAmongMultipleLines(): void
	{
		$contents = "^short1$\n" . self::anchoredPattern(201) . "\n^short2$\n";
		$errors = self::errors($contents, TRUE);
		$this->assertCount(1, $errors);
		$this->assertStringContainsString('line 2:', $errors[0]);
		$this->assertStringContainsString('200-character length cap', $errors[0]);
	}

	#[DataProvider('catastrophicShapeProvider')]
	public function testCatastrophicShapeIsRejectedRegardlessOfTheCapSetting(string $pattern): void
	{
		$error = self::oneError($pattern . "\n", TRUE);
		$this->assertStringContainsString('line 1:', $error);
		$this->assertStringContainsString('catastrophic-backtracking shape', $error);
	}

	#[DataProvider('benignProvider')]
	public function testBenignPatternIsAcceptedRegardlessOfTheCapSetting(string $pattern): void
	{
		$this->assertSame([], self::errors($pattern . "\n", TRUE), "{$pattern} must be accepted even with the cap on");
	}

	public function testEmptyContentsShortCircuitsWithoutSpawningAPythonProcess(): void
	{
		$errors = pfb_dnsbl_regex_validation_errors('', '/path/that/does/not/exist/python', TRUE);
		$this->assertSame([], $errors, 'an unusable python path would surface as an error if the short-circuit did not fire first');
	}

	public function testOverLengthPatternWithShellMetacharactersIsRejectedSafely(): void
	{
		$hostile = 'ads$(rm -rf /)`id`\'"\\' . str_repeat('a', 200);
		$this->assertGreaterThan(200, strlen($hostile));
		$error = self::oneError($hostile . "\n", TRUE);
		$this->assertStringContainsString('line 1:', $error);
		$this->assertStringContainsString('200-character length cap', $error);
	}

	public function testControlCharacterWinsOverLengthWhenBothPresent(): void
	{
		$pattern = "^ads\x00" . str_repeat('a', 210) . '$';
		$this->assertGreaterThan(200, strlen($pattern));
		$error = self::oneError($pattern . "\n", TRUE);
		$this->assertStringContainsString('control', strtolower($error));
		$this->assertStringNotContainsString('length cap', $error);
	}

	public function testHundredThousandCharacterLineIsRejectedByLengthCap(): void
	{
		$pattern = self::anchoredPattern(100000);
		$error = self::oneError($pattern . "\n", TRUE);
		$this->assertStringContainsString('200-character length cap', $error);
	}

	public function testProbeDefaultsCapOffWhenTheArgvFlagIsAbsent(): void
	{
		// issue #1765: the probe is the shipped pfb_dnsbl_regex_rules.py script now,
		// not an embedded nowdoc -- invoke it directly, with no argv[1].
		$script = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfb_dnsbl_regex_rules.py';
		$this->assertFileIsReadable($script);

		$descriptors = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
		$process = proc_open([self::$python, $script], $descriptors, $pipes);
		$this->assertIsResource($process);
		fwrite($pipes[0], self::anchoredPattern(300) . "\n");
		fclose($pipes[0]);
		$stdout = stream_get_contents($pipes[1]);
		$stderr = stream_get_contents($pipes[2]);
		fclose($pipes[1]);
		fclose($pipes[2]);
		$exitCode = proc_close($process);

		$this->assertSame(0, $exitCode, "probe must not crash on a missing argv flag; stderr: {$stderr}");
		$this->assertSame('', trim($stderr));
		$this->assertSame('', trim($stdout));
	}
}
