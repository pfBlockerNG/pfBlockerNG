<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Tests for the issue #1732 lint-endpoint diagnostic pipeline
 * (pfblockerng_extra.inc): the pure sh/py/regex stderr parsers, the shared
 * proc_open launcher, the per-lang diagnostic runners, and the dispatcher.
 *
 * Real /bin/sh differs across dev hosts (macOS ships bash as /bin/sh), so the
 * sh/py runner tests never rely on the host interpreter's own diagnostic
 * format -- they point $sh/$python/$timeout_bin at small fixture scripts
 * that emit pinned stderr/exit combinations instead (mirrors
 * DnsblRegexEntryErrorTest's python-wrapper technique).
 */
#[CoversFunction('pfb_lint_parse_sh_stderr')]
#[CoversFunction('pfb_lint_parse_py_stderr')]
#[CoversFunction('pfb_lint_parse_regex_errors')]
#[CoversFunction('pfb_lint_probe_run')]
#[CoversFunction('pfb_lint_sh_diagnostics')]
#[CoversFunction('pfb_lint_py_diagnostics')]
#[CoversFunction('pfb_lint_diagnostics')]
final class LintDiagnosticsTest extends TestCase
{
	private static string $python;
	private static string $timeout;

	/** @var list<string> tmp fixture paths to unlink in tearDown */
	private array $fixtures = [];

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

	protected function tearDown(): void
	{
		foreach ($this->fixtures as $path) {
			@unlink($path);
		}
		$this->fixtures = [];
		parent::tearDown();
	}

	/** Writes an executable `#!/bin/sh` fixture that runs $body verbatim. */
	private function fixture(string $body): string
	{
		$path = sys_get_temp_dir() . '/pfb_lint_fixture_' . getmypid() . '_' . bin2hex(random_bytes(4));
		file_put_contents($path, "#!/bin/sh\n{$body}\n");
		chmod($path, 0700);
		$this->fixtures[] = $path;
		return $path;
	}

	/**
	 * A fake `timeout` that consumes stdin before exiting. A fixture that exits without
	 * reading races the probe's write loop: when the child wins, the write EPIPEs and the
	 * probe reports a launch failure instead of the exit code under test.
	 */
	private function drainingFixture(string $body): string
	{
		return $this->fixture("cat >/dev/null\n{$body}");
	}

	// --- pfb_lint_parse_sh_stderr ---------------------------------------

	public function testShParserExtractsLineMappedSyntaxError(): void
	{
		$stderr = '/dev/stdin: 2: Syntax error: end of file unexpected (expecting "fi")';
		$this->assertSame(
			[['line' => 2, 'message' => 'Syntax error: end of file unexpected (expecting "fi")', 'severity' => 'error']],
			pfb_lint_parse_sh_stderr($stderr)
		);
	}

	public function testShParserPreservesDetailWithColonsAndParens(): void
	{
		$stderr = '/dev/stdin: 5: Syntax error: unexpected "fi" (expecting: "then")';
		$this->assertSame(
			[['line' => 5, 'message' => 'Syntax error: unexpected "fi" (expecting: "then")', 'severity' => 'error']],
			pfb_lint_parse_sh_stderr($stderr)
		);
	}

	public function testShParserHandlesMultiLineStderr(): void
	{
		$stderr = "/dev/stdin: 1: Syntax error: bad substitution\n/dev/stdin: 3: Syntax error: unexpected end of file";
		$this->assertSame(
			[
				['line' => 1, 'message' => 'Syntax error: bad substitution', 'severity' => 'error'],
				['line' => 3, 'message' => 'Syntax error: unexpected end of file', 'severity' => 'error'],
			],
			pfb_lint_parse_sh_stderr($stderr)
		);
	}

	public function testShParserDegradesUnmatchedStderrToLineOneDiagnostic(): void
	{
		$this->assertSame(
			[['line' => 1, 'message' => 'some garbage', 'severity' => 'error']],
			pfb_lint_parse_sh_stderr("some garbage\n")
		);
	}

	public function testShParserEmptyStderrReturnsEmptyArray(): void
	{
		$this->assertSame([], pfb_lint_parse_sh_stderr(''));
	}

	// --- pfb_lint_parse_py_stderr ----------------------------------------

	public function testPyParserExtractsLineMappedSyntaxError(): void
	{
		$this->assertSame(
			[['line' => 2, 'message' => 'invalid syntax', 'severity' => 'error']],
			pfb_lint_parse_py_stderr('line 2: invalid syntax')
		);
	}

	public function testPyParserDegradesUnmatchedStderrToLineOneDiagnostic(): void
	{
		$this->assertSame(
			[['line' => 1, 'message' => 'boom', 'severity' => 'error']],
			pfb_lint_parse_py_stderr("boom\n")
		);
	}

	public function testPyParserEmptyStderrReturnsEmptyArray(): void
	{
		$this->assertSame([], pfb_lint_parse_py_stderr(''));
	}

	// --- pfb_lint_parse_regex_errors --------------------------------------

	public function testRegexParserMapsLineAndMessage(): void
	{
		$this->assertSame(
			[['line' => 3, 'message' => "'foo(': missing ), unterminated subpattern at position 3", 'severity' => 'error']],
			pfb_lint_parse_regex_errors(["line 3: 'foo(': missing ), unterminated subpattern at position 3"])
		);
	}

	public function testRegexParserTreatsInfraStringsAsLineOneWarning(): void
	{
		$this->assertSame(
			[['line' => 1, 'message' => 'Python regex validator: interpreter unavailable', 'severity' => 'warning']],
			pfb_lint_parse_regex_errors(['Python regex validator: interpreter unavailable'])
		);
	}

	public function testRegexParserMixedListProducesBothShapes(): void
	{
		$this->assertSame(
			[
				['line' => 3, 'message' => "'foo(': missing ), unterminated subpattern at position 3", 'severity' => 'error'],
				['line' => 1, 'message' => 'Python regex validator: interpreter unavailable', 'severity' => 'warning'],
			],
			pfb_lint_parse_regex_errors([
				"line 3: 'foo(': missing ), unterminated subpattern at position 3",
				'Python regex validator: interpreter unavailable',
			])
		);
	}

	// --- pfb_lint_sh_diagnostics ------------------------------------------

	public function testShDiagnosticsEmptyContentShortCircuits(): void
	{
		$this->assertSame([], pfb_lint_sh_diagnostics('', '/nonexistent/sh', '/nonexistent/timeout'));
	}

	public function testShDiagnosticsParsesPinnedFixtureStderr(): void
	{
		// \n sits in the FORMAT string (before the %s value) so printf(1) expands it to a
		// real newline -- a \n glued onto the end of the %s-substituted VALUE itself is
		// never escape-processed and would ship as a literal backslash-n.
		$timeoutFixture = $this->drainingFixture(<<<'SH'
			printf '%s\n' '/dev/stdin: 2: Syntax error: end of file unexpected (expecting "fi")' 1>&2
			exit 2
			SH);
		$shFixture = $this->fixture('exit 0'); // never actually exec'd -- the fake timeout ignores argv
		$this->assertSame(
			[['line' => 2, 'message' => 'Syntax error: end of file unexpected (expecting "fi")', 'severity' => 'error']],
			pfb_lint_sh_diagnostics("if true; then\n", $shFixture, $timeoutFixture)
		);
	}

	public function testShDiagnosticsSilentZeroExitIsEmpty(): void
	{
		$timeoutFixture = $this->drainingFixture('exit 0');
		$shFixture = $this->fixture('exit 0');
		$this->assertSame([], pfb_lint_sh_diagnostics("echo ok\n", $shFixture, $timeoutFixture));
	}

	public function testShDiagnosticsMissingShIsLineOneWarning(): void
	{
		$timeoutFixture = $this->fixture('exit 0');
		$diagnostics = pfb_lint_sh_diagnostics("echo ok\n", '/nonexistent/sh', $timeoutFixture);
		$this->assertCount(1, $diagnostics);
		$this->assertSame(1, $diagnostics[0]['line']);
		$this->assertSame('warning', $diagnostics[0]['severity']);
	}

	public function testShDiagnosticsMissingTimeoutIsLineOneWarning(): void
	{
		$shFixture = $this->fixture('exit 0');
		$diagnostics = pfb_lint_sh_diagnostics("echo ok\n", $shFixture, '/nonexistent/timeout');
		$this->assertCount(1, $diagnostics);
		$this->assertSame(1, $diagnostics[0]['line']);
		$this->assertSame('warning', $diagnostics[0]['severity']);
	}

	public function testShDiagnosticsNonzeroExitWithEmptyStderrIsLineOneWarning(): void
	{
		$timeoutFixture = $this->drainingFixture('exit 5'); // e.g. timeout SIGTERM: nonzero, nothing on stderr
		$shFixture = $this->fixture('exit 0');
		$diagnostics = pfb_lint_sh_diagnostics("sleep 100\n", $shFixture, $timeoutFixture);
		$this->assertCount(1, $diagnostics);
		$this->assertSame(1, $diagnostics[0]['line']);
		$this->assertSame('warning', $diagnostics[0]['severity']);
		$this->assertStringContainsString('5', $diagnostics[0]['message']);
	}

	public function testShDiagnosticsRealShAndTimeoutAcceptValidScript(): void
	{
		$this->assertSame([], pfb_lint_sh_diagnostics("echo ok\n", '/bin/sh', self::$timeout));
	}

	public function testShDiagnosticsStdinWriteFailurePrefersParseableStderr(): void
	{
		// sh exits at the FIRST syntax error -- a body over the OS pipe buffer (~64KiB)
		// EPIPEs the stdin write loop while stderr already holds a line-mapped
		// diagnostic. The fake "timeout_bin" closes stdin immediately and writes that
		// diagnostic before exiting; $shFixture is never actually exec'd (ignored argv,
		// same technique as the pinned-fixture tests above).
		$timeoutFixture = $this->fixture(
			'exec 0<&-' . "\n" .
			'printf "/dev/stdin: 1: Syntax error: early exit\n" 1>&2' . "\n" .
			'exit 2'
		);
		$shFixture = $this->fixture('exit 0');
		// ~256KiB: over the OS pipe buffer, under the endpoint's 1MiB cap.
		$content = str_repeat('x', 300000) . "\n";
		$this->assertSame(
			[['line' => 1, 'message' => 'Syntax error: early exit', 'severity' => 'error']],
			pfb_lint_sh_diagnostics($content, $shFixture, $timeoutFixture)
		);
	}

	// --- pfb_lint_py_diagnostics -------------------------------------------

	public function testPyDiagnosticsEmptyContentShortCircuits(): void
	{
		$this->assertSame([], pfb_lint_py_diagnostics('', '/nonexistent/python', '/nonexistent/timeout'));
	}

	public function testPyDiagnosticsParsesPinnedFixtureStderr(): void
	{
		$timeoutFixture = $this->drainingFixture('printf "line 2: invalid syntax\n" 1>&2' . "\n" . 'exit 1');
		$pythonFixture = $this->fixture('exit 0'); // never actually exec'd -- the fake timeout ignores argv
		$this->assertSame(
			[['line' => 2, 'message' => 'invalid syntax', 'severity' => 'error']],
			pfb_lint_py_diagnostics("x = 1\ndef f(:\n", $pythonFixture, $timeoutFixture)
		);
	}

	public function testPyDiagnosticsSilentZeroExitIsEmpty(): void
	{
		$timeoutFixture = $this->drainingFixture('exit 0');
		$pythonFixture = $this->fixture('exit 0');
		$this->assertSame([], pfb_lint_py_diagnostics("print('ok')\n", $pythonFixture, $timeoutFixture));
	}

	public function testPyDiagnosticsStdinWriteFailurePrefersParseableStderr(): void
	{
		// The probe compiles what it reads, so a body over the OS pipe buffer (~64KiB) can
		// EPIPE the stdin write loop while stderr already holds the SyntaxError's line.
		// The fake "timeout_bin" closes stdin immediately and writes that diagnostic
		// before exiting; $pythonFixture is never actually exec'd (ignored argv).
		$timeoutFixture = $this->fixture(
			'exec 0<&-' . "\n" .
			'printf "line 2: invalid syntax\n" 1>&2' . "\n" .
			'exit 1'
		);
		$pythonFixture = $this->fixture('exit 0');
		// ~256KiB: over the OS pipe buffer, under the endpoint's 1MiB cap.
		$content = str_repeat('x', 300000) . "\n";
		$this->assertSame(
			[['line' => 2, 'message' => 'invalid syntax', 'severity' => 'error']],
			pfb_lint_py_diagnostics($content, $pythonFixture, $timeoutFixture)
		);
	}

	public function testPyDiagnosticsMissingPythonIsLineOneWarning(): void
	{
		$timeoutFixture = $this->fixture('exit 0');
		$diagnostics = pfb_lint_py_diagnostics("print('ok')\n", '/nonexistent/python', $timeoutFixture);
		$this->assertCount(1, $diagnostics);
		$this->assertSame(1, $diagnostics[0]['line']);
		$this->assertSame('warning', $diagnostics[0]['severity']);
	}

	public function testPyDiagnosticsMissingTimeoutIsLineOneWarning(): void
	{
		$pythonFixture = $this->fixture('exit 0');
		$diagnostics = pfb_lint_py_diagnostics("print('ok')\n", $pythonFixture, '/nonexistent/timeout');
		$this->assertCount(1, $diagnostics);
		$this->assertSame(1, $diagnostics[0]['line']);
		$this->assertSame('warning', $diagnostics[0]['severity']);
	}

	public function testPyDiagnosticsNonzeroExitWithEmptyStderrIsLineOneWarning(): void
	{
		$timeoutFixture = $this->drainingFixture('exit 5');
		$pythonFixture = $this->fixture('exit 0');
		$diagnostics = pfb_lint_py_diagnostics("print('ok')\n", $pythonFixture, $timeoutFixture);
		$this->assertCount(1, $diagnostics);
		$this->assertSame(1, $diagnostics[0]['line']);
		$this->assertSame('warning', $diagnostics[0]['severity']);
		$this->assertStringContainsString('5', $diagnostics[0]['message']);
	}

	public function testPyDiagnosticsRealPythonAndTimeoutAcceptValidScript(): void
	{
		$this->assertSame([], pfb_lint_py_diagnostics("print('ok')\n", self::$python, self::$timeout));
	}

	public function testPyDiagnosticsRealPythonAndTimeoutReportSyntaxError(): void
	{
		$diagnostics = pfb_lint_py_diagnostics("x = 1\ndef f(:\n", self::$python, self::$timeout);
		$this->assertCount(1, $diagnostics);
		$this->assertSame(2, $diagnostics[0]['line']);
		$this->assertSame('error', $diagnostics[0]['severity']);
		$this->assertNotSame('', $diagnostics[0]['message']);
	}

	// --- pfb_lint_diagnostics dispatcher -----------------------------------

	public function testDispatcherEmptyContentFastPathForEveryLang(): void
	{
		$this->assertSame([], pfb_lint_diagnostics('sh', '', false));
		$this->assertSame([], pfb_lint_diagnostics('py', '', false));
		$this->assertSame([], pfb_lint_diagnostics('regex', '', false));
	}

	public function testDispatcherRegexValidContentIsEmpty(): void
	{
		$this->assertSame(
			[],
			pfb_lint_diagnostics('regex', "^ads\\.example\\.com$\n", false, self::$python, null, self::$timeout)
		);
	}

	public function testDispatcherRegexSyntaxErrorIsLineMapped(): void
	{
		$diagnostics = pfb_lint_diagnostics('regex', "(unclosed\n", false, self::$python, null, self::$timeout);
		$this->assertCount(1, $diagnostics);
		$this->assertSame(1, $diagnostics[0]['line']);
		$this->assertSame('error', $diagnostics[0]['severity']);
		$this->assertStringContainsString("'(unclosed'", $diagnostics[0]['message']);
		// issue #3194: the Regex Exceptions holding pen is gone, so the diagnostic must
		// not offer to move the line into it -- help text pointing at a field that does
		// not exist is worse than no help at all.
		$this->assertDoesNotMatchRegularExpression(
			'/Regex Exceptions|cannot be moved|will never match/i',
			$diagnostics[0]['message']
		);
	}

	public function testDispatcherRegexInfraFailureIsLineOneWarning(): void
	{
		$diagnostics = pfb_lint_diagnostics('regex', "^ads\\.\n", false, '', null, self::$timeout);
		$this->assertSame(
			[['line' => 1, 'message' => 'Python regex validator: interpreter unavailable', 'severity' => 'warning']],
			$diagnostics
		);
	}

	public function testDispatcherFoldsCrlfBeforeReachingTheShPath(): void
	{
		$crDetector = $this->fixture(
			'cr=$(printf "\\r")' . "\n" .
			'if cat | grep -Fq "$cr"; then' . "\n" .
			'  printf "FOUND_CR\n" 1>&2' . "\n" .
			'  exit 2' . "\n" .
			'fi' . "\n" .
			'exit 0'
		);
		$shFixture = $this->fixture('exit 0');

		// Control: calling the sh runner DIRECTLY (no fold) on CRLF content proves the
		// detector fixture actually fires -- otherwise a silent false-negative below
		// would prove nothing.
		$this->assertSame(
			[['line' => 1, 'message' => 'FOUND_CR', 'severity' => 'error']],
			pfb_lint_sh_diagnostics("do\r\n", $shFixture, $crDetector)
		);

		// The dispatcher folds CRLF -> LF before content ever reaches the sh runner
		// (CodeMirror ships LF; a hand-crafted CRLF POST must not shift line numbers).
		$this->assertSame(
			[],
			pfb_lint_diagnostics('sh', "do\r\n", false, null, $shFixture, $crDetector)
		);
	}

	public function testDispatcherSanitizesControlBytesBeforeReachingTheShPath(): void
	{
		// Same fixture technique as the CRLF-fold test above: a fake "timeout_bin" that
		// greps its stdin for a literal DEL (\x7F) byte and, if found, reports a marker
		// diagnostic instead of running the real fixture. If the dispatcher's sanitizer
		// ever regresses to the old CRLF-only fold, this fires -- proving the fold saw
		// the raw control byte.
		$delDetector = $this->fixture(
			'del=$(printf \'\\177\')' . "\n" .
			'if cat | grep -Fq "$del"; then' . "\n" .
			'  printf "FOUND_DEL\n" 1>&2' . "\n" .
			'  exit 2' . "\n" .
			'fi' . "\n" .
			'printf "/dev/stdin: 2: Syntax error: unexpected end of file\n" 1>&2' . "\n" .
			'exit 2'
		);
		$shFixture = $this->fixture('exit 0');

		// Control: calling the sh runner DIRECTLY (no sanitize) on control-byte content
		// proves the detector fixture actually fires -- otherwise a silent false-negative
		// below would prove nothing.
		$this->assertSame(
			[['line' => 1, 'message' => 'FOUND_DEL', 'severity' => 'error']],
			pfb_lint_sh_diagnostics("foo\x7Fbar\ndo\n", $shFixture, $delDetector)
		);

		// The dispatcher sanitizes via the shared pfb_sanitize_text_area() helper before
		// content ever reaches the sh runner -- the DEL byte never reaches the detector,
		// and the line-2 diagnostic's line number stays 2 (the sanitizer preserves line
		// count: it never joins/removes lines, only strips control bytes and right-trims).
		$this->assertSame(
			[['line' => 2, 'message' => 'Syntax error: unexpected end of file', 'severity' => 'error']],
			pfb_lint_diagnostics('sh', "foo\x7Fbar\ndo\n", false, null, $shFixture, $delDetector)
		);
	}
}
