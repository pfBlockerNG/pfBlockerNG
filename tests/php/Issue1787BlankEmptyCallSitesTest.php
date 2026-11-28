<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #1787: call sites that answered "is this string blank/empty?" with a
 * flimsy idiom — empty() (which calls the valid row "0" empty) or
 * trim() === '' (which misses Unicode whitespace such as NBSP) — must give the
 * real answer via pfb_is_blank()/an exact '' match.
 *
 * Each test pins the corrected observable behaviour of one call site:
 *   - pfb_validate_suppression_line(): a Unicode-whitespace-only line is a
 *     blank no-op, not an "invalid subnet" input error.
 *   - pfb_lint_sh_diagnostics()/pfb_lint_py_diagnostics(): a stderr of only
 *     Unicode whitespace carries no diagnostic — degrade to the no-diagnostic/
 *     launch-failed warning instead of surfacing a whitespace "error".
 */
#[CoversFunction('pfb_validate_suppression_line')]
#[CoversFunction('pfb_lint_sh_diagnostics')]
#[CoversFunction('pfb_lint_py_diagnostics')]
final class Issue1787BlankEmptyCallSitesTest extends TestCase
{
	private const NBSP = "\u{00A0}";

	/** @var list<string> tmp fixture paths to unlink in tearDown */
	private array $fixtures = [];

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_resolve_map'] = [];
	}

	protected function tearDown(): void
	{
		foreach ($this->fixtures as $path) {
			@unlink($path);
		}
		$this->fixtures = [];
		unset($GLOBALS['config'], $GLOBALS['pfb_test_resolve_map']);
		parent::tearDown();
	}

	/** Writes an executable `#!/bin/sh` fixture that runs $body verbatim. */
	private function fixture(string $body): string
	{
		$path = sys_get_temp_dir() . '/pfb_1787_fixture_' . getmypid() . '_' . bin2hex(random_bytes(4));
		file_put_contents($path, "#!/bin/sh\n{$body}\n");
		chmod($path, 0700);
		$this->fixtures[] = $path;
		return $path;
	}

	// --- pfb_validate_suppression_line -----------------------------------

	public function testSuppressionLineOfOnlyUnicodeWhitespaceIsBlankNoOp(): void
	{
		// Given an ASCII-blank line is already a no-op
		$this->assertNull(pfb_validate_suppression_line('   ', 'ipv4'));
		// Then a Unicode-whitespace-only line is the same blank no-op, not an
		// input error naming an "invalid subnet".
		$this->assertNull(pfb_validate_suppression_line(self::NBSP, 'ipv4'));
		$this->assertNull(pfb_validate_suppression_line(self::NBSP . "\u{3000}", 'ipv6'));
	}

	public function testSuppressionCommentBehindLeadingWhitespaceIsStillAComment(): void
	{
		// A comment line is one whose first NONBLANK character is '#' —
		// leading whitespace (ASCII or Unicode) must not turn it into a
		// malformed "address".
		$this->assertNull(pfb_validate_suppression_line('  # ASCII-indented comment', 'ipv4'));
		$this->assertNull(pfb_validate_suppression_line(self::NBSP . '# NBSP-indented comment', 'ipv4'));
	}

	// --- pfb_lint_sh_diagnostics / pfb_lint_py_diagnostics ----------------

	public function testShUnicodeWhitespaceOnlyStderrIsNoDiagnosticWarning(): void
	{
		// Consume the complete probe before the nonzero exit; stderr = NBSP + newline.
		$timeoutFixture = $this->fixture(
			'cat >/dev/null' . "\n" .
			'printf "\302\240\n" 1>&2' . "\n" .
			'exit 1'
		);
		$shFixture = $this->fixture('exit 0'); // never exec'd — fake timeout ignores argv
		$diagnostics = pfb_lint_sh_diagnostics("echo ok\n", $shFixture, $timeoutFixture);
		$this->assertCount(1, $diagnostics);
		$this->assertSame(1, $diagnostics[0]['line']);
		$this->assertSame('warning', $diagnostics[0]['severity']);
		$this->assertStringContainsString('exited 1 with no diagnostic', $diagnostics[0]['message']);
	}

	public function testShStdinWriteFailureWithWhitespaceOnlyStderrIsLaunchFailedWarning(): void
	{
		// The fake "timeout_bin" closes stdin immediately (EPIPEs the write loop
		// for an over-pipe-buffer body) and leaves only whitespace on stderr —
		// there is no parseable diagnostic to prefer, so the generic
		// launch-failed warning must win.
		$timeoutFixture = $this->fixture(
			'exec 0<&-' . "\n" .
			'printf "\302\240\n" 1>&2' . "\n" .
			'exit 2'
		);
		$shFixture = $this->fixture('exit 0');
		// ~256KiB: over the OS pipe buffer, under the endpoint's 1MiB cap.
		$content = str_repeat('x', 300000) . "\n";
		$diagnostics = pfb_lint_sh_diagnostics($content, $shFixture, $timeoutFixture);
		$this->assertCount(1, $diagnostics);
		$this->assertSame(1, $diagnostics[0]['line']);
		$this->assertSame('warning', $diagnostics[0]['severity']);
		$this->assertStringContainsString('launch failed', $diagnostics[0]['message']);
	}

	public function testPyUnicodeWhitespaceOnlyStderrIsNoDiagnosticWarning(): void
	{
		$timeoutFixture = $this->fixture(
			'cat >/dev/null' . "\n" .
			'printf "\302\240\n" 1>&2' . "\n" .
			'exit 1'
		);
		$pythonFixture = $this->fixture('exit 0'); // never exec'd — fake timeout ignores argv
		$diagnostics = pfb_lint_py_diagnostics("print('ok')\n", $pythonFixture, $timeoutFixture);
		$this->assertCount(1, $diagnostics);
		$this->assertSame(1, $diagnostics[0]['line']);
		$this->assertSame('warning', $diagnostics[0]['severity']);
		$this->assertStringContainsString('exited 1 with no diagnostic', $diagnostics[0]['message']);
	}
}
