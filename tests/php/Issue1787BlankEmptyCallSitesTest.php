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
 *   - pfb_is_blank_or_comment_line(): the literal line "0" is DATA, not blank.
 *   - pfb_validate_suppression_line(): a Unicode-whitespace-only line is a
 *     blank no-op, not an "invalid subnet" input error.
 *   - pfb_get_hooks(): a hook whose script is only Unicode whitespace has no
 *     script and is skipped like an empty one.
 *   - pfb_feed_redirect_target(): a Location of only Unicode whitespace has no
 *     target — refuse it up front instead of resolving it as a relative URL.
 *   - pfb_lint_sh_diagnostics()/pfb_lint_py_diagnostics(): a stderr of only
 *     Unicode whitespace carries no diagnostic — degrade to the no-diagnostic/
 *     launch-failed warning instead of surfacing a whitespace "error".
 */
#[CoversFunction('pfb_is_blank_or_comment_line')]
#[CoversFunction('pfb_validate_suppression_line')]
#[CoversFunction('pfb_get_hooks')]
#[CoversFunction('pfb_feed_redirect_target')]
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

	// --- pfb_is_blank_or_comment_line ------------------------------------

	public function testLiteralZeroLineIsNotBlank(): void
	{
		// The contract (and pfb_dnsbl_is_skippable_control_line, its ADR-62
		// mirror) says blank detection is an exact '' match; empty('0') is TRUE,
		// which silently drops a "0" feed line as blank (issue #1707 class).
		$this->assertFalse(pfb_is_blank_or_comment_line('0'));
		// The genuine blank/comment shapes still match.
		$this->assertTrue(pfb_is_blank_or_comment_line(''));
		$this->assertTrue(pfb_is_blank_or_comment_line('# comment'));
	}

	public function testBlankOrCommentLineStripsItsOwnWhitespace(): void
	{
		// The helper strips the line itself (Unicode class included), so a
		// whitespace-only line is blank and a comment marker behind
		// indentation — which the caller's ASCII trim() cannot remove when
		// the whitespace is NBSP — is still a comment.
		$this->assertTrue(pfb_is_blank_or_comment_line('   '));
		$this->assertTrue(pfb_is_blank_or_comment_line(self::NBSP));
		$this->assertTrue(pfb_is_blank_or_comment_line(self::NBSP . '# comment'));
		$this->assertTrue(pfb_is_blank_or_comment_line(self::NBSP . '! ABP comment'));
		// Data behind the same indentation is still data.
		$this->assertFalse(pfb_is_blank_or_comment_line(self::NBSP . 'example.com'));
	}

	public function testSkippableControlLineStripsItsOwnWhitespace(): void
	{
		// Same self-stripping contract for the ADR-62 mirror: blank lines,
		// indented '!'/'//' comments, and an ABP section marker with trailing
		// whitespace are all control lines; a bracketed IPv6 literal and a
		// domain stay data.
		$this->assertTrue(pfb_dnsbl_is_skippable_control_line('   '));
		$this->assertTrue(pfb_dnsbl_is_skippable_control_line(self::NBSP . '! ABP comment'));
		$this->assertTrue(pfb_dnsbl_is_skippable_control_line('[Adblock Plus 2.0]' . self::NBSP));
		$this->assertFalse(pfb_dnsbl_is_skippable_control_line(self::NBSP . '[2604:2dc0::]'));
		$this->assertFalse(pfb_dnsbl_is_skippable_control_line(self::NBSP . 'example.com'));
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

	// --- pfb_get_hooks ----------------------------------------------------

	public function testHookWithUnicodeWhitespaceOnlyScriptIsSkipped(): void
	{
		$pfbconfig = ['hooks' => ['row' => [
			['enabled' => 'on', 'when' => 'pre', 'script' => 'echo ok'],
			['enabled' => 'on', 'when' => 'pre', 'script' => self::NBSP],
		]]];
		$hooks = pfb_get_hooks($pfbconfig, 'pre');
		// Only the hook with a real script survives; a Unicode-whitespace-only
		// script is as script-less as an empty one.
		$this->assertCount(1, $hooks);
		$this->assertSame('echo ok', $hooks[0]['script']);
	}

	// --- pfb_feed_redirect_target -----------------------------------------

	public function testRedirectLocationOfOnlyUnicodeWhitespaceHasNoTarget(): void
	{
		$reason = '';
		$pinned = '';
		$result = pfb_feed_redirect_target(self::NBSP, 'https://feed.example/list.txt', $reason, $pinned);
		// A whitespace-only Location is "no target" — refused before any
		// relative-URL resolution or host re-vetting runs.
		$this->assertFalse($result);
		$this->assertSame('feed redirect has no target', $reason);
		$this->assertSame('', $pinned);
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
