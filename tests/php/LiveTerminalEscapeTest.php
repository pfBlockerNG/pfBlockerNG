<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Pin the live-terminal output contract shared by the Update and Software pages
 * (pfblockerng_update.php / pfblockerng_software.php). Those pages stream log
 * output by flushing inline <script> chunks that assign to a textarea's .value;
 * the JS-string encoding and the sticky auto-follow both live in two helpers in
 * pfblockerng.inc -- pfb_js_string() and pfb_term_write_js() -- so they are unit
 * tested here off-appliance (bootstrap.php loads the real pfblockerng.inc).
 *
 * Two behaviours are pinned:
 *
 *   1. Correct escaping (issue #669). A textarea .value is a PLAIN-TEXT DOM
 *      property -- it does not decode HTML entities -- so the text must be a
 *      JavaScript string literal, NOT htmlspecialchars output. The old code
 *      htmlspecialchars'd the text, so a '>' rendered as the literal '&gt;'.
 *      pfb_js_string() must produce a literal that round-trips back to the exact
 *      input, never emits an HTML entity like '&gt;', and neutralises a
 *      '</script>' breakout and a trailing backslash.
 *
 *   2. Sticky auto-follow (issue #669). pfb_term_write_js() must measure the
 *      scroll position BEFORE changing the value and re-pin to the bottom ONLY
 *      when the user was already at the bottom -- so scrolling up to read pauses
 *      the follow instead of being snapped back on every refresh.
 */
#[CoversFunction('pfb_js_string')]
#[CoversFunction('pfb_term_write_js')]
final class LiveTerminalEscapeTest extends TestCase
{
	// ---- 1. pfb_js_string(): JS-string escaping, not HTML escaping --------------

	/**
	 * A '>' must survive as a real '>' in the textarea, never the literal '&gt;'.
	 * This is the exact #669 double-escape bug: htmlspecialchars turned '>' into
	 * '&gt;', which a plain-text .value shows verbatim.
	 */
	public function testAngleBracketIsNotHtmlEntityEncoded(): void
	{
		$literal = pfb_js_string('feed --> sink');

		// json_decode reverses a valid JS/JSON string literal, proving the value
		// the browser assigns to .value is byte-for-byte the original.
		$this->assertSame(
			'feed --> sink',
			json_decode($literal, FALSE, 512, JSON_THROW_ON_ERROR),
			"decoded literal must equal the input; got literal: {$literal}"
		);
		$this->assertStringNotContainsString(
			'&gt;',
			$literal,
			"must not HTML-entity-encode '>' (the #669 double-escape); got: {$literal}"
		);
		$this->assertStringNotContainsString('&amp;', $literal, "got: {$literal}");
	}

	/**
	 * A '</script>' in log data must not be able to terminate the inline <script>
	 * element. With JSON_HEX_TAG the '<' and '>' become < / >, so the
	 * literal sequence '</script>' never appears -- yet it still decodes back to
	 * the original text.
	 */
	public function testScriptCloserIsNeutralised(): void
	{
		$literal = pfb_js_string('oops</script><b>x</b>');

		$this->assertStringNotContainsString(
			'</script>',
			$literal,
			"a literal </script> would close the inline script element; got: {$literal}"
		);
		$this->assertSame(
			'oops</script><b>x</b>',
			json_decode($literal, FALSE, 512, JSON_THROW_ON_ERROR)
		);
	}

	/**
	 * A log line ending in a backslash must not break the literal. htmlspecialchars
	 * left '\' unescaped, so '...\' followed by the closing '"' produced '\"' --
	 * an escaped quote that ran the JS string past its end. json_encode escapes the
	 * backslash, so the literal stays well-formed and decodes to one backslash.
	 */
	public function testTrailingBackslashDoesNotBreakOut(): void
	{
		$literal = pfb_js_string('C:\\path\\');

		$this->assertSame(
			'C:\\path\\',
			json_decode($literal, FALSE, 512, JSON_THROW_ON_ERROR),
			"trailing backslash must round-trip; got literal: {$literal}"
		);
	}

	/** Quotes and newlines round-trip through the literal unchanged. */
	public function testQuotesAndNewlinesRoundTrip(): void
	{
		$input   = "say \"hi\"\nnext line\tand a tab";
		$literal = pfb_js_string($input);

		$this->assertSame($input, json_decode($literal, FALSE, 512, JSON_THROW_ON_ERROR));
	}

	/**
	 * Invalid UTF-8 in raw log bytes must NOT make json_encode return FALSE (which
	 * would emit nothing / corrupt the stream). JSON_INVALID_UTF8_SUBSTITUTE keeps
	 * it a valid, non-empty literal.
	 */
	public function testInvalidUtf8YieldsValidNonEmptyLiteral(): void
	{
		$literal = pfb_js_string("bad\xFFbyte");

		$this->assertNotSame('""', $literal, 'invalid UTF-8 must not collapse to an empty literal');
		// Still a decodable JSON string literal (the bad byte became U+FFFD).
		$this->assertIsString(json_decode($literal, FALSE, 512, JSON_THROW_ON_ERROR));
	}

	// ---- 2. pfb_term_write_js(): sticky auto-follow -----------------------------

	/**
	 * The follow is sticky: the at-bottom test must be computed BEFORE the value
	 * changes, and the re-pin must be guarded by it. Measuring after the value grew
	 * would always read "not at bottom" and the box would never follow.
	 */
	public function testStickyFollowMeasuresBeforeWriteAndRepinsConditionally(): void
	{
		$js = pfb_term_write_js('pfb_output', 'a line', TRUE);

		// Guard expression present (distance-from-bottom against the three metrics).
		$this->assertStringContainsString('scrollHeight', $js);
		$this->assertStringContainsString('scrollTop', $js);
		$this->assertStringContainsString('clientHeight', $js);

		$measurePos = strpos($js, '_pfb_atbottom');
		$writePos   = strpos($js, '.value');
		$this->assertNotFalse($measurePos);
		$this->assertNotFalse($writePos);
		$this->assertLessThan(
			$writePos,
			$measurePos,
			"the at-bottom measurement must precede the .value write so follow works; got: {$js}"
		);

		// The re-pin to the bottom is conditional on the pre-measured flag.
		$this->assertMatchesRegularExpression(
			'/if\s*\(\s*_pfb_atbottom\s*\)\s*\{[^}]*scrollTop\s*=[^}]*scrollHeight/',
			$js,
			"scroll-to-bottom must be guarded by the at-bottom flag; got: {$js}"
		);
	}

	/** Append mode adds to the end (live tail); the text is appended verbatim. */
	public function testAppendModeUsesPlusEquals(): void
	{
		$js = pfb_term_write_js('pfb_output', "x>y\n", TRUE);

		$this->assertStringContainsString('.value +=', $js);
		$this->assertStringNotContainsString('.value =', $js); // not the replace form
		// The appended chunk is the escaped literal of the exact text (newline kept).
		$this->assertStringContainsString(pfb_js_string("x>y\n"), $js);
	}

	/** Replace mode (a single status line) overwrites the whole value. */
	public function testReplaceModeUsesAssignment(): void
	{
		$js = pfb_term_write_js('pfb_status', 'Standby', FALSE);

		$this->assertStringContainsString('.value =', $js);
		$this->assertStringNotContainsString('.value +=', $js);
		$this->assertStringContainsString(pfb_js_string('Standby'), $js);
	}

	/** The targeted field name is honoured (no hard-coded element). */
	public function testFieldNameIsHonoured(): void
	{
		$js = pfb_term_write_js('pfb_custom', 'z', TRUE);
		$this->assertStringContainsString('forms[0].pfb_custom.value', $js);
	}
}
