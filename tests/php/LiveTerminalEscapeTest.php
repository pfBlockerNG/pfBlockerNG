<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Pin pfb_js_string() -- the JS-string encoder used wherever the Update/Software pages write text
 * into a JavaScript context (the one-shot status line, and the PHP-emitted strings the live-log
 * poller assigns to a textarea's .value).
 *
 * A textarea .value is a PLAIN-TEXT DOM property -- it does not decode HTML entities -- so the
 * text must be a JavaScript string literal, NOT htmlspecialchars output (issue #669). The old
 * code htmlspecialchars'd it, so a '>' rendered as the literal '&gt;'. pfb_js_string() must
 * produce a literal that round-trips back to the exact input, never emits an HTML entity like
 * '&gt;', neutralises a '</script>' breakout and a trailing backslash, and tolerates invalid
 * UTF-8 in raw log bytes.
 */
#[CoversFunction('pfb_js_string')]
final class LiveTerminalEscapeTest extends TestCase
{
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
}
