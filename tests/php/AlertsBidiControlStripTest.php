<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_hsc() strips Unicode bidirectional controls (issue #2041).
 *
 * htmlspecialchars() neutralises HTML metacharacters; bidi controls are not
 * metacharacters, so they survived encoding and reversed the display order of
 * everything after them. A log-derived domain, feed name or resolved hostname could
 * therefore render as something other than the bytes actually logged.
 *
 * Config text never arrived carrying one -- pfb_sanitize_text() strips \p{C} at the
 * persist boundary (issue #1723) -- but log-derived values have no such gate.
 */
#[CoversFunction('pfb_hsc')]
final class AlertsBidiControlStripTest extends TestCase
{
	public static function setUpBeforeClass(): void
	{
		require_once __DIR__ . '/AlertsPageLoader.php';
		pfb_test_load_alerts_page_functions();
	}

	/** Every character the pattern names, each of which reorders what follows. */
	public static function bidiControls(): array
	{
		return [
			'ALM  U+061C' => ["\u{061C}"],
			'LRM  U+200E' => ["\u{200E}"],
			'RLM  U+200F' => ["\u{200F}"],
			'LRE  U+202A' => ["\u{202A}"],
			'RLE  U+202B' => ["\u{202B}"],
			'PDF  U+202C' => ["\u{202C}"],
			'LRO  U+202D' => ["\u{202D}"],
			'RLO  U+202E' => ["\u{202E}"],
			'LRI  U+2066' => ["\u{2066}"],
			'RLI  U+2067' => ["\u{2067}"],
			'FSI  U+2068' => ["\u{2068}"],
			'PDI  U+2069' => ["\u{2069}"],
		];
	}

	#[DataProvider('bidiControls')]
	public function testBidiControlIsStripped(string $control): void
	{
		$out = pfb_hsc("evil{$control}gnp.exe");
		$this->assertStringNotContainsString(
			$control,
			$out,
			'bidi control survived encoding: ' . bin2hex($out)
		);
		$this->assertSame('evilgnp.exe', $out, 'surrounding text must be untouched');
	}

	/** The spoof from the issue: what is logged and what is displayed must agree. */
	public function testOverrideCannotReverseADomain(): void
	{
		$logged = "safe\u{202E}gnp.exe";
		$this->assertSame('safegnp.exe', pfb_hsc($logged));
	}

	/** HTML encoding is unchanged -- this must not become the only thing pfb_hsc does. */
	public function testHtmlMetacharactersStillEncoded(): void
	{
		$this->assertSame(
			'&lt;script&gt;alert(1)&lt;/script&gt;',
			pfb_hsc('<script>alert(1)</script>')
		);
		$this->assertSame('&quot;&amp;&#039;', pfb_hsc('"&\''));
	}

	/**
	 * Invalid UTF-8 must still render (issue #1814). preg_replace()'s /u modifier returns
	 * NULL on malformed input, so stripping before encoding would blank exactly the values
	 * ENT_SUBSTITUTE exists to preserve. Encoding first makes the input to preg valid.
	 */
	public function testInvalidUtf8StillRenders(): void
	{
		$out = pfb_hsc("abc\xC3\x28def");
		$this->assertNotSame('', $out, 'invalid UTF-8 blanked the whole value');
		$this->assertStringContainsString('abc', $out);
		$this->assertStringContainsString('def', $out);
	}

	/** A bidi control adjacent to invalid UTF-8: both handled, neither blanks the value. */
	public function testInvalidUtf8CarryingABidiControl(): void
	{
		$out = pfb_hsc("abc\xC3\x28\u{202E}def");
		$this->assertNotSame('', $out);
		$this->assertStringNotContainsString("\u{202E}", $out);
		$this->assertStringContainsString('def', $out);
	}

	/** Characters that merely look exotic are content, not controls, and must survive. */
	public function testNonControlUnicodeSurvives(): void
	{
		$this->assertSame('bücher.de', pfb_hsc('bücher.de'));
		$this->assertSame('日本.jp', pfb_hsc('日本.jp'));
	}
}
