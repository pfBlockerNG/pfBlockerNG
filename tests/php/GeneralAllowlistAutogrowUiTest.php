<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Block Private-Address Exceptions starts at one row and grows to five.
 * Editor-off uses the textarea helper; editor-on uses data-pfb-autogrow-max
 * which the CodeMirror shell already reads for height.
 */
final class GeneralAllowlistAutogrowUiTest extends TestCase
{
	private static function general(): string
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_general.php');
		if ($source === FALSE) {
			throw new RuntimeException('failed to read General page');
		}
		return $source;
	}

	public function testAllowlistTextareaStartsAtOneRowAndCapsAtFive(): void
	{
		$source = self::general();
		$this->assertSame(
			1,
			preg_match(
				"/new Form_Textarea\(\s*'pfb_feed_internal_allowlist'.*?\)\s*(->.*?;)/s",
				$source,
				$m
			)
		);
		$chain = $m[1];
		$this->assertStringContainsString("setAttribute('rows', '1')", $chain);
		$this->assertStringContainsString("setAttribute('data-pfb-autogrow-max', '5')", $chain);
		$this->assertStringContainsString('setWidth(8)', $chain);
		$this->assertStringNotContainsString('setWidth(12)', $chain);
	}

	public function testGeneralPageMountsTheTextareaAutogrowHelper(): void
	{
		$source = self::general();
		$this->assertStringContainsString(
			"pfb_autogrow_textarea_js('pfb_feed_internal_allowlist', 5)",
			$source
		);
	}

	public function testAutogrowHelperSkipsAHiddenCodeMirrorReplacedField(): void
	{
		$js = pfb_autogrow_textarea_js('pfb_feed_internal_allowlist', 5);
		$this->assertStringContainsString('pfb_feed_internal_allowlist', $js);
		$this->assertStringContainsString("style.display === 'none'", $js);
		$this->assertStringContainsString('overflowY', $js);
		$this->assertStringContainsString('scrollHeight', $js);
		$this->assertMatchesRegularExpression('/\b5\b/', $js);
	}

	public function testAutogrowHelperRejectsABadFieldId(): void
	{
		$this->assertSame('', pfb_autogrow_textarea_js('foo();alert(1)', 5));
		$this->assertSame('', pfb_autogrow_textarea_js('ok', 0));
	}
}
