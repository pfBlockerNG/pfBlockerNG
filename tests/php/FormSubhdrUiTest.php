<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * In-section dividers ship translucent. Page call-sites are asserted when
 * those pages start using the helper.
 */
final class FormSubhdrUiTest extends TestCase
{
	public function testCssRulesAreTranslucentGreyNotAHardcodedLightFill(): void
	{
		$css = pfb_form_subhdr_css_rules();
		$this->assertStringContainsString(
			'.pfb-subhdr { background-color: rgba(127, 127, 127, .38); border-top: 1px solid rgba(127, 127, 127, .58); text-align: center; padding-top: 3px; }',
			$css
		);
		$this->assertStringNotContainsString('#f0f0f0', $css);
		$this->assertStringNotContainsString('#ddd', $css);
		$this->assertStringContainsString('.pfb-subhdr > label.control-label { display: none; }', $css);
		$this->assertStringContainsString('.pfb-subhdr > div { width: 100%; float: none; }', $css);
		$this->assertStringContainsString(
			'.pfb-subhdr p.form-control-static { font-weight: 700; padding: 0; min-height: 0; margin: 0; line-height: 1.2; }',
			$css
		);
	}
}
