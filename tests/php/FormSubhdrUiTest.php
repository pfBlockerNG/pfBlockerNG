<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Full-width in-section dividers: one helper, one class, two pages.
 */
final class FormSubhdrUiTest extends TestCase
{
	public function testCssRulesLiveInTheHelperNotCopiedPerPage(): void
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

		$general = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_general.php');
		$dnsbl = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php');
		$this->assertNotFalse($general);
		$this->assertNotFalse($dnsbl);
		$this->assertStringContainsString('pfb_form_subhdr_css_rules()', $general);
		$this->assertStringContainsString('pfb_form_subhdr_css_rules()', $dnsbl);
		$this->assertStringNotContainsString('.pfb-loghdr { background-color: #f0f0f0;', $general);
		$this->assertStringNotContainsString('.pfb-subhdr { background-color: #f0f0f0;', $dnsbl);
	}

	public function testLogSettingsAndBypassShareTheHelper(): void
	{
		$general = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_general.php');
		$dnsbl = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php');
		$this->assertStringContainsString("pfb_form_subhdr(\$logdescr, 'pfb-loghdr')", $general);
		$bypass = strpos($dnsbl, "new Form_Section('DNS Bypass Prevention'");
		$this->assertNotFalse($bypass);
		$end = strpos($dnsbl, "new Form_Section('Regex List'", $bypass);
		$this->assertNotFalse($end);
		$chunk = substr($dnsbl, $bypass, $end - $bypass);
		$this->assertStringContainsString("pfb_form_subhdr('DNS Redirect')", $chunk);
		$this->assertStringContainsString("pfb_form_subhdr('DoT/DoQ Block')", $chunk);
		$this->assertStringContainsString("pfb_form_subhdr('DNS over HTTPS/TLS/QUIC')", $chunk);
	}
}
