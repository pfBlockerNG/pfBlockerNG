<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class DnsblRegexHighlightWiringTest extends TestCase
{
	public function testDisabledEditorEmitsNoAssetOrInitialization(): void
	{
		$rendered = pfb_dnsbl_editor_render(FALSE);
		$this->assertSame('', $rendered['asset']);
		$this->assertSame('', $rendered['regex']);
		$this->assertSame('', $rendered['lists']);
	}

	public function testEnabledEditorRendersAssetAndRegexInitialization(): void
	{
		$rendered = pfb_dnsbl_editor_render(TRUE);
		$asset = $rendered['asset'];
		$init  = $rendered['regex'];

		$this->assertStringContainsString('cm-regex.min.js?v=', $asset);
		$this->assertStringContainsString("getElementById('pfb_regex_list')", $init);
		$this->assertStringContainsString('window.pfbCM', $init);
		$this->assertStringContainsString('pfbCM.fromTextarea(', $init);
		$this->assertStringContainsString("lintUrl: '/pfblockerng/pfblockerng_lint.php'", $init);
		$this->assertStringContainsString("getElementById('pfb_regex_cap')", $init);
	}

	public function testRegexInitializationHasOneReachableMountAndLiveCapMapping(): void
	{
		$init = pfb_dnsbl_editor_render(TRUE)['regex'];

		$this->assertSame(1, substr_count($init, 'pfbCM.fromTextarea('));
		$this->assertSame(1, substr_count($init, "lintUrl: '/pfblockerng/pfblockerng_lint.php'"));
		$this->assertStringContainsString("(capEl && capEl.checked) ? '1' : '0'", $init);
	}
}
