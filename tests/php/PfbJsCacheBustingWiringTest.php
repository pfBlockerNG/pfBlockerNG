<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class PfbJsCacheBustingWiringTest extends TestCase
{
	private const ASSET_PATH = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfBlockerNG.js';

	private const PAGE_FUNCTIONS = [
		'pfblockerng_category.php' => 'pfb_category_js_asset_render',
		'pfblockerng_category_edit.php' => 'pfb_category_edit_js_asset_render',
		'pfblockerng_dnsbl.php' => 'pfb_dnsbl_js_asset_render',
		'pfblockerng_ip.php' => 'pfb_ip_js_asset_render',
		'pfblockerng_geoip.inc' => 'pfb_geoip_js_asset_render',
	];

	private function renderScript(string $name): string
	{
		$function = self::PAGE_FUNCTIONS[$name];
		return $function(self::ASSET_PATH);
	}

	public function testAssetCarriesTheRuntimeModificationVersion(): void
	{
		$expected = 'src="pfBlockerNG.js?v=' . pfb_file_mtime(self::ASSET_PATH) . '"';
		foreach (array_keys(self::PAGE_FUNCTIONS) as $page) {
			$script = $this->renderScript($page);
			$this->assertStringContainsString($expected, $script, $page);
			$this->assertStringContainsString('type="text/javascript"', $script, $page);
		}
	}

	public function testAssetRendersExactlyOneBustedScriptTag(): void
	{
		foreach (array_keys(self::PAGE_FUNCTIONS) as $page) {
			$script = $this->renderScript($page);
			$this->assertSame(1, substr_count($script, '<script'), $page);
			$this->assertSame(1, substr_count($script, 'src="pfBlockerNG.js?v='), $page);
			$this->assertStringNotContainsString('src="pfBlockerNG.js"', $script, $page);
		}
	}
}
