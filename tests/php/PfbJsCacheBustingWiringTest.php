<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class PfbJsCacheBustingWiringTest extends TestCase
{
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
		$path = dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfBlockerNG.js';
		return $function($path);
	}

	public function testAssetCarriesTheRuntimeModificationVersion(): void
	{
		$path = dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfBlockerNG.js';
		foreach (array_keys(self::PAGE_FUNCTIONS) as $page) {
			$script = $this->renderScript($page);
			$this->assertStringContainsString('src="pfBlockerNG.js?v=', $script, $page);
			$this->assertStringContainsString((string) pfb_file_mtime($path), $script, $page);
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
