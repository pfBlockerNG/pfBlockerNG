<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Unified log rows set background-color inline, which kills Bootstrap
 * table-striped. The overlay is a background-image on odd tbody rows, and
 * only on the Unified view of the shared alerts table.
 */
final class AlertsUnifiedStripeUiTest extends TestCase
{
	private static function source(): string
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_alerts.php');
		if ($source === FALSE) {
			throw new RuntimeException('failed to read Alerts page');
		}
		return $source;
	}

	public function testOverlayTintUsesTheExistingDarkFlag(): void
	{
		$source = self::source();
		$this->assertStringContainsString(
			"\$pfb_unified_tint = \$pfb_webgui_dark ? 'rgba(255,255,255,.06)' : 'rgba(0,0,0,.05)'",
			$source
		);
		$this->assertSame(
			1,
			substr_count($source, "strpos(\$pfb_webgui_css, 'dark')"),
			'theme detection stays the one $pfb_webgui_dark bind; the overlay must not add another strpos'
		);
	}

	public function testOddRowsGetABackgroundImageOverlay(): void
	{
		$source = self::source();
		$this->assertStringContainsString(
			'.pfb-unified tbody tr:nth-of-type(odd) {',
			$source
		);
		$this->assertStringContainsString(
			'background-image: linear-gradient(<?=$pfb_unified_tint?>, <?=$pfb_unified_tint?>);',
			$source
		);
	}

	public function testSharedLogTableGetsTheClassOnlyForUnified(): void
	{
		$source = self::source();
		$shared = 'class="table table-striped table-hover table-compact sortable-theme-bootstrap<?= $logtype == \'Unified\' ? \' pfb-unified\' : \'\' ?>"';
		$this->assertStringContainsString($shared, $source);
		$this->assertSame(1, substr_count($source, $shared));
		$this->assertStringContainsString(
			'class="table table-striped table-hover table-compact sortable-theme-bootstrap" data-sortable>',
			$source,
			'Unlocked IP/Domain tables keep the unadorned table-striped class'
		);
		$this->assertStringContainsString(
			'class="table table-responsive table-bordered table-striped table-hover table-compact sortable-theme-bootstrap"',
			$source,
			'Stats tables keep table-striped and must not gain pfb-unified'
		);
		$this->assertSame(
			2,
			substr_count($source, 'pfb-unified'),
			'pfb-unified is the CSS selector plus the one class ternary; a static class would add a third hit'
		);
	}

	public function testInlineRowColoursAreUntouched(): void
	{
		$source = self::source();
		$this->assertStringContainsString('style=\"background-color:{$bg}\"', $source);
	}
}
