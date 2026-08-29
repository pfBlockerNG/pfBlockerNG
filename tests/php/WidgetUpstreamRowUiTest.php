<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Dashboard widget: the Upstream row is synthetic — italic/dim, tooltip kept.
 * AJAX refresh rebuilds rows from the alias cell, so the class lives on that span.
 */
final class WidgetUpstreamRowUiTest extends TestCase
{
	private static function source(): string
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/widgets/widgets/pfblockerng.widget.php');
		if ($source === FALSE) {
			throw new RuntimeException('failed to read widget');
		}
		return $source;
	}

	public function testUpstreamAliasSpanCarriesSyntheticClassAndTooltip(): void
	{
		$source = self::source();
		$upstream = strpos($source, "if (\$pfb_alias === 'Upstream') {");
		$this->assertNotFalse($upstream);
		$window = substr($source, $upstream, 700);
		$this->assertStringContainsString('class="pfb-widget-upstream"', $window);
		$this->assertStringContainsString(
			'Domains blocked by your upstream DNS resolver rather than by a pfBlockerNG feed',
			$window
		);
	}

	public function testWidgetCssItalicDimsTheUpstreamName(): void
	{
		$source = self::source();
		$this->assertMatchesRegularExpression(
			'/\.pfb-widget-upstream\s*\{[^}]*font-style\s*:\s*italic/s',
			$source
		);
		$this->assertMatchesRegularExpression(
			'/\.pfb-widget-upstream\s*\{[^}]*opacity\s*:/s',
			$source
		);
	}

	public function testAliasPopupStillSkipsUpstream(): void
	{
		$source = self::source();
		$this->assertStringContainsString(
			"\$pfb['popup'] == 'on' && \$pfb_alias !== 'Upstream'",
			$source
		);
	}
}
