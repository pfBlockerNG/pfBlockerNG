<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** Painted Feeds rows keep visible link affordance on every shipped row background. */
final class FeedsPaintedRowLinkContrastTest extends TestCase
{
	private const PAINTED_ROW_CLASS = 'pfb-painted-feed-row';

	public static function setUpBeforeClass(): void
	{
		require_once __DIR__ . '/FeedsPredefinedTypeLoader.php';
		pfb_test_load_feeds_predefined_type_functions();
	}

	/** @return array<string, string> */
	private function feed(string $marker): array
	{
		return [
			'feed'     => $marker,
			'website'  => "https://{$marker}.example/",
			'url'      => "https://{$marker}.example/list.txt",
			'header'   => $marker,
			'register' => '',
		];
	}

	private function renderPredefinedRows(): string
	{
		$GLOBALS['ex_feeds']          = [];
		$GLOBALS['alt_feeds']         = [];
		$GLOBALS['fconfig']           = [];
		$GLOBALS['feed_alt_selected'] = [];
		$GLOBALS['alt_selected']      = '';
		$GLOBALS['feed_info_row']     = 0;
		$GLOBALS['aliasname_found']   = [];

		$info = ['ContrastAlias' => [
			'action' => 'block',
			'info'   => 'Contrast test alias',
			'feeds'  => [$this->feed('painted-predefined'), $this->feed('unpainted-predefined')],
		]];

		ob_start();
		pfb_feeds_render_predefined_type('ipv4', $info);
		return (string) ob_get_clean();
	}

	private function renderCustomRows(): string
	{
		$source = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_feeds.php'
		);
		if ($source === FALSE) {
			throw new RuntimeException('failed to read pfblockerng_feeds.php');
		}

		$table = strpos($source, "\n\t\t\t<tbody>\n");
		$start = strpos($source, "\t\t\t\t\$p_type = '';", $table === FALSE ? 0 : $table);
		$end   = strpos($source, "\n\t\t\t<tbody>\n\t\t\t</table>", $start === FALSE ? 0 : $start);
		if ($start === FALSE || $end === FALSE || $end <= $start) {
			throw new RuntimeException('could not locate the custom-feed row template');
		}

		$ex_feeds = ['ipv4' => [
			[
				'aliasname' => 'ContrastAlias',
				'url'       => 'https://painted-custom.example/list.txt',
				'header'    => 'painted-custom',
				'rowid'     => 1,
			],
			[
				'aliasname' => 'ContrastAlias',
				'url'       => 'https://unpainted-custom.example/list.txt',
				'header'    => 'unpainted-custom',
				'rowid'     => 2,
			],
		]];
		$gtype      = 'ipv4';
		$type_label = ['ipv4' => 'IPv4'];

		ob_start();
		eval('?>' . "<?php\n" . substr($source, $start, $end - $start));
		return (string) ob_get_clean();
	}

	private function rowContaining(string $html, string $marker): string
	{
		preg_match_all('/<tr\b[^>]*>.*?<\/tr>/s', $html, $matches);
		foreach ($matches[0] as $row) {
			if (str_contains($row, $marker)) {
				return $row;
			}
		}
		$this->fail("no rendered row contains {$marker}");
	}

	private function assertClassTracksBackground(string $html, string $paintedMarker, string $unpaintedMarker): void
	{
		$painted = $this->rowContaining($html, $paintedMarker);
		$this->assertStringContainsString('background-color:', $painted);
		$this->assertStringContainsString(self::PAINTED_ROW_CLASS, $painted);

		$unpainted = $this->rowContaining($html, $unpaintedMarker);
		$this->assertStringNotContainsString('background-color:', $unpainted);
		$this->assertStringNotContainsString(self::PAINTED_ROW_CLASS, $unpainted);
	}

	private static function relativeLuminance(string $hex): float
	{
		$channels = [];
		foreach ([1, 3, 5] as $offset) {
			$value = hexdec(substr($hex, $offset, 2)) / 255;
			$channels[] = $value <= 0.04045 ? $value / 12.92 : (($value + 0.055) / 1.055) ** 2.4;
		}
		return 0.2126 * $channels[0] + 0.7152 * $channels[1] + 0.0722 * $channels[2];
	}

	private static function contrastRatio(string $first, string $second): float
	{
		$lighter = max(self::relativeLuminance($first), self::relativeLuminance($second));
		$darker  = min(self::relativeLuminance($first), self::relativeLuminance($second));
		return ($lighter + 0.05) / ($darker + 0.05);
	}

	public function testPredefinedRowClassTracksPaintedBackground(): void
	{
		$this->assertClassTracksBackground(
			$this->renderPredefinedRows(),
			'painted-predefined.example',
			'unpainted-predefined.example'
		);
	}

	public function testCustomRowClassTracksPaintedBackground(): void
	{
		$this->assertClassTracksBackground(
			$this->renderCustomRows(),
			'painted-custom.example',
			'unpainted-custom.example'
		);
	}

	public function testScopedLinkColorsMeetNormalTextContrastOnEveryPaintedBackground(): void
	{
		$source = (string) file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_feeds.php'
		);
		$this->assertSame(1, preg_match(
			'/\.pfb-painted-feed-row\s+a\s*\{\s*color:\s*(#[0-9a-f]{6})\s*;\s*\}/i',
			$source,
			$normalMatch
		), 'painted Feeds rows must scope a normal link foreground');
		$this->assertSame(1, preg_match(
			'/\.pfb-painted-feed-row\s+a:hover\s*,\s*\.pfb-painted-feed-row\s+a:focus\s*'
			. '\{\s*color:\s*(#[0-9a-f]{6})\s*;\s*\}/i',
			$source,
			$interactiveMatch
		), 'painted Feeds rows must scope hover/focus link foregrounds');

		$colors = [strtoupper($normalMatch[1]), strtoupper($interactiveMatch[1])];
		$this->assertSame(['#004D40', '#003D33'], $colors);
		foreach ($colors as $foreground) {
			foreach (['#F5FBF6', '#EEF7EE', '#A0B8A0', '#B8B8B8'] as $background) {
				$ratio = self::contrastRatio($foreground, $background);
				$this->assertGreaterThanOrEqual(
					4.5,
					$ratio,
					"{$foreground} on {$background} has contrast {$ratio}, below 4.5:1"
				);
			}
		}
	}
}
