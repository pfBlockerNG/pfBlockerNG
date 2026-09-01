<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Painted Feeds rows keep visible link affordance on every shipped row background.
 *
 * The scoping rides the inline background the rows already carry, so it needs no extra
 * markup on the row: the four painted backgrounds are the only inline backgrounds this
 * page sets, and both row emitters put them in the row's own style attribute.
 */
final class FeedsPaintedRowLinkContrastTest extends TestCase
{
	private const NORMAL_LINK_COLOR = '#004D40';
	private const INTERACTIVE_LINK_COLOR = '#003D33';

	/** Every background the two Feeds tables paint inline. */
	private const PAINTED_BACKGROUNDS = ['#F5FBF6', '#EEF7EE', '#A0B8A0', '#B8B8B8'];

	/** The only selector shape that survives the live table's DOM normalisation. */
	private const SCOPED_SELECTOR_PATTERN = '/^#pfb_table2? tr\[style\*="background-color"\] a(:hover|:focus)?$/';

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

	private function assertPaintsInlineBackground(string $html, string $paintedMarker, string $unpaintedMarker): void
	{
		$painted = $this->rowContaining($html, $paintedMarker);
		$this->assertStringContainsString('background-color:', $painted);
		$this->assertStringContainsString('color: #212121', $painted);

		$unpainted = $this->rowContaining($html, $unpaintedMarker);
		$this->assertStringNotContainsString('background-color:', $unpainted);
	}

	/**
	 * The page-local link rules, as a selector => foreground map.
	 *
	 * Parsed rather than regex-matched whole so grouping and ordering are free to
	 * change without the assertions below pinning formatting.
	 *
	 * @return array<string, string>
	 */
	private function pageLinkRules(): array
	{
		$source = (string) file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_feeds.php'
		);
		$this->assertSame(
			1,
			preg_match('/<style>(.*?)<\/style>/s', $source, $style),
			'the Feeds page must ship exactly one page-local <style> block'
		);

		// Comments are stripped first: a rule is free to carry one without its selectors
		// arriving glued to the comment text.
		$css   = (string) preg_replace('#/\*.*?\*/#s', '', $style[1]);
		$rules = [];
		foreach (explode('}', $css) as $chunk) {
			if (!str_contains($chunk, '{')) {
				continue;
			}
			[$selectors, $body] = explode('{', $chunk, 2);
			if (preg_match('/(?<![-\w])color:\s*(#[0-9a-fA-F]{6})\s*;/', $body, $color) !== 1) {
				continue;
			}
			foreach (explode(',', $selectors) as $selector) {
				$selector = trim((string) preg_replace('/\s+/', ' ', $selector));
				if ($selector !== '') {
					$rules[$selector] = strtoupper($color[1]);
				}
			}
		}

		return $rules;
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

	public function testPredefinedRowPaintsInlineBackgroundWithItsForeground(): void
	{
		$this->assertPaintsInlineBackground(
			$this->renderPredefinedRows(),
			'painted-predefined.example',
			'unpainted-predefined.example'
		);
	}

	public function testCustomRowPaintsInlineBackgroundWithItsForeground(): void
	{
		$this->assertPaintsInlineBackground(
			$this->renderCustomRows(),
			'painted-custom.example',
			'unpainted-custom.example'
		);
	}

	public function testScopedLinkColorsMeetNormalTextContrastOnEveryPaintedBackground(): void
	{
		$rules = $this->pageLinkRules();

		$expected = [
			'#pfb_table tr[style*="background-color"] a'         => self::NORMAL_LINK_COLOR,
			'#pfb_table2 tr[style*="background-color"] a'        => self::NORMAL_LINK_COLOR,
			'#pfb_table tr[style*="background-color"] a:hover'   => self::INTERACTIVE_LINK_COLOR,
			'#pfb_table tr[style*="background-color"] a:focus'   => self::INTERACTIVE_LINK_COLOR,
			'#pfb_table2 tr[style*="background-color"] a:hover'  => self::INTERACTIVE_LINK_COLOR,
			'#pfb_table2 tr[style*="background-color"] a:focus'  => self::INTERACTIVE_LINK_COLOR,
		];
		foreach ($expected as $selector => $color) {
			$this->assertArrayHasKey(
				$selector,
				$rules,
				"painted Feeds rows must scope their link foreground by inline background: {$selector}"
			);
			$this->assertSame($color, $rules[$selector], $selector);
		}

		foreach ($rules as $selector => $color) {
			if (!in_array($color, [self::NORMAL_LINK_COLOR, self::INTERACTIVE_LINK_COLOR], TRUE)) {
				continue;
			}
			$this->assertMatchesRegularExpression(
				self::SCOPED_SELECTOR_PATTERN,
				$selector,
				"{$selector} scopes a painted-row link colour by something other than the inline "
					. 'background the painted rows already carry'
			);
		}

		foreach ([self::NORMAL_LINK_COLOR, self::INTERACTIVE_LINK_COLOR] as $foreground) {
			foreach (self::PAINTED_BACKGROUNDS as $background) {
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
