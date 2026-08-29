<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * An OPAQUE background may not be set without also setting a foreground
 * colour. A TRANSLUCENT background (rgba/hsla with alpha < 1) may omit it,
 * because it composites over whatever the theme paints and lets the theme's
 * own text colour through.
 *
 * Tier 1 (this file) is THEME-INDEPENDENT colour-pairing of source. It never
 * loads a stylesheet. It catches 4 of the 5 defects from this GUI round at
 * the point the package writes them. It cannot see inherited failures
 * (CodeMirror: a #fff pane inheriting body #ffffff) — that is Tier 2.
 *
 * Tier 2 (rendered WCAG contrast) is not built here. It needs
 * SMOKE_ADMIN_PASSWORD, must switch system/webgui/webguicss (not the user
 * key), assert the <head> stylesheet, restore pfSense-dark.css, reveal
 * collapsed panels / infoblocks / gated fields before measuring, and
 * parametrise page × theme.
 */
final class ThemeSafetyUiTest extends TestCase
{
	/** Client block page: no pfSense theme applies. */
	private const ALLOWLIST = [
		'src/usr/local/www/pfblockerng/www/dnsbl_default.php',
	];

	/**
	 * Owner has not ruled (2026-08-29). Remove an entry when that site is
	 * fixed. Do not add new ones silently — a new hit must fail the suite.
	 *
	 * @var array<string, list<string>>
	 */
	private const TODO_OPAQUE_WITHOUT_FOREGROUND_20260829 = [
		'src/usr/local/www/pfblockerng/pfblockerng_feeds.php' => [
			'background-color: #F5FBF6',
			'background-color: #EEF7EE',
			'background-color: #A0B8A0',
			'background-color: #B8B8B8',
		],
		'src/usr/local/www/pfblockerng/pfblockerng_alerts.php' => [
			'background-color: #424242',
		],
		'src/usr/local/pkg/pfblockerng/pfblockerng_geoip.inc' => [
			'background-color: #d6d6d6',
		],
		// Pre-existing Log Settings header band. Same defect class; kept
		// out of this change so the readability failures stay scoped.
		'src/usr/local/www/pfblockerng/pfblockerng_general.php' => [
			'background-color: #f0f0f0',
		],
	];

	public function testOpaqueSnippetWithoutForegroundIsAViolation(): void
	{
		$bad = [
			'.example-band { background-color: #f0f0f0; border-top: 1px solid #ddd; }',
			"->setAttribute('style', 'background:#fafafa; width: 100%')",
			'EditorView.theme({ "&": { border: "1px solid #b7b7b7", backgroundColor: "#fff" } })',
			'$tr_style = \'background-color: #F5FBF6;\';',
			'<span style="font-size:12px; background-color: #424242;">',
			'<hr style="height: 1px; border: none; background-color: #d6d6d6;"/>',
		];
		foreach ($bad as $src) {
			$this->assertNotSame([], self::scan($src), 'expected a violation in: ' . $src);
		}
	}

	public function testTranslucentOrPairedForegroundIsNotAViolation(): void
	{
		$good = [
			'.example-band { background-color: rgba(127, 127, 127, .38); border-top: 1px solid rgba(127, 127, 127, .58); }',
			'<span style="color: black; background-color: #FFFF00; border-style: groove;">Failed</span>',
			'EditorView.theme({ "&": { backgroundColor: "#fff", color: "#212121" } })',
			'td style=\'font-size:10px; color: red; background-color: rgba(128, 128, 128, 0.2);\'',
			'setAttribute(\'style\', "background: {$pfb[$u_key]}")',
			'colors: { background: null, segmentStroke: "#ffffff" }',
		];
		foreach ($good as $src) {
			$this->assertSame([], self::scan($src), 'false positive in: ' . $src);
		}
	}

	public function testCurrentTreeInventoryMatchesTheDatedTodo(): void
	{
		$root = dirname(__DIR__, 2);
		$found = [];
		foreach (self::scanTree($root) as $rel => $hits) {
			if (in_array($rel, self::ALLOWLIST, TRUE)) {
				continue;
			}
			$found[$rel] = array_values(array_unique(array_map(
				static fn(array $h): string => self::excerptKey($h['excerpt']),
				$hits
			)));
		}

		$todo = self::TODO_OPAQUE_WITHOUT_FOREGROUND_20260829;
		$extra = array_diff_key($found, $todo);
		$stale = array_diff_key($todo, $found);
		$this->assertSame([], $extra, 'new opaque-without-foreground site — do not allowlist it, fix it or get an owner ruling');
		$this->assertSame([], $stale, 'TODO entry is fixed; remove it from TODO_OPAQUE_WITHOUT_FOREGROUND_20260829');

		foreach ($todo as $rel => $needles) {
			$joined = implode("\n", $found[$rel]);
			foreach ($needles as $needle) {
				$this->assertTrue(
					self::listContainsNeedle($found[$rel], $needle),
					$rel . ' TODO needle missing: ' . $needle . ' (have: ' . $joined . ')'
				);
			}
			foreach ($found[$rel] as $have) {
				$this->assertTrue(
					self::listContainsNeedle($needles, $have),
					$rel . ' extra opaque-without-foreground hit: ' . $have
				);
			}
		}
	}

	/**
	 * @return list<array{line:int, excerpt:string}>
	 */
	public static function scan(string $source): array
	{
		$hits = [];
		if (preg_match_all(
			'/background(?:-color)?\s*:\s*([^;}\n]+)|backgroundColor\s*:\s*(["\'])([^"\']+)\2/i',
			$source,
			$matches,
			PREG_OFFSET_CAPTURE
		) !== FALSE) {
			$count = count($matches[0]);
			for ($i = 0; $i < $count; $i++) {
				$full = $matches[0][$i][0];
				$offset = $matches[0][$i][1];
				$cssVal = self::firstColorToken($matches[1][$i][0] ?? '');
				$jsVal = trim($matches[3][$i][0] ?? '');
				$value = $cssVal !== '' ? $cssVal : $jsVal;
				if ($value === '' || self::isInterpolated($value) || self::isTranslucent($value)) {
					continue;
				}
				$ctx = self::declarationContext($source, $offset);
				if (self::contextHasForeground($ctx)) {
					continue;
				}
				if (self::themeRootPinsForeground($source, $offset)) {
					continue;
				}
				$line = substr_count(substr($source, 0, $offset), "\n") + 1;
				$hits[] = ['line' => $line, 'excerpt' => trim($full)];
			}
		}
		return $hits;
	}

	/**
	 * @return array<string, list<array{line:int, excerpt:string}>>
	 */
	public static function scanTree(string $root): array
	{
		$found = [];
		$dirs = [
			$root . '/src/usr/local/www/pfblockerng',
			$root . '/src/usr/local/pkg/pfblockerng',
			$root . '/src/usr/local/www/widgets',
			$root . '/tools/webassets',
		];
		foreach ($dirs as $dir) {
			if (!is_dir($dir)) {
				continue;
			}
			$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));
			foreach ($it as $file) {
				if (!$file->isFile()) {
					continue;
				}
				$path = $file->getPathname();
				if (str_contains($path, '/node_modules/') || str_contains($path, '/vendor/codemirror/')) {
					continue;
				}
				if (str_contains($path, '/tools/webassets/test/')) {
					continue;
				}
				$ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
				if (!in_array($ext, ['php', 'inc', 'js', 'css'], TRUE)) {
					continue;
				}
				$source = file_get_contents($path);
				if ($source === FALSE) {
					continue;
				}
				$hits = self::scan($source);
				if ($hits === []) {
					continue;
				}
				$rel = substr($path, strlen($root) + 1);
				$found[$rel] = $hits;
			}
		}
		return $found;
	}

	private static function declarationContext(string $source, int $offset): string
	{
		$before = substr($source, 0, $offset);
		$brace = strrpos($before, '{');
		if ($brace !== FALSE) {
			$end = strpos($source, '}', $brace);
			if ($end !== FALSE && $end >= $offset) {
				return substr($source, $brace, $end - $brace + 1);
			}
		}
		$sq = strrpos($before, "'");
		$dq = strrpos($before, '"');
		if ($sq !== FALSE && ($dq === FALSE || $sq > $dq)) {
			$start = $sq;
			$quote = "'";
		} elseif ($dq !== FALSE) {
			$start = $dq;
			$quote = '"';
		} else {
			return substr($source, max(0, $offset - 80), 160);
		}
		$end = strpos($source, $quote, $start + 1);
		return $end === FALSE ? substr($source, $start) : substr($source, $start, $end - $start + 1);
	}

	private static function contextHasForeground(string $ctx): bool
	{
		return (bool)preg_match('/(?<![A-Za-z-])color\s*:/i', $ctx);
	}

	private static function themeRootPinsForeground(string $source, int $offset): bool
	{
		$pos = strrpos(substr($source, 0, $offset), 'EditorView.theme(');
		if ($pos === FALSE) {
			return FALSE;
		}
		$chunk = substr($source, $pos, 2000);
		return (bool)preg_match('/"&"\s*:\s*\{[^}]*\bcolor\s*:/', $chunk);
	}

	private static function firstColorToken(string $raw): string
	{
		$raw = trim($raw);
		if ($raw === '') {
			return '';
		}
		if (preg_match('/^((?:rgba?|hsla?)\s*\([^)]*\))/i', $raw, $m)) {
			return $m[1];
		}
		if (preg_match('/^([^,;}\n]+)/', $raw, $m)) {
			return trim($m[1], " \t\"'");
		}
		return $raw;
	}

	private static function isInterpolated(string $value): bool
	{
		return str_contains($value, '{$')
			|| (bool)preg_match('/\$[a-zA-Z_]/', $value);
	}

	private static function isTranslucent(string $value): bool
	{
		$v = strtolower(trim($value, " \t\"',"));
		if ($v === 'transparent' || $v === 'none' || $v === 'null' || $v === '') {
			return TRUE;
		}
		if (preg_match('/^(?:rgba|hsla)\s*\(\s*[^,]+,[^,]+,[^,]+,\s*([0-9.]+)\s*\)/', $v, $m)) {
			return (float)$m[1] < 1.0;
		}
		if (preg_match('/^#([0-9a-f]{8})$/', $v, $m)) {
			return hexdec(substr($m[1], 6, 2)) < 255;
		}
		if (preg_match('/^#([0-9a-f]{4})$/', $v, $m)) {
			return hexdec(str_repeat($m[1][3], 2)) < 255;
		}
		return FALSE;
	}

	private static function excerptKey(string $excerpt): string
	{
		if (preg_match('/background(?:-color)?\s*:\s*[^;]+|backgroundColor\s*:\s*["\'][^"\']+["\']/i', $excerpt, $m)) {
			return trim($m[0], " ;");
		}
		return $excerpt;
	}

	/** @param list<string> $list */
	private static function listContainsNeedle(array $list, string $needle): bool
	{
		foreach ($list as $item) {
			if (str_contains($item, $needle) || str_contains($needle, $item)) {
				return TRUE;
			}
		}
		return FALSE;
	}
}
