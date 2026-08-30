<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
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
	];

	public function testOpaqueSnippetWithoutForegroundIsAViolation(): void
	{
		$bad = [
			'.pfb-subhdr { background-color: #f0f0f0; border-top: 1px solid #ddd; }',
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
			'.pfb-subhdr { background-color: rgba(127, 127, 127, .38); border-top: 1px solid rgba(127, 127, 127, .58); }',
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

	/**
	 * Every syntax scan() detects, in its unpaired and paired form.
	 *
	 * @return array<string, array{0: string, 1: string}>
	 */
	public static function backgroundSyntaxes(): array
	{
		return [
			'css declaration'   => ['a { background-color: #fff; }', 'a { background-color: #fff; color: #000; }'],
			'css shorthand'     => ['a { background: #fff; }', 'a { background: #fff; color: #000; }'],
			'js bare key'       => ['{ backgroundColor: "#fff" }', '{ backgroundColor: "#fff", color: "#000" }'],
			'js quoted key'     => ['{ "background-color": "#fff" }', '{ "background-color": "#fff", "color": "#000" }'],
			'js quoted camel'   => ['{ "backgroundColor": "#fff" }', '{ "backgroundColor": "#fff", "color": "#000" }'],
			'jquery setter'     => ["\$(x).css('background-color', '#fff');", "\$(x).css({'background-color': '#fff', 'color': '#000'});"],
			'jquery on a var'   => ["\$el.css('background-color', '#fff');", "\$el.css({'background-color': '#fff', 'color': '#000'});"],
			'jquery on this'    => ["this.css('background-color', '#fff');", "this.css({'background-color': '#fff', 'color': '#000'});"],
			'jquery camel'      => ["\$(x).css('backgroundColor', '#fff');", "\$(x).css({'backgroundColor': '#fff', 'color': '#000'});"],
			'jquery double-q'   => ['$(x).css("background-color", "#fff");', '$(x).css({"background-color": "#fff", "color": "#000"});'],
			'setProperty'       => ["e.style.setProperty('background-color', '#fff');", "e.style.setProperty('background-color', '#fff'); e.style.setProperty('color', '#000');"],
			'setProperty dbl-q' => ['e.style.setProperty("background-color", "#fff");', 'e.style.setProperty("background-color", "#fff"); e.style.setProperty("color", "#000");'],
			'style assignment'  => ["e.style.backgroundColor = '#fff';", "e.style.backgroundColor = '#fff'; e.style.color = '#000';"],
		];
	}

	/**
	 * scan()'s background vocabulary and contextHasForeground()'s foreground vocabulary are
	 * separate patterns that must agree. They have drifted apart twice (issue #2864): once
	 * leaving a form undetected, once rejecting a form that was correctly paired. Every
	 * detected syntax is exercised BOTH ways here, so a future addition to one pattern that
	 * is not mirrored in the other fails instead of shipping.
	 */
	#[DataProvider('backgroundSyntaxes')]
	public function testEveryDetectedFormIsAlsoRecognisedWhenPaired(string $unpaired, string $paired): void
	{
		$this->assertNotSame([], self::scan($unpaired),
			'scan() must detect this background syntax: ' . $unpaired);
		$this->assertSame([], self::scan($paired),
			'contextHasForeground() must accept the pairing idiom native to this syntax: ' . $paired);
	}

	/**
	 * issue #2866: a `color:` on a NEIGHBOURING element must not satisfy the pairing
	 * check for an unrelated background. In pfblockerng_category_edit.php the unpaired
	 * `$failed_bg` background sits in the same PHP block as a separate span that pins
	 * `color: black`, so the block-level context window laundered the violation.
	 */
	public function testNeighbouringElementForegroundDoesNotPair(): void
	{
		$span = '$failed = "<span style=\"color: black; background-color: #FFFF00; border-style: groove;\">Failed</span>";';
		$defect = "if (true) {\n\t\$failed_bg = 'background-color: #FFFF00;';\n\t" . $span . "\n}";
		$this->assertNotSame([], self::scan($defect),
			'a colour belonging to a neighbouring element must not pair an unrelated background');
		$paired = "if (true) {\n\t\$failed_bg = 'background-color: #FFFF00; color: black;';\n\t" . $span . "\n}";
		$this->assertSame([], self::scan($paired),
			'a foreground in the same declaration string must still pair');
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

		// Collected, not asserted one at a time: a new hit inside a file the TODO already
		// lists is invisible to a key-wise diff, and an early assert would abort before the
		// per-needle loop that does see it. One verdict reports every violation at once.
		$problems = [];
		foreach (array_keys($found + $todo) as $rel) {
			$have = $found[$rel] ?? [];
			$needles = $todo[$rel] ?? [];
			if (!array_key_exists($rel, $todo)) {
				$problems[] = $rel . ': new opaque-without-foreground site -- do not allowlist it, '
					. 'fix it or get an owner ruling: ' . implode(', ', $have);
				continue;
			}
			if ($have === []) {
				$problems[] = $rel . ': TODO entry is fixed; remove it from '
					. 'TODO_OPAQUE_WITHOUT_FOREGROUND_20260829';
				continue;
			}
			foreach ($needles as $needle) {
				if (!self::listContainsNeedle($have, $needle)) {
					$problems[] = $rel . ': TODO needle missing: ' . $needle
						. ' (have: ' . implode(' | ', $have) . ')';
				}
			}
			foreach ($have as $hit) {
				if (!self::listContainsNeedle($needles, $hit)) {
					$problems[] = $rel . ': extra opaque-without-foreground hit: ' . $hit;
				}
			}
		}

		$this->assertSame([], $problems,
			"the tree's opaque-without-foreground inventory no longer matches the dated TODO:\n  "
			. implode("\n  ", $problems));
	}

	/**
	 * @return list<array{line:int, excerpt:string}>
	 */
	public static function scan(string $source): array
	{
		$hits = [];
		// issue #2864: every shape that can set a background, not just the declaration and
		// the bare object key. Named groups, because an alternation numbers groups globally
		// and a hand-written backreference silently points at the wrong branch.
		if (preg_match_all(
			'/background(?:-color)?\s*:\s*(?<css>[^;}\n]+)'
			. '|backgroundColor\s*:\s*(?<jsq>["\'])(?<js>[^"\']+)\k<jsq>'
			. '|(?<objq>["\'])background(?:-color|Color)?\k<objq>\s*:\s*(?<objvq>["\'])(?<obj>[^"\']*+)\k<objvq>'
			. '|(?:\.css\(|(?<![A-Za-z0-9_])setProperty\()\s*(?<setq>["\'])background(?:-color|Color)?\k<setq>\s*,\s*'
			. '(?<setvq>["\'])(?<set>[^"\']*+)\k<setvq>'
			. '|\.style\.backgroundColor\s*=\s*(?<domq>["\'])(?<dom>[^"\']*+)\k<domq>/i',
			$source,
			$matches,
			PREG_OFFSET_CAPTURE
		) !== FALSE) {
			$count = count($matches[0]);
			for ($i = 0; $i < $count; $i++) {
				$full = $matches[0][$i][0];
				$offset = $matches[0][$i][1];
				$value = self::firstColorToken($matches['css'][$i][0] ?? '');
				$value = $value !== '' ? $value : trim($matches['js'][$i][0] ?? '');
				$value = $value !== '' ? $value : trim($matches['obj'][$i][0] ?? '');
				$value = $value !== '' ? $value : trim($matches['set'][$i][0] ?? '');
				$value = $value !== '' ? $value : trim($matches['dom'][$i][0] ?? '');
				if ($value === '' || self::isInterpolated($value) || self::isTranslucent($value)) {
					continue;
				}
				[$ctx, $ctxStart] = self::declarationContext($source, $offset);
				if (self::contextHasForeground($source, $offset, $ctx, $ctxStart)) {
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

	/**
	 * @return array{0: string, 1: int} the context window and its absolute start offset
	 *         in $source, so callers can map matches inside the window back to $source.
	 */
	private static function declarationContext(string $source, int $offset): array
	{
		$before = substr($source, 0, $offset);
		$brace = strrpos($before, '{');
		if ($brace !== FALSE) {
			$end = strpos($source, '}', $brace);
			if ($end !== FALSE && $end >= $offset) {
				return [substr($source, $brace, $end - $brace + 1), $brace];
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
			return [substr($source, max(0, $offset - 80), 160), max(0, $offset - 80)];
		}
		$end = strpos($source, $quote, $start + 1);
		return [$end === FALSE ? substr($source, $start) : substr($source, $start, $end - $start + 1), $start];
	}

	private static function contextHasForeground(string $source, int $bgOffset, string $ctx, int $ctxStart): bool
	{
		// Every way a foreground can be set must be recognised here, or code paired through
		// a form scan() detects but this does not reports as a violation. The two
		// vocabularies are kept in lockstep by testEveryDetectedFormIsAlsoRecognisedWhenPaired.
		//
		// issue #2866: the pairing foreground must belong to the SAME element as the
		// background. In a brace context (a PHP block, not a CSS rule) a `color:` can sit
		// in a neighbouring element's markup — e.g. the separate failed-download span that
		// laundered category_edit's unpaired $failed_bg. A foreground with an HTML tag
		// starting between it and the background belongs to a different element and does
		// not satisfy the pairing check.
		if (preg_match_all(
			'/(?<![A-Za-z0-9_-])color["\']?\s*:'
			. '|(?<![A-Za-z0-9_-])color\s*='
			. '|setProperty\(\s*["\']color["\']/i',
			$ctx,
			$m,
			PREG_OFFSET_CAPTURE
		) === FALSE) {
			return FALSE;
		}
		foreach ($m[0] as [$text, $rel]) {
			$colorOffset = $ctxStart + $rel;
			$gap = substr($source, min($bgOffset, $colorOffset), abs($colorOffset - $bgOffset));
			if (!preg_match('/<[A-Za-z\/]/', $gap)) {
				return TRUE;
			}
		}
		return FALSE;
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
