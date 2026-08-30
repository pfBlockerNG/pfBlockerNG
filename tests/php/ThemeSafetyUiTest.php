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
	 * Backgrounds a neighbouring colour used to launder, and the pairings that are real.
	 *
	 * The window that decides "is this background paired" is the whole guard. Both defects
	 * it had were a colour belonging to a different element landing inside that window:
	 * a nested object's (issue #2892) and an adjacent statement's (issue #2866). Each row
	 * states the shape and whether it is genuinely paired.
	 *
	 * @return array<string, array{0: string, 1: bool}>
	 */
	public static function pairingWindows(): array
	{
		return [
			// Nested scopes: a colour one level in never pairs a background one level out.
			'nested object colour'      => ['$(x).css({"background-color": "#123456", extra: {color: "nope"}});', FALSE],
			'nested rule colour'        => ['.a { background-color: #123456; nested: { color: red; } }', FALSE],
			'nested block before it'    => ['.a { nested: { color: red; } background-color: #123456; }', FALSE],
			'pairing after that block'  => ['.a { background-color: #123456; nested: { top: 0; } color: red; }', TRUE],
			'outer rule pairs nested'   => ['.a { color: red; background-color: #123456; nested: { top: 0; } }', TRUE],
			// Issue #2866: a code block is not a rule, so a sibling statement cannot pair.
			'sibling statement colour'  => ["if (\$x) {\n\t\$bg = 'background-color: #FFFF00;';\n\t\$f = \"<span style=\\\"color: black; background-color: #FFFF00;\\\">x</span>\";\n}", FALSE],
			'inline style, unpaired'    => ['$bg = \'background-color: #FFFF00;\';', FALSE],
			'inline style, paired'      => ['$bg = \'background-color: #FFFF00; color: black;\';', TRUE],
			// A literal is often a whole fragment: one element must not pair another's.
			'sibling element colour'    => ['$s = "<span style=\"color: black;\"></span><input style=\"background-color: #123456;\">";', FALSE],
			'same element colour'       => ['$s = "<span style=\"color: black; background-color: #FFFF00;\">x</span>";', TRUE],
			'single-quoted attribute'   => ['$s = \'<input style="background-color: #123456;">\';', FALSE],
			// An apostrophe in prose is not a string opener.
			'apostrophe in prose'       => ["/* don't */ .a { background-color: #123456; } .b { color: red; }", FALSE],
			'apostrophe, pair below'    => ["/* it's fine */ .a { background-color: #123456;\n color: red; }", TRUE],
			// The two fallbacks, each pinned by a pairing further away than the window.
			'no scope at all'           => ['background-color: #123456;' . str_repeat(' ', 200) . 'color: red;', FALSE],
			'unclosed block pairs'      => ['.a { background-color: #123456;' . str_repeat(' ', 200) . 'color: red;', TRUE],
			// Same-scope pairings that must keep working.
			'same object colour'        => ['$(x).css({"background-color": "#123456", color: "red"});', TRUE],
			'same rule colour'          => ['.a { background-color: #123456; color: red; }', TRUE],
		];
	}

	#[DataProvider('pairingWindows')]
	public function testOnlyAColourOnTheSameElementPairsABackground(string $source, bool $paired): void
	{
		$this->assertSame($paired, self::scan($source) === [],
			($paired ? 'wrongly reported unpaired: ' : 'a neighbouring colour laundered: ') . $source);
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

	/**
	 * The declarations that actually share an element with the background at $offset.
	 *
	 * Three shapes, most specific first. A background written inside a string literal is an
	 * inline style attribute, so only that string can pair it -- the enclosing PHP or JS
	 * block is code, not a rule, and its neighbours belong to other elements (issue #2866).
	 * A background in a real block is paired only by that block's own declarations, so
	 * nested blocks are removed rather than read as siblings (issue #2892).
	 */
	private static function declarationContext(string $source, int $offset): string
	{
		$inline = self::enclosingString($source, $offset);
		if ($inline !== NULL) {
			return $inline;
		}
		$block = self::enclosingBlock($source, $offset);
		if ($block !== NULL) {
			return self::withoutNestedBlocks(substr($source, $block[0], $block[1] - $block[0] + 1));
		}
		return substr($source, max(0, $offset - 80), 160);
	}

	/** The string literal containing $offset, or NULL when it is not inside one. */
	private static function enclosingString(string $source, int $offset): ?string
	{
		$lineStart = strrpos(substr($source, 0, $offset), "\n");
		$lineStart = $lineStart === FALSE ? 0 : $lineStart + 1;

		$quote = NULL;
		$open = 0;
		for ($i = $lineStart; $i < $offset; $i++) {
			if ($source[$i] === '\\') {
				$i++;
				continue;
			}
			if ($source[$i] !== "'" && $source[$i] !== '"') {
				continue;
			}
			if ($quote === NULL) {
				$quote = $source[$i];
				$open = $i;
			} elseif ($quote === $source[$i]) {
				$quote = NULL;
			}
		}
		if ($quote === NULL) {
			return NULL;
		}

		$lineEnd = strpos($source, "\n", $offset);
		$lineEnd = $lineEnd === FALSE ? strlen($source) : $lineEnd;
		for ($i = $offset; $i < $lineEnd; $i++) {
			if ($source[$i] === '\\') {
				$i++;
				continue;
			}
			if ($source[$i] === $quote) {
				return self::styleAttribute($source, $open, $i, $offset)
					?? substr($source, $open, $i - $open + 1);
			}
		}
		// The quote never closed on this line, so it was an apostrophe in prose, not a
		// string opener. Truncating a context at end-of-line hides a pairing on the next
		// one; let the block resolver answer instead.
		return NULL;
	}

	/**
	 * The innermost style="..." attribute inside a literal, when the background is in one.
	 *
	 * A PHP string is routinely a whole HTML fragment, not one attribute -- several sites
	 * build a <span> and an <input> in the same literal. Resolving to the literal lets one
	 * element's colour pair another's background, which is the #2866 defect one scope out.
	 */
	private static function styleAttribute(string $source, int $open, int $close, int $offset): ?string
	{
		$literal = substr($source, $open, $close - $open + 1);
		$rel = $offset - $open;
		if (preg_match_all('/style\s*=\s*(\\\\?)(["\'])/i', $literal, $matches, PREG_OFFSET_CAPTURE) < 1) {
			return NULL;
		}
		$count = count($matches[0]);
		for ($i = 0; $i < $count; $i++) {
			$start = $matches[0][$i][1] + strlen($matches[0][$i][0]);
			// The attribute's closing delimiter is written exactly as its opener was: in a
			// PHP double-quoted literal that is \", so the backslash terminates rather
			// than escapes. Skipping it as an escape runs the context past the element.
			$terminator = $matches[1][$i][0] . $matches[2][$i][0];
			$end = strpos($literal, $terminator, $start);
			$end = $end === FALSE ? strlen($literal) : $end;
			if ($rel >= $start && $rel < $end) {
				return substr($literal, $start, $end - $start);
			}
		}
		return NULL;
	}

	/**
	 * Offsets of the innermost brace block containing $offset, or NULL at top level.
	 *
	 * @return array{0: int, 1: int}|null
	 */
	private static function enclosingBlock(string $source, int $offset): ?array
	{
		$stack = [];
		for ($i = 0; $i < $offset; $i++) {
			if ($source[$i] === '{') {
				$stack[] = $i;
			} elseif ($source[$i] === '}') {
				array_pop($stack);
			}
		}
		if ($stack === []) {
			return NULL;
		}

		$start = (int)end($stack);
		$depth = 0;
		$length = strlen($source);
		for ($i = $start; $i < $length; $i++) {
			if ($source[$i] === '{') {
				$depth++;
			} elseif ($source[$i] === '}') {
				$depth--;
				if ($depth === 0) {
					return [$start, $i];
				}
			}
		}
		return [$start, $length - 1];
	}

	/** The block's own declarations, with every nested block's contents dropped. */
	private static function withoutNestedBlocks(string $block): string
	{
		$out = '';
		$depth = 0;
		$length = strlen($block);
		for ($i = 0; $i < $length; $i++) {
			if ($block[$i] === '{') {
				$depth++;
				if ($depth === 1) {
					$out .= $block[$i];
				}
				continue;
			}
			if ($block[$i] === '}') {
				$depth--;
				if ($depth === 0) {
					$out .= $block[$i];
				}
				continue;
			}
			if ($depth <= 1) {
				$out .= $block[$i];
			}
		}
		return $out;
	}

	private static function contextHasForeground(string $ctx): bool
	{
		// Every way a foreground can be set must be recognised here, or code paired through
		// a form scan() detects but this does not reports as a violation. The two
		// vocabularies are kept in lockstep by testEveryDetectedFormIsAlsoRecognisedWhenPaired.
		return (bool)preg_match(
			'/(?<![A-Za-z0-9_-])color["\']?\s*:'
			. '|(?<![A-Za-z0-9_-])color\s*='
			. '|setProperty\(\s*["\']color["\']/i',
			$ctx
		);
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
