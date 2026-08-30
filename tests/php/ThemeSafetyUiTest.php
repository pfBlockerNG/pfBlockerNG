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
	/**
	 * Every character that opens a string literal in the languages scanTree() reads.
	 *
	 * The backtick is one of them: it delimits a JS template literal, and a background
	 * inside one had no string to be scoped to (issue #2930). It is also how a PHP comment
	 * writes a markdown code span, which is why the file-wide scan reads comments.
	 */
	private const DELIMITERS = "'\"`";

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
			// Issue #2928: a multi-line literal opens its quote on an EARLIER line. A scan
			// that starts at the offset's own line finds no quote there, concludes the
			// background is not in a string at all, and hands the question to the block
			// resolver -- where a sibling statement pairs it. That is the #2866 shape
			// reached by a different route, so it is pinned in both directions: a literal
			// that genuinely does not pair, and one that genuinely does.
			'multi-line literal'        => ["if (\$x) {\n\t\$s = \"aaaa\nbackground-color: #123456;\nbbbb\";\n\tcolor: red;\n}", FALSE],
			'multi-line same literal'   => ['$s = "background-color: #123456;' . str_repeat(' ', 200) . "\n" . ' color: red;";', TRUE],
			// A literal that never closes is not a literal. Without that test the scan would
			// hand back everything from the quote to end of file, which is the desync it exists
			// to prevent, so the pairing sits past the no-scope window to tell the two apart.
			'literal never closes'      => ['$s = "background-color: #123456;' . str_repeat(' ', 200) . "\ncolor: red;", FALSE],
			// A comment apostrophe desynchronises the line-scoped toggle, which then reports
			// nothing rather than the genuine single-line literal beside it. The file-wide scan
			// reads the comment and finds that literal, and the literal carries no foreground,
			// so the neighbouring statement must not pair it.
			'literal beside a comment'  => ["/* don't */ \$bg = 'background-color: #123456;'; color: red;", FALSE],
			'that literal, paired'      => ["/* don't */ \$bg = 'background-color: #123456; color: red;';", TRUE],
			// Issue #2930: two body forms carry no delimiter the quote scans track, so a
			// background inside one resolved through the brace path or the no-scope window and
			// a colour belonging to other code paired it. Each form is pinned unpaired and
			// paired, and every paired row puts its colour past the no-scope window so the row
			// cannot pass on that fallback instead of on the literal.
			'heredoc, unpaired'         => ["if (\$x) {\n\t\$s = <<<EOT\nbackground-color: #123456;\nEOT;\n\tcolor: red;\n}", FALSE],
			'heredoc, paired'           => ["\$s = <<<EOT\ncolor: black;" . str_repeat(' ', 200) . "\nbackground-color: #123456;\nEOT;", TRUE],
			'nowdoc, unpaired'          => ["if (\$x) {\n\t\$s = <<<'EOT'\nbackground-color: #123456;\nEOT;\n\tcolor: red;\n}", FALSE],
			'nowdoc, paired'            => ["\$s = <<<'EOT'\ncolor: black;" . str_repeat(' ', 200) . "\nbackground-color: #123456;\nEOT;", TRUE],
			// The marker is a line of its own, and it is the whole identifier. One that appears
			// mid-body does not end the body, and neither does a longer word starting with it;
			// ending a body early drops the rest of it back into the code around the heredoc.
			'heredoc marker mid-body'   => ["\$s = <<<EOT\nthis EOT is not the end\nbackground-color: #123456;\nEOT;\ncolor: red;", FALSE],
			'heredoc marker is a prefix'=> ["\$s = <<<EOT\nEOTHER\nbackground-color: #123456;\nEOT;\ncolor: red;", FALSE],
			// A `<<<` with no marker below it is not a heredoc -- it ends a comment, or sits in
			// a string, or the file is malformed. It must answer nothing rather than report a
			// body running to end of file, which would swallow every declaration under it.
			'heredoc opener in comment' => ["// the marker is written <<<EOT\nbackground-color: #123456;" . str_repeat(' ', 200) . "\ncolor: red;", FALSE],
			'heredoc opener in string'  => ["\$s = \"<<<END\nmore text\";\nbackground-color: #123456;" . str_repeat(' ', 200) . "\ncolor: red;", FALSE],
			// An empty heredoc's single newline has to serve as both the opener's and the
			// marker's. Read as unterminated, it takes the NEXT heredoc's marker as its own and
			// the two bodies merge, which pairs a background with a colour outside its body.
			'empty heredoc body'        => ["\$e = <<<EOT\nEOT;\ncolor: red;\n\$s = <<<EOT\nbackground-color: #123456;\nEOT;", FALSE],
			// A body is one literal, so it is the scope -- the quote scans must not answer
			// first and hand back a quoted run inside it as if it were its own literal.
			'heredoc outranks quotes'   => ["\$s = <<<EOT\n'background-color: #123456;' color: red;\nEOT;", TRUE],
			'template literal, unpaired'=> ["function f() {\n\tconst a = `background-color: #123456;`;\n\tconst b = \"color: red;\";\n}", FALSE],
			'template literal, paired'  => ["const a = `color: black;" . str_repeat(' ', 200) . "\nbackground-color: #123456;`;", TRUE],
			// A backtick is a delimiter in JS and a markdown code span in a PHP comment, and
			// this tree has 208 of the second kind in pfblockerng.inc alone. An unbalanced span
			// must not open a literal that swallows the lines below it.
			'backtick span in prose'    => ["// see `background-color\nbackground-color: #123456;" . str_repeat(' ', 200) . "\ncolor: red;\n// and `color", FALSE],
			'multi-line attribute pairs'=> ['$s = "<span style=\"color: black;' . str_repeat(' ', 200) . "\n" . ' background-color: #123456;\">x</span>";', TRUE],
			// ...and the reason the scan was scoped to one line in the first place, which any
			// fix has to keep: an apostrophe in prose is not a string opener, so it must not
			// open a literal that swallows the lines beneath it. The pairing sits past the
			// no-scope fallback window and a second apostrophe waits below it, so a whole-file
			// quote toggle pairs the two and launders the background.
			'prose apostrophe above'    => ["/* don't */\nbackground-color: #123456;" . str_repeat(' ', 200) . "\ncolor: red;\n/* the user's guide */", FALSE],
			// Prose does not only put a quote inside a word. A possessive after a closing
			// bracket and a quote written as itself are both prose too, and neither is preceded
			// by a letter -- the tree carries the first shape at
			// pfblockerng_hook_edit.inc:180. What they have in common is not the character
			// before them, it is that they are in a comment.
			'prose quote after bracket' => ["/* fail pfb_hook_scripts()' membership */\nbackground-color: #123456;" . str_repeat(' ', 200) . "\ncolor: red;\n/* it's */", FALSE],
			'prose quote written alone' => ["/* use the ' character */\nbackground-color: #123456;" . str_repeat(' ', 200) . "\ncolor: red;\n/* it's */", FALSE],
			'line comment holds one too'=> ["// use the ' character\nbackground-color: #123456;" . str_repeat(' ', 200) . "\ncolor: red;\n// it's", FALSE],
			// Not all prose is in a comment: a .php page is inline HTML outside its tags, and
			// an apostrophe in body text is no more a delimiter there than in a docblock. A
			// quote is not one where a letter or digit runs straight into it.
			'apostrophe in page text'   => ["<p>Don't do that</p>\nbackground-color: #123456;" . str_repeat(' ', 200) . "\ncolor: red;\n<p>It's fine</p>", FALSE],
			// '>' is the one opener character that is also ordinary markup. It has to be
			// accepted as PHP's '=>' and rejected as a closing tag, or a quote in page
			// prose opens a literal over everything below it.
			'array arrow opens a value' => ["\$a = [\n  'k' => \"aaa\nbackground-color: #123456;\nbbb\",\n];\ncolor: red;", FALSE],
			'closing tag does not'      => ["<span>'Tis the season</span>\nbackground-color: #123456;" . str_repeat(' ', 200) . "\ncolor: red;\n<span>'more'</span>", FALSE],
			// Reading comments cuts both ways: a `//` that is not a comment opener must not eat
			// the rest of its line. In a URL it follows the scheme's colon or the opening
			// bracket, and skipping from there loses the quote that opens the literal below.
			// A `#` comment is a comment too. The tree writes banner blocks of them
			// (pfblockerng_apply.inc:4540), and a lone quote in one desynchronises the scan
			// exactly as it does in the other two comment forms. What `#` must NOT swallow is a
			// colour, which is the same character and is why it went unread until now.
			'hash comment holds a quote'=> ["# the ' character\nbackground-color: #123456;" . str_repeat(' ', 200) . "\ncolor: red;\n# it's", FALSE],
			'hash colour is not one'    => [".a { color: #fff; } \$s = 'background-color: #123456;\nbbb'", FALSE],
			// The closing scan honours an escape, or a literal ends at its first \" and the
			// pairing that follows it is read as code outside the string.
			'escaped quote in a literal'=> ['$s = "aaa' . "\n" . 'background-color: #123456;\" color: red;' . "\n" . 'bbb";', TRUE],
			// A style attribute that is not this background's cannot pair it either.
			'unrelated attribute'       => ['$s = ".a { background-color: #123456; } <span style=\"color: black;\"></span>";', FALSE],
			'unrelated attr, no braces' => ['$s = \'background-color: #123456; <span style="color:black;"></span>\';', FALSE],
			'own attribute pairs it'    => ['$s = "<input style=\"color: black; background-color: #123456;\">";', TRUE],
			// Only a real style attribute opens a span: data-style and chart_style do not.
			'decoy carries a colour'    => ['$s = "<div data-style=\"color: red\"></div> background-color: #123456;";', FALSE],
			'decoy attribute name'      => ['$s = "<div data-style=\"dark\">x</div> background-color: #123456; foo({color: \'red\'})";', FALSE],
			'real attribute still pairs'=> ['$s = "<div data-style=\"dark\" style=\"color: red; background-color: #123456;\">";', TRUE],
			// A background flanked by two attributes: both values go, and the later span's
			// offsets must still be valid when the earlier one is removed.
			'flanked by two attributes' => ['$s = "<a style=\"color:red\"></a> background-color: #123456; <b style=\"color:blue\"></b>";', FALSE],
			// A brace group before an attribute: the cuts interleave, so they must be
			// ordered before they are applied back to front.
			'group then attribute'      => ['$s = "foo({color:\'red\'}) background-color: #123456; <b style=\"color:blue\"></b>";', FALSE],
			// A literal nests exactly as a rule does, so it is scoped the same way.
			'nested inside a literal'   => ['$s = "foo({outer: {background-color: \'#123456\'}, color: \'red\'})";', FALSE],
			'nested three deep'         => ['$s = "foo({a: {b: {background-color: \'#123456\'}}, color: \'red\'})";', FALSE],
			'same level in that group'  => ['$s = "foo({background-color: \'#123456\', color: \'red\'})";', TRUE],
			'subgroup of that group'    => ['$s = "foo({background-color: \'#123456\', sub: {color: \'red\'}})";', FALSE],
			'stylesheet is an attribute'=> ['$s = "<div stylesheet=\"color: red;\"></div> background-color: #123456;";', FALSE],
			// A quoted brace desynchronises the depth count; the surviving cuts must still
			// leave the background's own scope standing.
			'quoted brace desync'       => ['$s = "foo({background-color: \'#123456\', n1: \'{\', n2: \'{\', sub: {color: \'red\'}})";', FALSE],
			// An attribute inside a foreign group puts one cut inside another; removing the
			// inner one first must not invalidate the outer one's end.
			'attribute inside a group'  => ['$s = "foo({a: \'<div style=\"color: red; xxxxxxxxxxxxxxxxxxxxxxxx\">\'}) background-color: #123456; color: blue;";', TRUE],
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
		$heredoc = self::enclosingHeredoc($source, $offset);
		if ($heredoc !== NULL) {
			return $heredoc;
		}
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
			if (!str_contains(self::DELIMITERS, $source[$i])) {
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
			return self::enclosingMultiLineString($source, $offset);
		}

		$lineEnd = strpos($source, "\n", $offset);
		$lineEnd = $lineEnd === FALSE ? strlen($source) : $lineEnd;
		for ($i = $offset; $i < $lineEnd; $i++) {
			if ($source[$i] === '\\') {
				$i++;
				continue;
			}
			if ($source[$i] === $quote) {
				$literal = substr($source, $open, $i - $open + 1);
				return self::styleContext($literal, $offset - $open);
			}
		}
		// The quote never closed on this line: either it was an apostrophe in prose, or it
		// opened a literal that runs on past end-of-line. Only the multi-line resolver can
		// tell those apart, and truncating a context at end-of-line would hide a pairing on
		// the next line, so this scan never answers from its own line alone.
		return self::enclosingMultiLineString($source, $offset);
	}

	/**
	 * The literal containing $offset when that literal spans more than one line.
	 *
	 * The line-scoped scan above structurally cannot see one: a multi-line literal opens
	 * its quote on a line that scan never reads, so the background reads as loose code and
	 * the block resolver lets a sibling statement pair it -- the issue #2866 shape reached
	 * by a different route (issue #2928).
	 *
	 * Scanning the whole file for quotes is what the line scoping was defending against:
	 * an apostrophe in prose then opens a literal that swallows every line beneath it
	 * until the next apostrophe, and desynchronises the file. Prose lives in comments, so
	 * the scan reads them and skips them rather than guessing from the character before a
	 * quote -- a possessive after a closing bracket and a quote written as itself are both
	 * prose and neither follows a letter, and the tree carries the first shape at
	 * pfblockerng_hook_edit.inc:180.
	 *
	 * An apostrophe inside a word (don't, the user's guide) is demoted as well, because a
	 * quote is not a delimiter where a letter or digit runs into it. That test is the
	 * second line rather than the first, and it is not applied to a closing quote, which
	 * routinely follows one of the literal's own characters.
	 *
	 * One further condition keeps a desynchronised scan from inventing a context: the
	 * literal must actually CLOSE at or after $offset, so an unterminated quote answers
	 * nothing rather than handing back the rest of the file.
	 */
	private static function enclosingMultiLineString(string $source, int $offset): ?string
	{
		$quote = NULL;
		$open = 0;
		for ($i = 0; $i < $offset; $i++) {
			if ($source[$i] === '\\') {
				$i++;
				continue;
			}
			if (!str_contains(self::DELIMITERS, $source[$i])) {
				continue;
			}
			if ($quote === $source[$i]) {
				$quote = NULL;
				continue;
			}
			if ($quote !== NULL) {
				continue;
			}
			if (!self::opensAValue($source, $i)) {
				continue;
			}
			$quote = $source[$i];
			$open = $i;
		}
		if ($quote === NULL) {
			return NULL;
		}

		$length = strlen($source);
		for ($i = $offset; $i < $length; $i++) {
			if ($source[$i] === '\\') {
				$i++;
				continue;
			}
			if ($source[$i] !== $quote) {
				continue;
			}
			return self::styleContext(substr($source, $open, $i - $open + 1), $offset - $open);
		}
		return NULL;
	}

	/**
	 * TRUE when the quote at $at sits where a value may begin.
	 *
	 * The scan has to answer one question -- is this quote a DELIMITER or is it prose --
	 * and three rounds of review established that it cannot be answered by recognising
	 * the carrier prose arrives in. `#` opens a CSS colour, a CSS id selector and a PHP
	 * comment; `//` opens a comment and a URL; and scan() reads php, inc, js and css with
	 * no per-language dispatch to tell them apart. Every discriminator added for one of
	 * those closed one hole and opened another, in the direction that launders.
	 *
	 * So the carrier is not consulted at all. A literal opens where a value may begin --
	 * after an assignment, a bracket, a separator, an operator, or at the start of a line
	 * -- and prose quotes do not: `don't`, `the user's guide`, `pfb_hook_scripts()'` and
	 * `#header 'x'` all follow a letter, a digit or a closing bracket.
	 *
	 * The failure direction matters and is the reason this shape is safe where the other
	 * was not. A quote wrongly REJECTED is a literal not resolved, which returns NULL and
	 * leaves the answer exactly as it was before this resolver existed. A quote wrongly
	 * ACCEPTED invents a literal and launders a background. This test only ever errs the
	 * first way, so no input is worse off than devel.
	 */
	private static function opensAValue(string $source, int $at): bool
	{
		for ($i = $at - 1; $i >= 0; $i--) {
			if ($source[$i] === ' ' || $source[$i] === "\t") {
				continue;
			}
			if ($source[$i] === '>') {
				// '>' opens a value only as PHP's '=>'. A bare one closes a tag, and
				// scan() reads php and inc, which carry markup: <span>'Tis the season
				// is prose, and accepting it invents a literal over the lines below.
				return $i > 0 && $source[$i - 1] === '=';
			}
			return strpos("=(,[{:;.+&|?<!\r\n", $source[$i]) !== FALSE;
		}
		return TRUE;
	}

	/**
	 * The heredoc or nowdoc body containing $offset, or NULL when it is in neither.
	 *
	 * A heredoc body carries no delimiter character at all, so every quote scan reports
	 * that a background inside one is not in a string and the brace path answers with the
	 * code around the heredoc instead (issue #2930). A body IS a string literal, so it is
	 * resolved before the quote scans and given the same treatment a quoted literal gets:
	 * an HTML fragment in a heredoc still scopes to the style attribute that owns it.
	 *
	 * Opener and closing marker are matched as ONE pattern, which is what makes the
	 * resolver fail closed. A `<<<EOT` with no closing marker below it -- ending a comment,
	 * sitting inside a string, or simply malformed -- matches nothing and answers NULL,
	 * rather than reporting a body that runs to end of file and swallowing every
	 * declaration under it. Matching the pair also means an opener INSIDE a body is body
	 * text: the scan resumes after each whole match, so it is never seen.
	 *
	 * The marker is a line of its own -- optional indentation, the identifier, then a
	 * non-identifier character. One that merely appears in the body does not end it. The
	 * body's leading newline is matched by a lookahead rather than consumed, so an empty
	 * heredoc, whose one newline has to serve as both the opener's and the marker's, is
	 * still a body of zero characters and not an unterminated one.
	 */
	private static function enclosingHeredoc(string $source, int $offset): ?string
	{
		$bodies = preg_match_all(
			'/<<<[ \t]*(["\']?)([A-Za-z_]\w*)\1[ \t]*(?=(\R))(.*?)\R[ \t]*\2(?![A-Za-z0-9_])/s',
			$source,
			$matches,
			PREG_OFFSET_CAPTURE
		);
		for ($i = 0; $i < $bodies; $i++) {
			$start = $matches[4][$i][1] + strlen($matches[3][$i][0]);
			$end = $matches[4][$i][1] + strlen($matches[4][$i][0]);
			if ($offset >= $start && $offset < $end) {
				return self::styleContext(substr($source, $start, $end - $start), $offset - $start);
			}
		}
		return NULL;
	}

	/**
	 * Spans of every style attribute's value inside a literal.
	 *
	 * The closing delimiter is written exactly as the opener was: in a PHP double-quoted
	 * literal that is \", so the backslash terminates rather than escapes. Skipping it as
	 * an escape runs the span past the element it belongs to.
	 *
	 * data-style and chart_style count too: whatever the attribute is named, its value
	 * belongs to its own element and cannot pair a background somewhere else.
	 *
	 * @return list<array{0: int, 1: int}>
	 */
	private static function styleAttributeSpans(string $literal): array
	{
		if (preg_match_all('/[-\w]*style[-\w]*\s*=\s*(\\\\?)(["\'])/i', $literal, $matches, PREG_OFFSET_CAPTURE) < 1) {
			return [];
		}
		$spans = [];
		$count = count($matches[0]);
		for ($i = 0; $i < $count; $i++) {
			$start = $matches[0][$i][1] + strlen($matches[0][$i][0]);
			$end = strpos($literal, $matches[1][$i][0] . $matches[2][$i][0], $start);
			$spans[] = [$start, $end === FALSE ? strlen($literal) : $end];
		}
		return $spans;
	}

	/**
	 * The declarations that share an element with a background inside a literal.
	 *
	 * A PHP string is routinely a whole HTML fragment. If the background sits in a style
	 * attribute, only that attribute can pair it; otherwise the other elements' attributes
	 * are still theirs, so their values are removed rather than read as neighbours. Spans
	 * are excised back to front, or an earlier removal shifts the offsets of a later one.
	 */
	private static function styleContext(string $literal, int $rel): string
	{
		$spans = self::styleAttributeSpans($literal);
		foreach ($spans as [$start, $end]) {
			if ($rel >= $start && $rel < $end) {
				return substr($literal, $start, $end - $start);
			}
		}

		// Scope to the group the background is actually in, then drop that group's own
		// nested groups. A literal carries the same nesting a rule does, so it gets the
		// same treatment: a colour one level out is not the background's.
		$group = self::enclosingBlock($literal, $rel);
		if ($group !== NULL) {
			$out = self::withoutNestedBlocks(substr($literal, $group[0], $group[1] - $group[0] + 1));
			$cuts = self::styleAttributeSpans($out);
		} else {
			$out = $literal;
			$cuts = array_merge($spans, self::foreignBraceGroups($literal, $rel));
		}

		foreach (array_reverse(self::mergedCuts($cuts)) as [$start, $end]) {
			$out = substr($out, 0, $start) . substr($out, $end);
		}
		return $out;
	}

	/**
	 * Cuts ordered and merged, so no cut sits inside another.
	 *
	 * An attribute can live inside a brace group, which puts one span inside the other.
	 * Removing the inner one first leaves the outer one's end offset pointing past where
	 * its text now ends, and the removal eats whatever followed -- including the pairing
	 * the background actually had.
	 *
	 * @param list<array{0: int, 1: int}> $cuts
	 * @return list<array{0: int, 1: int}>
	 */
	private static function mergedCuts(array $cuts): array
	{
		usort($cuts, static fn (array $a, array $b): int => [$a[0], $b[1]] <=> [$b[0], $a[1]]);
		$merged = [];
		foreach ($cuts as [$start, $end]) {
			$last = count($merged) - 1;
			if ($last >= 0 && $start <= $merged[$last][1]) {
				$merged[$last][1] = max($merged[$last][1], $end);
				continue;
			}
			$merged[] = [$start, $end];
		}
		return $merged;
	}

	/**
	 * Spans of the brace groups inside a literal that do not contain $rel.
	 *
	 * The same rule blocks already follow: a colour one scope in never pairs a background
	 * one scope out. A literal can carry both -- an object argument beside a declaration --
	 * so the groups the background is not in are dropped with the other elements'
	 * attributes.
	 *
	 * @return list<array{0: int, 1: int}>
	 */
	private static function foreignBraceGroups(string $text, int $rel): array
	{
		$groups = [];
		$depth = 0;
		$start = 0;
		$length = strlen($text);
		for ($i = 0; $i < $length; $i++) {
			if ($text[$i] === '{') {
				if ($depth === 0) {
					$start = $i;
				}
				$depth++;
				continue;
			}
			if ($text[$i] === '}' && $depth > 0) {
				$depth--;
				if ($depth === 0 && ($rel < $start || $rel > $i)) {
					$groups[] = [$start, $i + 1];
				}
			}
		}
		return $groups;
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
