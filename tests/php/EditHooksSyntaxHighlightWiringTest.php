<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1669 Part B slice B2 -- live CodeMirror 6 syntax highlighting (python + shell
 * modes only, no PHP -- ADR-12 addendum) for the Edit Hooks page's
 * #pfb_hook_editor_content textarea, gated by the same General-settings
 * `pfb_syntax_highlight` toggle DnsblRegexHighlightWiringTest pins for the DNSBL
 * regex-list field (registered in pfb_cfg_registry(), default on).
 *
 * pfblockerng_edit_hooks.php carries top-level render execution (require_once('guiconfig.inc')
 * et al.) and cannot be require()d/rendered off-appliance -- same constraint documented on
 * DnsblRegexHighlightWiringTest/FeedsUrlCompareIconRenderTest/CategoryEditReservedHeaderTest.
 * This test pins the CONDITIONAL STRUCTURE itself (the pfb_editor_enabled() accessor
 * comparison, and the gated script tag / JS init all being driven by the same PHP boolean),
 * plus vacuity-safe exactly-once occurrence counts, rather than asserting the markup is
 * unconditionally present. Reading the real source file IS reading the render for this
 * content (same rationale as DnsblRegexHighlightWiringTest); this remains the Tier-A
 * ui_render coverage for this www/ change together with tests/smoke/ui/test_render_smoke.py's
 * "edit_hooks" marker (present only because the toggle defaults on for a fresh box).
 */
final class EditHooksSyntaxHighlightWiringTest extends TestCase
{
	private static string $src;

	public static function setUpBeforeClass(): void
	{
		$path = dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_edit_hooks.php';
		$src  = file_get_contents($path);
		if ($src === false) {
			throw new RuntimeException('failed to read pfblockerng_edit_hooks.php');
		}
		self::$src = $src;
	}

	public function testGatingBooleanReadsThePfbSyntaxHighlightToggle(): void
	{
		// Same enum-comparison idiom as pfblockerng_dnsbl.php's $pfb_syntaxhl_on -- LENIENT
		// (issue #1887 accessor) -- see DnsblRegexHighlightWiringTest's docblock for
		// why a default-on field needs the lenient adapter.
		$this->assertMatchesRegularExpression(
			"#\\\$pfb_syntaxhl_on\\s*=\\s*pfb_editor_enabled\\(\\)#",
			self::$src,
			'expected a $pfb_syntaxhl_on boolean derived from pfb_editor_enabled() (issue #1887 named accessor)'
		);
	}

	public function testCmHooksScriptIsIncludedWithCacheBustingInsideTheGate(): void
	{
		// Tempered-dot gaps ((?:(?!endif).)*?), not bare .*? -- see
		// DnsblRegexHighlightWiringTest's identical comment for why a bare .*? risks
		// bridging past this gate's own close into a later, unrelated if/endif block.
		$this->assertMatchesRegularExpression(
			'#if\s*\(\s*\$pfb_syntaxhl_on\s*\)\s*:(?:(?!endif).)*?'
			. '<script src="vendor/codemirror/cm-hooks\.min\.js\?v=<\?=pfb_file_mtime\(\'/usr/local/www/pfblockerng/vendor/codemirror/cm-hooks\.min\.js\'\)\?>"></script>'
			. '(?:(?!endif).)*?endif#s',
			self::$src,
			'expected the cm-hooks.min.js include, with mtime cache-busting, wrapped inside an if ($pfb_syntaxhl_on) gate'
		);
	}

	public function testEditorInitTargetsThePfbHookEditorContentElementAndChecksWindowPfbHooksCM(): void
	{
		$this->assertStringContainsString(
			"getElementById('pfb_hook_editor_content')",
			self::$src,
			'expected the CM6 init to look up the pfb_hook_editor_content element by id'
		);
		$this->assertStringContainsString(
			'window.pfbHooksCM',
			self::$src,
			'expected the CM6 init to guard on window.pfbHooksCM (the vendored cm-hooks bundle\'s IIFE global) being defined'
		);
		$this->assertMatchesRegularExpression(
			'/pfbHooksCM\.fromTextarea\(/',
			self::$src,
			'expected the CM6 init to call pfbHooksCM.fromTextarea() on the located element'
		);
	}

	public function testEditorInitPassesTheServerComputedLanguage(): void
	{
		// Mode selection follows the hook file's extension -- decided server-side by
		// pfb_hook_editor_lang_for(), rendered as fromTextarea()'s second argument (a
		// quoted 'py'|'sh' literal echoed from PHP), never re-derived in JS.
		$this->assertStringContainsString('pfb_hook_editor_lang_for(', self::$src, 'expected the page to call pfb_hook_editor_lang_for()');
		// [,)] after the language literal, not a bare `\)`: issue #1732 step 2 added a
		// third (opts) argument, so the call no longer necessarily closes right after
		// the language literal -- the second-argument contract itself is unchanged.
		$this->assertMatchesRegularExpression(
			"/pfbHooksCM\\.fromTextarea\\([^)]*,\\s*'<\\?=\\\$pfb_eh_lang\\?>'\\s*[,)]/",
			self::$src,
			'expected fromTextarea() to be called with a second argument echoing $pfb_eh_lang'
		);
	}

	public function testEditorInitIsGatedInsideEventsPushBehindTheSameBoolean(): void
	{
		$this->assertMatchesRegularExpression(
			'#events\.push\(function\(\)\s*\{(?:(?!endif).)*?if\s*\(\s*\$pfb_syntaxhl_on\s*\)\s*:(?:(?!endif).)*?'
			. "getElementById\\('pfb_hook_editor_content'\\)(?:(?!endif).)*?pfbHooksCM\\.fromTextarea\\((?:(?!endif).)*?endif#s",
			self::$src,
			'expected the pfb_hook_editor_content CM6 init inside events.push(), gated by if ($pfb_syntaxhl_on)'
		);
	}

	/**
	 * Vacuity-safe "off emits nothing new" proof -- same rationale as
	 * DnsblRegexHighlightWiringTest::testCmRegexAssetAndFromTextareaCallEachAppearExactlyOnceInTheWholeFile():
	 * the earlier gate-shape regexes only prove a gated occurrence EXISTS, not that no
	 * second, unguarded copy exists elsewhere. Counting occurrences closes that gap.
	 */
	public function testCmHooksAssetAndFromTextareaCallEachAppearExactlyOnceInTheWholeFile(): void
	{
		$this->assertSame(
			1,
			substr_count(self::$src, '<script src="vendor/codemirror/cm-hooks.min.js?v='),
			'expected exactly one cm-hooks.min.js <script> tag in the whole file (the gated include) -- '
			. 'a second, unguarded <script> tag would defeat the off-emits-nothing contract'
		);
		$this->assertSame(
			1,
			substr_count(self::$src, 'pfbHooksCM.fromTextarea('),
			'expected exactly one pfbHooksCM.fromTextarea( call in the whole file (the gated events.push init) -- '
			. 'a second, unguarded call would defeat the off-emits-nothing contract'
		);
	}

	/**
	 * issue #1732 step 2: the Edit Hooks page's fromTextarea() call now also wires the
	 * advisory server-lint endpoint, still inside the SAME $pfb_syntaxhl_on gate --
	 * toggling syntax highlighting off must keep emitting zero lint bytes too.
	 */
	public function testEditorInitPassesTheLintUrlInsideTheSameGate(): void
	{
		$this->assertMatchesRegularExpression(
			"#events\\.push\\(function\\(\\)\\s*\\{(?:(?!endif).)*?if\\s*\\(\\s*\\\$pfb_syntaxhl_on\\s*\\)\\s*:(?:(?!endif).)*?"
			. "pfbHooksCM\\.fromTextarea\\([^;]*?lintUrl:\\s*'/pfblockerng/pfblockerng_lint\\.php'(?:(?!endif).)*?endif#s",
			self::$src,
			"expected pfbHooksCM.fromTextarea(...) to pass lintUrl: '/pfblockerng/pfblockerng_lint.php' inside the \$pfb_syntaxhl_on gate"
		);
	}

	/**
	 * Vacuity-safe count for the new lintUrl wiring, same rationale as
	 * testCmHooksAssetAndFromTextareaCallEachAppearExactlyOnceInTheWholeFile.
	 */
	public function testLintUrlAppearsExactlyOnceInTheWholeFile(): void
	{
		$this->assertSame(
			1,
			substr_count(self::$src, "lintUrl: '/pfblockerng/pfblockerng_lint.php'"),
			'expected exactly one lintUrl wiring in the whole file (the gated events.push init)'
		);
	}

	public function testOriginalHookEditorTextareaFieldIsUnchanged(): void
	{
		// The save handler's $_POST['pfb_eh_content'] read keys off this exact
		// Form_Textarea('pfb_eh_content', ...) name -- this slice must not touch it; the
		// CM6 overlay is a pure client-side progressive enhancement layered on top.
		$this->assertMatchesRegularExpression(
			"#new Form_Textarea\\(\\s*'pfb_eh_content',#",
			self::$src,
			'expected the underlying pfb_eh_content Form_Textarea field to remain unchanged'
		);
	}
}
