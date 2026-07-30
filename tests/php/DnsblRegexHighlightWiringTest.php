<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1669 slice C -- live CodeMirror 6 syntax highlighting for the DNSBL
 * Python-regex list field (`pfb_regex_list`), gated by the new General-settings
 * `pfb_syntax_highlight` toggle (registered in pfb_cfg_registry(), default on).
 *
 * pfblockerng_dnsbl.php carries top-level render execution (require_once('guiconfig.inc')
 * et al.) and cannot be require()d/rendered off-appliance -- same constraint documented
 * on FeedsUrlCompareIconRenderTest/CategoryEditReservedHeaderTest. Slice 2 (the retired
 * Prism version) pinned unconditional literal source directly, because its markup was
 * unconditional. This slice's markup is CONDITIONAL (the asset include + the JS init are
 * both gated behind the toggle, per the pivot decision to emit zero highlight bytes when
 * it is off), so this test pins the CONDITIONAL STRUCTURE itself -- the PfbConfig read,
 * the pfb_editor_enabled() accessor (issue #1887 — hides the key, the registered
 * default and the stored token behind one bool), and the gated script tag /
 * JS init all being driven by the same PHP boolean -- rather than asserting the markup is
 * unconditionally present. A separate exactly-once occurrence count on both the script
 * src and the fromTextarea call is the vacuity-safe proof that "off emits nothing new":
 * a regex that merely finds a match inside *a* gate would still pass if a second,
 * unguarded reference existed elsewhere in the file; counting occurrences closes that gap.
 * Reading the real source file IS reading the render for this content (same rationale as
 * slice 2); this remains the Tier-A ui_render coverage for this www/ change together with
 * tests/smoke/ui/test_render_smoke.py's marker (present only because the toggle defaults
 * on for a fresh box).
 */
final class DnsblRegexHighlightWiringTest extends TestCase
{
	private static string $src;

	public static function setUpBeforeClass(): void
	{
		$path = dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php';
		$src  = file_get_contents($path);
		if ($src === false) {
			throw new RuntimeException('failed to read pfblockerng_dnsbl.php');
		}
		self::$src = $src;
	}

	public function testGatingBooleanReadsThePfbSyntaxHighlightToggle(): void
	{
		// The single PHP boolean gating BOTH the asset include and the JS init must be
		// derived from PfbConfig::read('pfb_syntax_highlight') compared against
		// pfb_editor_enabled() -- the issue #1887 named accessor every editor page's
		// pfb_cache_flush read already establishes (PfbConfig::read() returns the enum
		// directly here, not ->value). LENIENT, not PfbToggle -- see the class docblock.
		$this->assertMatchesRegularExpression(
			"#\\\$pfb_syntaxhl_on\\s*=\\s*pfb_editor_enabled\\(\\)#",
			self::$src,
			'expected a $pfb_syntaxhl_on boolean derived from pfb_editor_enabled() (issue #1887 named accessor)'
		);
	}

	public function testCmRegexScriptIsIncludedWithCacheBustingInsideTheGate(): void
	{
		// The script tag must be textually gated by the same $pfb_syntaxhl_on boolean,
		// i.e. an `if ($pfb_syntaxhl_on)` PHP block wrapping the <script> tag -- toggle
		// off must emit zero new bytes (no script tag at all).
		// Tempered-dot gaps ((?:(?!endif).)*?), not bare .*? -- a bare .*? (even
		// non-greedy, under /s) can consume a literal "endif" substring, letting the
		// match bridge PAST this gate's own close and land on a DIFFERENT, later
		// if($pfb_syntaxhl_on):...endif block's content -- a false pass if the script
		// tag were ever accidentally moved out of this gate to sit between the two
		// gates in the real file. Tempered dot forbids consuming "endif", so the match
		// can't cross this gate's boundary.
		$this->assertMatchesRegularExpression(
			'#if\s*\(\s*\$pfb_syntaxhl_on\s*\)\s*:(?:(?!endif).)*?'
			. '<script src="vendor/codemirror/cm-regex\.min\.js\?v=<\?=pfb_file_mtime\(\'/usr/local/www/pfblockerng/vendor/codemirror/cm-regex\.min\.js\'\)\?>"></script>'
			. '(?:(?!endif).)*?endif#s',
			self::$src,
			'expected the cm-regex.min.js include, with mtime cache-busting, wrapped inside an if ($pfb_syntaxhl_on) gate'
		);
	}

	public function testRegexListInitTargetsThePfbRegexListElementAndChecksWindowPfbCM(): void
	{
		$this->assertStringContainsString(
			"getElementById('pfb_regex_list')",
			self::$src,
			'expected the CM6 init to look up the pfb_regex_list element by id'
		);
		$this->assertStringContainsString(
			'window.pfbCM',
			self::$src,
			'expected the CM6 init to guard on window.pfbCM (the vendored bundle\'s IIFE global) being defined'
		);
		$this->assertMatchesRegularExpression(
			'/pfbCM\.fromTextarea\(/',
			self::$src,
			'expected the CM6 init to call pfbCM.fromTextarea() on the located element'
		);
	}

	public function testRegexListInitIsGatedInsideEventsPushBehindTheSameBoolean(): void
	{
		// The JS init must live inside the existing events.push(function(){...}) block
		// and be gated by the same $pfb_syntaxhl_on boolean as the asset include -- not
		// a second, independently-computed condition.
		// Tempered-dot gaps here too (see testCmRegexScriptIsIncludedWithCacheBustingInsideTheGate's
		// comment) -- same bridging-past-this-gate's-endif risk applies to the
		// events.push()/getElementById/fromTextarea chain.
		$this->assertMatchesRegularExpression(
			'#events\.push\(function\(\)\{(?:(?!endif).)*?if\s*\(\s*\$pfb_syntaxhl_on\s*\)\s*:(?:(?!endif).)*?'
			. "getElementById\\('pfb_regex_list'\\)(?:(?!endif).)*?pfbCM\\.fromTextarea\\((?:(?!endif).)*?endif#s",
			self::$src,
			'expected the pfb_regex_list CM6 init inside events.push(), gated by if ($pfb_syntaxhl_on)'
		);
	}

	/**
	 * Vacuity-safe "off emits nothing new" proof: the earlier gate-shape regexes
	 * (testCmRegexScriptIsIncludedWithCacheBustingInsideTheGate,
	 * testRegexListInitIsGatedInsideEventsPushBehindTheSameBoolean) only prove that
	 * a gated occurrence EXISTS -- they would still pass if a second, UNGUARDED
	 * reference to the same asset/call existed elsewhere in the file (e.g. a stray
	 * unconditional <script> tag added later by mistake). Counting occurrences closes
	 * that gap: exactly one `cm-regex.min.js` reference and exactly one
	 * `pfbCM.fromTextarea(` call in the whole file means every emission this slice
	 * adds lives behind the one $pfb_syntaxhl_on gate -- toggling it off truly emits
	 * zero new bytes, not just "at least one guarded copy plus stray unguarded ones".
	 */
	public function testCmRegexAssetAndFromTextareaCallEachAppearExactlyOnceInTheWholeFile(): void
	{
		// The <script src="..."> tag legitimately mentions "cm-regex.min.js" TWICE --
		// once in the src path, once inside the pfb_file_mtime() cache-buster argument --
		// so the vacuity-safe count targets the tag's opening (`<script src="...` up to
		// the query string), which appears exactly once iff there is exactly one <script>
		// tag emitting this asset, regardless of the mtime-argument's own duplicate path.
		$this->assertSame(
			1,
			substr_count(self::$src, '<script src="vendor/codemirror/cm-regex.min.js?v='),
			'expected exactly one cm-regex.min.js <script> tag in the whole file (the gated include) -- '
			. 'a second, unguarded <script> tag would defeat the off-emits-nothing contract'
		);
		$this->assertSame(
			1,
			substr_count(self::$src, 'pfbCM.fromTextarea('),
			'expected exactly one pfbCM.fromTextarea( call in the whole file (the gated events.push init) -- '
			. 'a second, unguarded call would defeat the off-emits-nothing contract'
		);
	}

	/**
	 * issue #1732 step 2: the DNSBL page's fromTextarea() call now also wires the
	 * advisory server-lint endpoint, still inside the SAME $pfb_syntaxhl_on gate --
	 * toggling syntax highlighting off must keep emitting zero lint bytes too.
	 */
	public function testRegexListInitPassesTheLintUrlInsideTheSameGate(): void
	{
		$this->assertMatchesRegularExpression(
			"#events\\.push\\(function\\(\\)\\{(?:(?!endif).)*?if\\s*\\(\\s*\\\$pfb_syntaxhl_on\\s*\\)\\s*:(?:(?!endif).)*?"
			. "pfbCM\\.fromTextarea\\([^;]*?lintUrl:\\s*'/pfblockerng/pfblockerng_lint\\.php'(?:(?!endif).)*?endif#s",
			self::$src,
			"expected pfbCM.fromTextarea(...) to pass lintUrl: '/pfblockerng/pfblockerng_lint.php' inside the \$pfb_syntaxhl_on gate"
		);
	}

	/**
	 * The cap diagnostic must reflect the LIVE checkbox state (what save would enforce
	 * right now), not the page-load value -- the lintExtraParams function reads
	 * pfb_regex_cap's checked state at lint time and maps it to '1'/'0'.
	 */
	public function testRegexListLintExtraParamsReadsTheLiveCapCheckboxState(): void
	{
		$this->assertMatchesRegularExpression(
			"#lintExtraParams:\\s*function\\s*\\(\\)\\s*\\{[^}]*getElementById\\('pfb_regex_cap'\\)[^}]*\\}#s",
			self::$src,
			"expected lintExtraParams to be a function reading getElementById('pfb_regex_cap')"
		);
		$this->assertMatchesRegularExpression(
			"#capEl\\s*&&\\s*capEl\\.checked\\)\\s*\\?\\s*'1'\\s*:\\s*'0'#",
			self::$src,
			"expected the cap checkbox's checked state to map to '1'/'0'"
		);
	}

	/**
	 * Vacuity-safe count for the new lintUrl wiring, same rationale as
	 * testCmRegexAssetAndFromTextareaCallEachAppearExactlyOnceInTheWholeFile.
	 */
	public function testLintUrlAppearsExactlyOnceInTheWholeFile(): void
	{
		$this->assertSame(
			1,
			substr_count(self::$src, "lintUrl: '/pfblockerng/pfblockerng_lint.php'"),
			'expected exactly one lintUrl wiring in the whole file (the gated events.push init)'
		);
	}

	public function testOriginalRegexTextareaFieldIsUnchanged(): void
	{
		// The save handler's mb_detect_encoding()/base64_encode() calls key off this exact
		// Form_Textarea('pfb_regex_list', ...) name -- this slice must not touch it; the
		// CM6 overlay is a pure client-side progressive enhancement layered on top, and
		// the POST contract stays exactly as it was pre-slice-C.
		$this->assertMatchesRegularExpression(
			"#new Form_Textarea\\(\\s*'pfb_regex_list',#",
			self::$src,
			'expected the underlying pfb_regex_list Form_Textarea field to remain unchanged'
		);
	}
}
