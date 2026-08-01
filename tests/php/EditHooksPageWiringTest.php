<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1669 — literal-source
 * pins for the gated "Edit Hooks" hook-script editor page
 * (pfblockerng_edit_hooks.php). This is SECURITY-SURFACE work (a new privilege gate
 * plus a file-write path), so the gate SHAPE itself is pinned here at the source-text
 * level, not just behaviourally: a future edit that reorders the gate after a $_POST
 * read, drops the redirect+exit, or re-adds the edit-hooks page to
 * pfblockerng.priv.inc's match list must fail THIS class, red, before it ever reaches
 * a live box.
 *
 * These are structural/textual assertions on the shipped source, not an executed
 * render (the page require_once()s guiconfig.inc/head.inc, which need the full
 * pfSense webConfigurator runtime this off-appliance PHPUnit tier does not stand up --
 * the render itself is covered by the Tier-A ui_render smoke entry,
 * tests/smoke/ui/test_render_smoke.py).
 */
final class EditHooksPageWiringTest extends TestCase
{
	private const PAGE_PATH = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_edit_hooks.php';
	private const UPDATE_PAGE_PATH = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_update.php';
	private const HOOKS_PAGE_PATH = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_hooks.php';
	private const PRIV_INC_PATH = __DIR__ . '/../../src/etc/inc/priv/pfblockerng.priv.inc';

	private function readSource(string $path): string
	{
		$src = file_get_contents($path);
		$this->assertNotFalse($src, "test oracle: failed to read {$path}");
		return $src;
	}

	// ------------------------------------------------------------------
	// The privilege gate itself.
	// ------------------------------------------------------------------

	/**
	 * The prior version
	 * of this oracle only scanned for '$_POST' occurrences AFTER the located gate, so
	 * a mutant with a $_POST read BEFORE the gate (the gate moved below the
	 * create-branch reads) still passed -- the "before any POST handling" requirement
	 * was never actually checked in the direction that matters. Fixed to zero-tolerance:
	 * find the gate position, then assert NONE of '$_POST' / '$_GET' / '$_REQUEST'
	 * (as literal substrings -- comments included, no whitelist) appear anywhere in the
	 * source BEFORE that position. The page's own top-of-file comments are written to
	 * avoid these literal tokens for exactly this reason (see the gate's own comment
	 * block, which now says "any request superglobal" instead of naming '$_GET'/'$_POST').
	 */
	private function assertNoRequestSuperglobalReadBeforeGate(string $src, string $label): void
	{
		// The real gate SHAPE, not a bare substring -- a prose mention of
		// isAllowedPage('diag_command.php') elsewhere must not give strpos() a
		// false-early hit on the gate's OWN position.
		$gatePos = strpos($src, "if (!isAllowedPage('diag_command.php')) {");
		$this->assertNotFalse($gatePos, "{$label}: the diag_command.php isAllowedPage() gate is missing");

		$before = substr($src, 0, $gatePos);
		foreach (['$_POST', '$_GET', '$_REQUEST'] as $superglobal) {
			$this->assertStringNotContainsString(
				$superglobal,
				$before,
				"{$label}: {$superglobal} must not appear anywhere before the gate (zero-tolerance, comments " .
					'included) -- the gate must be provably the first thing on the page that could ever observe ' .
					'a request, so it can never be silently reordered after a read'
			);
		}
	}

	public function testNoRequestSuperglobalReadBeforeGate(): void
	{
		$this->assertNoRequestSuperglobalReadBeforeGate($this->readSource(self::PAGE_PATH), 'pfblockerng_edit_hooks.php');
	}

	public function testGateRedirectsToIndexAndExits(): void
	{
		$src = $this->readSource(self::PAGE_PATH);

		$gatePos = strpos($src, "if (!isAllowedPage('diag_command.php')) {");
		$this->assertNotFalse($gatePos, 'gate is not the expected if (!isAllowedPage(...)) { ... } shape');

		$blockEnd = strpos($src, '}', $gatePos);
		$this->assertNotFalse($blockEnd, 'test oracle: gate block has no closing brace');
		$block = substr($src, $gatePos, $blockEnd - $gatePos);

		$this->assertStringContainsString("header('Location: /index.php');", $block, 'gate must redirect to /index.php');
		$this->assertStringContainsString('exit;', $block, 'gate must exit after the redirect');
	}

	public function testWarningBannerCallPresent(): void
	{
		$src = $this->readSource(self::PAGE_PATH);

		$this->assertStringContainsString('print_callout(', $src, 'the advanced-users warning banner call is missing');
		$this->assertStringContainsString("'danger'", $src, "the warning banner must use the 'danger' style");
		$this->assertStringContainsString('Advanced Users Only', $src, 'the warning banner heading text is missing');
		$this->assertStringContainsString(
			'Command Prompt',
			$src,
			'the warning banner must name the Command-Prompt-equivalent trust class it mirrors'
		);
	}

	public function testPrivIncDoesNotMatchThisPage(): void
	{
		$src = $this->readSource(self::PRIV_INC_PATH);

		// Scope the assertion to the ACTUAL match-array entries (not the file's prose
		// comments, which are allowed -- and expected -- to name the page while
		// explaining the deliberate omission). A real match entry looks like:
		//   $priv_list['page-firewall-pfblockerng']['match'][] = "pfblockerng/....php...";
		$matchCount = preg_match_all(
			"/\\\$priv_list\\['page-firewall-pfblockerng'\\]\\['match'\\]\\[\\] = \"([^\"]+)\";/",
			$src,
			$m
		);
		$this->assertGreaterThan(0, $matchCount, 'test oracle: no match[] entries found at all -- priv file shape changed?');

		$target = 'pfblockerng/pfblockerng_edit_hooks.php';
		foreach ($m[1] as $matchValue) {
			// A bare
			// assertStringNotContainsString($matchValue) misses a FUTURE glob entry (e.g.
			// "pfblockerng/pfblockerng_*") that would cover this page at RUNTIME under
			// pfSense's own match semantics while never literally containing its filename
			// as a substring. Reimplements pfSense's OWN cmp_page_matches() wildcard
			// algorithm (src/etc/inc/auth_func.inc, verified against pfSense master):
			// '.' -> '\.', '*' -> '.*', '?' -> '\?', anchored @^/{$match}$@ against
			// '/{$page}' -- so this asserts the same MATCH SEMANTICS pfSense applies, not
			// a substring proxy for them.
			$regex = str_replace(['.', '*', '?'], ['\.', '.*', '\?'], $matchValue);
			$this->assertSame(
				0,
				preg_match("@^/{$regex}\$@", "/{$target}"),
				"pfblockerng.priv.inc match entry \"{$matchValue}\" matches {$target} under pfSense's own " .
					'cmp_page_matches() wildcard semantics -- the isAllowedPage() secondary gate must be the only ' .
					'thing that can ever govern access to it'
			);
		}
	}

	// ------------------------------------------------------------------
	// Picker / save / render use ONLY the three pure helpers -- never an inline
	// regex or a raw path decision of their own.
	// ------------------------------------------------------------------

	public function testPickerUsesPfbHookScripts(): void
	{
		$src = $this->readSource(self::PAGE_PATH);
		$this->assertStringContainsString('pfb_hook_scripts(', $src, 'the picker must list files via pfb_hook_scripts()');
	}

	public function testSavePathUsesTheThreeHelpersNotInlineValidation(): void
	{
		$src = $this->readSource(self::PAGE_PATH);

		foreach (
			[
				'pfb_hook_editor_compose_filename(',
				'pfb_hook_editor_path(',
				'pfb_hook_editor_template(',
				'pfb_hook_script_valid(',
			] as $needle
		) {
			$this->assertStringContainsString($needle, $src, "the page must call {$needle} — no inline reimplementation");
		}

		// The page must never inline the name-core allow-list regex itself -- that
		// decision belongs SOLELY to pfb_hook_editor_compose_filename().
		$this->assertStringNotContainsString(
			'A-Za-z0-9_',
			$src,
			'the page must not inline the hook-name-core regex -- it belongs only to pfb_hook_editor_compose_filename()'
		);
	}

	// ------------------------------------------------------------------
	// pfSense's own
	// Form_Textarea::_getInput() / Form_Input::_getInput() ALREADY call
	// htmlspecialchars() on the value at render (verified against pfSense master and
	// RELENG_2_7_2) -- wrapping the value in htmlspecialchars() again at the PAGE
	// level double-escapes it. The browser then decodes only ONE layer of entities,
	// so the user sees the still-escaped remainder (e.g. "&quot;" instead of a
	// literal double quote), and Save writes that mangled text straight back -- the
	// very first load->save of the shipped hook template (which contains literal
	// double quotes) corrupts it. Fixed by passing the RAW php variable into every
	// Form_Textarea/Form_Input constructor call here and letting the framework
	// escape exactly once, at render.
	// ------------------------------------------------------------------

	/**
	 * Locates the constructor call whose head matches $pattern and returns the
	 * position of its OWN opening '(' -- not the first ");" after it, which a
	 * multi-line comment inside the argument list (e.g. "(no transformation);")
	 * can trip: a balanced-paren scan (extractBalancedParens()) is what actually
	 * finds the matching close, regardless of what stray "(" / ")" pairs a comment
	 * carries.
	 */
	private function locateCallOpenParen(string $src, string $pattern, string $label): int
	{
		$this->assertMatchesRegularExpression($pattern, $src, "{$label}: call site not found");
		preg_match($pattern, $src, $m, PREG_OFFSET_CAPTURE);
		$callPos = $m[0][1];
		$openParenPos = strpos($src, '(', $callPos);
		$this->assertNotFalse($openParenPos, "{$label}: call site has no opening (");
		return $openParenPos;
	}

	private function extractBalancedParens(string $src, int $openParenPos): string
	{
		$depth = 0;
		$len = strlen($src);
		for ($i = $openParenPos; $i < $len; $i++) {
			if ($src[$i] === '(') {
				$depth++;
			} elseif ($src[$i] === ')') {
				$depth--;
				if ($depth === 0) {
					return substr($src, $openParenPos, $i - $openParenPos + 1);
				}
			}
		}
		$this->fail('test oracle: unbalanced parentheses while scanning a call site');
	}

	private function assertConstructorPassesRawVariable(string $src, string $pattern, string $variable, string $label): void
	{
		$openParenPos = $this->locateCallOpenParen($src, $pattern, $label);
		$block = $this->extractBalancedParens($src, $openParenPos);

		$this->assertStringNotContainsString(
			'htmlspecialchars(',
			$block,
			"{$label}: must pass the RAW {$variable} -- pfSense's Form_Input/Form_Textarea framework classes already " .
				'htmlspecialchars() the value at render, so a page-level call here double-escapes it'
		);
		$this->assertStringContainsString($variable, $block, "{$label}: expected the raw {$variable} in the call site");
	}

	public function testTextareaContentPassedRawNotDoubleEscaped(): void
	{
		$this->assertConstructorPassesRawVariable(
			$this->readSource(self::PAGE_PATH),
			"/new Form_Textarea\\(/",
			'$pfb_eh_content',
			'pfb_eh_content Form_Textarea'
		);
	}

	public function testNewCoreInputValuePassedRaw(): void
	{
		$this->assertConstructorPassesRawVariable(
			$this->readSource(self::PAGE_PATH),
			"/new Form_Input\\(\\s*'pfb_eh_new_core',/",
			'$pfb_eh_new_core_val',
			'pfb_eh_new_core Form_Input'
		);
	}

	public function testHiddenCurrentWhenAndScriptFieldsPassedRaw(): void
	{
		$src = $this->readSource(self::PAGE_PATH);

		$this->assertConstructorPassesRawVariable(
			$src,
			"/new Form_Input\\('pfb_eh_cur_when',/",
			'$pfb_eh_sel_when',
			'pfb_eh_cur_when hidden Form_Input'
		);
		$this->assertConstructorPassesRawVariable(
			$src,
			"/new Form_Input\\('pfb_eh_cur_script',/",
			'$pfb_eh_sel_script',
			'pfb_eh_cur_script hidden Form_Input'
		);
	}

	/**
	 * The MANDATORY red/green proof for finding F1: simulates the real rendering
	 * chain end to end using PHP's own htmlspecialchars()/html_entity_decode() --
	 * page value -> ONE framework htmlspecialchars() at render -> ONE browser decode
	 * -- and asserts it reproduces a real hook-script template byte-for-byte.
	 * Whether the page currently double-escapes is read from the ACTUAL source text
	 * (not hardcoded), so this goes red again if the page-level htmlspecialchars()
	 * wrapper around $pfb_eh_content is ever reintroduced.
	 */
	public function testTextareaRoundTripFidelityThroughFrameworkEscapeAndBrowserDecode(): void
	{
		$src = $this->readSource(self::PAGE_PATH);

		$openParenPos = $this->locateCallOpenParen($src, "/new Form_Textarea\\(/", 'pfb_eh_content Form_Textarea');
		$block = $this->extractBalancedParens($src, $openParenPos);
		$pageDoublesEscape = str_contains($block, 'htmlspecialchars(');

		$original = pfb_hook_editor_template('pre', 'sh');
		$this->assertStringContainsString(
			'"',
			$original,
			'test oracle: the template fixture must contain a literal double quote for this round-trip to be meaningful'
		);

		// The real chain: page hands a value to Form_Textarea -> Form_Textarea::_getInput()
		// calls htmlspecialchars() on it EXACTLY ONCE at render (pfSense master +
		// RELENG_2_7_2) -> the browser parses that markup and decodes entities exactly
		// once when the textarea's value is read back out (displayed, or re-POSTed by
		// a same-page Save).
		$pageValue      = $pageDoublesEscape ? htmlspecialchars($original) : $original;
		$rendered       = htmlspecialchars($pageValue);
		$browserDecoded = html_entity_decode($rendered);

		$this->assertSame(
			$original,
			$browserDecoded,
			'page value -> one framework htmlspecialchars() -> one browser decode must reproduce the original ' .
				'template byte-for-byte; a page-level htmlspecialchars() wrapper around $pfb_eh_content double-escapes ' .
				'it, so the first load->save of the shipped template corrupts it'
		);
	}

	// ------------------------------------------------------------------
	// The Create/Save buttons post the
	// action fields the server keys on DIRECTLY as their own submit name -- a
	// clicked <button type="submit" name="pfb_eh_create"|"pfb_eh_save"> is included
	// in the browser's OWN POST natively (no separate click-handler JS needed to
	// inject a same-named hidden field first).
	// ------------------------------------------------------------------

	public function testSubmitButtonsUseNativeNamesWithNoJsInjection(): void
	{
		$src = $this->readSource(self::PAGE_PATH);

		$this->assertMatchesRegularExpression(
			"/new Form_Button\\(\\s*'pfb_eh_create',/",
			$src,
			'the Create button must be named pfb_eh_create directly so the browser posts it natively'
		);
		$this->assertMatchesRegularExpression(
			"/new Form_Button\\(\\s*'pfb_eh_save',/",
			$src,
			'the Save button must be named pfb_eh_save directly so the browser posts it natively'
		);

		// Quoted literals, not bare substrings: the PHP local variables
		// $pfb_eh_create_btn/$pfb_eh_save_btn are kept as-is (only the Form_Button
		// NAME/submit-field string argument changed), so a bare substring check would
		// false-positive on those unrelated variable names.
		foreach (["'pfb_eh_create_btn'", "'pfb_eh_save_btn'", 'pfbEhSubmitAs'] as $stale) {
			$this->assertStringNotContainsString(
				$stale,
				$src,
				"the old JS-injection wiring ({$stale}) must be fully removed now the buttons post natively"
			);
		}
	}

	// ------------------------------------------------------------------
	// The create flow must open the target
	// with fopen 'x' (atomic create-exclusive, closing the file_exists/write TOCTOU),
	// check the write byte count, and unlink the partial file on a failed write/chmod.
	// Structural oracle: the page cannot run off-appliance,
	// so pin the source text of the create block instead.
	// ------------------------------------------------------------------

	public function testCreateFlowUsesAtomicOpenWithPartialWriteCleanup(): void
	{
		$src = $this->readSource(self::PAGE_PATH);

		$this->assertMatchesRegularExpression(
			"/@?fopen\\(\\\$path,\\s*'x'\\)/",
			$src,
			"the create flow must open the hook file with fopen(..., 'x') -- atomic create-exclusive -- " .
				'not a separate file_exists() check followed by a plain write (TOCTOU)'
		);
		// NOTE: no blanket "no file_put_contents" assertion -- the SAVE path (line ~161)
		// legitimately overwrites an existing vetted file in place; only the CREATE flow
		// needs create-exclusive semantics, pinned by the fopen 'x' assertion above.
		$this->assertMatchesRegularExpression(
			'/\\$pfb_eh_new_written\\s*!==\\s*strlen\\(\\$pfb_eh_new_template\\)/',
			$src,
			'the create flow must compare the fwrite() return against the full template length (partial-write detection)'
		);
		$this->assertMatchesRegularExpression(
			'/@?unlink\\(\\$path\\)/',
			$src,
			'a failed write/chmod must unlink the partial file so it never lingers for the picker or a retry'
		);
		$this->assertMatchesRegularExpression(
			"/@?chmod\\(\\\$path,\\s*0700\\)/",
			$src,
			'the create flow must chmod the new hook file to 0700, not a laxer mode -- the runner always execs ' .
				'it as root and pfb_hook_scripts() has no is_executable filter, so no group/other bits are ever ' .
				'needed (owner-only is least privilege)'
		);
	}

	// ------------------------------------------------------------------
	// "Edit Hooks" sub-tab: directly after "Hooks", on every page that declares the
	// Update sub-tab row (coverage matrix: pfblockerng_update.php, pfblockerng_hooks.php,
	// and this page itself, each re-declaring the full row with its own tab active).
	// ------------------------------------------------------------------

	private function assertEditHooksTabDirectlyAfterHooksTab(string $src, string $label): void
	{
		$hooksPos = strpos($src, "array(gettext('Hooks'),");
		$this->assertNotFalse($hooksPos, "{$label}: the 'Hooks' sub-tab entry is missing");

		$editHooksPos = strpos($src, "array(gettext('Edit Hooks'),");
		$this->assertNotFalse($editHooksPos, "{$label}: the 'Edit Hooks' sub-tab entry is missing");

		$this->assertGreaterThan($hooksPos, $editHooksPos, "{$label}: 'Edit Hooks' must be declared directly after 'Hooks'");
		$this->assertStringContainsString(
			"/pfblockerng/pfblockerng_edit_hooks.php'",
			$src,
			"{$label}: the 'Edit Hooks' sub-tab must link pfblockerng_edit_hooks.php"
		);

		// Nothing else may sit between the two entries in the sub-tab array (directly
		// after, not just somewhere after).
		$between = substr($src, $hooksPos, $editHooksPos - $hooksPos);
		$this->assertSame(
			1,
			substr_count($between, '$tab_array_sub[]'),
			"{$label}: another sub-tab entry sits between 'Hooks' and 'Edit Hooks'"
		);
	}

	/**
	 * issue #1884: Enter in the Name field submits as Create (only text input +
	 * first submit button), so the create-failure path fires from a stray
	 * keypress. It must restore the loaded script and the unsaved buffer from
	 * the posted cur_ and content fields — the same shape the failed-delete
	 * branch uses — instead of blanking the editor.
	 */
	public function testCreateFailureRestoresTheLoadedScriptAndBuffer(): void
	{
		$src = $this->readSource(self::PAGE_PATH);

		$createPos = strpos($src, "isset(\$_POST['pfb_eh_create'])");
		$this->assertNotFalse($createPos, 'vacuity: the create branch must exist');
		$deletePos = strpos($src, "isset(\$_POST['pfb_eh_delete'])", $createPos);
		$this->assertNotFalse($deletePos, 'vacuity: the delete branch must follow the create branch');

		$branch = substr($src, $createPos, $deletePos - $createPos);
		$this->assertStringContainsString("\$pfb_eh_sel_when   = (string) (\$_POST['pfb_eh_cur_when'] ?? '');", $branch,
			'a failed create must restore the loaded Pre/Post from the posted cur_when');
		$this->assertStringContainsString("\$pfb_eh_sel_script = (string) (\$_POST['pfb_eh_cur_script'] ?? '');", $branch,
			'a failed create must restore the loaded script from the posted cur_script');
		$this->assertStringContainsString("\$pfb_eh_content    = pfb_sanitize_text_area((string) (\$_POST['pfb_eh_content'] ?? ''));", $branch,
			'a failed create must restore the unsaved buffer (sanitized at ingestion, #1723) instead of blanking it');
		$this->assertStringNotContainsString("\$pfb_eh_content      = '';", $branch,
			'the blanking assignment is the data-loss defect — it must be gone');

		// The typed create-When echo must survive the restore: the create-When
		// select prefers the explicit echo over the restored loaded-script when.
		$this->assertStringContainsString('$pfb_eh_new_when_echo = $post_when;', $branch,
			'the typed create-When choice must still echo after a validation error');
		$this->assertStringContainsString("\$pfb_eh_new_when_val = (\$pfb_eh_new_when_echo === 'pre' || \$pfb_eh_new_when_echo === 'post')", $src,
			'the create-When select must prefer the typed echo over the restored loaded-script when');
	}

	public function testEditHooksTabOnUpdatePage(): void
	{
		$this->assertEditHooksTabDirectlyAfterHooksTab($this->readSource(self::UPDATE_PAGE_PATH), 'pfblockerng_update.php');
	}

	public function testEditHooksTabOnHooksPage(): void
	{
		$this->assertEditHooksTabDirectlyAfterHooksTab($this->readSource(self::HOOKS_PAGE_PATH), 'pfblockerng_hooks.php');
	}

	public function testEditHooksTabOnItself(): void
	{
		$this->assertEditHooksTabDirectlyAfterHooksTab($this->readSource(self::PAGE_PATH), 'pfblockerng_edit_hooks.php (self)');
	}

	public function testEditHooksTabIsActiveOnlyOnItself(): void
	{
		// TRUE on itself...
		$src = $this->readSource(self::PAGE_PATH);
		$this->assertStringContainsString("array(gettext('Edit Hooks'),\tTRUE,", $src, 'self: Edit Hooks tab must be active');

		// ...FALSE on the two sibling pages.
		foreach ([self::UPDATE_PAGE_PATH => 'update', self::HOOKS_PAGE_PATH => 'hooks'] as $path => $label) {
			$src = $this->readSource($path);
			$this->assertStringContainsString(
				"array(gettext('Edit Hooks'),\tFALSE,",
				$src,
				"{$label}: Edit Hooks tab must be inactive"
			);
		}
	}

	// ------------------------------------------------------------------
	// The save flow
	// must sanitize $_POST content through the shared persist-boundary helper
	// before it is ever written, and
	// stage the write to a temp file in the same directory and rename() it into
	// place atomically -- never truncate+write the live target in place, since
	// pfb_run_hooks() may exec it as root concurrently with a save. The GET
	// picker-load path must reject invalid-UTF-8 file content before populating the
	// editor. Structural oracles: the page
	// cannot run off-appliance, so these pin the source-text shape of the blocks.
	// ------------------------------------------------------------------

	private function extractSaveFlowBlock(string $src): string
	{
		$blockStart = strpos($src, "isset(\$_POST['pfb_eh_save'])");
		$this->assertNotFalse($blockStart, 'test oracle: save-flow block start marker not found');
		$blockEnd = strpos($src, '// GET picker load', $blockStart);
		$this->assertNotFalse($blockEnd, 'test oracle: save-flow block end marker not found');
		return substr($src, $blockStart, $blockEnd - $blockStart);
	}

	/**
	 * issue #1734: the save path joins the #1723 persist-boundary standard -- the shared
	 * pfb_sanitize_text_area() replaces the hand-rolled pfb_hook_editor_normalize_content().
	 * The shared helper still performs the identical CRLF/CR -> LF collapse first, so the
	 * shebang-corruption regression the old helper existed for stays fixed, and it
	 * additionally scrubs legacy encodings, control characters, the BOM, and per-line
	 * trailing whitespace before the content ever reaches disk.
	 */
	public function testSavePathSanitizesContentBeforeWrite(): void
	{
		$block = $this->extractSaveFlowBlock($this->readSource(self::PAGE_PATH));

		// Pin the CALL-shape assignment, not the
		// bare function-name token -- the save block's own comment names the helper, so
		// a substring assertion passes even with the call stripped (coverage theater;
		// the mutant survived 19/19). A comment can never satisfy this assignment regex.
		$callShape = '/\\$post_content\\s*=\\s*pfb_sanitize_text_area\\(/';
		$this->assertSame(
			1,
			preg_match($callShape, $block, $m, PREG_OFFSET_CAPTURE),
			'the save flow must ASSIGN $post_content through the shared pfb_sanitize_text_area() -- writing the ' .
				"raw \$_POST value persists the browser's CRLF textarea normalization straight into the hook " .
				"script file, breaking its shebang exec (e.g. \"#!/bin/sh\\r\" -> ENOENT), and leaves control " .
				'characters and trailing per-line whitespace in the saved script'
		);

		$sanitizePos = $m[0][1];
		$writePos = strpos($block, 'file_put_contents(');
		$this->assertNotFalse($writePos, 'test oracle: no file_put_contents( call found in the save-flow block');
		$this->assertLessThan(
			$writePos,
			$sanitizePos,
			'content must be sanitized BEFORE it is written to the temp file, not after'
		);
	}

	/**
	 * issue #1734: the hand-rolled helper is removed, not merely bypassed -- a surviving
	 * call would mean the content is sanitized twice, or (worse) that a later edit
	 * silently reverted the save path to the narrower normalization.
	 */
	public function testSavePathNoLongerUsesTheHandRolledNormalizer(): void
	{
		$this->assertStringNotContainsString(
			'pfb_hook_editor_normalize_content',
			$this->readSource(self::PAGE_PATH),
			'pfb_hook_editor_normalize_content() was retired by #1734 -- the page must not reference it at all, ' .
				'in code or in a comment that would outlive it'
		);
	}

	public function testSaveFlowWritesAtomicallyViaTempFileAndRename(): void
	{
		$block = $this->extractSaveFlowBlock($this->readSource(self::PAGE_PATH));

		$this->assertStringContainsString(
			'tempnam(dirname($path)',
			$block,
			'the save flow must stage the new content to a temp file in the SAME directory as the target ' .
				'(tempnam(dirname($path), ...)) -- a cross-filesystem temp file would break the atomic rename() below'
		);
		$this->assertMatchesRegularExpression(
			'/@?rename\\(/',
			$block,
			'the save flow must atomically rename() the temp file over the target -- an in-place truncate+write ' .
				'lets a concurrent pfb_run_hooks() exec see an empty/partial script'
		);
		$this->assertDoesNotMatchRegularExpression(
			"/file_put_contents\\(\\\$path,/",
			$block,
			'the save flow must never file_put_contents() the live target path directly (in-place truncate) -- ' .
				'it must write the temp file and rename() it into place instead'
		);
		$this->assertMatchesRegularExpression(
			'/@?chmod\\(\\$pfb_eh_tmp,\\s*0700\\)/',
			$block,
			'the save flow must chmod the temp file to 0700, not a laxer mode, before rename() -- same ' .
				'least-privilege rationale as the create flow (root-only exec, no is_executable filter)'
		);
	}

	public function testLoadPathRejectsInvalidUtf8ContentBeforePopulatingEditor(): void
	{
		$src = $this->readSource(self::PAGE_PATH);

		$this->assertStringContainsString(
			'mb_check_encoding(',
			$src,
			'the GET picker-load path must validate the loaded file is valid UTF-8 before populating the editor ' .
				'-- htmlspecialchars(ENT_SUBSTITUTE) silently mangles invalid bytes to U+FFFD on display, and a ' .
				'subsequent save would persist that corruption back to disk'
		);

		$blockStart = strpos($src, "if (!\$_POST && isset(\$_GET['when'], \$_GET['script']))");
		$this->assertNotFalse($blockStart, 'test oracle: GET picker-load block start marker not found');
		$blockEnd = strpos($src, '$pfb_eh_lang = pfb_hook_editor_lang_for(', $blockStart);
		$this->assertNotFalse($blockEnd, 'test oracle: GET picker-load block end marker not found');
		$block = substr($src, $blockStart, $blockEnd - $blockStart);

		$checkPos = strpos($block, 'mb_check_encoding(');
		$assignPos = strpos($block, '$pfb_eh_content    = $body;');
		$this->assertNotFalse($checkPos, 'test oracle: mb_check_encoding( not found inside the picker-load block');
		$this->assertNotFalse($assignPos, 'test oracle: $pfb_eh_content assignment not found inside the picker-load block');
		$this->assertLessThan(
			$assignPos,
			$checkPos,
			'the UTF-8 validity check must gate the $pfb_eh_content assignment, not follow it'
		);
	}
}
