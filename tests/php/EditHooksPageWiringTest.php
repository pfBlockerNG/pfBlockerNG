<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1669 Part B / ADR-12 post-acceptance addendum (2026-07-24) — literal-source
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
	 * Coordinator gate finding F2 (2026-07-24, test-oracle defect): the prior version
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
		foreach ($m[1] as $matchValue) {
			$this->assertStringNotContainsString(
				'pfblockerng_edit_hooks.php',
				$matchValue,
				'pfblockerng.priv.inc must NOT match() the edit-hooks page -- the isAllowedPage() ' .
					'secondary gate is the only thing that may govern access to it'
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

	public function testContentRenderedThroughHtmlspecialchars(): void
	{
		$src = $this->readSource(self::PAGE_PATH);
		$this->assertStringContainsString(
			'htmlspecialchars($pfb_eh_content)',
			$src,
			'the loaded/edited hook content must be rendered through htmlspecialchars()'
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
}
