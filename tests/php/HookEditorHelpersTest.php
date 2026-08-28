<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1669 — behavioural
 * coverage for the three PURE decision helpers behind the gated "Edit Hooks" GUI
 * hook-script editor (pfblockerng_edit_hooks.php): pfb_hook_editor_compose_filename(),
 * pfb_hook_editor_path(), pfb_hook_editor_template(). The page uses ONLY these for
 * every validation/path decision, so this is the load-bearing test class for the
 * slice's hostile-input rows (this is SECURITY-SURFACE work: a new privilege gate
 * plus a file-write path, so every row here is a tested contract, not a nicety).
 */
#[CoversFunction('pfb_hook_editor_compose_filename')]
#[CoversFunction('pfb_hook_editor_path')]
#[CoversFunction('pfb_hook_editor_template')]
#[CoversFunction('pfb_hook_editor_lang_for')]
final class HookEditorHelpersTest extends TestCase
{
	private string $dir = '';

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_hook_editor_' . uniqid('', TRUE);
		mkdir($this->dir, 0755, TRUE);
	}

	protected function tearDown(): void
	{
		foreach (glob("{$this->dir}/*") ?: [] as $path) {
			is_link($path) ? unlink($path) : @unlink($path);
		}
		@rmdir($this->dir);
		// The symlink-escape test also creates a sibling "outside" dir.
		$outside = "{$this->dir}_outside";
		if (is_dir($outside)) {
			foreach (glob("{$outside}/*") ?: [] as $path) {
				unlink($path);
			}
			rmdir($outside);
		}
	}

	// ------------------------------------------------------------------
	// pfb_hook_editor_compose_filename()
	// ------------------------------------------------------------------

	public function testComposeRejectsPathTraversalCore(): void
	{
		$this->assertNull(pfb_hook_editor_compose_filename('pre', '../../etc/rc', 'sh'));
	}

	public function testComposeRejectsEmptyCore(): void
	{
		$this->assertNull(pfb_hook_editor_compose_filename('pre', '', 'sh'));
	}

	public function testComposeRejectsDottedCore(): void
	{
		$this->assertNull(pfb_hook_editor_compose_filename('pre', 'a.b', 'sh'));
	}

	public function testComposeRejectsUnicodeCore(): void
	{
		$this->assertNull(pfb_hook_editor_compose_filename('pre', "na\u{00EF}ve", 'sh'));
	}

	public function testComposeRejectsSpaceInCore(): void
	{
		$this->assertNull(pfb_hook_editor_compose_filename('pre', 'my hook', 'sh'));
	}

	/**
	 * A bare '/^[A-Za-z0-9_]+$/' anchors '$' before a single trailing "\n" in PCRE
	 * (not just at the true end of the subject), so 'x' . "\n" WOULD PASS the old
	 * regex — composing 'hook_pre_x\n.sh' and letting the create-flow write a file
	 * whose basename carries an embedded LF. '\A...\z' has no such special case, so
	 * every row here must be rejected once the helper uses '\A[A-Za-z0-9_]{1,200}\z'.
	 */
	public function testComposeRejectsTrailingNewlineCore(): void
	{
		$this->assertNull(pfb_hook_editor_compose_filename('pre', "x\n", 'sh'));
	}

	public function testComposeRejectsLeadingNewlineCore(): void
	{
		$this->assertNull(pfb_hook_editor_compose_filename('pre', "\nx", 'sh'));
	}

	public function testComposeRejectsTrailingCarriageReturnCore(): void
	{
		$this->assertNull(pfb_hook_editor_compose_filename('pre', "x\r", 'sh'));
	}

	public function testComposeRejectsTrailingCrlfCore(): void
	{
		$this->assertNull(pfb_hook_editor_compose_filename('pre', "x\r\n", 'sh'));
	}

	public function testComposeRejectsInvalidWhen(): void
	{
		$this->assertNull(pfb_hook_editor_compose_filename('both', 'myhook', 'sh'));
		$this->assertNull(pfb_hook_editor_compose_filename('other', 'myhook', 'sh'));
	}

	/**
	 * EXPLICIT: PHP is never an offered hook language (ADR-12 addendum -- the owner
	 * resolved the issue #1669 language fork against widening the runner's
	 * accepted-extension contract to .php).
	 */
	public function testComposeRejectsPhpLanguage(): void
	{
		$this->assertNull(pfb_hook_editor_compose_filename('pre', 'myhook', 'php'));
	}

	public function testComposeRejectsUnknownLanguage(): void
	{
		$this->assertNull(pfb_hook_editor_compose_filename('pre', 'myhook', 'rb'));
	}

	public function testComposeAccepts200CharCore(): void
	{
		$core = str_repeat('a', 200);
		$this->assertSame('hook_pre_' . $core . '.sh', pfb_hook_editor_compose_filename('pre', $core, 'sh'));
	}

	public function testComposeRejectsCoreOver200Chars(): void
	{
		$core = str_repeat('a', 201);
		$this->assertNull(pfb_hook_editor_compose_filename('pre', $core, 'sh'));
	}

	public function testComposeAcceptsUppercaseCore(): void
	{
		$this->assertSame('hook_post_MyHook.py', pfb_hook_editor_compose_filename('post', 'MyHook', 'py'));
	}

	public function testComposeAcceptsUnderscoreCore(): void
	{
		$this->assertSame('hook_pre_my_hook_1.sh', pfb_hook_editor_compose_filename('pre', 'my_hook_1', 'sh'));
	}

	// ------------------------------------------------------------------
	// pfb_hook_editor_path()
	// ------------------------------------------------------------------

	public function testPathRejectsParentTraversal(): void
	{
		$this->assertNull(pfb_hook_editor_path('../hook_pre_x.sh', $this->dir));
	}

	public function testPathRejectsNestedSubdirectory(): void
	{
		$this->assertNull(pfb_hook_editor_path('hooks2/hook_pre_x.sh', $this->dir));
	}

	public function testPathRejectsAbsolutePath(): void
	{
		$this->assertNull(pfb_hook_editor_path('/etc/passwd', $this->dir));
	}

	public function testPathRejectsEmptyBasename(): void
	{
		$this->assertNull(pfb_hook_editor_path('', $this->dir));
	}

	/**
	 * basename() keeps a
	 * NUL byte in a PHP string (it is not a path-separator character), so
	 * 'hook_pre_x\0.sh' passes the basename($b) === $b equality check unchanged and
	 * would previously fall through to file_exists(), which silently returns false
	 * on a NUL-bearing path -- returning a bogus non-existent-file PATH instead of
	 * NULL. Unreachable via the page's own flows today (pfb_hook_editor_compose_filename()
	 * and pfb_hook_script_valid() both already reject a NUL-bearing name earlier),
	 * but this is the LAST function that turns a name into a filesystem path, so the
	 * NUL rejection is tested directly here too.
	 */
	public function testPathRejectsNulByteInBasename(): void
	{
		$this->assertNull(pfb_hook_editor_path("hook_pre_x\0.sh", $this->dir));
	}

	public function testPathAcceptsPlainBasenameInRealDir(): void
	{
		$target = "{$this->dir}/hook_pre_x.sh";
		file_put_contents($target, "#!/bin/sh\necho hi\n");

		$resolved = pfb_hook_editor_path('hook_pre_x.sh', $this->dir);
		$this->assertNotNull($resolved);
		$this->assertSame(realpath($target), $resolved);
	}

	public function testPathAcceptsNotYetExistingBasenameForCreateFlow(): void
	{
		$resolved = pfb_hook_editor_path('hook_pre_new.sh', $this->dir);
		$this->assertSame(realpath($this->dir) . '/hook_pre_new.sh', $resolved);
	}

	public function testPathRejectsSymlinkEscapingTheDirectory(): void
	{
		$outside = "{$this->dir}_outside";
		mkdir($outside, 0755, TRUE);
		$real_target = "{$outside}/secret.sh";
		file_put_contents($real_target, "#!/bin/sh\necho leaked\n");

		$link = "{$this->dir}/hook_pre_escape.sh";
		$this->assertTrue(symlink($real_target, $link), 'test setup: failed to create escape symlink');

		$this->assertNull(pfb_hook_editor_path('hook_pre_escape.sh', $this->dir));
	}

	public function testPathRejectsWhenDirectoryDoesNotExist(): void
	{
		$this->assertNull(pfb_hook_editor_path('hook_pre_x.sh', "{$this->dir}/does-not-exist"));
	}

	// ------------------------------------------------------------------
	// pfb_hook_editor_template()
	// ------------------------------------------------------------------

	/**
	 * The full PFB_* inventory pfb_run_hooks() actually exports, pinned here from the
	 * source (pfblockerng.inc pfb_run_hooks()/pfb_hook_lifecycle_ctx(), the pre/post
	 * call sites in pfblockerng_apply.inc, and the "Environment" help text on
	 * pfblockerng_hooks.php) — NOT copied from memory/the issue body, which listed
	 * only 7 of these 10. A future runner var added without a template update fails
	 * this test because it is pinned independently here, not derived from production.
	 */
	private const EXPECTED_ENV_VARS = [
		'PFB_WHEN', 'PFB_TRIGGER', 'PFB_POST_INSTALL', 'PFB_PRE_UNINSTALL', 'PFB_PKG_OP',
		'PFB_IP_CHANGED', 'PFB_DNSBL_CHANGED', 'PFB_STATUS', 'PFB_CHANGED_IP_ALIASES', 'PFB_CHANGED_DNSBL_GROUPS',
	];

	public function testShellTemplateContainsEveryEnvVar(): void
	{
		$tpl = pfb_hook_editor_template('pre', 'sh');
		foreach (self::EXPECTED_ENV_VARS as $var) {
			$this->assertStringContainsString($var, $tpl, "sh template is missing {$var}");
		}
	}

	public function testPythonTemplateContainsEveryEnvVar(): void
	{
		$tpl = pfb_hook_editor_template('post', 'py');
		foreach (self::EXPECTED_ENV_VARS as $var) {
			$this->assertStringContainsString($var, $tpl, "py template is missing {$var}");
		}
	}

	public function testShellTemplateHasShShebangAndHelloWorldUsesVar(): void
	{
		$tpl = pfb_hook_editor_template('pre', 'sh');
		$this->assertStringStartsWith("#!/bin/sh\n", $tpl);
		$this->assertStringContainsString('${PFB_WHEN}', $tpl);
		$this->assertStringContainsString('${PFB_TRIGGER}', $tpl);
	}

	public function testPythonTemplateHasPythonShebangAndHelloWorldUsesVar(): void
	{
		$tpl = pfb_hook_editor_template('post', 'py');
		$this->assertStringStartsWith("#!/usr/local/pkg/pfblockerng/pfb_python.sh\n", $tpl);
		$this->assertStringContainsString('import os', $tpl);
		$this->assertStringContainsString("os.environ.get('PFB_WHEN')", $tpl);
	}

	public function testTemplateDocumentsFailureSemantics(): void
	{
		$tpl = pfb_hook_editor_template('pre', 'sh');
		$this->assertStringContainsString('non-zero exit', $tpl);
		$this->assertStringContainsString('timeout', $tpl);
		$this->assertStringContainsString('CONTINUES', $tpl);
		$this->assertStringContainsString('SIGTERM', $tpl);
		$this->assertStringContainsString('SIGKILL', $tpl);
	}

	// ------------------------------------------------------------------
	// pfb_hook_editor_lang_for() -- issue #1669: picks the CodeMirror 6
	// hook-editor mode ('py' | 'sh') from the loaded script's own extension, falling
	// back to the create-flow's typed Language choice when nothing is loaded yet.
	// ------------------------------------------------------------------

	public function testLangForReturnsPyForADotPyScript(): void
	{
		$this->assertSame('py', pfb_hook_editor_lang_for('hook_pre_myhook.py', 'sh'));
	}

	public function testLangForReturnsShForADotShScript(): void
	{
		$this->assertSame('sh', pfb_hook_editor_lang_for('hook_post_myhook.sh', 'py'));
	}

	public function testLangForFallsBackToTheFallbackWhenScriptIsEmpty(): void
	{
		$this->assertSame('py', pfb_hook_editor_lang_for('', 'py'));
		$this->assertSame('sh', pfb_hook_editor_lang_for('', 'sh'));
	}

	/**
	 * A fallback value outside {'py', 'sh'} (e.g. a stray '' default) must never leak
	 * through as the JS-facing lang value -- the helper coerces it to 'sh' the same
	 * way pfb_eh_new_lang_val is coerced on the page itself.
	 */
	public function testLangForCoercesAnUnrecognisedFallbackToSh(): void
	{
		$this->assertSame('sh', pfb_hook_editor_lang_for('', 'anything-else'));
	}

	public function testLangForUsesFallbackForAnUnknownScriptExtension(): void
	{
		// An extension outside {py, sh} (defensive -- pfb_hook_script_valid() already
		// gates $script to the real allow-list before this is ever called) falls back
		// rather than propagating an unrecognised mode string to the JS side.
		$this->assertSame('py', pfb_hook_editor_lang_for('hook_pre_myhook.txt', 'py'));
	}
}
