<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1871 — pfb_hook_editor_delete(), the removal half of the GUI hook-script
 * editor.
 *
 * Deleting a hook is a file removal performed as root on behalf of a GUI request,
 * so it is security-surface work and every row here is a tested contract. The
 * helper deletes NOTHING it did not first clear through pfb_hook_script_valid() —
 * the same allow-list the picker offers from, the save handler accepts, and the
 * runner executes. A crafted POST therefore cannot reach a path outside the
 * hook-script directory, and cannot remove a file in that directory that is not a
 * hook script for the stated Pre/Post.
 *
 * Each negative row asserts the target SURVIVES, not merely that the call returned
 * FALSE: a guard that returned FALSE after unlinking would pass a return-value-only
 * test while still destroying the file.
 */
#[CoversFunction('pfb_hook_editor_delete')]
final class HookEditorDeleteTest extends TestCase
{
	private string $dir = '';
	private string $outside = '';

	/**
	 * Load the one file that defines the deletion, directly.
	 *
	 * pfblockerng_hook_edit.inc is included by pfblockerng_edit_hooks.php and by
	 * nothing else in the shipping tree (pinned by HookEditFileContainmentTest), so
	 * it is not in scope after the normal bootstrap and has to be required here.
	 * That is the point of the split rather than an inconvenience: a destructive
	 * root-privileged unlink() should not be reachable from every page that happens
	 * to include the package-wide helpers.
	 */
	public static function setUpBeforeClass(): void
	{
		parent::setUpBeforeClass();
		require_once dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_hook_edit.inc';
	}

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_hook_delete_' . uniqid('', TRUE);
		$this->outside = $this->dir . '_outside';
		mkdir($this->dir, 0755, TRUE);
		mkdir($this->outside, 0755, TRUE);
	}

	protected function tearDown(): void
	{
		foreach ([$this->dir, $this->outside] as $dir) {
			foreach (glob("{$dir}/*") ?: [] as $path) {
				is_link($path) ? unlink($path) : @unlink($path);
			}
			@rmdir($dir);
		}
	}

	private function makeHook(string $basename, string $body = "#!/bin/sh\nexit 0\n"): string
	{
		$path = "{$this->dir}/{$basename}";
		file_put_contents($path, $body);
		chmod($path, 0700);
		return $path;
	}

	public function testRefusesWhenTheCallerLacksTheHookEditorPrivilege(): void
	{
		// The privilege belongs to the OPERATION, not merely to the page that hosts
		// it. Containment (this file being included by one gated page and no other)
		// is the first line and is pinned by HookEditFileContainmentTest; this is the
		// second. A caller that reached the function without passing the page's own
		// isAllowedPage() gate still must not be able to remove a hook. Same
		// privilege the hook editor demands: diag_command.php, the shell-equivalent
		// trust class (ADR-12).
		$keep = $this->makeHook('hook_post_probe.sh');
		$GLOBALS['pfb_test_allowed_pages'] = ['diag_command.php' => false];
		try {
			$this->assertFalse(pfb_hook_editor_delete('hook_post_probe.sh', 'post', $this->dir));
			$this->assertFileExists($keep, 'an unprivileged caller must not remove anything');
		} finally {
			unset($GLOBALS['pfb_test_allowed_pages']);
		}
	}

	public function testDeletesOnceThePrivilegeIsGranted(): void
	{
		// The other side of the gate: with the privilege explicitly present the same
		// call succeeds, so the refusal above is the privilege doing the work rather
		// than some unrelated guard.
		$path = $this->makeHook('hook_post_probe.sh');
		$GLOBALS['pfb_test_allowed_pages'] = ['diag_command.php' => true];
		try {
			$this->assertTrue(pfb_hook_editor_delete('hook_post_probe.sh', 'post', $this->dir));
			$this->assertFileDoesNotExist($path);
		} finally {
			unset($GLOBALS['pfb_test_allowed_pages']);
		}
	}

	public function testRefusesWhenTheHookDirectoryIsNotWritable(): void
	{
		// unlink() needs write+execute on the DIRECTORY, not on the file. Root
		// bypasses file permissions entirely, so this cannot be simulated as root --
		// the same guard the repo's other permission-denial tests use.
		if (function_exists('posix_getuid') && posix_getuid() === 0) {
			$this->markTestSkipped('root bypasses directory permissions; the denial cannot be simulated');
		}
		$path = $this->makeHook('hook_post_probe.sh');
		chmod($this->dir, 0555);
		try {
			$this->assertFalse(pfb_hook_editor_delete('hook_post_probe.sh', 'post', $this->dir));
			$this->assertFileExists($path, 'a read-only hook directory must leave the hook in place');
		} finally {
			chmod($this->dir, 0755);
		}
	}

	public function testDeletesAnAllowListedHookAndReportsSuccess(): void
	{
		$path = $this->makeHook('hook_post_probe.sh');
		$this->assertTrue(pfb_hook_editor_delete('hook_post_probe.sh', 'post', $this->dir));
		$this->assertFileDoesNotExist($path);
	}

	public function testDeletesAPythonHookToo(): void
	{
		// Both extensions the allow-list recognises; a .sh-only delete would strand
		// every Python hook in the picker forever.
		$path = $this->makeHook('hook_pre_probe.py', "import sys\n");
		$this->assertTrue(pfb_hook_editor_delete('hook_pre_probe.py', 'pre', $this->dir));
		$this->assertFileDoesNotExist($path);
	}

	public function testRefusesAPathTraversalAndLeavesTheTargetInPlace(): void
	{
		$victim = "{$this->outside}/victim.sh";
		file_put_contents($victim, "#!/bin/sh\n");
		$this->assertFalse(pfb_hook_editor_delete('../' . basename($this->outside) . '/victim.sh', 'post', $this->dir));
		$this->assertFileExists($victim);
	}

	public function testRefusesAnAbsolutePathAndLeavesTheTargetInPlace(): void
	{
		$victim = "{$this->outside}/victim.sh";
		file_put_contents($victim, "#!/bin/sh\n");
		$this->assertFalse(pfb_hook_editor_delete($victim, 'post', $this->dir));
		$this->assertFileExists($victim);
	}

	public function testRefusesAFileInTheDirectoryThatIsNotAHookScript(): void
	{
		// Present in the allowed directory, but not named hook_<when>_*.{sh,py},
		// so pfb_hook_scripts() never offers it and this must not remove it.
		$path = "{$this->dir}/notahook.sh";
		file_put_contents($path, "#!/bin/sh\n");
		$this->assertFalse(pfb_hook_editor_delete('notahook.sh', 'post', $this->dir));
		$this->assertFileExists($path);
	}

	public function testRefusesTheWrongPrePostForAnExistingHook(): void
	{
		// A post hook deleted "as pre" is not on the pre allow-list. Without this
		// the When field would be decorative and a mismatched POST would delete a
		// hook the request never named correctly.
		$path = $this->makeHook('hook_post_probe.sh');
		$this->assertFalse(pfb_hook_editor_delete('hook_post_probe.sh', 'pre', $this->dir));
		$this->assertFileExists($path);
	}

	public function testRefusesAnInvalidWhenValue(): void
	{
		$path = $this->makeHook('hook_post_probe.sh');
		$this->assertFalse(pfb_hook_editor_delete('hook_post_probe.sh', 'sideways', $this->dir));
		$this->assertFileExists($path);
	}

	public function testRefusesASymlinkPointingOutsideTheHookDirectory(): void
	{
		// pfb_hook_scripts() already excludes a symlink whose real path leaves the
		// directory; deleting through one would remove the TARGET, not the link.
		$victim = "{$this->outside}/victim.sh";
		file_put_contents($victim, "#!/bin/sh\n");
		$link = "{$this->dir}/hook_post_link.sh";
		if (!@symlink($victim, $link)) {
			$this->markTestSkipped('symlink() unavailable on this filesystem');
		}
		$this->assertFalse(pfb_hook_editor_delete('hook_post_link.sh', 'post', $this->dir));
		$this->assertFileExists($victim);
	}

	public function testRefusesAnEmptyScriptName(): void
	{
		$keep = $this->makeHook('hook_post_keep.sh');
		$this->assertFalse(pfb_hook_editor_delete('', 'post', $this->dir));
		$this->assertFileExists($keep, 'an empty name must not remove anything');
	}

	public function testDeletingASymlinkInTheDirectoryRemovesTheLinkNotItsTarget(): void
	{
		// pfb_hook_editor_path() resolves through symlinks, so unlinking its return
		// value would delete the link's TARGET. A link named as a POST hook pointing
		// at a PRE hook would then make the post row's trash can silently remove a
		// different hook -- and the UI would report success, because the dangling
		// link stops being listed either way.
		$target = $this->makeHook('hook_pre_target.sh');
		$link = "{$this->dir}/hook_post_alias.sh";
		if (!@symlink($target, $link)) {
			$this->markTestSkipped('symlink() unavailable on this filesystem');
		}

		$this->assertTrue(pfb_hook_editor_delete('hook_post_alias.sh', 'post', $this->dir));
		$this->assertFileExists($target, 'the symlink target is a different hook and must survive');
		$this->assertFalse(is_link($link), 'the named entry itself must be gone');
	}

	public function testDeletingAHardLinkLeavesTheOutsideFileIntact(): void
	{
		// A hard link shares an inode with a file outside the directory. Removing the
		// in-directory name must not destroy the outside file's content -- unlink()
		// drops one directory entry, never the inode while another name holds it.
		$outside = "{$this->outside}/victim.sh";
		file_put_contents($outside, "#!/bin/sh\nVICTIM\n");
		$link = "{$this->dir}/hook_post_hard.sh";
		if (!@link($outside, $link)) {
			$this->markTestSkipped('link() unavailable on this filesystem');
		}

		$this->assertTrue(pfb_hook_editor_delete('hook_post_hard.sh', 'post', $this->dir));
		$this->assertFileExists($outside, 'the outside name must still exist');
		$this->assertStringContainsString('VICTIM', (string) file_get_contents($outside));
	}

	public function testRefusesANameCarryingANulByte(): void
	{
		$path = $this->makeHook('hook_post_probe.sh');
		$this->assertFalse(pfb_hook_editor_delete("hook_post_probe.sh\0.txt", 'post', $this->dir));
		$this->assertFileExists($path);
	}

	public function testASecondDeleteOfTheSameHookReportsFailure(): void
	{
		// The double-submit case: once the file is gone it is no longer on the
		// allow-list, so the repeat is refused rather than reported as a success.
		$this->makeHook('hook_post_probe.sh');
		$this->assertTrue(pfb_hook_editor_delete('hook_post_probe.sh', 'post', $this->dir));
		$this->assertFalse(pfb_hook_editor_delete('hook_post_probe.sh', 'post', $this->dir));
	}

	public function testLeavesSiblingHooksUntouched(): void
	{
		$keep = $this->makeHook('hook_post_keep.sh');
		$this->makeHook('hook_post_probe.sh');
		$this->assertTrue(pfb_hook_editor_delete('hook_post_probe.sh', 'post', $this->dir));
		$this->assertFileExists($keep);
	}
}
