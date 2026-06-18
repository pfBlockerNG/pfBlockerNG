<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_filter(..., PFB_FILTER_URL, ...) — the LOCAL-FILE branch (input that is not a
 * URL is treated as a local filesystem path).
 *
 * PFBL-02 Phase 2 hardens this branch: the path is canonicalized with realpath()
 * BEFORE any membership test, then required to sit DIRECTLY in one of the hardcoded
 * allowed directories (no subfolders), with a plain basename and as a regular file.
 * The branch matrix:
 *
 *   - a path with '..' that realpath-escapes an allowed dir   -> REJECTED
 *   - a redundant-separator variant of an escaping path       -> REJECTED
 *   - a non-existent path (realpath() returns FALSE)          -> REJECTED
 *   - a symlink in an allowed dir pointing OUTSIDE it         -> REJECTED
 *   - a symlink in an allowed dir whose target is in-bounds   -> ALLOWED
 *   - a real regular file DIRECTLY under an allowed dir       -> ALLOWED
 *
 * The ALLOWED case needs a real file under a real allowed directory (the allow-list
 * is hardcoded absolute paths in production); when the test environment cannot create
 * one (non-root CI), that single case skips rather than failing — the REJECT cases,
 * which need no privileged filesystem, always run.
 */
#[CoversFunction('pfb_filter')]
final class FeedUrlLocalFileTest extends TestCase
{
	/** The validator verdict for a local-file path: TRUE = accepted. */
	private function validate(string $path): bool
	{
		return pfb_filter($path, PFB_FILTER_URL, 'localfile', '', true) !== false;
	}

	/**
	 * A relative-escape path ('..' climbing out of an allowed dir) must be rejected:
	 * realpath() collapses it to /etc/passwd, which is not under any allowed dir.
	 */
	public function testRealpathEscapeRejected(): void
	{
		$this->assertFalse(
			$this->validate('/var/db/pfblockerng/deny/../../../etc/passwd'),
			'a path escaping the allowed dir via ".." must be rejected'
		);
	}

	/**
	 * The same escape with redundant separators must also be rejected — canonicalization
	 * happens before the membership test, so the cosmetic form does not matter.
	 */
	public function testRedundantSlashEscapeRejected(): void
	{
		$this->assertFalse(
			$this->validate('/var/db/pfblockerng/deny//..//..//../etc//passwd'),
			'a redundant-separator escape must be rejected'
		);
	}

	/**
	 * A path that does not exist makes realpath() return FALSE and must be rejected
	 * (fail-closed): even a name that LOOKS like it sits in an allowed dir is not
	 * accepted unless the file actually exists there.
	 */
	public function testNonExistentPathRejected(): void
	{
		$this->assertFalse(
			$this->validate('/var/db/pfblockerng/deny/this-file-does-not-exist-' . getmypid() . '.txt'),
			'a non-existent path must be rejected'
		);
	}

	/**
	 * A real regular file sitting DIRECTLY in an allowed directory is accepted. Proves
	 * the hardening did not break the legitimate local-file case. Skips (does not fail)
	 * when the environment cannot create the hardcoded allowed dir.
	 */
	public function testRealFileInAllowedDirAccepted(): void
	{
		$dir  = '/var/db/pfblockerng/deny';
		$file = $dir . '/pfb_localfile_unit_' . getmypid() . '.txt';

		if (!@is_dir($dir) && !@mkdir($dir, 0o755, true) && !@is_dir($dir)) {
			$this->markTestSkipped("cannot create allowed dir {$dir} in this environment");
		}
		if (@file_put_contents($file, "test\n") === false) {
			$this->markTestSkipped("cannot write {$file} in this environment");
		}

		try {
			// Before-state: a sibling path that escapes the same dir is rejected,
			// proving acceptance below is the containment check, not a blanket allow.
			$this->assertFalse(
				$this->validate($dir . '/../passwd'),
				'an escaping sibling path is rejected even when the allowed dir exists'
			);

			// The real file directly under the allowed dir is accepted.
			$this->assertTrue($this->validate($file), 'a real file directly in an allowed dir must be allowed');
		} finally {
			@unlink($file);
		}
	}

	/**
	 * A symlink placed INSIDE an allowed directory but pointing OUTSIDE it must be
	 * rejected: realpath() resolves the link to its target, whose canonical directory
	 * is not in the allow-list. Paired with the in-bounds symlink test below, this proves
	 * the verdict follows the canonical TARGET location, not the link's own path — the
	 * core reason canonicalization is required. Skips (does not fail) when the environment
	 * cannot create the allowed dir, the out-of-bounds target, or the symlink.
	 */
	public function testSymlinkEscapingAllowedDirRejected(): void
	{
		$dir = '/var/db/pfblockerng/deny';
		if (!@is_dir($dir) && !@mkdir($dir, 0o755, true) && !@is_dir($dir)) {
			$this->markTestSkipped("cannot create allowed dir {$dir} in this environment");
		}

		// Target OUTSIDE every allowed dir.
		$outside = tempnam(sys_get_temp_dir(), 'pfb_outside_');
		if ($outside === false) {
			$this->markTestSkipped('cannot create an out-of-bounds target file');
		}

		// Make the "outside" precondition explicit and deterministic: if this
		// environment's temp dir happens to resolve INSIDE the allowed dir, the
		// rejection below would not be exercised, so skip rather than assert.
		$real_dir     = realpath($dir);
		$real_outside = realpath($outside);
		if ($real_dir === false || $real_outside === false ||
		    str_starts_with($real_outside, rtrim($real_dir, '/') . '/')) {
			@unlink($outside);
			$this->markTestSkipped('temp target is not outside the allowed dir in this environment');
		}

		$link = $dir . '/pfb_symlink_escape_' . getmypid() . '.txt';
		@unlink($link);
		if (!@symlink($outside, $link)) {
			@unlink($outside);
			$this->markTestSkipped('cannot create a symlink in this environment');
		}

		try {
			$this->assertFalse(
				$this->validate($link),
				'a symlink inside an allowed dir pointing outside it must be rejected'
			);
		} finally {
			@unlink($link);
			@unlink($outside);
		}
	}

	/**
	 * The companion in-bounds case: a symlink inside an allowed dir whose target is a
	 * regular file ALSO directly under an allowed dir is accepted. Establishes that the
	 * rejection above is caused by the target ESCAPING the allow-list, not by the input
	 * merely being a symlink — without it, an "always reject symlinks" implementation
	 * would pass the escape test for the wrong reason. Skips when the environment cannot
	 * create the files/link.
	 */
	public function testSymlinkWithinAllowedDirAccepted(): void
	{
		$dir = '/var/db/pfblockerng/deny';
		if (!@is_dir($dir) && !@mkdir($dir, 0o755, true) && !@is_dir($dir)) {
			$this->markTestSkipped("cannot create allowed dir {$dir} in this environment");
		}

		$target = $dir . '/pfb_symlink_target_' . getmypid() . '.txt';
		if (@file_put_contents($target, "test\n") === false) {
			$this->markTestSkipped("cannot write {$target} in this environment");
		}

		$link = $dir . '/pfb_symlink_inbounds_' . getmypid() . '.txt';
		@unlink($link);
		if (!@symlink($target, $link)) {
			@unlink($target);
			$this->markTestSkipped('cannot create a symlink in this environment');
		}

		try {
			$this->assertTrue(
				$this->validate($link),
				'a symlink whose target is a regular file directly in an allowed dir must be allowed'
			);
		} finally {
			@unlink($link);
			@unlink($target);
		}
	}
}
