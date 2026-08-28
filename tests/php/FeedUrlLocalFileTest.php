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
 * The ALLOWED cases need a real file under a real allowed directory. Most of the
 * allow-list is hardcoded absolute paths under /var/db/pfblockerng, which only root
 * can create — so these tests drive the one allowed directory production derives at
 * runtime instead: $pfb['dbdir'], appended to the allow-list whenever it resolves.
 * Pointing it at a temp directory gives every uid a real allowed dir, so the ALLOWED
 * and symlink cases run everywhere rather than skipping off-appliance (issue #2356).
 */
#[CoversFunction('pfb_filter')]
final class FeedUrlLocalFileTest extends TestCase
{
	/** The temp directory registered as $pfb['dbdir'] — an allowed dir for this test. */
	private string $dbdir = '';

	/** Whether $pfb['dbdir'] existed before setUp(), and its prior value. */
	private bool $hadDbdir = FALSE;
	private mixed $savedDbdir = NULL;

	/** Files created OUTSIDE the allowed dir, removed in tearDown(). @var list<string> */
	private array $outside = [];

	/**
	 * A real regular file one level ABOVE the allowed dir — the out-of-bounds target
	 * the escape cases point at. It sits in the parent of $pfb['dbdir'], which no
	 * allow-list entry covers, so a verdict of "allowed" for it can only come from a
	 * broken containment check.
	 */
	private function makeOutsideFile(): string
	{
		$path = dirname($this->dbdir) . '/pfb_outside_' . getmypid() . '_' . uniqid() . '.txt';
		$this->assertNotFalse(file_put_contents($path, "outside\n"), "could not write {$path}");
		$this->outside[] = $path;

		return $path;
	}

	protected function setUp(): void
	{
		$dir = sys_get_temp_dir() . '/pfb_localfile_' . getmypid() . '_' . uniqid();
		$this->assertTrue(mkdir($dir, 0o755, TRUE), "could not create the test dbdir {$dir}");
		$real = realpath($dir);
		$this->assertNotFalse($real, "could not resolve the test dbdir {$dir}");
		$this->dbdir = (string) $real;

		$this->hadDbdir   = array_key_exists('dbdir', $GLOBALS['pfb'] ?? []);
		$this->savedDbdir = $GLOBALS['pfb']['dbdir'] ?? NULL;

		$GLOBALS['pfb']['dbdir'] = $this->dbdir;
	}

	protected function tearDown(): void
	{
		if ($this->hadDbdir) {
			$GLOBALS['pfb']['dbdir'] = $this->savedDbdir;
		} else {
			unset($GLOBALS['pfb']['dbdir']);
		}

		if ($this->dbdir !== '' && is_dir($this->dbdir)) {
			foreach ((array) scandir($this->dbdir) as $entry) {
				if ($entry === '.' || $entry === '..') {
					continue;
				}
				@unlink($this->dbdir . '/' . $entry);
			}
			@rmdir($this->dbdir);
		}

		foreach ($this->outside as $path) {
			@unlink($path);
		}
		$this->outside = [];
	}

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
	 * the hardening did not break the legitimate local-file case.
	 */
	public function testRealFileInAllowedDirAccepted(): void
	{
		$dir  = $this->dbdir;
		$file = $dir . '/pfb_localfile_unit_' . getmypid() . '.txt';

		$this->assertNotFalse(file_put_contents($file, "test\n"), "could not write {$file}");

		try {
			// Before-state: an EXISTING regular file one level outside the same dir,
			// reached through it, is rejected — so acceptance below is the containment
			// check and not "any resolvable path".
			$outside = $this->makeOutsideFile();
			$this->assertFalse(
				$this->validate($dir . '/../' . basename($outside)),
				'an escaping sibling path is rejected even when the target file exists'
			);

			// The real file directly under the allowed dir is accepted.
			$this->assertTrue($this->validate($file), 'a real file directly in an allowed dir must be allowed');
		} finally {
			@unlink($file);
		}
	}

	/**
	 * A DIRECTORY sitting directly in an allowed dir is rejected: the branch requires a
	 * regular file, so a path that satisfies containment can still fail on its type. The
	 * accepted case above cannot distinguish the two — with the regular-file requirement
	 * dropped, a directory would be handed to the download path as a feed source.
	 */
	public function testDirectoryInAllowedDirRejected(): void
	{
		$dir = $this->dbdir . '/pfb_localfile_subdir_' . getmypid();
		$this->assertTrue(mkdir($dir, 0o755), "could not create the test directory {$dir}");

		try {
			$this->assertFalse(
				$this->validate($dir),
				'a directory inside an allowed dir must be rejected: the branch requires a regular file'
			);
		} finally {
			@rmdir($dir);
		}
	}

	/**
	 * A symlink placed INSIDE an allowed directory but pointing OUTSIDE it must be
	 * rejected: realpath() resolves the link to its target, whose canonical directory
	 * is not in the allow-list. Paired with the in-bounds symlink test below, this proves
	 * the verdict follows the canonical TARGET location, not the link's own path — the
	 * core reason canonicalization is required.
	 */
	public function testSymlinkEscapingAllowedDirRejected(): void
	{
		$dir = $this->dbdir;

		// Target OUTSIDE every allowed dir.
		$outside = $this->makeOutsideFile();

		$link = $dir . '/pfb_symlink_escape_' . getmypid() . '.txt';
		$this->assertTrue(symlink($outside, $link), "could not create the symlink {$link}");

		try {
			$this->assertFalse(
				$this->validate($link),
				'a symlink inside an allowed dir pointing outside it must be rejected'
			);
		} finally {
			@unlink($link);
		}
	}

	/**
	 * The companion in-bounds case: a symlink inside an allowed dir whose target is a
	 * regular file ALSO directly under an allowed dir is accepted. Establishes that the
	 * rejection above is caused by the target ESCAPING the allow-list, not by the input
	 * merely being a symlink — without it, an "always reject symlinks" implementation
	 * would pass the escape test for the wrong reason.
	 */
	public function testSymlinkWithinAllowedDirAccepted(): void
	{
		$dir = $this->dbdir;

		$target = $dir . '/pfb_symlink_target_' . getmypid() . '.txt';
		$this->assertNotFalse(file_put_contents($target, "test\n"), "could not write {$target}");

		$link = $dir . '/pfb_symlink_inbounds_' . getmypid() . '.txt';
		$this->assertTrue(symlink($target, $link), "could not create the symlink {$link}");

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
