<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-12 (hardened): pfb_hook_scripts() / pfb_hook_script_valid() — the allow-list
 * that makes a hook run a VETTED on-box script file, never a GUI-entered command.
 * pfb_hook_scripts() enumerates the picker's options (hook_<when>_*.{sh,py} in the
 * hook-script dir); pfb_hook_script_valid() is the gate the save handler (reject)
 * and the runner (skip) both apply. Pinned against a fixture directory.
 *
 * Branch coverage: prefix filter (pre vs post), extension filter (.sh/.py only),
 * decoy prefixes excluded, sorted output; and for the validator — a real file
 * passes, a Pre/Post mismatch / missing file / wrong extension / path traversal /
 * absolute path / empty value all reject.
 */
#[CoversFunction('pfb_hook_scripts')]
#[CoversFunction('pfb_hook_script_valid')]
final class PfbHookScriptsTest extends TestCase
{
	private static function dir(): string
	{
		return __DIR__ . '/fixtures/hook_scripts';
	}

	public function testEnumeratesPreScriptsSortedByBasename(): void
	{
		// Only hook_pre_*.{sh,py}; the ip_pre_ decoy and .txt excluded.
		// hook_pre_noexec.sh (0644) is included — exec bit is not a gate.
		$this->assertSame(
			[
				'hook_pre_alpha.sh'  => 'hook_pre_alpha.sh',
				'hook_pre_beta.py'   => 'hook_pre_beta.py',
				'hook_pre_noexec.sh' => 'hook_pre_noexec.sh',
			],
			pfb_hook_scripts('pre', self::dir())
		);
	}

	/**
	 * Given: hook_pre_noexec.sh is a regular 0644 file (no execute bit) in the hook dir.
	 * When:  pfb_hook_scripts('pre', $dir) is called.
	 * Then:  the file IS included — exec bit is not required.
	 *
	 * Red→green: with the old `|| !is_executable($real)` guard the file would be
	 * excluded; without it the file is present in the enumerated set.
	 */
	public function testNonExecutableRegularFileIsIncluded(): void
	{
		$scripts = pfb_hook_scripts('pre', self::dir());
		$this->assertArrayHasKey('hook_pre_noexec.sh', $scripts,
			'A non-executable (0644) regular file must be included — exec bit is not a gate');
		$this->assertTrue(
			pfb_hook_script_valid('hook_pre_noexec.sh', 'pre', self::dir()),
			'Validator must accept the non-executable file as it is contained + regular'
		);
	}

	public function testEnumeratesPostScriptsSortedByBasename(): void
	{
		$this->assertSame(
			['hook_post_delta.py' => 'hook_post_delta.py', 'hook_post_gamma.sh' => 'hook_post_gamma.sh'],
			pfb_hook_scripts('post', self::dir())
		);
	}

	public function testEnumerationExcludesDecoyPrefixAndWrongExtension(): void
	{
		$pre = pfb_hook_scripts('pre', self::dir());
		$this->assertArrayNotHasKey('ip_pre_decoy.sh', $pre);	// list pre-script prefix, not a hook
		$this->assertArrayNotHasKey('hook_pre_note.txt', $pre);	// .txt is not .sh/.py
	}

	public function testInvalidWhenEnumeratesNothing(): void
	{
		$this->assertSame([], pfb_hook_scripts('mid', self::dir()));
		$this->assertSame([], pfb_hook_scripts('', self::dir()));
	}

	public function testValidAcceptsAnExistingScriptForItsWhen(): void
	{
		$this->assertTrue(pfb_hook_script_valid('hook_pre_alpha.sh', 'pre', self::dir()));
		$this->assertTrue(pfb_hook_script_valid('hook_post_delta.py', 'post', self::dir()));
	}

	public function testValidRejectsPrePostMismatch(): void
	{
		// A pre script must NOT validate as a post hook (and vice versa): the picker
		// only offers the matching prefix, and the save handler enforces it.
		$this->assertFalse(pfb_hook_script_valid('hook_pre_alpha.sh', 'post', self::dir()));
		$this->assertFalse(pfb_hook_script_valid('hook_post_gamma.sh', 'pre', self::dir()));
	}

	public function testValidRejectsMissingWrongExtensionAndDecoy(): void
	{
		$this->assertFalse(pfb_hook_script_valid('hook_pre_zzz.sh', 'pre', self::dir()));	// not present
		$this->assertFalse(pfb_hook_script_valid('hook_pre_note.txt', 'pre', self::dir()));	// wrong ext
		$this->assertFalse(pfb_hook_script_valid('ip_pre_decoy.sh', 'pre', self::dir()));	// decoy prefix
	}

	public function testValidRejectsTraversalAbsoluteAndEmpty(): void
	{
		// The basename guard fires BEFORE the filesystem is touched.
		$this->assertFalse(pfb_hook_script_valid('../hook_pre_alpha.sh', 'pre', self::dir()));
		$this->assertFalse(pfb_hook_script_valid('sub/hook_pre_alpha.sh', 'pre', self::dir()));
		$this->assertFalse(pfb_hook_script_valid('/etc/passwd', 'pre', self::dir()));
		$this->assertFalse(pfb_hook_script_valid('', 'pre', self::dir()));
	}

	// -----------------------------------------------------------------------
	// Symlink-containment tests (realpath parity with pfb_filter LOCALFILE).
	// Symlinks are built at runtime in a temp dir — not committed to the repo.
	// -----------------------------------------------------------------------

	/** @return string path to an executable file OUTSIDE the hook dir */
	private static function makeOutsideScript(): string
	{
		$f = tempnam(sys_get_temp_dir(), 'pfb_outside_');
		file_put_contents($f, "#!/bin/sh\n");
		chmod($f, 0755);
		return $f;
	}

	/**
	 * Build a throwaway hook dir with:
	 *   hook_pre_real.sh          — plain file (included)
	 *   hook_pre_alias.sh         — symlink → hook_pre_real.sh in same dir (included)
	 *   hook_pre_escape.sh        — symlink → executable OUTSIDE dir (excluded)
	 *   hook_pre_todir.sh         — symlink → a directory (excluded)
	 *   hook_pre_dangle.sh        — dangling symlink (excluded)
	 *
	 * Returns ['dir' => ..., 'outside' => ...] so the caller can clean up.
	 */
	private static function makeSymlinkFixture(): array
	{
		$tmp    = sys_get_temp_dir() . '/pfb_hook_test_' . getmypid();
		mkdir($tmp, 0755, TRUE);

		$outside = self::makeOutsideScript();

		// Plain real file
		file_put_contents("{$tmp}/hook_pre_real.sh", "#!/bin/sh\n");
		chmod("{$tmp}/hook_pre_real.sh", 0755);

		// In-dir alias (contained)
		symlink("{$tmp}/hook_pre_real.sh", "{$tmp}/hook_pre_alias.sh");

		// Escape: points to an executable outside the dir
		symlink($outside, "{$tmp}/hook_pre_escape.sh");

		// Symlink to a directory
		symlink($tmp, "{$tmp}/hook_pre_todir.sh");

		// Dangling symlink
		symlink("{$tmp}/nonexistent_target.sh", "{$tmp}/hook_pre_dangle.sh");

		return ['dir' => $tmp, 'outside' => $outside];
	}

	private static function cleanSymlinkFixture(array $fixture): void
	{
		foreach (glob($fixture['dir'] . '/*') as $f) {
			// unlink works on both files and symlinks; rmdir for the dir entry below
			if (is_link($f) || is_file($f)) {
				unlink($f);
			}
		}
		rmdir($fixture['dir']);
		if (file_exists($fixture['outside'])) {
			unlink($fixture['outside']);
		}
	}

	/**
	 * Given: a hook dir with a plain file, an in-dir alias, an escaping symlink,
	 *        a symlink-to-dir, and a dangling symlink.
	 * When:  pfb_hook_scripts('pre', $dir) is called.
	 * Then:  only the plain file and the in-dir alias are enumerated, keyed by
	 *        the symlink's own basename (not the target's).
	 */
	public function testEnumerationExcludesSymlinksEscapingTheDirAndIncludesContainedAlias(): void
	{
		$fixture = self::makeSymlinkFixture();
		try {
			$scripts = pfb_hook_scripts('pre', $fixture['dir']);

			// Escaping symlink, symlink-to-dir, dangling symlink must NOT appear.
			$this->assertArrayNotHasKey('hook_pre_escape.sh', $scripts,
				'Escaping symlink must be excluded (realpath escapes the hook dir)');
			$this->assertArrayNotHasKey('hook_pre_todir.sh', $scripts,
				'Symlink-to-directory must be excluded (is_file rejects dirs)');
			$this->assertArrayNotHasKey('hook_pre_dangle.sh', $scripts,
				'Dangling symlink must be excluded (realpath returns FALSE)');

			// Plain file and contained alias must appear.
			$this->assertArrayHasKey('hook_pre_real.sh', $scripts,
				'Plain executable file must be included');
			$this->assertArrayHasKey('hook_pre_alias.sh', $scripts,
				'Contained in-dir alias must be included, keyed by the link\'s own basename');

			// Values equal the basename (the picker's requirement).
			$this->assertSame('hook_pre_alias.sh', $scripts['hook_pre_alias.sh']);
		} finally {
			self::cleanSymlinkFixture($fixture);
		}
	}

	/**
	 * Given: hook_pre_escape.sh symlinks to an executable outside the hook dir.
	 * When:  pfb_hook_script_valid('hook_pre_escape.sh', 'pre', $dir) is called.
	 * Then:  it returns FALSE (the escaping script is not in the enumerated set).
	 *
	 * Before the fix pfb_hook_scripts() would have included the escape target and
	 * this test would have returned TRUE — red→green proof of the containment fix.
	 */
	public function testValidatorRejectsEscapingSymlink(): void
	{
		$fixture = self::makeSymlinkFixture();
		try {
			$this->assertFalse(
				pfb_hook_script_valid('hook_pre_escape.sh', 'pre', $fixture['dir']),
				'Escaping symlink must be rejected by the validator'
			);
		} finally {
			self::cleanSymlinkFixture($fixture);
		}
	}

	/**
	 * Given: hook_pre_alias.sh is a symlink to hook_pre_real.sh in the same dir.
	 * When:  pfb_hook_script_valid('hook_pre_alias.sh', 'pre', $dir) is called.
	 * Then:  it returns TRUE (contained alias is allowed).
	 */
	public function testValidatorAcceptsContainedAliasSymlink(): void
	{
		$fixture = self::makeSymlinkFixture();
		try {
			$this->assertTrue(
				pfb_hook_script_valid('hook_pre_alias.sh', 'pre', $fixture['dir']),
				'In-dir alias symlink must be accepted by the validator'
			);
		} finally {
			self::cleanSymlinkFixture($fixture);
		}
	}
}
