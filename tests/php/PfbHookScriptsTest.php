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
		// Only hook_pre_*.{sh,py}; the ip_pre_ decoy and the .txt are excluded.
		$this->assertSame(
			['hook_pre_alpha.sh' => 'hook_pre_alpha.sh', 'hook_pre_beta.py' => 'hook_pre_beta.py'],
			pfb_hook_scripts('pre', self::dir())
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
}
