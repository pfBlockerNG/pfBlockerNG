<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_resolve_list_script() — per-feed list pre/post transform script resolver.
 *
 * Policy: a config-stored basename is resolved to an absolute path only when
 * its canonical path (via realpath) sits directly inside one of the allowed
 * dirs. Containment + regular-file are the authorization; executable bit is
 * NOT required. $dirs is injectable for off-appliance tests.
 *
 * Branch coverage: contained file (primary dir), legacy fallback dir, non-exec
 * file, symlink escaping dir, symlink-to-dir, traversal input, empty name.
 */
#[CoversFunction('pfb_resolve_list_script')]
final class PfbResolveListScriptTest extends TestCase
{
	/** @var string primary temp dir */
	private string $dir1;
	/** @var string secondary (legacy fallback) temp dir */
	private string $dir2;
	/** @var list<string> files/links to clean up */
	private array $temps = [];

	protected function setUp(): void
	{
		$base = sys_get_temp_dir() . '/pfb_rls_' . getmypid();
		$this->dir1 = "{$base}_1";
		$this->dir2 = "{$base}_2";
		mkdir($this->dir1, 0755, TRUE);
		mkdir($this->dir2, 0755, TRUE);
	}

	protected function tearDown(): void
	{
		foreach ($this->temps as $f) {
			if (is_link($f) || is_file($f)) {
				unlink($f);
			}
		}
		foreach ([$this->dir1, $this->dir2] as $d) {
			foreach (glob("{$d}/*") ?: [] as $f) {
				if (is_link($f) || is_file($f)) {
					unlink($f);
				}
			}
			if (is_dir($d)) {
				rmdir($d);
			}
		}
	}

	private function makeFile(string $dir, string $name, int $mode = 0755): string
	{
		$path = "{$dir}/{$name}";
		file_put_contents($path, "#!/bin/sh\n");
		chmod($path, $mode);
		return $path;
	}

	private function dirs(): array
	{
		return [$this->dir1, $this->dir2];
	}

	/**
	 * Given: a regular 0755 file in the primary dir.
	 * When:  pfb_resolve_list_script is called with its basename.
	 * Then:  returns the path inside the primary dir.
	 */
	public function testContainedFileResolvesToPrimaryDir(): void
	{
		$this->makeFile($this->dir1, 'ip_pre_test.sh');
		$result = pfb_resolve_list_script('ip_pre_test.sh', $this->dirs());
		$this->assertSame("{$this->dir1}/ip_pre_test.sh", $result);
	}

	/**
	 * Given: a regular file with mode 0644 (no execute bit).
	 * When:  pfb_resolve_list_script is called.
	 * Then:  returns the path — exec bit is NOT a gate.
	 *
	 * Red→green: adding an is_executable($real) check to the resolver would make
	 * this test fail — proving the exec bit is deliberately NOT a gate. With
	 * containment + is_file only, a 0644 file in the dir resolves.
	 */
	public function testNonExecutableFileResolves(): void
	{
		$this->makeFile($this->dir1, 'ip_pre_noexec.sh', 0644);
		$result = pfb_resolve_list_script('ip_pre_noexec.sh', $this->dirs());
		$this->assertSame("{$this->dir1}/ip_pre_noexec.sh", $result,
			'A non-executable regular file must resolve — exec bit is not required');
	}

	/**
	 * Given: file exists only in the legacy fallback (second) dir, not the primary.
	 * When:  pfb_resolve_list_script is called.
	 * Then:  resolves via the fallback dir (upgrade compatibility).
	 */
	public function testLegacyFallbackDirIsHonored(): void
	{
		$this->makeFile($this->dir2, 'ip_pre_legacy.sh');
		$result = pfb_resolve_list_script('ip_pre_legacy.sh', $this->dirs());
		$this->assertSame("{$this->dir2}/ip_pre_legacy.sh", $result,
			'Legacy fallback dir must be checked when file absent from primary');
	}

	/**
	 * Given: a symlink inside the dir whose TARGET is a file OUTSIDE the dir.
	 * When:  pfb_resolve_list_script is called with the symlink's basename.
	 * Then:  returns FALSE — realpath resolves to outside; dirname check rejects it.
	 */
	public function testSymlinkEscapingDirReturnsFalse(): void
	{
		$outside = tempnam(sys_get_temp_dir(), 'pfb_out_');
		$this->temps[] = $outside;
		file_put_contents($outside, "#!/bin/sh\n");
		chmod($outside, 0755);
		symlink($outside, "{$this->dir1}/ip_pre_escape.sh");

		$result = pfb_resolve_list_script('ip_pre_escape.sh', $this->dirs());
		$this->assertFalse($result,
			'Symlink whose target is outside the dir must return FALSE (containment check)');
	}

	/**
	 * Given: a symlink to a DIRECTORY inside the dir.
	 * When:  pfb_resolve_list_script is called.
	 * Then:  returns FALSE — is_file rejects directories.
	 */
	public function testSymlinkToDirReturnsFalse(): void
	{
		symlink($this->dir2, "{$this->dir1}/ip_pre_todir.sh");
		$result = pfb_resolve_list_script('ip_pre_todir.sh', $this->dirs());
		$this->assertFalse($result, 'Symlink to a directory must return FALSE (is_file rejects)');
	}

	/**
	 * Given: a name with path traversal ("../other").
	 * When:  pfb_resolve_list_script is called.
	 * Then:  basename() strips the traversal; the resulting name does not exist → FALSE.
	 */
	public function testTraversalInputIsStrippedByBasename(): void
	{
		// Put a file in the parent's sister dir that would be reachable by traversal.
		$this->makeFile($this->dir2, 'victim.sh');
		// The traversal tries to reach dir2 from dir1 via "../<base2>/victim.sh"
		$traversal = "../" . basename($this->dir2) . "/victim.sh";
		$result     = pfb_resolve_list_script($traversal, [$this->dir1]);
		$this->assertFalse($result,
			'Traversal input must be basename()-stripped; the escaped name must not resolve');
	}

	/**
	 * Given: a name with a sub-path separator ("subdir/script.sh").
	 * When:  pfb_resolve_list_script is called.
	 * Then:  basename() reduces it to "script.sh"; if that does not exist → FALSE.
	 */
	public function testSubpathInputIsStrippedByBasename(): void
	{
		$result = pfb_resolve_list_script('subdir/ip_pre_test.sh', $this->dirs());
		$this->assertFalse($result, 'Sub-path separator must be basename()-stripped');
	}

	/**
	 * Given: an empty name string.
	 * When:  pfb_resolve_list_script is called.
	 * Then:  returns FALSE immediately (early-exit guard).
	 */
	public function testEmptyNameReturnsFalse(): void
	{
		$this->assertFalse(pfb_resolve_list_script('', $this->dirs()));
		$this->assertFalse(pfb_resolve_list_script('/', $this->dirs()),
			'basename("/") is empty string → FALSE');
	}
}
