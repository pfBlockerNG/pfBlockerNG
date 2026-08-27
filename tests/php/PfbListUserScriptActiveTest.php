<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1960: pfb_list_user_script_active() is the has_user_script term
 * shared by the IP and DNSBL feed loops' early verbatim-reuse fast paths and
 * their normalization-level reuse gates (pfb_ip_norm_reuse_skip() /
 * pfb_dnsbl_norm_reuse_skip()) -- one helper keeps every caller in lock-step
 * by construction instead of re-deriving the ($script && is_file($script))
 * pair at each call site. Parameters stay untyped: pfb_resolve_list_script()
 * returns FALSE or a string, and every caller holds that same union.
 */
#[CoversFunction('pfb_list_user_script_active')]
final class PfbListUserScriptActiveTest extends TestCase
{
	private string $tmp;

	protected function setUp(): void
	{
		$this->tmp = sys_get_temp_dir() . '/pfb_lusa_' . getmypid() . '_' . bin2hex(random_bytes(4));
		mkdir($this->tmp, 0755, TRUE);
	}

	protected function tearDown(): void
	{
		exec('chmod -R u+rwx ' . escapeshellarg($this->tmp));
		exec('rm -rf ' . escapeshellarg($this->tmp));
	}

	private function makeFile(string $name): string
	{
		$path = "{$this->tmp}/{$name}";
		file_put_contents($path, "#!/bin/sh\nexit 0\n");
		return $path;
	}

	// -----------------------------------------------------------------
	// Row 1 -- pre-script configured and the file exists -> TRUE.
	// -----------------------------------------------------------------

	public function testPreScriptConfiguredAndExistsIsTrue(): void
	{
		$pre = $this->makeFile('pre.sh');
		$this->assertTrue(pfb_list_user_script_active($pre, FALSE),
			'a configured pre-script that exists on disk must report the feed as script-active');
	}

	// -----------------------------------------------------------------
	// Row 2 -- post-script configured and the file exists -> TRUE.
	// -----------------------------------------------------------------

	public function testPostScriptConfiguredAndExistsIsTrue(): void
	{
		$post = $this->makeFile('post.sh');
		$this->assertTrue(pfb_list_user_script_active(FALSE, $post),
			'a configured post-script that exists on disk must report the feed as script-active');
	}

	// -----------------------------------------------------------------
	// Row 3 -- BOTH configured -> TRUE.
	// -----------------------------------------------------------------

	public function testBothScriptsConfiguredAndExistIsTrue(): void
	{
		$pre  = $this->makeFile('pre.sh');
		$post = $this->makeFile('post.sh');
		$this->assertTrue(pfb_list_user_script_active($pre, $post),
			'both a pre- and post-script configured and present must report script-active');
	}

	// -----------------------------------------------------------------
	// Row 4 -- NEITHER configured (both FALSE, the pfb_resolve_list_script()
	// failure value) -> FALSE; pins the ordinary no-script feed keeps its
	// fast path.
	// -----------------------------------------------------------------

	public function testNeitherScriptConfiguredIsFalse(): void
	{
		$this->assertFalse(pfb_list_user_script_active(FALSE, FALSE),
			'the ordinary no-script feed (pfb_resolve_list_script() failure value on both) must keep its fast path');
	}

	// -----------------------------------------------------------------
	// Row 5 -- a path that is configured but does NOT exist on disk ->
	// FALSE; a retired/deleted script must not permanently disable reuse.
	// -----------------------------------------------------------------

	public function testConfiguredPathThatDoesNotExistOnDiskIsFalse(): void
	{
		$missing = "{$this->tmp}/retired_pre.sh";
		$this->assertFileDoesNotExist($missing, 'before: the path must not exist on disk');

		$this->assertFalse(pfb_list_user_script_active($missing, FALSE),
			'a retired/deleted script must not permanently disable reuse');
	}

	// -----------------------------------------------------------------
	// Row 6 -- a path that exists but is a DIRECTORY -> FALSE (is_file()
	// semantics, not file_exists()).
	// -----------------------------------------------------------------

	public function testConfiguredPathThatIsADirectoryIsFalse(): void
	{
		$dir = "{$this->tmp}/a_directory";
		mkdir($dir, 0755, TRUE);
		$this->assertDirectoryExists($dir, 'before: the directory must exist');

		$this->assertFalse(pfb_list_user_script_active($dir, FALSE),
			'is_file() semantics, not file_exists() -- a directory must not count as a configured script');
	}

	// -----------------------------------------------------------------
	// Row 7 -- empty-string path -> FALSE; pfb_resolve_list_script()
	// returns FALSE, but a caller passing '' must not be truthy.
	// -----------------------------------------------------------------

	public function testEmptyStringPathIsFalse(): void
	{
		$this->assertFalse(pfb_list_user_script_active('', ''),
			"a caller passing an empty string (rather than pfb_resolve_list_script()'s FALSE) must not be truthy");
	}
}
