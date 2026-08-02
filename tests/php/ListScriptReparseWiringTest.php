<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** The shared decision seam exposes the same routes used by IP and DNSBL rows. */
final class ListScriptReparseWiringTest extends TestCase
{
	private string $dir;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_script_reuse_' . getmypid() . '_' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir($this->dir, 0700, TRUE));
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->dir);
		$this->assertDirectoryDoesNotExist($this->dir);
	}

	private function script(string $name): string
	{
		$path = "{$this->dir}/{$name}";
		file_put_contents($path, "#!/bin/sh\nexit 0\n");
		chmod($path, 0755);
		return $path;
	}

	public function testDnsblScriptedRowWithOrigUsesLocalReparseInsteadOfVerbatimFastPath(): void
	{
		$pre  = $this->script('pre.sh');
		$orig = "{$this->dir}/feed.orig";
		file_put_contents($orig, "example.org\n");

		$decision = pfb_dnsbl_script_reuse_decision(TRUE, $pre, FALSE, $orig);

		$this->assertTrue($decision['has_user_script']);
		$this->assertTrue($decision['orig_exists']);
		$this->assertTrue($decision['reparse']);
		$this->assertFalse($decision['verbatim']);
	}

	public function testIpScriptedRowWithOrigUsesLocalReparseInsteadOfVerbatimFastPath(): void
	{
		$pre  = $this->script('pre.sh');
		$orig = "{$this->dir}/feed.orig";
		file_put_contents($orig, "192.0.2.1\n");

		$decision = pfb_ip_script_reuse_decision(TRUE, $pre, FALSE, $orig);

		$this->assertTrue($decision['has_user_script']);
		$this->assertTrue($decision['orig_exists']);
		$this->assertTrue($decision['reparse']);
		$this->assertFalse($decision['verbatim']);
	}

	public function testDnsblScriptedHoldWithoutOrigStaysOnVerbatimFastPath(): void
	{
		$pre = $this->script('pre.sh');
		$orig = "{$this->dir}/missing.orig";
		$this->assertFileDoesNotExist($orig);

		$decision = pfb_dnsbl_script_reuse_decision(TRUE, $pre, FALSE, $orig);

		$this->assertTrue($decision['has_user_script']);
		$this->assertFalse($decision['orig_exists']);
		$this->assertFalse($decision['reparse']);
		$this->assertTrue($decision['verbatim']);
	}

	public function testIpScriptedHoldWithoutOrigStaysOnVerbatimFastPath(): void
	{
		$pre = $this->script('pre.sh');
		$orig = "{$this->dir}/missing.orig";
		$this->assertFileDoesNotExist($orig);

		$decision = pfb_ip_script_reuse_decision(TRUE, $pre, FALSE, $orig);

		$this->assertTrue($decision['has_user_script']);
		$this->assertFalse($decision['orig_exists']);
		$this->assertFalse($decision['reparse']);
		$this->assertTrue($decision['verbatim']);
	}

	public function testNoScriptWithoutOrigRemainsVerbatim(): void
	{
		$decision = pfb_list_script_reuse_decision(TRUE, FALSE, '', "{$this->dir}/missing.orig");

		$this->assertFalse($decision['has_user_script']);
		$this->assertFalse($decision['orig_exists']);
		$this->assertFalse($decision['reparse']);
		$this->assertTrue($decision['verbatim']);
	}

	public function testRejectedVerbatimStateNeverBecomesScriptReparse(): void
	{
		$pre  = $this->script('pre.sh');
		$orig = "{$this->dir}/feed.orig";
		file_put_contents($orig, "example.org\n");

		$decision = pfb_list_script_reuse_decision(FALSE, $pre, FALSE, $orig);

		$this->assertTrue($decision['has_user_script']);
		$this->assertTrue($decision['orig_exists']);
		$this->assertFalse($decision['reparse']);
		$this->assertFalse($decision['verbatim']);
	}

	public function testDirectoryAndMissingScriptPathsAreInactive(): void
	{
		$directory = "{$this->dir}/scripts";
		$this->assertTrue(mkdir($directory, 0700));
		$decision = pfb_list_script_reuse_decision(TRUE, $directory, "{$this->dir}/gone.sh", "{$this->dir}/missing.orig");

		$this->assertFalse($decision['has_user_script']);
		$this->assertTrue($decision['verbatim']);
	}
}
