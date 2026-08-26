<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** Script-active rows must reach both facility normalization passes. */
final class ListScriptTransformRerunWiringTest extends TestCase
{
	private string $dir;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_transform_' . getmypid() . '_' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir($this->dir, 0700, TRUE));
	}

	protected function tearDown(): void
	{
		foreach (glob("{$this->dir}/*") ?: [] as $file) {
			@unlink($file);
		}
		@rmdir($this->dir);
	}

	private function script(): string
	{
		$path = "{$this->dir}/pre.sh";
		file_put_contents($path, "#!/bin/sh\nexit 0\n");
		chmod($path, 0755);
		return $path;
	}

	public function testDnsblDecisionReportsUserScript(): void
	{
		$script = $this->script();
		$orig   = "{$this->dir}/feed.orig";
		file_put_contents($orig, "example.org\n");

		$decision = pfb_dnsbl_script_reuse_decision(TRUE, $script, FALSE, $orig);
		$this->assertTrue($decision['has_user_script']);
		$this->assertTrue($decision['reparse']);
		$this->assertFalse($decision['verbatim']);
	}

	public function testIpDecisionReportsUserScript(): void
	{
		$script = $this->script();
		$orig   = "{$this->dir}/feed.orig";
		file_put_contents($orig, "192.0.2.1\n");

		$decision = pfb_ip_script_reuse_decision(TRUE, $script, FALSE, $orig);
		$this->assertTrue($decision['has_user_script']);
		$this->assertTrue($decision['reparse']);
		$this->assertFalse($decision['verbatim']);
	}

	public function testUserScriptPreventsIpNormalizationReuse(): void
	{
		$this->assertFalse(pfb_ip_norm_reuse_skip(TRUE, FALSE, FALSE, FALSE, TRUE, TRUE));
	}

	public function testUserScriptPreventsDnsblNormalizationReuse(): void
	{
		$this->assertFalse(pfb_dnsbl_norm_reuse_skip(TRUE, FALSE, FALSE, FALSE, TRUE, TRUE, TRUE));
	}

	public function testFreshNormalizedContentWithoutScriptStillTakesFastPath(): void
	{
		$this->assertTrue(pfb_ip_norm_reuse_skip(TRUE, FALSE, FALSE, FALSE, TRUE, FALSE));
		$this->assertTrue(pfb_dnsbl_norm_reuse_skip(TRUE, FALSE, FALSE, FALSE, TRUE, TRUE, FALSE));
	}

	/**
	 * issue #993: sync_package_pfblockerng() drives live downloads, scripts,
	 * firewall state, and services, so PHPUnit cannot execute either feed loop.
	 * Keep only these comment-free outer dispatch pins; helper behavior above
	 * proves the effect once each independently scoped call runs.
	 */
	public function testBothLiveLoopsDispatchThroughTheBehaviorSeams(): void
	{
		$code = php_strip_whitespace(
			dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc'
		);
		$this->assertIsString($code);

		$this->assertSame(1, preg_match(
			'/\$pfb_dnsbl_reuse_decision\s*=\s*pfb_dnsbl_script_reuse_decision\(\s*'
			. '\$pfb_dnsbl_verbatim_reuse,\s*\$pfb_row_script_pre,\s*\$pfb_row_script_post,\s*'
			. '"\{\$pfborig\}\/\{\$header\}\.orig"\);\s*\$pfb_dnsbl_user_script\s*=\s*'
			. '\$pfb_dnsbl_reuse_decision\[\x27has_user_script\x27\];/',
			$code
		), 'DNSBL loop must call its decision seam and consume its result');
		$this->assertSame(1, preg_match(
			'/pfb_dnsbl_norm_reuse_skip\(\s*\$downloaded_fresh,\s*\(bool\)\s*\$custom,\s*'
			. '\$orig_content_stale,\s*\$pfb_norm\[\x27changed\x27\],\s*'
			. 'file_exists\(\s*"\{\$pfbfolder\}\/\{\$header\}\.txt"\s*\),\s*\$staging_current_generation,\s*'
			. '\$pfb_dnsbl_user_script\s*\)/',
			$code
		), 'DNSBL normalization fast path must receive the seam effect');
		$this->assertSame(1, preg_match(
			'/\$pfb_ip_reuse_decision\s*=\s*pfb_ip_script_reuse_decision\(\s*'
			. '\$pfb_ip_verbatim_reuse,\s*\$pfb_script_pre,\s*\$pfb_script_post,\s*'
			. '"\{\$pfborig\}\/\{\$header\}\.orig"\);\s*\$pfb_user_script\s*=\s*'
			. '\$pfb_ip_reuse_decision\[\x27has_user_script\x27\];/',
			$code
		), 'IP loop must call its distinct decision seam and consume its result');
		$this->assertSame(1, preg_match(
			'/pfb_ip_norm_reuse_skip\(\s*\$downloaded_fresh,\s*\(bool\)\s*\$custom,\s*'
			. '\$orig_content_stale,\s*\$pfb_norm\[\x27changed\x27\],\s*'
			. 'file_exists\(\s*"\{\$pfbfolder\}\/\{\$header\}\.txt"\s*\),\s*\$pfb_user_script\s*\)/',
			$code
		), 'IP normalization fast path must receive the seam effect');
	}

	public function testDnsblSiblingRowsRestoreGroupScriptsBeforeSelection(): void
	{
		$code = php_strip_whitespace(
			dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc'
		);
		$this->assertIsString($code);
		$this->assertMatchesRegularExpression(
			'/foreach\s*\(\$list\[\x27row\x27\]\s+as\s+\$key\s*=>\s*\$row\)\s*\{\s*'
			. '\$pfb_row_script_pre\s*=\s*\$pfb_dnsbl_script_pre;\s*'
			. '\$pfb_row_script_post\s*=\s*\$pfb_dnsbl_script_post;\s*'
			. 'if\s*\(!empty\(\$row\[\x27url\x27\]\)\s*&&\s*\$row\[\x27state\x27\]\s*!=\s*\x27Disabled\x27\)/',
			$code,
			'Each sibling row must restore group scripts before an unselected row can continue.'
		);
	}
}
