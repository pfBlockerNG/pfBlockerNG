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
		$this->assertTrue(pfb_ip_norm_reuse_skip(TRUE, FALSE, FALSE, FALSE, TRUE, FALSE));
		$this->assertFalse(pfb_ip_norm_reuse_skip(TRUE, FALSE, FALSE, FALSE, TRUE, TRUE));
	}

	public function testUserScriptPreventsDnsblNormalizationReuse(): void
	{
		$this->assertTrue(pfb_dnsbl_norm_reuse_skip(TRUE, FALSE, FALSE, FALSE, TRUE, TRUE, FALSE));
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

		$this->assertStringContainsString(
			'$pfb_dnsbl_reuse_decision = pfb_dnsbl_script_reuse_decision( '
			. '$pfb_dnsbl_verbatim_reuse, $pfb_dnsbl_script_pre, $pfb_dnsbl_script_post, '
			. '"{$pfborig}/{$header}.orig"); $pfb_dnsbl_user_script = '
			. '$pfb_dnsbl_reuse_decision[\'has_user_script\'];',
			$code,
			'DNSBL loop must call its decision seam and consume its result'
		);
		$this->assertStringContainsString(
			'pfb_dnsbl_norm_reuse_skip($downloaded_fresh, (bool) $custom, '
			. '$orig_content_stale, $pfb_norm[\'changed\'], '
			. 'file_exists("{$pfbfolder}/{$header}.txt"), $staging_current_generation, '
			. '$pfb_dnsbl_user_script)',
			$code,
			'DNSBL normalization fast path must receive the seam effect'
		);
		$this->assertStringContainsString(
			'$pfb_ip_reuse_decision = pfb_ip_script_reuse_decision( '
			. '$pfb_ip_verbatim_reuse, $pfb_script_pre, $pfb_script_post, '
			. '"{$pfborig}/{$header}.orig"); $pfb_user_script = '
			. '$pfb_ip_reuse_decision[\'has_user_script\'];',
			$code,
			'IP loop must call its distinct decision seam and consume its result'
		);
		$this->assertStringContainsString(
			'pfb_ip_norm_reuse_skip($downloaded_fresh, (bool) $custom, '
			. '$orig_content_stale, $pfb_norm[\'changed\'], '
			. 'file_exists("{$pfbfolder}/{$header}.txt"), $pfb_user_script)',
			$code,
			'IP normalization fast path must receive the seam effect'
		);
	}
}
