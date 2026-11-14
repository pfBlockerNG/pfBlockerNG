<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

#[CoversNothing]
final class FeedPhaseCallSitesTest extends TestCase
{
	private const APPLY = 'src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';
	private const CRON = 'src/usr/local/pkg/pfblockerng/pfblockerng_cron.inc';

	public function testDnsblFeedPhasePrecedesDnsblipAssemblyAndIpPhase(): void
	{
		$source = file_get_contents(self::APPLY);
		$this->assertIsString($source);
		$this->assertSame(2, preg_match_all('/pfb_core_feed_phase_groups\(\s*\'(?:dnsbl|ip)\'/', $source));
		$dnsbl = preg_match('/pfb_core_feed_phase_groups\(\s*\'dnsbl\'/', $source, $dnsblMatch, PREG_OFFSET_CAPTURE) === 1
			? $dnsblMatch[0][1] : FALSE;
		$dnsblip = strpos($source, 'pfb_dnsblip_rebuild_check');
		$ip = preg_match('/pfb_core_feed_phase_groups\(\s*\'ip\'/', $source, $ipMatch, PREG_OFFSET_CAPTURE) === 1
			? $ipMatch[0][1] : FALSE;
		$this->assertIsInt($dnsbl);
		$this->assertIsInt($dnsblip);
		$this->assertIsInt($ip);
		$this->assertLessThan($dnsblip, $dnsbl);
		$this->assertLessThan($ip, $dnsblip);
	}

	public function testFeedLoopsContainNoPhpDownloadNormalizeOrParserFallback(): void
	{
		$apply = file_get_contents(self::APPLY);
		$cron = file_get_contents(self::CRON);
		$this->assertIsString($apply);
		$this->assertIsString($cron);
		foreach ([
			'pfb_feed_normalize(', 'pfb_dnsbl_parse_feed(', 'pfb_dnsbl_parse_line(',
			'pfb_ip_parse_feed(', 'pfb_ip_parse_line(', 'pfb_list_pre_script_run(',
		] as $symbol) {
			$this->assertFalse(str_contains($apply, $symbol), "legacy feed path remains: {$symbol}");
		}
		$this->assertFalse(
			str_contains($apply, 'pfb_download(new PfbDownloadRequest('),
			'feed loops still download through the PHP client'
		);
		$this->assertFalse(str_contains($cron, 'pfb_download('), 'scheduled change detection still fetches in PHP');
		$this->assertFalse(str_contains($cron, 'pfb_local_feed_changed('), 'scheduled change detection still hashes local feeds in PHP');
	}

	public function testCoreArtifactNamesAndSyntheticIdsAreWired(): void
	{
		$source = file_get_contents(self::APPLY);
		$this->assertIsString($source);
		foreach ([
			'.parsed.ndjson', '.parsed.v4.ip', '.parsed.v6.ip', '_v4.parsed.ip', '_v6.parsed.ip',
			'custom:dnsbl:', 'custom:ipv4:', 'custom:ipv6:',
			'synthetic:ipv4:DNSBLIP_v4', 'synthetic:ipv6:DNSBLIP_v6',
		] as $contract) {
			$this->assertTrue(str_contains($source, $contract), "FeedPhase wiring lacks {$contract}");
		}
		$this->assertTrue(str_contains($source, 'pfb_list_post_script_stage('), 'post-scripts must remain in PHP');
	}

	public function testWhoisconvertDispatchIsRemoved(): void
	{
		$shell = file_get_contents('src/usr/local/pkg/pfblockerng/pfblockerng.sh');
		$cli = file_get_contents('src/usr/local/www/pfblockerng/pfblockerng.php');
		$this->assertIsString($shell);
		$this->assertIsString($cli);
		$this->assertFalse(str_contains($shell, 'whoisconvert()'));
		$this->assertFalse(str_contains($cli, ' whoisconvert '));
	}

	public function testAsnDatabaseRefreshPrecedesIpFeedPhase(): void
	{
		$source = file_get_contents(self::APPLY);
		$this->assertIsString($source);
		$refresh = strpos($source, "pfb_reentry_exec('asn_shell', ['scheduled']");
		$phase = preg_match('/pfb_core_feed_phase_groups\(\s*\'ip\'/', $source, $phaseMatch, PREG_OFFSET_CAPTURE) === 1
			? $phaseMatch[0][1] : FALSE;
		$this->assertIsInt($refresh);
		$this->assertIsInt($phase);
		$this->assertLessThan($phase, $refresh);
	}
}
