<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issues #1323/#2114 -- custom rows must stay Enabled and carry explicit parser
 * metadata. The three live sync routes share one row-construction decision;
 * behavior tests exercise that decision with each route's inputs.
 */
#[CoversFunction('pfb_dnsbl_custom_row')]
final class DnsblCustomRowStateEnabledInvariantTest extends TestCase
{
	public function testDnsblNormalizationRouteBuildsEnabledCustomRow(): void
	{
		$this->assertSame(
			[
				'header' => 'normalization_custom',
				'custom' => 'normal.example',
				'format' => 'regex',
				'state'  => 'Enabled',
				'url'    => 'custom',
			],
			pfb_dnsbl_custom_row('normalization', 'normal.example')
		);
	}

	public function testDnsblDownloadRouteBuildsEnabledCustomRow(): void
	{
		$this->assertSame(
			[
				'header' => 'download_custom',
				'custom' => ['download.example', '||ads.download.example^'],
				'format' => 'regex',
				'state'  => 'Enabled',
				'url'    => 'custom',
			],
			pfb_dnsbl_custom_row('download', ['download.example', '||ads.download.example^'])
		);
	}

	public function testIpAliasDownloadRouteBuildsEnabledCustomRow(): void
	{
		$this->assertSame(
			[
				'header' => 'ip-alias_custom',
				'custom' => "192.0.2.1\n198.51.100.7",
				'format' => 'regex',
				'state'  => 'Enabled',
				'url'    => 'custom',
			],
			pfb_dnsbl_custom_row('ip-alias', "192.0.2.1\n198.51.100.7")
		);
	}

	public function testLiveSyncDispatchKeepsAllThreeRoutesOnSharedRowSeam(): void
	{
		$source = php_strip_whitespace(
			dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc'
		);
		$call = 'pfb_dnsbl_custom_row($list[\'aliasname\'], $list[\'custom\'])';
		$this->assertSame(
			3,
			substr_count($source, $call),
			'live sync_package_pfblockerng download/firewall/service dispatch has no '
			. 'off-appliance PHPUnit driver (#993); this executable-code pin keeps all '
			. 'three routes on the shared custom-row synthesis seam'
		);
	}

	public function testSynthesizedCustomRowIsNeverHold(): void
	{
		$customRow = pfb_dnsbl_custom_row('Some', 'example.com');
		$this->assertNotSame('Hold', $customRow['state'], 'a synthesized custom row must never read as Hold');
	}
}
