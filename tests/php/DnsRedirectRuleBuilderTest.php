<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** ADR-36/#3400: pin each assigned-interface and fallback IPv6 redirect target. */
#[CoversFunction('pfb_dns_redirect_rule')]
final class DnsRedirectRuleBuilderTest extends TestCase
{
	protected function setUp(): void
	{
		$GLOBALS['config']['aliases']['alias'] = [];
	}

	protected function tearDown(): void
	{
		$GLOBALS['config']['aliases']['alias'] = [];
	}

	public function testIpv4RowIsTheAdr36Shape(): void
	{
		$this->assertSame(
			[
				'source'             => ['any' => ''],
				'destination'        => ['network' => '(self)', 'not' => '', 'port' => '53'],
				'ipprotocol'         => 'inet',
				'protocol'           => 'tcp/udp',
				'target'             => '127.0.0.1',
				'local-port'         => '53',
				'interface'          => 'lan',
				'descr'              => 'pfB_DNS_Redirect_lan_v4',
				'associated-rule-id' => 'pass',
				'natreflection'      => 'disable',
			],
			pfb_dns_redirect_rule('lan', 'inet', '')
		);
	}

	public function testIpv6RowOnLanTargetsTheLanAddressKeyword(): void
	{
		$this->assertSame(
			[
				'source'             => ['any' => ''],
				'destination'        => ['network' => '(self)', 'not' => '', 'port' => '53'],
				'ipprotocol'         => 'inet6',
				'protocol'           => 'tcp/udp',
				'target'             => 'lanip',
				'local-port'         => '53',
				'interface'          => 'lan',
				'descr'              => 'pfB_DNS_Redirect_lan_v6',
				'associated-rule-id' => 'pass',
				'natreflection'      => 'disable',
			],
			pfb_dns_redirect_rule('lan', 'inet6', '')
		);
	}

	#[DataProvider('assignedInterfaces')]
	public function testIpv6TargetOnAssignedInterfaceIsItsAddressKeyword(string $iface): void
	{
		$this->assertSame("{$iface}ip", pfb_dns_redirect_rule($iface, 'inet6', '')['target']);
	}

	public static function assignedInterfaces(): array
	{
		return ['wan' => ['wan'], 'lan' => ['lan'], 'opt1' => ['opt1'], 'opt12' => ['opt12']];
	}

	#[DataProvider('fallbackInterfaces')]
	public function testIpv6TargetOnOtherInterfaceStaysLoopback(string $iface): void
	{
		$this->assertSame('::1', pfb_dns_redirect_rule($iface, 'inet6', '')['target']);
	}

	public static function fallbackInterfaces(): array
	{
		return [
			'enc0' => ['enc0'], 'openvpn' => ['openvpn'], 'l2tp' => ['l2tp'],
			'wireguard' => ['wireguard'], 'wlan0' => ['wlan0'], 'lan2' => ['lan2'], 'opt1x' => ['opt1x'],
		];
	}

	public function testUsableExceptionAliasBecomesNegatedSourceForBothFamilies(): void
	{
		$GLOBALS['config']['aliases']['alias'] = [['name' => 'DNS_Exceptions', 'type' => 'network']];

		foreach (['inet', 'inet6'] as $family) {
			$this->assertSame(
				['address' => 'DNS_Exceptions', 'not' => ''],
				pfb_dns_redirect_rule('lan', $family, 'DNS_Exceptions')['source'],
				$family
			);
		}
	}
}
