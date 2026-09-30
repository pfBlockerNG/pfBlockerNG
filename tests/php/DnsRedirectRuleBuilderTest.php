<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * ADR-36: the DNS-redirect NAT rdr row builder, pfb_dns_redirect_rule().
 *
 * Issue #3400: FreeBSD drops a packet that pf redirects to ::1 when it arrived on a
 * non-loopback interface (ip6_input scope check), so the IPv6 rule must not target ::1.
 * On an assigned interface (wan/lan/optN) it targets pfSense's own "<Iface> address"
 * NAT keyword, '<iface>ip'. filter.inc resolves that keyword to the interface's current
 * IPv6 address on every filter reload, so static, track6, SLAAC and DHCPv6 addresses all
 * resolve. The unassigned pseudo-interfaces the redirect list offers (enc0, openvpn,
 * l2tp) have no such keyword. They keep ::1: IPv6 DNS there stays dropped (fails
 * closed) instead of the rule being skipped, which would let IPv6 DNS through
 * unredirected.
 */
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

	#[DataProvider('optInterfaces')]
	public function testIpv6TargetOnOptInterfaceIsItsAddressKeyword(string $iface): void
	{
		$this->assertSame("{$iface}ip", pfb_dns_redirect_rule($iface, 'inet6', '')['target']);
	}

	public static function optInterfaces(): array
	{
		return ['opt1' => ['opt1'], 'opt12' => ['opt12']];
	}

	#[DataProvider('pseudoInterfaces')]
	public function testIpv6TargetOnUnassignedPseudoInterfaceStaysLoopback(string $iface): void
	{
		$this->assertSame('::1', pfb_dns_redirect_rule($iface, 'inet6', '')['target']);
	}

	public static function pseudoInterfaces(): array
	{
		return ['enc0' => ['enc0'], 'openvpn' => ['openvpn'], 'l2tp' => ['l2tp']];
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
