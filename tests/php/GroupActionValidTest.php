<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** Issue #1346 — group actions belong to either IP/GeoIP or DNSBL. */
#[CoversFunction('pfb_group_action_valid')]
#[CoversFunction('pfb_dnsblip_action_value')]
final class GroupActionValidTest extends TestCase
{
	/** @return iterable<string,array{string}> */
	public static function ipActionProvider(): iterable
	{
		foreach ([
			'Disabled',
			'Deny_Inbound', 'Deny_Outbound', 'Deny_Both',
			'Permit_Inbound', 'Permit_Outbound', 'Permit_Both',
			'Match_Inbound', 'Match_Outbound', 'Match_Both',
			'Alias_Deny', 'Alias_Permit', 'Alias_Match', 'Alias_Native',
		] as $action) {
			yield $action => [$action];
		}
	}

	/** @return iterable<string,array{mixed}> */
	public static function hostileIpActionProvider(): iterable
	{
		yield 'DNSBL action' => ['unbound'];
		yield 'uppercase DNSBL action' => ['UNBOUND'];
		yield 'lowercase IP action' => ['deny_both'];
		yield 'case-mutated IP action' => ['Deny_both'];
		yield 'leading whitespace' => [' Deny_Both'];
		yield 'trailing whitespace' => ['Deny_Both '];
		yield 'empty string' => [''];
		yield 'numeric string' => ['0'];
		yield 'integer' => [0];
		yield 'null' => [NULL];
		yield 'false' => [FALSE];
		yield 'true' => [TRUE];
		yield 'array' => [['Deny_Both']];
	}

	/** @return iterable<string,array{mixed,string,bool}> */
	public static function actionProvider(): iterable
	{
		yield 'IPv4 deny' => ['Deny_Both', 'ipv4', TRUE];
		yield 'IPv6 alias' => ['Alias_Native', 'ipv6', TRUE];
		yield 'GeoIP permit' => ['Permit_Inbound', 'geoip', TRUE];
		yield 'DNSBL unbound' => ['unbound', 'dnsbl', TRUE];
		yield 'disabled IP' => ['Disabled', 'ipv4', TRUE];
		yield 'disabled DNSBL' => ['Disabled', 'dnsbl', TRUE];
		yield 'DNSBL action on IP' => ['unbound', 'ipv4', FALSE];
		yield 'IP action on DNSBL' => ['Deny_Both', 'dnsbl', FALSE];
		yield 'unknown group' => ['Disabled', 'bogus', FALSE];
		yield 'array action' => [['Deny_Both'], 'ipv4', FALSE];
		yield 'integer action' => [0, 'ipv4', FALSE];
		yield 'boolean action' => [FALSE, 'dnsbl', FALSE];
		yield 'null action' => [NULL, 'dnsbl', FALSE];
	}

	#[DataProvider('actionProvider')]
	public function testAcceptsOnlyExactActionForGroup($action, string $gtype, bool $expected): void
	{
		$this->assertSame($expected, pfb_group_action_valid($action, $gtype));
	}

	#[DataProvider('ipActionProvider')]
	public function testDnsblIpAcceptsAndPreservesEveryIpAction(string $action): void
	{
		$this->assertTrue(pfb_group_action_valid($action, 'ipv4'));
		$this->assertSame($action, pfb_dnsblip_action_value($action));
	}

	#[DataProvider('hostileIpActionProvider')]
	public function testDnsblIpHostileActionFailsClosedToDisabled($action): void
	{
		$this->assertFalse(pfb_group_action_valid($action, 'ipv4'));
		$this->assertSame('Disabled', pfb_dnsblip_action_value($action));
	}
}
