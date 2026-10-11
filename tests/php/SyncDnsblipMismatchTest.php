<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfblockerng_sync_dnsblip_mismatch')]
final class SyncDnsblipMismatchTest extends TestCase
{
	#[DataProvider('mismatchCases')]
	public function testDetectsOnlyActiveDnsblIpRuleSyncMismatches(
		string $row,
		bool $expected,
		string $scope,
		mixed $synconchanges,
		PfbToggle $enable,
		PfbToggle $dnsbl,
		mixed $dnsblIpAction,
		mixed $hasyncRules
	): void {
		$this->assertSame(
			$expected,
			pfblockerng_sync_dnsblip_mismatch(
				$scope,
				$synconchanges,
				$enable,
				$dnsbl,
				$dnsblIpAction,
				$hasyncRules
			),
			"{$row}: mismatch result"
		);
	}

	/** @return iterable<string, array{string, bool, string, mixed, PfbToggle, PfbToggle, mixed, mixed}> */
	public static function mismatchCases(): iterable
	{
		yield 'R1 all active with automatic sync' => [
			'R1 all active with automatic sync', TRUE, 'lists', 'auto', PfbToggle::On, PfbToggle::On, 'Deny_Both', 'on',
		];
		yield 'R2 all active with manual sync' => [
			'R2 all active with manual sync', TRUE, 'lists', 'manual', PfbToggle::On, PfbToggle::On, 'Deny_Both', 'on',
		];
		yield 'R3 Alias Native does not generate firewall rules' => [
			'R3 Alias Native does not generate firewall rules', FALSE, 'lists', 'auto', PfbToggle::On, PfbToggle::On, 'Alias_Native', 'on',
		];
		yield 'Deny Inbound generates firewall rules' => [
			'Deny Inbound generates firewall rules', TRUE, 'lists', 'auto', PfbToggle::On, PfbToggle::On, 'Deny_Inbound', 'on',
		];
		yield 'Deny Outbound generates firewall rules' => [
			'Deny Outbound generates firewall rules', TRUE, 'lists', 'auto', PfbToggle::On, PfbToggle::On, 'Deny_Outbound', 'on',
		];
		yield 'Alias Deny does not generate firewall rules' => [
			'Alias Deny does not generate firewall rules', FALSE, 'lists', 'auto', PfbToggle::On, PfbToggle::On, 'Alias_Deny', 'on',
		];
		foreach (['Permit_Inbound', 'Permit_Outbound', 'Permit_Both', 'Match_Inbound', 'Match_Outbound', 'Match_Both'] as $action) {
			yield "{$action} generates firewall rules" => [
				"{$action} generates firewall rules", TRUE, 'lists', 'auto', PfbToggle::On, PfbToggle::On, $action, 'on',
			];
		}
		foreach (['Alias_Permit', 'Alias_Match'] as $action) {
			yield "{$action} does not generate firewall rules" => [
				"{$action} does not generate firewall rules", FALSE, 'lists', 'auto', PfbToggle::On, PfbToggle::On, $action, 'on',
			];
		}
		yield 'R4 all settings still sync (legacy all scope)' => [
			'R4 all settings still sync (legacy all scope)', FALSE, 'all', 'auto', PfbToggle::On, PfbToggle::On, 'Deny_Both', 'on',
		];
		yield 'R4a policy scope carries DNSBL policy to the peer' => [
			'R4a policy scope carries DNSBL policy to the peer', FALSE, 'policy', 'auto', PfbToggle::On, PfbToggle::On, 'Deny_Both', 'on',
		];
		yield 'R4b policy scope with manual sync' => [
			'R4b policy scope with manual sync', FALSE, 'policy', 'manual', PfbToggle::On, PfbToggle::On, 'Deny_Both', 'on',
		];
		yield 'R4c empty scope is not lists' => [
			'R4c empty scope is not lists', FALSE, '', 'auto', PfbToggle::On, PfbToggle::On, 'Deny_Both', 'on',
		];
		yield 'R4d unknown scope is not lists' => [
			'R4d unknown scope is not lists', FALSE, 'bogus', 'auto', PfbToggle::On, PfbToggle::On, 'Deny_Both', 'on',
		];
		yield 'R4e scope token is case sensitive' => [
			'R4e scope token is case sensitive', FALSE, 'Lists', 'auto', PfbToggle::On, PfbToggle::On, 'Deny_Both', 'on',
		];
		yield 'R5 change sync is disabled' => [
			'R5 change sync is disabled', FALSE, 'lists', 'disabled', PfbToggle::On, PfbToggle::On, 'Deny_Both', 'on',
		];
		yield 'R6 change sync is empty' => [
			'R6 change sync is empty', FALSE, 'lists', '', PfbToggle::On, PfbToggle::On, 'Deny_Both', 'on',
		];
		yield 'R7 pfBlockerNG is disabled' => [
			'R7 pfBlockerNG is disabled', FALSE, 'lists', 'auto', PfbToggle::Off, PfbToggle::On, 'Deny_Both', 'on',
		];
		yield 'R8 DNSBL is disabled' => [
			'R8 DNSBL is disabled', FALSE, 'lists', 'auto', PfbToggle::On, PfbToggle::Off, 'Deny_Both', 'on',
		];
		yield 'R9 DNSBL IP action is disabled' => [
			'R9 DNSBL IP action is disabled', FALSE, 'lists', 'auto', PfbToggle::On, PfbToggle::On, 'Disabled', 'on',
		];
		yield 'R10 invalid DNSBL IP action normalises to disabled' => [
			'R10 invalid DNSBL IP action normalises to disabled', FALSE, 'lists', 'auto', PfbToggle::On, PfbToggle::On, 'Deny_Everything', 'on',
		];
		yield 'R11 foreign DNSBL group action normalises to disabled' => [
			'R11 foreign DNSBL group action normalises to disabled', FALSE, 'lists', 'auto', PfbToggle::On, PfbToggle::On, 'unbound', 'on',
		];
		yield 'R12 absent DNSBL IP action normalises to disabled' => [
			'R12 absent DNSBL IP action normalises to disabled', FALSE, 'lists', 'auto', PfbToggle::On, PfbToggle::On, NULL, 'on',
		];
		yield 'R13 absent HA rule sync' => [
			'R13 absent HA rule sync', FALSE, 'lists', 'auto', PfbToggle::On, PfbToggle::On, 'Deny_Both', NULL,
		];
		yield 'hostile change sync array' => [
			'hostile change sync array', FALSE, 'lists', ['auto'], PfbToggle::On, PfbToggle::On, 'Deny_Both', 'on',
		];
		yield 'hostile change sync case' => [
			'hostile change sync case', FALSE, 'lists', 'AUTO', PfbToggle::On, PfbToggle::On, 'Deny_Both', 'on',
		];
		yield 'hostile HA rule sync case' => [
			'hostile HA rule sync case', FALSE, 'lists', 'auto', PfbToggle::On, PfbToggle::On, 'Deny_Both', 'ON',
		];
		yield 'hostile HA rule sync boolean' => [
			'hostile HA rule sync boolean', FALSE, 'lists', 'auto', PfbToggle::On, PfbToggle::On, 'Deny_Both', TRUE,
		];
		yield 'hostile DNSBL IP action array' => [
			'hostile DNSBL IP action array', FALSE, 'lists', 'auto', PfbToggle::On, PfbToggle::On, ['Deny_Both'], 'on',
		];
	}
}
