<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** Group-action validation is shared by GUI, migration, and runtime consumers. */
final class GroupActionWiringTest extends TestCase
{
	public function testValidatorAcceptsOnlyActionsForTheirGroup(): void
	{
		foreach (['Disabled', 'Deny_Inbound', 'Permit_Both', 'Alias_Native'] as $action) {
			$this->assertTrue(pfb_group_action_valid($action, 'ipv4'), "valid IP action rejected: {$action}");
			$this->assertTrue(pfb_group_action_valid($action, 'geoip'), "valid GeoIP action rejected: {$action}");
		}
		$this->assertTrue(pfb_group_action_valid('unbound', 'dnsbl'));
		$this->assertFalse(pfb_group_action_valid('Deny_Inbound', 'dnsbl'));
		$this->assertFalse(pfb_group_action_valid('unbound', 'ipv4'));
		$this->assertFalse(pfb_group_action_valid('Deny_Inbound', 'unknown'));
		$this->assertFalse(pfb_group_action_valid(['Deny_Inbound'], 'ipv4'));
	}

	public function testDnsblIpBoundaryNormalizesInvalidPersistedActions(): void
	{
		$this->assertSame('Deny_Both', pfb_dnsblip_action_value('Deny_Both'));
		$this->assertSame('Disabled', pfb_dnsblip_action_value('unbound'));
		$this->assertSame('Disabled', pfb_dnsblip_action_value(NULL));
	}

	public function testMatchdirHeaderPlanDoesNotClassifyInvalidActionsAsDeny(): void
	{
		$plan = pfb_matchdir_config_headers(
			['_v4' => [
				['action' => 'Deny_Inbound', 'aliasname' => 'Good', 'custom' => '1', 'row' => []],
				['action' => 'not-an-action', 'aliasname' => 'Bad', 'custom' => '1', 'row' => []],
			]],
			['action' => 'Deny_Both'],
			['Europe' => ['action' => 'Deny_Outbound']]
		);
		$this->assertSame(['Good_custom_v4', 'Bad_custom_v4'], $plan['match']);
		$this->assertContains('Good_custom_v4', $plan['deny']);
		$this->assertContains('DNSBLIP_v4', $plan['deny']);
		$this->assertContains('DNSBLIP_v6', $plan['deny']);
		$this->assertContains('Europe_v4', $plan['deny']);
		$this->assertContains('Europe_v6', $plan['deny']);
		$this->assertNotContains('Bad_custom_v4', $plan['deny']);
	}

	public function testMatchdirHeaderPlanRetainsRowsIndependentlyOfAction(): void
	{
		$plan = pfb_matchdir_config_headers(
			['_v6' => [['action' => 'Disabled', 'aliasname' => 'Feed', 'row' => [
				['header' => 'Sample', 'url' => '/var/db/pfblockerng/sample.txt'],
			]]]],
			[],
			[]
		);
		$this->assertSame(['Sample_v6'], $plan['match']);
		$this->assertSame([], $plan['deny']);
		$this->assertSame([['list' => 'Feed', 'header' => 'Sample', 'url' => '/var/db/pfblockerng/sample.txt']], $plan['rows']);
	}

	public function testReachablePagesUseTheSharedValidator(): void
	{
		$root = dirname(__DIR__, 2);
		$paths = [
			"{$root}/src/usr/local/www/pfblockerng/pfblockerng_category.php",
			"{$root}/src/usr/local/www/pfblockerng/pfblockerng_category_edit.php",
			"{$root}/src/usr/local/pkg/pfblockerng/pfblockerng_geoip.inc",
		];
		foreach ($paths as $path) {
			$source = php_strip_whitespace($path);
			$this->assertNotSame('', $source, "page source missing: {$path}");
			$this->assertStringContainsString('pfb_group_action_valid(', $source, "shared validator missing: {$path}");
		}
	}

	/**
	 * Alerts and cron are appliance-only entrypoints (one exits during dispatch). Keep their
	 * wiring pin executable-code-only; comments/docblocks cannot satisfy it.
	 */
	public function testOffApplianceEntrypointsUseTheSharedValidator(): void
	{
		$root = dirname(__DIR__, 2);
		foreach ([
			"{$root}/src/usr/local/www/pfblockerng/pfblockerng_alerts.php",
			"{$root}/src/usr/local/pkg/pfblockerng/pfblockerng_cron.inc",
		] as $path) {
			$source = php_strip_whitespace($path);
			$this->assertNotSame('', $source, "entrypoint source missing: {$path}");
			$this->assertStringContainsString('pfb_group_action_valid(', $source, "shared validator missing: {$path}");
		}
	}
}
