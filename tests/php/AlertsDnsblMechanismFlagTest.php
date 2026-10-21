<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3539 -- the Alerts page maps a group's effective mechanism to the DNSBL logging flag through
 * the ONE shared pfb_dnsbl_mechanism_flag(), not its own if/elseif copy. The swap is
 * behaviour-identical for every concrete mechanism (the resolver only ever hands the page one of the
 * seven): the flag table below is the page's pre-#3539 chain, so it pins that nothing moved.
 *
 * The page cannot be required off-appliance; its OWN mapping region is extracted from the shipped
 * source and evaluated (PageStatementLoader.php).
 */
#[CoversNothing]
final class AlertsDnsblMechanismFlagTest extends TestCase
{
	private const PAGE = 'src/usr/local/www/pfblockerng/pfblockerng_alerts.php';

	public static function setUpBeforeClass(): void
	{
		require_once __DIR__ . '/PageStatementLoader.php';
	}

	/** @return array<string, array{0: string, 1: string}> mechanism => the flag the page produced before the swap */
	public static function concreteMechanismFlags(): array
	{
		return [
			'enabled'      => ['enabled', '1'],
			'disabled_log' => ['disabled_log', '0'],
			'disabled'     => ['disabled', '2'],
			'nxdomain_log' => ['nxdomain_log', '3'],
			'nxdomain'     => ['nxdomain', '4'],
			'nodata_log'   => ['nodata_log', '5'],
			'nodata'       => ['nodata', '6'],
		];
	}

	private static function mappingRegion(): string
	{
		return pfb_test_page_region(self::PAGE, '$d_log = pfb_dnsbl_effective_logging(', "\$clists[\$type][\$lname]['log'] = \$d_type;");
	}

	#[DataProvider('concreteMechanismFlags')]
	public function testEveryConcreteMechanismMapsToItsUnchangedFlag(string $mechanism, string $flag): void
	{
		// Override mode makes the effective mechanism the global one, whatever the group stores.
		$scope = pfb_test_page_eval(self::mappingRegion(), [
			'row' => 0,
			'pfb' => ['dnsbl_global_log' => $mechanism, 'dnsbl_global_mode' => PfbDnsblGlobalMode::Override, 'dnsbl_policy_legacy' => FALSE],
		]);
		$this->assertSame($mechanism, $scope['d_log'], 'fixture: the page resolved the mechanism under test');
		$this->assertSame($flag, $scope['d_type']);
	}

	public function testPageUsesTheSharedFlagFunctionNotAnOwnChain(): void
	{
		$region = self::mappingRegion();
		$this->assertStringContainsString('pfb_dnsbl_mechanism_flag($d_log)', $region);
		$this->assertStringNotContainsString("\$d_log == '", $region, 'no residual per-token comparison chain');
	}
}
