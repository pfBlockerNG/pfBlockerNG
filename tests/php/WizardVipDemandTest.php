<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3539 -- the setup wizard asks for a DNSBL VIP (and ports) only when the default DNSBL setup
 * it is about to write answers a block with the VIP. The candidate is exactly what step 4 writes: the
 * DNSBL settings section (pfb_wizard_dnsbl_section) plus its ADs_Basic group built from the feed
 * catalog (pfb_wizard_group_rows), judged by the same predicate the apply uses.
 *
 * step3_submitphpaction() is loaded verbatim by tests/php/bootstrap.php and driven directly;
 * WizardVipAutoTest keeps the Auto-VIP gate, this file the demand gate.
 */
#[CoversFunction('step3_submitphpaction')]
#[CoversFunction('pfb_wizard_group_rows')]
#[CoversFunction('pfb_wizard_dnsbl_section')]
#[CoversFunction('pfb_wizard_vip_demand')]
final class WizardVipDemandTest extends TestCase
{
	private const NO_VIP_ERROR = 'DNSBL: no VIP configured';

	private string $feedsPath = '';
	private mixed $savedFeeds = NULL;
	private bool $hadFeeds    = FALSE;

	protected function setUp(): void
	{
		$GLOBALS['input_errors'] = [];
		$GLOBALS['stepid']       = 2;
		$_POST                   = [];

		$this->hadFeeds   = array_key_exists('feeds', $GLOBALS['pfb'] ?? []);
		$this->savedFeeds = $GLOBALS['pfb']['feeds'] ?? NULL;
		$this->feedsPath  = sys_get_temp_dir() . '/pfb_wizard_feeds_' . getmypid() . '_' . uniqid() . '.json';
	}

	protected function tearDown(): void
	{
		@unlink($this->feedsPath);
		if ($this->hadFeeds) {
			$GLOBALS['pfb']['feeds'] = $this->savedFeeds;
		} else {
			unset($GLOBALS['pfb']['feeds']);
		}
		$_POST                   = [];
		$GLOBALS['input_errors'] = [];
	}

	/** @param list<array<string, mixed>> $feeds the ADs_Basic catalog feeds */
	private static function catalog(array $feeds): array
	{
		return ['dnsbl' => ['ADs_Basic' => ['description' => 'ADs Basic', 'feeds' => $feeds]]];
	}

	private static function usableFeed(): array
	{
		return ['url' => 'https://example.com/hosts', 'header' => 'Example_ADs'];
	}

	private function installCatalog(array $catalog): void
	{
		file_put_contents($this->feedsPath, json_encode($catalog));
		$GLOBALS['pfb']['feeds'] = $this->feedsPath;
	}

	/** A step-3 POST: manual VIP mode, nothing selected, valid ports unless overridden. */
	private function submit(array $over = []): void
	{
		$GLOBALS['input_errors'] = [];
		$_POST = array_replace([
			'back'            => '',
			'pfb_dnsvip4'     => 'none',
			'pfb_dnsvip6'     => 'none',
			'pfb_dnsport'     => '8081',
			'pfb_dnsport_ssl' => '8443',
		], $over);
		step3_submitphpaction();
	}

	/** @return list<string> */
	private function errors(): array
	{
		return array_values(array_filter($GLOBALS['input_errors'], 'is_string'));
	}

	// -----------------------------------------------------------------------
	// The wizard's own builders
	// -----------------------------------------------------------------------

	public function testGroupRowsKeepOnlyFeedsTheWizardInstalls(): void
	{
		$rows = pfb_wizard_group_rows(['feeds' => [
			['url' => 'https://example.com/a', 'header' => 'A'],
			['url' => 'https://example.com/b', 'header' => 'B', 'register' => 'yes'],
			['url' => 'https://example.com/c', 'header' => 'C', 'status' => 'discontinued'],
			['url' => 'https://example.com/d', 'header' => 'D', 'status' => 'active'],
		]]);

		$this->assertSame([
			['format' => 'auto', 'state' => 'Enabled', 'url' => 'https://example.com/a', 'header' => 'A'],
			['format' => 'auto', 'state' => 'Enabled', 'url' => 'https://example.com/d', 'header' => 'D'],
		], $rows);
	}

	public function testGroupRowsOfAnEmptyCatalogEntryAreEmpty(): void
	{
		$this->assertSame([], pfb_wizard_group_rows([]));
	}

	public function testSectionCarriesTheManualVipPortsAndTheDnsblSwitch(): void
	{
		$this->assertSame([
			'pfb_dnsvip_auto' => '',
			'pfb_dnsvip4'     => '_vip4',
			'pfb_dnsvip6'     => '_vip6',
			'pfb_dnsport'     => '8081',
			'pfb_dnsport_ssl' => '8443',
			'pfb_dnsbl'       => 'on',
		], pfb_wizard_dnsbl_section(FALSE, '_vip4', '_vip6', '8081', '8443'));
	}

	public function testSectionOmitsTheManualVipIdsInAutoMode(): void
	{
		$section = pfb_wizard_dnsbl_section(TRUE, '_vip4', '_vip6', '8081', '8443');

		$this->assertSame('on', $section['pfb_dnsvip_auto']);
		$this->assertArrayNotHasKey('pfb_dnsvip4', $section);
		$this->assertArrayNotHasKey('pfb_dnsvip6', $section);
	}

	// -----------------------------------------------------------------------
	// The candidate's demand
	// -----------------------------------------------------------------------

	public function testDefaultSetupWithAUsableFeedDemandsTheVip(): void
	{
		$section = pfb_wizard_dnsbl_section(FALSE, '', '', '8081', '8443');

		$this->assertTrue(pfb_wizard_vip_demand($section, self::catalog([self::usableFeed()])));
	}

	public function testSetupWithoutAnyInstallableFeedHasNoDemand(): void
	{
		$section = pfb_wizard_dnsbl_section(FALSE, '', '', '8081', '8443');
		$feeds   = [
			['url' => 'https://example.com/r', 'header' => 'R', 'register' => 'yes'],
			['url' => 'https://example.com/x', 'header' => 'X', 'status' => 'discontinued'],
		];

		$this->assertFalse(pfb_wizard_vip_demand($section, self::catalog($feeds)));
		$this->assertFalse(pfb_wizard_vip_demand($section, []), 'a catalog without the ADs_Basic group');
	}

	public function testSectionPolicyDecidesTheDemand(): void
	{
		$catalog = self::catalog([self::usableFeed()]);
		$base    = pfb_wizard_dnsbl_section(FALSE, '', '', '8081', '8443');

		$this->assertTrue(pfb_wizard_vip_demand($base, $catalog), 'before-state: the unset policy resolves Default to the legacy VIP mechanism');
		$this->assertFalse(
			pfb_wizard_vip_demand($base + ['global_log_mode' => 'default', 'global_log' => 'disabled_log'], $catalog),
			'a Default policy on Null Blocking answers with 0.0.0.0'
		);
	}

	/**
	 * The candidate group is built from the wizard's real step-4 group: whatever step 4 writes for
	 * action/logging, the demand must agree with the predicate applied to that group.
	 */
	public function testDemandAgreesWithTheGroupStep4Writes(): void
	{
		$catalog = self::catalog([self::usableFeed()]);
		$source  = (string) file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/wizards/pfblockerng_wizard.inc');
		$after   = (int) strpos($source, '// Selected Alias/Groups to add to default installation');
		$start   = (int) strpos($source, "\t\t\tif (strpos(\$key, 'dnsbl') !== FALSE)", $after);
		$end     = (int) strpos($source, "\n\t\t\t\$new_config[\$key]['config'][] = \$add;", $start);
		$this->assertTrue($after > 0 && $start > $after && $end > $start, 'test bootstrap: step 4 group region found');

		$add                  = ['aliasname' => 'ADs_Basic', 'row' => pfb_wizard_group_rows($catalog['dnsbl']['ADs_Basic'])];
		$key                  = 'pfblockerngdnsbl';
		$pfb_general_schedule = ['pfb_schedule_weekday' => '7', 'pfb_schedule_hour' => '0', 'pfb_schedule_minute' => '0'];
		eval(substr($source, $start, $end - $start));

		$verdicts = [];
		foreach ([
			'no policy keys'            => [],
			'Default on Null Blocking'  => ['global_log_mode' => 'default', 'global_log' => 'disabled_log'],
			'Default on VIP'            => ['global_log_mode' => 'default', 'global_log' => 'enabled'],
			'Override on NODATA'        => ['global_log_mode' => 'override', 'global_log' => 'nodata'],
		] as $name => $policy) {
			$section = pfb_wizard_dnsbl_section(FALSE, '', '', '8081', '8443') + $policy;
			$this->assertSame(
				pfb_dnsbl_vip_demand($section, [$add], []),
				pfb_wizard_vip_demand($section, $catalog),
				"the wizard's demand must equal the predicate on the group step 4 writes ({$name})"
			);
			$verdicts[] = pfb_wizard_vip_demand($section, $catalog);
		}
		$this->assertContains(TRUE, $verdicts, 'vacuity guard: some policy demands the VIP');
		$this->assertContains(FALSE, $verdicts, 'vacuity guard: some policy does not');
	}

	// -----------------------------------------------------------------------
	// step 3
	// -----------------------------------------------------------------------

	public function testStepAsksForAVipWhenTheDefaultSetupDemandsOne(): void
	{
		$this->installCatalog(self::catalog([self::usableFeed()]));

		$this->submit();

		$this->assertSame([self::NO_VIP_ERROR], $this->errors());
	}

	public function testStepAcceptsNoVipWhenNoBlockAnswersWithIt(): void
	{
		$this->installCatalog(self::catalog([['url' => 'https://example.com/r', 'header' => 'R', 'register' => 'yes']]));

		$this->submit();

		$this->assertSame([], $this->errors());
	}

	public function testStepAcceptsNoVipWhenTheCatalogCannotBeRead(): void
	{
		$GLOBALS['pfb']['feeds'] = $this->feedsPath;	// the file does not exist

		$this->submit();

		$this->assertSame([], $this->errors(), 'step 4 reports the missing catalog; step 3 has nothing to judge');
	}

	public function testStepStillClearsTheNoneSentinelWhenNoVipIsRequired(): void
	{
		$this->installCatalog(self::catalog([]));

		$this->submit();

		$this->assertSame('', $_POST['pfb_dnsvip4']);
		$this->assertSame('', $_POST['pfb_dnsvip6']);
	}

	public function testAutoVipNeedsNoVipEvenWithDemand(): void
	{
		$this->installCatalog(self::catalog([self::usableFeed()]));

		$this->submit(['pfb_dnsvip_auto' => 'on']);

		$this->assertSame([], $this->errors());
	}

	public function testPortsAreCheckedWhenTheDefaultSetupDemandsTheWebserver(): void
	{
		$this->installCatalog(self::catalog([self::usableFeed()]));

		$this->submit(['pfb_dnsvip_auto' => 'on', 'pfb_dnsport' => 'abc']);

		$this->assertSame(['DNSBL Ports: A valid port must be defined.'], $this->errors());
	}

	public function testPortsAreNotCheckedWhenNoBlockAnswersWithTheVip(): void
	{
		$this->installCatalog(self::catalog([]));

		$this->submit(['pfb_dnsport' => 'abc']);

		$this->assertSame([], $this->errors());
	}
}
