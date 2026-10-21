<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3539 -- the setup wizard writes a fresh DNSBL setup: the settings section (pfb_wizard_dnsbl_section)
 * carries the fresh-install policy (Default on Null Blocking), and its ADs_Basic group follows it, so no
 * block answers with the deprecated VIP. Step 3 therefore asks for no VIP and no ports; a port that is
 * given must still be valid.
 *
 * step3_submitphpaction() is loaded verbatim by tests/php/bootstrap.php and driven directly;
 * WizardVipAutoTest keeps the Auto-VIP gate.
 */
#[CoversFunction('step3_submitphpaction')]
#[CoversFunction('pfb_wizard_group_rows')]
#[CoversFunction('pfb_wizard_dnsbl_section')]
final class WizardVipDemandTest extends TestCase
{
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

	public function testAdsBasicBuilderKeepsTheGroupTheWizardWritesOnDefault(): void
	{
		$info = self::catalog([self::usableFeed()])['dnsbl']['ADs_Basic'];
		$this->assertSame([
			'aliasname' => 'ADs_Basic', 'description' => 'ADs Basic',
			'row' => pfb_wizard_group_rows($info),
			'action' => 'unbound', 'cron' => 'EveryDay', 'logging' => 'default', 'order' => 'default',
		], pfb_wizard_dnsbl_group($info));
		$this->assertArrayNotHasKey('row', pfb_wizard_dnsbl_group([]), 'an empty catalog entry has no row');
	}

	public function testSectionCarriesTheManualVipPortsTheDnsblSwitchAndTheFreshPolicy(): void
	{
		$this->assertSame([
			'pfb_dnsvip_auto' => '',
			'pfb_dnsvip4'     => '_vip4',
			'pfb_dnsvip6'     => '_vip6',
			'pfb_dnsport'     => '8081',
			'pfb_dnsport_ssl' => '8443',
			'pfb_dnsbl'       => 'on',
			'global_log_mode' => 'default',
			'global_log'      => 'disabled_log',
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
	// step 3
	// -----------------------------------------------------------------------

	public function testStepAsksForNoVipOrPortsForTheDefaultSetup(): void
	{
		$this->installCatalog(self::catalog([self::usableFeed()]));

		$this->submit(['pfb_dnsport' => '', 'pfb_dnsport_ssl' => '']);

		$this->assertSame([], $this->errors(), 'a usable feed on Null Blocking needs neither a VIP nor ports');
	}

	public function testStepStillClearsTheNoneSentinel(): void
	{
		$this->submit();

		$this->assertSame('', $_POST['pfb_dnsvip4']);
		$this->assertSame('', $_POST['pfb_dnsvip6']);
	}

	public function testAGivenPortMustStillBeValid(): void
	{
		$this->submit(['pfb_dnsport_ssl' => 'abc']);

		$this->assertSame(['DNSBL Ports: A valid port must be defined.'], $this->errors());
	}

	// -----------------------------------------------------------------------
	// The setup step 4 writes
	// -----------------------------------------------------------------------

	public function testTheSetupStep4WritesHasNoVipDemand(): void
	{
		$catalog = self::catalog([self::usableFeed()]);
		$section = pfb_wizard_dnsbl_section(FALSE, '', '', '8081', '8443');
		$group   = pfb_wizard_dnsbl_group($catalog['dnsbl']['ADs_Basic']);

		$this->assertFalse(pfb_dnsbl_vip_demand($section, [$group], []), "the wizard's group follows the fresh Null Blocking policy");
		$this->assertTrue(
			pfb_dnsbl_vip_demand(array_replace($section, ['global_log' => 'enabled']), [$group], []),
			'vacuity guard: the same group on the VIP mechanism demands the VIP'
		);
	}
}
