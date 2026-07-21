<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Frozen compatibility observations for the shipped nested feed catalog.
 *
 * These tests deliberately use the real catalog and real consumer function. The
 * installer and wizard are procedural, so their small conversion/selection
 * blocks are eval-loaded verbatim from the shipped source to observe the data
 * they save without running their appliance-only side effects.
 */
#[CoversFunction('convert_feeds_json')]
final class CatalogCompatibilityOracleTest extends TestCase
{
	private array $savedPfb;
	private mixed $savedConfig;

	public static function setUpBeforeClass(): void
	{
		if (!function_exists('array_get_path')) {
			function array_get_path(array $array, string $path, $default = null) {
				foreach (explode('/', trim($path, '/')) as $key) {
					if (!is_array($array) || !array_key_exists($key, $array)) {
						return $default;
					}
					$array = $array[$key];
				}
				return $array;
			}
		}
		self::loadFeedAltSelection();
		self::loadEasyListConversion();
		self::loadWizardDefaults();
	}

	protected function setUp(): void
	{
		$this->savedPfb = $GLOBALS['pfb'];
		$this->savedConfig = $GLOBALS['config'] ?? null;
		$GLOBALS['pfb']['feeds'] = dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_feeds.json';
		$GLOBALS['config'] = ['installedpackages' => ['pfblockerngglobal' => []]];
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb'] = $this->savedPfb;
		if ($this->savedConfig === null) {
			unset($GLOBALS['config']);
		} else {
			$GLOBALS['config'] = $this->savedConfig;
		}
	}

	/** @param array<string, mixed> $patches */
	private function convert(array $patches = [], bool $assertNoWarnings = TRUE): array
	{
		$GLOBALS['config']['installedpackages']['pfblockerngglobal'] = $patches;
		$warnings = [];
		set_error_handler(static function (int $errno, string $message) use (&$warnings): bool {
			$warnings[] = $message;
			return TRUE;
		}, E_WARNING | E_NOTICE);
		try {
			$result = convert_feeds_json();
		} finally {
			restore_error_handler();
		}
		if ($assertNoWarnings) {
			$this->assertSame([], $warnings, 'catalog conversion must not emit PHP warnings');
		}
		return $result;
	}

	public function testCurrentCatalogProjectsOrdinaryBothAlternatesHistoryAndStatuses(): void
	{
		$feeds = $this->convert();

		$this->assertSame(['ipv4', 'ipv6', 'dnsbl', 'count'], array_keys($feeds));
		$this->assertSame(['ipv4' => 83, 'ipv6' => 32, 'dnsbl' => 126], $feeds['count']);
		$this->assertSame('Abuse_Feodo_C2', $feeds['ipv4']['PRI1']['feeds'][0]['header']);
		$this->assertSame(
			['Abuse_Feodo_C2_med', 'Abuse_Feodo_C2_Agr'],
			array_column($feeds['ipv4']['PRI1']['feeds'][0]['alternate'], 'header')
		);
		$this->assertSame(
			[
				'https://isc.sans.edu/api/sources/attacks/1000/1?text',
				'https://isc.sans.edu/api/sources/attacks/1000/7?text',
				'https://isc.sans.edu/api/sources/attacks/1000/14?text',
				'https://isc.sans.edu/api/sources/attacks/1000/30?text',
				'https://isc.sans.edu/api/sources/attacks/1000/60?text',
				'https://isc.sans.edu/api/sources/attacks/1000/90?text',
				'https://isc.sans.edu/api/sources/attacks/1000/120?text',
			],
			$this->rowByHeader($feeds['ipv4']['PRI1']['feeds'], 'ISC_Block')['past_urls']
		);
		$this->assertSame(
			'https://public-dns.info/nameservers.txt',
			$this->rowByHeader($feeds['ipv4']['DNS_4']['feeds'], 'Public_DNS4')['url']
		);
		$this->assertSame(
			'https://public-dns.info/nameservers.txt',
			$this->rowByHeader($feeds['ipv6']['DNS_6']['feeds'], 'Public_DNS6')['url']
		);
		$this->assertNull($this->findRow($feeds['ipv4']['PRI2']['feeds'], 'Alienvault'));
		$this->assertSame('Suspended', $this->rowByHeader($feeds['dnsbl']['Phishing']['feeds'], 'ISC_SDH')['status']);
		$this->assertSame('https://someonewhocares.org/hosts/hosts', $this->rowByHeader(
			$feeds['dnsbl']['Malicious']['feeds'], 'SWC'
		)['url']);
		$this->assertSame('https://someonewhocares.org/hosts/zero/hosts', $this->rowByHeader(
			$feeds['dnsbl']['Firebog_Suspicious']['feeds'], 'SWC'
		)['url']);
	}

	public function testRootFeedAliasesRenameAndMergeWithoutChangingRows(): void
	{
		$feeds = $this->convert(['feed_pri1' => 'MergedIP', 'feed_mail' => 'MergedIP'], FALSE);

		$this->assertSame('MergedIP', $GLOBALS['pfb']['feeds_list']['ipv4']['PRI1']);
		$this->assertSame('MergedIP', $GLOBALS['pfb']['feeds_list']['ipv4']['MAIL']);
		$this->assertArrayNotHasKey('PRI1', $feeds['ipv4']);
		$this->assertArrayNotHasKey('MAIL', $feeds['ipv4']);
		$this->assertSame(
			'MergedIP - Collection of Feeds from the most reputable blocklist providers. (Primary tier)',
			$feeds['ipv4']['MergedIP']['description']
		);
		$this->assertSame(11, count($feeds['ipv4']['MergedIP']['feeds']));
		$this->assertSame('Abuse_Feodo_C2', $feeds['ipv4']['MergedIP']['feeds'][0]['header']);
		$this->assertSame('Toastedspam', $feeds['ipv4']['MergedIP']['feeds'][10]['header']);
	}

	public function testFeedAltRootPatchSelectionUsesStoredValues(): void
	{
		$this->assertSame(
			['EasyList_Arabic', 'Public_DNS4'],
			pfb_catalog_oracle_feed_alt_selection([
				'feed_alt_easylist' => 'EasyList_Arabic',
				'feed_alt_public_dns4' => 'Public_DNS4',
			])
		);
	}

	public function testEasyListInstallerConversionSavesOnlyEnabledHeaders(): void
	{
		$GLOBALS['config']['installedpackages']['pfblockerngdnsbleasylist'] = [
			'config' => [0 => [
				'aliasname' => 'LegacyEasy',
				'description' => 'Legacy EasyList',
				'row' => [
					['state' => 'Enabled', 'header' => 'EasyList'],
					['state' => 'Enabled', 'header' => 'EasyPrivacy'],
					['state' => 'Disabled', 'header' => 'EasyList_Adware'],
				],
				'action' => 'unbound', 'cron' => 'EveryDay', 'dow' => '1',
				'logging' => 'enabled', 'order' => 'default',
			]],
		];

		$converted = pfb_catalog_oracle_easylist_conversion();
		$this->assertArrayNotHasKey('pfblockerngdnsbleasylist', $GLOBALS['config']['installedpackages']);
		$this->assertSame([
			'aliasname' => 'LegacyEasy',
			'description' => 'Legacy EasyList',
			'row' => [
				['format' => 'auto', 'state' => 'Enabled', 'url' => 'https://easylist-downloads.adblockplus.org/easylist_noelemhide.txt', 'header' => 'EasyList'],
				['format' => 'auto', 'state' => 'Enabled', 'url' => 'https://easylist.to/easylist/easyprivacy.txt', 'header' => 'EasyPrivacy'],
			],
			'action' => 'unbound', 'cron' => 'EveryDay', 'dow' => '1',
			'logging' => 'enabled', 'order' => 'default',
		], $converted[0]);
	}

	public function testWizardDefaultsSelectLiteralPri1AndAdsBasicRows(): void
	{
		set_error_handler(static fn (): bool => TRUE, E_WARNING | E_NOTICE);
		try {
			$selected = pfb_catalog_oracle_wizard_defaults();
		} finally {
			restore_error_handler();
		}
		$this->assertSame('PRI1', $selected['ipv4']['alias']);
		$this->assertSame('ADs_Basic', $selected['dnsbl']['alias']);
		$this->assertSame(
			['format' => 'auto', 'state' => 'Enabled', 'url' => 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt', 'header' => 'Abuse_Feodo_C2'],
			$this->rowByHeader($selected['ipv4']['feeds'], 'Abuse_Feodo_C2')
		);
		$this->assertSame(
			['format' => 'auto', 'state' => 'Enabled', 'url' => 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', 'header' => 'StevenBlack_ADs'],
			$this->rowByHeader($selected['dnsbl']['feeds'], 'StevenBlack_ADs')
		);
		$this->assertNull($this->findRow($selected['ipv4']['feeds'], 'Pulsedive'));
		$this->assertNull($this->findRow($selected['ipv4']['feeds'], 'Abuse_IPBL'));
	}

	/** @return array<string, mixed> */
	private function catalog(): array
	{
		$catalog = json_decode((string) file_get_contents($GLOBALS['pfb']['feeds']), TRUE);
		$this->assertIsArray($catalog);
		return $catalog;
	}

	/** @param array<int, array<string, mixed>> $rows */
	private function rowByHeader(array $rows, string $header): array
	{
		$row = $this->findRow($rows, $header);
		$this->assertNotNull($row, "missing catalog header {$header}");
		return $row;
	}

	/** @param array<int, array<string, mixed>> $rows */
	private function findRow(array $rows, string $header): ?array
	{
		foreach ($rows as $row) {
			if (($row['header'] ?? null) === $header) {
				return $row;
			}
		}
		return null;
	}

	private static function loadFeedAltSelection(): void
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_feeds.php');
		if ($source === FALSE || !preg_match('/\/\/ Collect all \'selected\' Alternative URL selections\.\n(.*?)\n\n\/\/ \$input_errors/s', $source, $match)) {
			throw new RuntimeException('feeds page selection block not found');
		}
		eval('function pfb_catalog_oracle_feed_alt_selection(array $fconfig): array { ' . $match[1] . ' return $feed_alt_selected; }');
	}

	private static function loadEasyListConversion(): void
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_install.inc');
		if ($source === FALSE || !preg_match('/\/\/ Collect all enabled EasyLists\n(.*?)\n}\n\nif \(\$ufound\)/s', $source, $match)) {
			throw new RuntimeException('EasyList conversion block not found');
		}
		eval('function pfb_catalog_oracle_easylist_conversion(): array { global $pfb; $ufound = FALSE; if (!empty(PfbConfig::readSection(\'installedpackages/pfblockerngdnsbleasylist\'))) { ' . $match[1] . ' } return PfbConfig::readSection(\'installedpackages/pfblockerngdnsbl/config\'); }');
	}

	private static function loadWizardDefaults(): void
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/wizards/pfblockerng_wizard.inc');
		if ($source === FALSE || !preg_match('/\/\/ Selected Alias\/Groups to add to default installation\n(.*?)\n\n\t\/\/ foreign structure: bulk wizard init/s', $source, $match)) {
			throw new RuntimeException('wizard default-selection block not found');
		}
		eval('function pfb_catalog_oracle_wizard_defaults(): array { global $pfb; $feed_info_raw = json_decode(@file_get_contents("{$pfb[\'feeds\']}"), TRUE); $new_config = []; ' . $match[1] . ' return [\'ipv4\' => [\'alias\' => $new_config[\'pfblockernglistsv4\'][\'config\'][0][\'aliasname\'], \'feeds\' => $new_config[\'pfblockernglistsv4\'][\'config\'][0][\'row\']], \'dnsbl\' => [\'alias\' => $new_config[\'pfblockerngdnsbl\'][\'config\'][0][\'aliasname\'], \'feeds\' => $new_config[\'pfblockerngdnsbl\'][\'config\'][0][\'row\']]]; }');
	}
}
