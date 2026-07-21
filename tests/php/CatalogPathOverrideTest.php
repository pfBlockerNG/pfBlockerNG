<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Compatibility seams must honor the configured catalog path so tests and
 * package callers can supply an alternate immutable catalog or fail closed.
 */
final class CatalogPathOverrideTest extends TestCase
{
	private array $savedPfb;
	private mixed $savedConfig;
	private string $tempCatalog;

	public static function setUpBeforeClass(): void
	{
		if (!function_exists('array_get_path')) {
			function array_get_path(array $array, string $path, $default = NULL) {
				foreach (explode('/', trim($path, '/')) as $key) {
					if (!is_array($array) || !array_key_exists($key, $array)) {
						return $default;
					}
					$array = $array[$key];
				}
				return $array;
			}
		}
		self::loadEasyListConversion();
		self::loadWizardDefaults();
	}

	protected function setUp(): void
	{
		$this->savedPfb = $GLOBALS['pfb'];
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$this->tempCatalog = (string) tempnam(sys_get_temp_dir(), 'pfb-catalog-');
		$GLOBALS['pfb']['feeds'] = dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_feeds.json';
		$GLOBALS['config'] = ['installedpackages' => ['pfblockerngglobal' => []]];
	}

	protected function tearDown(): void
	{
		@unlink($this->tempCatalog);
		$GLOBALS['pfb'] = $this->savedPfb;
		if ($this->savedConfig === NULL) {
			unset($GLOBALS['config']);
		} else {
			$GLOBALS['config'] = $this->savedConfig;
		}
	}

	public function testConvertUsesConfiguredCatalogPath(): void
	{
		$this->writeCatalogOverride('Abuse_Feodo_C2', 'https://override.example.test/convert.txt');
		$GLOBALS['pfb']['feeds'] = $this->tempCatalog;

		$feeds = convert_feeds_json();
		$this->assertSame(
			'https://override.example.test/convert.txt',
			$this->rowByHeader($feeds['ipv4']['PRI1']['feeds'], 'Abuse_Feodo_C2')['url']
		);
	}

	public function testConvertMissingConfiguredCatalogFailsClosed(): void
	{
		$GLOBALS['pfb']['feeds'] = $this->tempCatalog . '.missing';

		$this->assertSame(['blank' => ''], convert_feeds_json());
	}

	public function testInstallerUsesConfiguredCatalogPath(): void
	{
		$this->writeCatalogOverride('EasyList', 'https://override.example.test/easylist.txt');
		$GLOBALS['pfb']['feeds'] = $this->tempCatalog;
		$GLOBALS['config']['installedpackages']['pfblockerngdnsbleasylist'] = [
			'config' => [0 => [
				'aliasname' => 'LegacyEasy',
				'description' => 'Legacy EasyList',
				'row' => [['state' => 'Enabled', 'header' => 'EasyList']],
				'action' => 'unbound', 'cron' => 'EveryDay', 'dow' => '1',
				'logging' => 'enabled', 'order' => 'default',
			]],
		];

		$converted = pfb_path_override_easylist_conversion();
		$this->assertSame('https://override.example.test/easylist.txt', $converted[0]['row'][0]['url']);
	}

	public function testInstallerMissingConfiguredCatalogDoesNotConvert(): void
	{
		$GLOBALS['pfb']['feeds'] = $this->tempCatalog . '.missing';
		$GLOBALS['config']['installedpackages']['pfblockerngdnsbleasylist'] = [
			'config' => [0 => [
				'aliasname' => 'LegacyEasy',
				'description' => '',
				'row' => [['state' => 'Enabled', 'header' => 'EasyList']],
				'action' => 'unbound', 'cron' => 'EveryDay', 'dow' => '1',
				'logging' => 'enabled', 'order' => 'default',
			]],
		];

		$this->assertSame([], pfb_path_override_easylist_conversion());
	}

	public function testWizardUsesConfiguredCatalogPath(): void
	{
		$this->writeCatalogOverride('Abuse_Feodo_C2', 'https://override.example.test/wizard.txt');
		$GLOBALS['pfb']['feeds'] = $this->tempCatalog;

		set_error_handler(static fn (): bool => TRUE, E_WARNING | E_NOTICE);
		try {
			$selected = pfb_path_override_wizard_defaults();
		} finally {
			restore_error_handler();
		}
		$this->assertSame(
			'https://override.example.test/wizard.txt',
			$this->rowByHeader($selected['ipv4']['feeds'], 'Abuse_Feodo_C2')['url']
		);
	}

	/** @return array<string, mixed> */
	private function rowByHeader(array $rows, string $header): array
	{
		foreach ($rows as $row) {
			if (($row['header'] ?? NULL) === $header) {
				return $row;
			}
		}
		$this->fail("missing catalog header {$header}");
	}

	private function writeCatalogOverride(string $header, string $url): void
	{
		$path = dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_feeds.json';
		$catalog = json_decode((string) file_get_contents($path), TRUE, 64, JSON_THROW_ON_ERROR);
		foreach ($catalog['feeds'] as &$feed) {
			foreach ($feed['legacy_locators'] as $locator) {
				if (($locator['legacy_header'] ?? NULL) === $header) {
					$feed['latest_url'] = $url;
					file_put_contents($this->tempCatalog, json_encode($catalog, JSON_THROW_ON_ERROR));
					return;
				}
			}
		}
		$this->fail("missing catalog header {$header}");
	}

	private static function loadEasyListConversion(): void
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_install.inc');
		if ($source === FALSE || !preg_match('/\/\/ Collect all enabled EasyLists\n(.*?)\n}\n\nif \(\$ufound\)/s', $source, $match)) {
			throw new RuntimeException('EasyList conversion block not found');
		}
		eval('function pfb_path_override_easylist_conversion(): array { global $pfb; $ufound = FALSE; if (!empty(PfbConfig::readSection(\'installedpackages/pfblockerngdnsbleasylist\'))) { ' . $match[1] . ' } return PfbConfig::readSection(\'installedpackages/pfblockerngdnsbl/config\'); }');
	}

	private static function loadWizardDefaults(): void
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/wizards/pfblockerng_wizard.inc');
		if ($source === FALSE || !preg_match('/\/\/ Selected Alias\/Groups to add to default installation\n(.*?)\n\n\t\/\/ foreign structure: bulk wizard init/s', $source, $match)) {
			throw new RuntimeException('wizard default-selection block not found');
		}
		eval('function pfb_path_override_wizard_defaults(): array { global $pfb; $feed_info_raw = PfbRegistry::legacyCatalog(PfbRegistry::catalog($pfb[\'feeds\'])); $new_config = []; ' . $match[1] . ' return [\'ipv4\' => [\'feeds\' => $new_config[\'pfblockernglistsv4\'][\'config\'][0][\'row\']], \'dnsbl\' => [\'feeds\' => $new_config[\'pfblockerngdnsbl\'][\'config\'][0][\'row\']]]; }');
	}
}
