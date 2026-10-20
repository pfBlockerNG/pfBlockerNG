<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- pfB-DNS is a top-level pfBlockerNG tab of its own, placed directly after the DNSBL tab in every copy of
 * the tab bar (each page builds its own `$tab_array`; nothing shares one), reachable through the package privilege, and
 * the DNSBL page no longer carries the toggle.
 *
 * The tab bars are found by scanning the sources for the DNSBL tab entry, so a page that joins the package later and
 * copies the bar without the pfB-DNS entry fails here instead of silently missing the tab.
 */
final class PfbDnsPageWiringTest extends TestCase
{
	// The active flag is a literal on most pages and `$active['dnsbl']` on the two category pages.
	private const DNSBL_TAB = "/\\\$tab_array\\[\\]\\s*=\\s*array\\(gettext\\('DNSBL'\\),\\s*([^,]+),\\s*'\\/pfblockerng\\/pfblockerng_dnsbl\\.php'\\);/";
	private const DNS_TAB = "/^\\s*\\\$tab_array\\[\\]\\s*=\\s*array\\(gettext\\('pfB-DNS'\\),\\s*([A-Z]+),\\s*'\\/pfblockerng\\/pfblockerng_dns\\.php'\\);\\s*\$/";

	/** Every file that carries the main tab bar, with how many copies it holds: the 15 pages, the new one, geoip.inc twice. */
	private const TAB_BAR_COPIES = [
		'pkg/pfblockerng/pfblockerng_geoip.inc' => 2,
		'www/pfblockerng/pfblockerng_alerts.php' => 1,
		'www/pfblockerng/pfblockerng_blacklist.php' => 1,
		'www/pfblockerng/pfblockerng_category.php' => 1,
		'www/pfblockerng/pfblockerng_category_edit.php' => 1,
		'www/pfblockerng/pfblockerng_dns.php' => 1,
		'www/pfblockerng/pfblockerng_dnsbl.php' => 1,
		'www/pfblockerng/pfblockerng_edit_hooks.php' => 1,
		'www/pfblockerng/pfblockerng_feeds.php' => 1,
		'www/pfblockerng/pfblockerng_general.php' => 1,
		'www/pfblockerng/pfblockerng_hooks.php' => 1,
		'www/pfblockerng/pfblockerng_ip.php' => 1,
		'www/pfblockerng/pfblockerng_log.php' => 1,
		'www/pfblockerng/pfblockerng_safesearch.php' => 1,
		'www/pfblockerng/pfblockerng_software.php' => 1,
		'www/pfblockerng/pfblockerng_sync.php' => 1,
		'www/pfblockerng/pfblockerng_update.php' => 1,
	];

	/** The DoH/DoQ settings in the order the page shows them (issue #3513). */
	private const LISTENER_FIELDS = [
		'pfb_dns_doh', 'pfb_dns_doh_port', 'pfb_dns_doh_interface', 'pfb_dns_doh_trusted',
		'pfb_dns_doq', 'pfb_dns_doq_port', 'pfb_dns_doq_interface',
	];

	private static function src(string $relative): string
	{
		$text = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/' . $relative);
		self::assertIsString($text, "cannot read {$relative}");
		return $text;
	}

	/** @return array<string,list<array{line:int,active:string,next:string}>> file => each DNSBL tab entry and the line after it */
	private static function dnsblTabEntries(): array
	{
		$found = [];
		foreach (array_merge(
			glob(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/*.php') ?: [],
			glob(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/*.inc') ?: []
		) as $path) {
			$lines = preg_split('/\R/', (string) file_get_contents($path)) ?: [];
			foreach ($lines as $index => $line) {
				if (preg_match(self::DNSBL_TAB, $line, $match) === 1) {
					$relative = str_replace(dirname(__DIR__, 2) . '/src/usr/local/', '', $path);
					$found[$relative][] = ['line' => $index + 1, 'active' => $match[1], 'next' => $lines[$index + 1] ?? ''];
				}
			}
		}
		ksort($found);
		return $found;
	}

	public function testEveryCopyOfTheTabBarListsPfbDnsRightAfterDnsbl(): void
	{
		$entries = self::dnsblTabEntries();

		$this->assertSame(
			self::TAB_BAR_COPIES,
			array_map('count', $entries),
			'the files (and copies per file) that carry the DNSBL tab: a new copy must carry the pfB-DNS tab too'
		);
		foreach ($entries as $file => $copies) {
			foreach ($copies as $copy) {
				$this->assertMatchesRegularExpression(
					self::DNS_TAB,
					$copy['next'],
					"{$file}:{$copy['line']}: the pfB-DNS tab follows the DNSBL tab directly"
				);
			}
		}
	}

	public function testOnlyThePfbDnsPageMarksItsOwnTabActive(): void
	{
		foreach (self::dnsblTabEntries() as $file => $copies) {
			foreach ($copies as $copy) {
				preg_match(self::DNS_TAB, $copy['next'], $next);
				$own = ($file === 'www/pfblockerng/pfblockerng_dns.php');
				$this->assertSame($own ? 'TRUE' : 'FALSE', $next[1] ?? NULL, "{$file}: the pfB-DNS tab is active only on its own page");
			}
		}
	}

	public function testThePrivilegeReachesThePage(): void
	{
		$GLOBALS['priv_list'] = [];
		require dirname(__DIR__, 2) . '/src/etc/inc/priv/pfblockerng.priv.inc';

		$this->assertContains(
			'pfblockerng/pfblockerng_dns.php*',
			$GLOBALS['priv_list']['page-firewall-pfblockerng']['match'] ?? [],
			'the package privilege matches the pfB-DNS page, or no scoped operator reaches it'
		);
		unset($GLOBALS['priv_list']);
	}

	public function testThePageCarriesTheEnableToggleAndAnExperimentalWarning(): void
	{
		$page = self::src('www/pfblockerng/pfblockerng_dns.php');

		$this->assertStringContainsString("'pfb_dns',", $page, 'the enable checkbox');
		$this->assertStringContainsString("PfbConfig::read('dns/pfb_dns')", $page, 'read through the gateway');
		$this->assertMatchesRegularExpression('/<strong>Experimental\./', $page, 'the help says so plainly, in bold');
	}

	public function testTheHelpNamesTheCustomOptionsLinesThatStopTheMove(): void
	{
		$page = self::src('www/pfblockerng/pfblockerng_dns.php');

		$this->assertStringContainsString('<code>include:</code>', $page, 'an include is named: the move refuses it');
		$this->assertStringContainsString('nothing is changed', $page, 'a refused move changes nothing, and the help says so');
	}

	public function testTheDnsblPageNoLongerCarriesTheToggleOrItsHelp(): void
	{
		$page = self::src('www/pfblockerng/pfblockerng_dnsbl.php');

		foreach (['pfb_dns_proxy', "'pfb_dns'", "dns/pfb_dns", 'DNS Proxy', 'pfBlockerNG DNS proxy'] as $needle) {
			$this->assertStringNotContainsString($needle, $page, "the DNSBL page has no trace of the toggle: {$needle}");
		}
	}

	public function testTheDnsblPageSavesUnderTheSameConfigLockAsThePfbDnsPage(): void
	{
		$page = self::src('www/pfblockerng/pfblockerng_dnsbl.php');

		$this->assertSame(1, substr_count($page, '$pfb_config_lock = pfb_dns_config_lock();'), 'its whole-section save runs under the lock the pfB-DNS page and the Resolver move take');
		$this->assertSame(1, substr_count($page, 'unlock($pfb_config_lock);'), 'released after write_config()');
	}

	public function testThePageCarriesTheSevenDohAndDoqSettingsBelowTheEnableToggleReadAndSavedThroughTheDnsSection(): void
	{
		// Given the pfB-DNS page
		$page = self::src('www/pfblockerng/pfblockerng_dns.php');

		// Then its enable toggle comes first and the seven settings follow it in order, each read from the dns section
		$after = (int) strpos($page, "'pfb_dns',");
		$this->assertGreaterThan(0, $after, 'the enable checkbox');
		foreach (self::LISTENER_FIELDS as $field) {
			$at = strpos($page, "'{$field}',", $after);
			$this->assertNotFalse($at, "the page has the {$field} control below the previous one");
			$after = $at;
			$this->assertStringContainsString("PfbConfig::read('dns/{$field}')", $page, "{$field} is read through the gateway from the dns section");
		}

		// And the save is validated, canonicalised and written to the same section, under the lock the snapshot needs
		$this->assertStringContainsString('pfb_validate_dns_proxy_listeners_post(', $page, 'the seven fields are validated');
		$this->assertStringContainsString('pfb_dns_proxy_listeners_stored(', $page, 'and stored canonically');
		$this->assertStringContainsString("PfbConfig::write('dns/' . ", $page, 'into the dns section');
		$this->assertLessThan(
			(int) strpos($page, 'pfb_dns_proxy_listeners_stored('),
			(int) strpos($page, 'pfb_dns_config_lock()'),
			'the lock is held before anything is stored'
		);
	}

	public function testTheDnsblPageCarriesNoneOfTheSevenSettingsAndNoCodeThatSavesThem(): void
	{
		// Given the DNSBL page, from which the settings moved
		$page = self::src('www/pfblockerng/pfblockerng_dnsbl.php');

		// Then neither the fields nor their old names nor their save code are left there
		foreach (self::LISTENER_FIELDS as $field) {
			$this->assertStringNotContainsString($field, $page, "the DNSBL page has no trace of {$field}");
		}
		foreach (['pfb_dns_proxy_do', 'pfb_validate_dns_proxy_listeners_post', 'pfb_dns_proxy_listeners_stored', 'options_dns_proxy_interface'] as $needle) {
			$this->assertStringNotContainsString($needle, $page, "the DNSBL page has no trace of {$needle}");
		}
	}

	public function testNoSourceStillNamesAnOldDohOrDoqSettingKey(): void
	{
		// The feature never shipped: the old names are gone from every reader, with no alias and no migration
		$root = dirname(__DIR__, 2) . '/src';
		$found = [];
		$files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
		foreach ($files as $file) {
			if (!$file->isFile() || !preg_match('/\.(php|inc|xml|sh)$/', $file->getFilename())) {
				continue;
			}
			if (preg_match('/dnsbl\/pfb_dns_proxy_do[hq]|pfb_dns_proxy_do[hq]/', (string) file_get_contents($file->getPathname())) === 1) {
				$found[] = substr($file->getPathname(), strlen($root) + 1);
			}
		}
		$this->assertSame([], $found, 'files that still name pfb_dns_proxy_doh/doq');
	}

	public function testNoShippedSourceStillNamesTheRetiredGatewayBinary(): void
	{
		// The package ships pfb-dns (bin/<target>/pfb-dns, run through pfb_dns.sh); the single pfb_dns_gateway binary
		// never shipped, so no page, include, script or doc string in the package may still send an operator to it
		$root = dirname(__DIR__, 2) . '/src';
		$found = [];
		$files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
		foreach ($files as $file) {
			if (!$file->isFile() || !preg_match('/\.(php|inc|xml|sh|py)$/', $file->getFilename())) {
				continue;
			}
			if (str_contains((string) file_get_contents($file->getPathname()), 'pfb_dns_gateway')) {
				$found[] = substr($file->getPathname(), strlen($root) + 1);
			}
		}
		$this->assertSame([], $found, 'files that still name pfb_dns_gateway');
	}
}
