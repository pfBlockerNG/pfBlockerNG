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
		$this->assertMatchesRegularExpression('/<span class="text-warning"><strong>Experimental\./', $page, 'the help says so plainly, in the warning style');
	}

	public function testTheDnsblPageNoLongerCarriesTheToggleOrItsHelp(): void
	{
		$page = self::src('www/pfblockerng/pfblockerng_dnsbl.php');

		foreach (['pfb_dns_proxy', "'pfb_dns'", "dns/pfb_dns", 'DNS Proxy', 'pfBlockerNG DNS proxy'] as $needle) {
			$this->assertStringNotContainsString($needle, $page, "the DNSBL page has no trace of the toggle: {$needle}");
		}
		$this->assertStringNotContainsString('pfb_dns_config_lock', $page, 'nor of the lock that only the snapshot needed');
	}
}
