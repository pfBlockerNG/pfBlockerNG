<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3456 — a stored DNSBL VIP id that no longer exists in virtualip/vip (VIP deleted and
 * re-created gets a new uniqid) must produce its own validation reason naming the id, not the
 * misleading "VIP not found on interface". The DNSBL page warns (manual mode only) so the
 * user knows to re-select the VIP.
 *
 * The doubled get_configured_vip_interface() (pfsense_doubles.php) returns NULL for
 * '_vip_gone_*' ids — pfSense's answer for an unknown uniqid — and 'opt-double' for
 * '_vip_test_*' ids.
 */
#[CoversFunction('pfb_dnsbl_vip_missing')]
#[CoversFunction('pfb_validate_vips')]
#[CoversFunction('pfb_dnsbl_stale_vip_warning')]
final class DnsblStaleVipTest extends TestCase
{
	// --- pfb_dnsbl_vip_missing ---

	public function testVipMissingIsFalseForEmptyAndNull(): void
	{
		$this->assertFalse(pfb_dnsbl_vip_missing(''));
		$this->assertFalse(pfb_dnsbl_vip_missing(null));
	}

	public function testVipMissingIsTrueOnlyWhenPfsenseReturnsNull(): void
	{
		$this->assertTrue(pfb_dnsbl_vip_missing('_vip_gone_a'));
		$this->assertFalse(pfb_dnsbl_vip_missing('_vip_test_4'));
	}

	// --- pfb_validate_vips ---

	public function testMissingIpv4VipNamesTheId(): void
	{
		$this->assertSame(
			[FALSE, 'IPv4 VIP _vip_gone_a no longer exists in Firewall > Virtual IPs'],
			pfb_validate_vips('lo0', '_vip_gone_a', '')
		);
	}

	public function testMissingIpv6VipNamesTheId(): void
	{
		$this->assertSame(
			[FALSE, 'IPv6 VIP _vip_gone_b no longer exists in Firewall > Virtual IPs'],
			pfb_validate_vips('lo0', '', '_vip_gone_b')
		);
	}

	public function testBothMissingReportsIpv4First(): void
	{
		$this->assertSame(
			[FALSE, 'IPv4 VIP _vip_gone_a no longer exists in Firewall > Virtual IPs'],
			pfb_validate_vips('lo0', '_vip_gone_a', '_vip_gone_b')
		);
	}

	public function testIpv6MissingBeatsIpv4WrongInterface(): void
	{
		$this->assertSame(
			[FALSE, 'IPv6 VIP _vip_gone_b no longer exists in Firewall > Virtual IPs'],
			pfb_validate_vips('lo0', '_vip_test_4', '_vip_gone_b')
		);
	}

	public function testIpv4MissingBeatsIpv6WrongInterface(): void
	{
		$this->assertSame(
			[FALSE, 'IPv4 VIP _vip_gone_a no longer exists in Firewall > Virtual IPs'],
			pfb_validate_vips('lo0', '_vip_gone_a', '_vip_test_6')
		);
	}

	// --- pfb_dnsbl_stale_vip_warning ---

	public function testWarningNamesMissingIpv4Only(): void
	{
		$html = pfb_dnsbl_stale_vip_warning(PfbToggle::Off, '_vip_gone_a', '', TRUE);
		$this->assertStringContainsString('_vip_gone_a', $html);
		$this->assertStringContainsString('re-select the DNSBL Virtual IP', $html);
		$this->assertStringContainsString('IPv4 VIP', $html);
		$this->assertStringNotContainsString('IPv6 VIP', $html);
	}

	public function testWarningNamesMissingIpv6Only(): void
	{
		$html = pfb_dnsbl_stale_vip_warning(PfbToggle::Off, '', '_vip_gone_b', TRUE);
		$this->assertStringContainsString('IPv6 VIP (_vip_gone_b)', $html);
		$this->assertStringNotContainsString('IPv4 VIP', $html);
	}

	public function testWarningNamesBothWithIpv4First(): void
	{
		$html = pfb_dnsbl_stale_vip_warning(PfbToggle::Off, '_vip_gone_a', '_vip_gone_b', TRUE);
		$this->assertStringContainsString('IPv4 VIP (_vip_gone_a)', $html);
		$this->assertStringContainsString('IPv6 VIP (_vip_gone_b)', $html);
		$this->assertLessThan(strpos($html, 'IPv6 VIP'), strpos($html, 'IPv4 VIP'));
	}

	public function testWarningIsEmptyInAutoMode(): void
	{
		$this->assertSame('', pfb_dnsbl_stale_vip_warning(PfbToggle::On, '_vip_gone_a', '_vip_gone_b', TRUE));
	}

	public function testWarningIsEmptyWhenNothingIsMissing(): void
	{
		$this->assertSame('', pfb_dnsbl_stale_vip_warning(PfbToggle::Off, '_vip_test_4', '', TRUE));
		$this->assertSame('', pfb_dnsbl_stale_vip_warning(PfbToggle::Off, '', '', TRUE));
		$this->assertSame('', pfb_dnsbl_stale_vip_warning(PfbToggle::Off, null, null, TRUE));
	}

	public function testWarningEscapesHostileVipId(): void
	{
		$html = pfb_dnsbl_stale_vip_warning(PfbToggle::Off, '_vip_gone_"><script>x</script>', '', TRUE);
		$this->assertStringContainsString('&lt;script&gt;', $html);
		$this->assertStringNotContainsString('<script>', $html);

		$html6 = pfb_dnsbl_stale_vip_warning(PfbToggle::Off, '', '_vip_gone_"><script>x</script>', TRUE);
		$this->assertStringContainsString('&lt;script&gt;', $html6);
		$this->assertStringNotContainsString('<script>', $html6);
	}

	// --- issue #3539: a VIP nobody answers with is not worth a warning ---

	public function testWarningIsEmptyWithoutVipDemand(): void
	{
		// A missing manual VIP warns only while a block answers with it.
		$this->assertNotSame('', pfb_dnsbl_stale_vip_warning(PfbToggle::Off, '_vip_gone_a', '_vip_gone_b', TRUE));

		$this->assertSame('', pfb_dnsbl_stale_vip_warning(PfbToggle::Off, '_vip_gone_a', '_vip_gone_b', FALSE));
	}

	// --- the DNSBL page's own call (extracted from the shipped page) ---

	/** Run the page's warning statement for the stored VIP ids; any PHP diagnostic is collected, not thrown. */
	private function pageWarning(array $dnsbl_section, bool $demand, array &$diagnostics = []): string
	{
		require_once __DIR__ . '/PageStatementLoader.php';
		$had_config = array_key_exists('config', $GLOBALS);
		$saved = $GLOBALS['config'] ?? null;
		$GLOBALS['config'] = [];
		if ($dnsbl_section !== []) {
			config_set_path('installedpackages/pfblockerngdnsblsettings/config/0', $dnsbl_section);
		}
		set_error_handler(static function (int $no, string $message) use (&$diagnostics): bool {
			$diagnostics[] = $message;
			return true;
		});
		try {
			$scope = pfb_test_page_eval(
				pfb_test_page_statement('src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php', '/\$pfb_stale_vip_warning\s*=/'),
				['pfb' => ['dnsbl_vip_demand' => $demand]]
			);
		} finally {
			restore_error_handler();
			if ($had_config) {
				$GLOBALS['config'] = $saved;
			} else {
				unset($GLOBALS['config']);
			}
		}
		return $scope['pfb_stale_vip_warning'];
	}

	public function testPageWarnsOnlyWhileTheStoredConfigurationDemandsAVip(): void
	{
		$stored = ['pfb_dnsvip4' => '_vip_gone_a'];

		$this->assertStringContainsString('_vip_gone_a', $this->pageWarning($stored, TRUE));
		$this->assertSame('', $this->pageWarning($stored, FALSE));
	}

	public function testPageToleratesStoredVipIdsThatAreAbsent(): void
	{
		// An automatic teardown with no demand unsets both ids; the page must read that as "no VIP", quietly.
		$diagnostics = [];

		$this->assertSame('', $this->pageWarning(['pfb_dnsbl' => 'on'], TRUE, $diagnostics));
		$this->assertSame([], $diagnostics);
	}

	public function testPagePrefillReadsAbsentVipIdsAsTheNoneSentinelQuietly(): void
	{
		require_once __DIR__ . '/PageStatementLoader.php';
		$diagnostics = [];
		set_error_handler(static function (int $no, string $message) use (&$diagnostics): bool {
			$diagnostics[] = $message;
			return true;
		});
		try {
			foreach (['pfb_dnsvip4', 'pfb_dnsvip6'] as $key) {
				$scope = pfb_test_page_eval(
					pfb_test_page_statement('src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php', "/\\\$pconfig\\['{$key}'\\]\\s*=/"),
					['pconfig' => []]
				);
				$this->assertSame('none', $scope['pconfig'][$key], "an absent {$key} renders as the widget's empty option");
			}
		} finally {
			restore_error_handler();
		}
		$this->assertSame([], $diagnostics);
	}
}
