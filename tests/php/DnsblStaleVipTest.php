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

	public function testWrongInterfaceStillSaysNotFoundOnInterface(): void
	{
		$this->assertSame(
			[FALSE, 'IPv4 VIP not found on interface lo0'],
			pfb_validate_vips('lo0', '_vip_test_4', '')
		);
	}

	// --- pfb_dnsbl_stale_vip_warning ---

	public function testWarningNamesMissingIpv4Only(): void
	{
		$html = pfb_dnsbl_stale_vip_warning(PfbToggle::Off, '_vip_gone_a', '');
		$this->assertStringContainsString('_vip_gone_a', $html);
		$this->assertStringContainsString('re-select the DNSBL Virtual IP', $html);
		$this->assertStringContainsString('IPv4 VIP', $html);
		$this->assertStringNotContainsString('IPv6 VIP', $html);
	}

	public function testWarningNamesMissingIpv6Only(): void
	{
		$html = pfb_dnsbl_stale_vip_warning(PfbToggle::Off, '', '_vip_gone_b');
		$this->assertStringContainsString('IPv6 VIP (_vip_gone_b)', $html);
		$this->assertStringNotContainsString('IPv4 VIP', $html);
	}

	public function testWarningNamesBothWithIpv4First(): void
	{
		$html = pfb_dnsbl_stale_vip_warning(PfbToggle::Off, '_vip_gone_a', '_vip_gone_b');
		$this->assertStringContainsString('IPv4 VIP (_vip_gone_a)', $html);
		$this->assertStringContainsString('IPv6 VIP (_vip_gone_b)', $html);
		$this->assertLessThan(strpos($html, 'IPv6 VIP'), strpos($html, 'IPv4 VIP'));
	}

	public function testWarningIsEmptyInAutoMode(): void
	{
		$this->assertSame('', pfb_dnsbl_stale_vip_warning(PfbToggle::On, '_vip_gone_a', '_vip_gone_b'));
	}

	public function testWarningIsEmptyWhenNothingIsMissing(): void
	{
		$this->assertSame('', pfb_dnsbl_stale_vip_warning(PfbToggle::Off, '_vip_test_4', ''));
		$this->assertSame('', pfb_dnsbl_stale_vip_warning(PfbToggle::Off, '', ''));
		$this->assertSame('', pfb_dnsbl_stale_vip_warning(PfbToggle::Off, null, null));
	}

	public function testWarningEscapesHostileVipId(): void
	{
		$html = pfb_dnsbl_stale_vip_warning(PfbToggle::Off, '_vip_gone_"><script>x</script>', '');
		$this->assertStringContainsString('&lt;script&gt;', $html);
		$this->assertStringNotContainsString('<script>', $html);
	}
}
