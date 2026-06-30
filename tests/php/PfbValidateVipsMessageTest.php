<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_validate_vips() — the interface-mismatch reason string. When the configured DNSBL VIP
 * resolves to an interface other than the expected one, validation fails with a reason that is
 * surfaced to the user (Update log + DNSBL save). The wording is "VIP not FOUND on interface
 * <iface>" — clearer than the old "VIP not on interface", which read ambiguously ("is there no
 * VIP, or is it elsewhere?").
 *
 * The doubled get_configured_vip_interface() (pfsense_doubles.php) returns 'opt-double' for any
 * '_vip_test_*' VIP id, so passing expected interface 'lo0' forces the mismatch branch (which
 * returns BEFORE pfb_get_vips(), so no further VIP state is needed). Both families are asserted.
 *
 * Red→green: the old message ("not on interface") lacks "found", so each assertion fails on the
 * pre-change code and passes after.
 */
#[CoversFunction('pfb_validate_vips')]
final class PfbValidateVipsMessageTest extends TestCase
{
	public function testIpv4InterfaceMismatchSaysNotFoundOnInterface(): void
	{
		[$ok, $reason] = pfb_validate_vips('lo0', '_vip_test_4', '');
		$this->assertFalse($ok, 'an IPv4 VIP on the wrong interface must fail validation');
		$this->assertSame('IPv4 VIP not found on interface lo0', $reason);
	}

	public function testIpv6InterfaceMismatchSaysNotFoundOnInterface(): void
	{
		[$ok, $reason] = pfb_validate_vips('lo0', '', '_vip_test_6');
		$this->assertFalse($ok, 'an IPv6 VIP on the wrong interface must fail validation');
		$this->assertSame('IPv6 VIP not found on interface lo0', $reason);
	}
}
