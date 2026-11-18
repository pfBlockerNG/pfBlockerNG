<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Issue #4053 slice 3: the HSTS preload list existed only for the block page, so it is gone with it. No setting, no
 * Core field and no DNSBL page control remains.
 */
final class DnsblHstsRetiredTest extends TestCase
{
	private const DNSBL_PAGE = 'src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php';

	public function testTheRegistryHoldsNoHstsSetting(): void
	{
		$this->assertArrayNotHasKey('dnsbl/pfb_hsts', pfb_cfg_registry());
	}

	public function testCoreDnsSettingsCarryNoHstsField(): void
	{
		$this->assertArrayNotHasKey('hstsNullBlocking', pfb_core_dns_fields());
	}

	public function testTheDnsblPageOffersNoHstsControl(): void
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/' . self::DNSBL_PAGE);
		$this->assertNotFalse($source);
		$this->assertStringNotContainsString("'pfb_hsts'", $source);
		$this->assertStringNotContainsString('HSTS mode', $source);
	}
}
