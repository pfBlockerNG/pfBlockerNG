<?php

use PHPUnit\Framework\TestCase;

/**
 * pfb_dnsbl_webpage() — issue #713.
 *
 * The DNSBL block-page template filename is a FOREIGN config key stored at
 * installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_webpage (written
 * directly by www/pfblockerng_dnsbl.php). The install/upgrade code that
 * refreshes dnsbl_active.php previously read the never-written registry
 * mis-spelling 'dnsblwebpage' (via PfbConfig::read), which always returned ''
 * — so the refresh was dead even when the user was on the default page.
 *
 * These tests pin that the reader returns the value actually stored under the
 * real 'dnsbl_webpage' key, defaulting to 'dnsbl_default.php' (matching the
 * settings page's own `?: 'dnsbl_default.php'`) when nothing is stored.
 */
final class DnsblWebpageForeignReadTest extends TestCase
{
	private const PATH = 'installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_webpage';

	private $prevConfig;

	protected function setUp(): void
	{
		// Save the ambient config and start each test from a known-empty baseline.
		$this->prevConfig = $GLOBALS['config'] ?? null;
		$GLOBALS['config'] = [];
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = $this->prevConfig;
	}

	public function testConfiguredCustomWebpageIsReturned(): void
	{
		// Given a user-selected custom block page stored under the real key,
		config_set_path(self::PATH, 'my_custom.php');
		// the reader returns it — the old dead 'dnsblwebpage' read returned ''.
		$this->assertSame('my_custom.php', pfb_dnsbl_webpage());
	}

	public function testConfiguredDefaultWebpageIsReturned(): void
	{
		// A user whose block page IS the default: the reader reports it so the
		// install/upgrade refresh (== 'dnsbl_default.php') actually fires.
		config_set_path(self::PATH, 'dnsbl_default.php');
		$this->assertSame('dnsbl_default.php', pfb_dnsbl_webpage());
	}

	public function testAbsentWebpageDefaultsToDnsblDefault(): void
	{
		// An install that never saved DNSBL settings uses the default page
		// (mirrors pfblockerng_dnsbl.php's `?: 'dnsbl_default.php'`), so the
		// refresh still fires for it.
		$this->assertSame('dnsbl_default.php', pfb_dnsbl_webpage());
	}
}
