<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-29 Phase 8 — www/ group C gateway routing tests.
 *
 * Covers the pages routed in Phase 8:
 *   - pfblockerng_alerts.php   (pfblockerngglobal: foreign section; whitelist/tld_wildcard_exclusion/global_log/
 *                               v4suppression [ADR-53]: registered)
 *   - pfblockerng_sync.php     (pfblockerngsync/config/0: foreign section)
 *   - pfblockerng_software.php (pfb_software_check: registered)
 *   - pfblockerng_log.php      (no pfblockerng* config access — no routing work)
 *   - pfblockerng.widget.php   (pfblockerngglobal: foreign section; widget-* per-key writes: foreign)
 *   - pfblockerng_wizard.inc   (pfblockerng_wizard/*: entirely foreign temp section; bulk installedpackages write: foreign)
 *
 * Test groups:
 *
 * A — LOAD DEFAULT PARITY
 *   Registered keys (pfb_software_check, global_log, whitelist, tld_wildcard_exclusion,
 *   v4suppression [ADR-53]):
 *     Assert PfbConfig::read($key) on an absent section returns the correct default
 *     (parity with prior page behaviour before routing).
 *
 *   Foreign keys (pfblockerngglobal widget-*, pfblockerngsync, pfblockerngipsettings/enable_dup):
 *     Assert registry lookup throws (proving they are NOT in the registry and must
 *     stay on direct config_*_path). v4suppression -- the ADR-53 sibling in the same
 *     pfblockerngipsettings section -- is now registered; see group A's v4suppression
 *     tests below rather than this foreign-key list.
 *
 * B — SAVE ROUND-TRIP IDENTITY (section blobs)
 *   For every section routed through PfbConfig::readSection/writeSection, assert that
 *   writing an array and reading it back returns byte-identical values.
 *
 * Scenario (group A — registered key defaults):
 *   Background: config.xml empty — no relevant sections seeded.
 *     Given PfbConfig::read($key) with no seed.
 *     When the key is absent.
 *     Then the gateway default equals the prior page fallback (parity).
 *
 * Scenario (group B — section round-trip):
 *   Background: a representative section array is built.
 *     Given a section array mirroring what a page save handler would produce.
 *     When PfbConfig::writeSection(section, array) is called.
 *     Then PfbConfig::readSection(section) returns the same array byte-for-byte.
 */
final class WwwGroupCGatewayTest extends TestCase
{
	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
	}

	// -----------------------------------------------------------------------
	// A — Load default parity: registered keys in group C pages
	// -----------------------------------------------------------------------

	/**
	 * pfb_software_check: absent → On (the registered default 'on' since issue #1887;
	 * pfb_software_check_enabled() is zero-arg and reads the gateway itself).
	 */
	public function testSoftwareCheckAbsentDefaultIsOn(): void
	{
		$path = 'installedpackages/pfblockerng/config/0/pfb_software_check';

		// Before: key absent.
		$this->assertNull(config_get_path($path), 'pfb_software_check must be absent before read');

		// When: gateway read.
		$result = PfbConfig::read('gen/pfb_software_check');

		// Then: On — issue #1887 moved the effective ON default from the hand-written
		// reader (`!== 'off'`) into the registry; absent still means enabled.
		$this->assertSame(PfbToggle::On, $result, 'pfb_software_check absent -> On (registry default)');
	}

	/**
	 * pfb_software_check toggle round-trip: write 'on', then 'off', assert both states visible.
	 */
	public function testSoftwareCheckToggleRoundTrips(): void
	{
		// Before: absent → the registered default On (issue #1887).
		$this->assertSame(PfbToggle::On, PfbConfig::read('gen/pfb_software_check'), 'initial absent -> On');

		// When: write 'on'.
		PfbConfig::write('gen/pfb_software_check', 'on');

		// Then: read back On.
		$this->assertSame(PfbToggle::On, PfbConfig::read('gen/pfb_software_check'), 'after write "on" -> On');

		// When: write 'off'.
		PfbConfig::write('gen/pfb_software_check', 'off');

		// Then: read back Off.
		$this->assertSame(PfbToggle::Off, PfbConfig::read('gen/pfb_software_check'), 'after write "off" -> Off');
	}

	/**
	 * global_log: absent → '' (registry default; page uses `?: ''` after gateway read).
	 */
	public function testGlobalLogAbsentDefaultIsEmptyString(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/global_log';

		// Before: key absent.
		$this->assertNull(config_get_path($path), 'global_log must be absent before read');

		// When: gateway read.
		$result = PfbConfig::read('dnsbl/global_log');

		// Then: '' — prior page did `config_get_path(...) ?: ''`.
		$this->assertSame('', $result, 'global_log absent -> "" (parity with prior page fallback)');
	}

	/**
	 * global_log round-trip: write a logging mode string, read it back.
	 */
	public function testGlobalLogRoundTrips(): void
	{
		// Before: absent → ''.
		$this->assertSame('', PfbConfig::read('dnsbl/global_log'), 'initial absent -> ""');

		// When: write 'enabled'.
		PfbConfig::write('dnsbl/global_log', 'enabled');

		// Then: read back 'enabled'.
		$this->assertSame('enabled', PfbConfig::read('dnsbl/global_log'), 'after write "enabled" -> "enabled"');

		// When: write 'disabled_log'.
		PfbConfig::write('dnsbl/global_log', 'disabled_log');

		// Then: read back 'disabled_log'.
		$this->assertSame('disabled_log', PfbConfig::read('dnsbl/global_log'), 'after write "disabled_log" -> "disabled_log"');
	}

	/**
	 * whitelist: absent → '' (registry default; prior page did `config_get_path(...) ?: ''`).
	 */
	public function testWhitelistAbsentDefaultIsEmptyString(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/whitelist';

		// Before: key absent.
		$this->assertNull(config_get_path($path), 'whitelist must be absent before read');

		// When: gateway read.
		$result = PfbConfig::read('dnsbl/whitelist');

		// Then: '' — parity with prior page coalesce `?: ''`.
		$this->assertSame('', $result, 'whitelist absent -> "" (parity with prior page fallback)');
	}

	/**
	 * whitelist round-trip: write a base64 blob, read it back byte-identically.
	 */
	public function testWhitelistRoundTrips(): void
	{
		$blob = base64_encode("example.com\r\n.blocked.net\r\n");

		// Before: absent → ''.
		$this->assertSame('', PfbConfig::read('dnsbl/whitelist'), 'initial absent -> ""');

		// When: write a base64 blob.
		PfbConfig::write('dnsbl/whitelist', $blob);

		// Then: read back byte-identically.
		$this->assertSame($blob, PfbConfig::read('dnsbl/whitelist'), 'whitelist after write round-trips byte-identically');
	}

	/**
	 * tld_wildcard_exclusion: absent → '' (registry default; prior page did `config_get_path(...) ?: ''`).
	 */
	public function testTldExclusionAbsentDefaultIsEmptyString(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/tld_wildcard_exclusion';

		// Before: key absent.
		$this->assertNull(config_get_path($path), 'tld_wildcard_exclusion must be absent before read');

		// When: gateway read.
		$result = PfbConfig::read('dnsbl/tld_wildcard_exclusion');

		// Then: '' — parity with prior page coalesce `?: ''`.
		$this->assertSame('', $result, 'tld_wildcard_exclusion absent -> "" (parity with prior page fallback)');
	}

	/**
	 * tld_wildcard_exclusion round-trip: write a base64 blob, read it back byte-identically.
	 */
	public function testTldExclusionRoundTrips(): void
	{
		$blob = base64_encode("example.com\r\n.test.org\r\n");

		// Before: absent → ''.
		$this->assertSame('', PfbConfig::read('dnsbl/tld_wildcard_exclusion'), 'initial absent -> ""');

		// When: write a base64 blob.
		PfbConfig::write('dnsbl/tld_wildcard_exclusion', $blob);

		// Then: read back byte-identically.
		$this->assertSame($blob, PfbConfig::read('dnsbl/tld_wildcard_exclusion'), 'tld_wildcard_exclusion after write round-trips byte-identically');
	}

	/**
	 * v4suppression: absent -> '' (registry default; ADR-53 P2 migrates the raw
	 * pfblockerng_alerts.php call sites onto the gateway -- parity with the prior
	 * page's `config_get_path(...) ?: ''` fallback).
	 *
	 * Red->green: before this phase, v4suppression was a foreign key and
	 * PfbConfig::read('ip/v4suppression') threw InvalidArgumentException (the former
	 * testV4SuppressionIsNotInRegistry pin this test-pair replaces).
	 */
	public function testV4SuppressionAbsentDefaultIsEmptyString(): void
	{
		$path = 'installedpackages/pfblockerngipsettings/config/0/v4suppression';

		// Before: key absent.
		$this->assertNull(config_get_path($path), 'v4suppression must be absent before read');

		// When: gateway read.
		$result = PfbConfig::read('ip/v4suppression');

		// Then: '' — parity with prior page coalesce `?: ''`.
		$this->assertSame('', $result, 'v4suppression absent -> "" (parity with prior page fallback)');
	}

	/**
	 * v4suppression round-trip: write a base64 blob, read it back byte-identically.
	 */
	public function testV4SuppressionRoundTrips(): void
	{
		$blob = base64_encode("192.168.1.1/32\r\n192.168.1.2/32\r\n");

		// Before: absent → ''.
		$this->assertSame('', PfbConfig::read('ip/v4suppression'), 'initial absent -> ""');

		// When: write a base64 blob.
		PfbConfig::write('ip/v4suppression', $blob);

		// Then: read back byte-identically.
		$this->assertSame($blob, PfbConfig::read('ip/v4suppression'), 'v4suppression after write round-trips byte-identically');
	}

	/**
	 * Foreign section keys must NOT be in the registry.
	 * widget-popup is a pfblockerngglobal widget key — registry lookup must throw.
	 */
	public function testWidgetGlobalKeyIsNotInRegistry(): void
	{
		$this->expectException(InvalidArgumentException::class);
		PfbConfig::read('widget-popup');
	}

	/**
	 * enable_dup is a pfblockerngipsettings key (foreign section) — registry lookup must
	 * throw. (v4suppression, the ADR-53 sibling in this same section, is now registered
	 * — see testV4SuppressionAbsentDefaultIsEmptyString / testV4SuppressionRoundTrips above.)
	 */
	public function testEnableDupIsNotInRegistry(): void
	{
		$this->expectException(InvalidArgumentException::class);
		PfbConfig::read('enable_dup');
	}

	// -----------------------------------------------------------------------
	// B — Save round-trip identity: section blobs
	// -----------------------------------------------------------------------

	/**
	 * pfblockerngglobal section round-trip (Alerts page and widget use readSection/writeSection).
	 *
	 * Scenario:
	 *   Given a representative pfblockerngglobal array (alert colour + widget settings).
	 *   When PfbConfig::writeSection() persists it.
	 *   Then PfbConfig::readSection() returns an identical array (byte-for-byte).
	 */
	public function testAlertsGlobalSectionRoundTripsByteIdentically(): void
	{
		$section = 'installedpackages/pfblockerngglobal';

		$data = [
			'alertrefresh'      => 'on',
			'pfbpageload'       => 'unified',
			'pfbmaxtable'       => '1000',
			'uniblock'          => '#FFF9C4',
			'unipermit'         => '#80CBC4',
			'unimatch'          => '#B3E5FC',
			'unidnsbl'          => '#EF9A9A',
			'unireply'          => '#E8E8E8',
			'uniblock2'         => '#83791D',
			'unipermit2'        => '#3B8780',
			'unimatch2'         => '#42809D',
			'unidnsbl2'         => '#E84E4E',
			'unireply2'         => '#54585E',
			'pfbchartcnt'       => '24',
			'pfbchartstyle'     => 'twotone',
			'widget-popup'      => 'off',
			'widget-sortmix'    => 'off',
			'widget-sortcolumn' => 'count',
			'widget-sortdir'    => 'asc',
			'widget-dnsblquery' => '5',
			'widget-maxfails'   => '3',
			'widget-maxheight'  => '2500',
			'widget-clearip'    => 'never',
			'widget-cleardnsbl' => 'never',
		];

		// Before: section absent.
		$this->assertSame([], PfbConfig::readSection($section), 'pfblockerngglobal section absent -> [] before write');

		// When: write the section blob.
		PfbConfig::writeSection($section, $data);

		// Then: read back byte-identically.
		$this->assertSame($data, PfbConfig::readSection($section), 'pfblockerngglobal section round-trips byte-identically');
	}

	/**
	 * pfblockerngsync/config/0 section round-trip (Sync page uses readSection/writeSection).
	 *
	 * Scenario:
	 *   Given a representative sync section (scalar fields + row XMLRPC targets).
	 *   When PfbConfig::writeSection() persists it.
	 *   Then PfbConfig::readSection() returns an identical array (byte-for-byte).
	 */
	public function testSyncSectionRoundTripsByteIdentically(): void
	{
		$section = 'installedpackages/pfblockerngsync/config/0';

		$data = [
			'varsynconchanges' => 'manual',
			'varsynctimeout'   => '150',
			'syncinterfaces'   => '',
			'row'              => [
				0 => [
					'varsyncdestinenable' => 'on',
					'varsyncprotocol'     => 'https',
					'varsyncipaddress'    => '192.0.2.10',
					'varsyncport'         => '443',
					'varsyncusername'     => 'admin',
					'varsyncpassword'     => 'secret',
				],
				1 => [
					'varsyncdestinenable' => '',
					'varsyncprotocol'     => 'http',
					'varsyncipaddress'    => '192.0.2.20',
					'varsyncport'         => '80',
					'varsyncusername'     => 'admin',
					'varsyncpassword'     => 'other',
				],
			],
		];

		// Before: section absent.
		$this->assertSame([], PfbConfig::readSection($section), 'pfblockerngsync section absent -> [] before write');

		// When: write the section blob.
		PfbConfig::writeSection($section, $data);

		// Then: read back byte-identically.
		$this->assertSame($data, PfbConfig::readSection($section), 'pfblockerngsync section round-trips byte-identically');
	}

	/**
	 * Sync section toggle round-trip: write disabled state, confirm, then switch to auto.
	 */
	public function testSyncSectionToggleRoundTrips(): void
	{
		$section = 'installedpackages/pfblockerngsync/config/0';

		$disabled = ['varsynconchanges' => 'disabled', 'varsynctimeout' => '150', 'syncinterfaces' => ''];
		$auto     = ['varsynconchanges' => 'auto',     'varsynctimeout' => '300', 'syncinterfaces' => 'on'];

		// Before: absent → empty.
		$this->assertSame([], PfbConfig::readSection($section), 'absent before write');

		// When: write disabled.
		PfbConfig::writeSection($section, $disabled);

		// Then: read back disabled.
		$this->assertSame($disabled, PfbConfig::readSection($section), 'disabled state round-trips');

		// When: switch to auto.
		PfbConfig::writeSection($section, $auto);

		// Then: read back auto.
		$this->assertSame($auto, PfbConfig::readSection($section), 'auto state round-trips');
	}

	/**
	 * Widget section round-trip: pfblockerngglobal with widget-* keys.
	 * Confirms that widget-* dynamic keys survive the section blob gateway unchanged.
	 */
	public function testWidgetGlobalSectionWithWidgetKeysRoundTrip(): void
	{
		$section = 'installedpackages/pfblockerngglobal';

		$data = [
			'widget-popup'      => 'on',
			'widget-sortmix'    => 'on',
			'widget-sortcolumn' => 'alias',
			'widget-sortdir'    => 'des',
			'widget-dnsblquery' => '10',
			'widget-maxfails'   => '5',
			'widget-maxheight'  => '1500',
			'widget-clearip'    => 'daily',
			'widget-cleardnsbl' => 'weekly',
		];

		// Before: absent.
		$this->assertSame([], PfbConfig::readSection($section), 'pfblockerngglobal section absent -> [] before write');

		// When: write.
		PfbConfig::writeSection($section, $data);

		// Then: read back byte-identically.
		$this->assertSame($data, PfbConfig::readSection($section), 'widget section round-trips byte-identically');
	}

	/**
	 * whitelist + tld_wildcard_exclusion together in their section: both registered keys.
	 * Write both via PfbConfig::write(), then read both via PfbConfig::read().
	 */
	public function testWhitelistAndTldExclusionCoexistInSection(): void
	{
		$whiteblob = base64_encode("example.com\r\n");
		$tldblob   = base64_encode(".test.org\r\n");

		// When: write both registered keys.
		PfbConfig::write('dnsbl/whitelist', $whiteblob);
		PfbConfig::write('dnsbl/tld_wildcard_exclusion', $tldblob);

		// Then: each reads back independently and byte-identically.
		$this->assertSame($whiteblob, PfbConfig::read('dnsbl/whitelist'), 'whitelist after write');
		$this->assertSame($tldblob, PfbConfig::read('dnsbl/tld_wildcard_exclusion'), 'tld_wildcard_exclusion after write');
	}
}
