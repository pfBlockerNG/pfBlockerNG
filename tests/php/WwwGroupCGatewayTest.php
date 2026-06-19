<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-29 Phase 8 — www/ group C gateway routing tests.
 *
 * Covers the pages routed in Phase 8:
 *   - pfblockerng_alerts.php   (pfblockerngglobal: foreign section; suppression/tldexclusion/global_log: registered)
 *   - pfblockerng_sync.php     (pfblockerngsync/config/0: foreign section)
 *   - pfblockerng_software.php (pfb_software_check: registered)
 *   - pfblockerng_log.php      (no pfblockerng* config access — no routing work)
 *   - pfblockerng.widget.php   (pfblockerngglobal: foreign section; widget-* per-key writes: foreign)
 *   - pfblockerng_wizard.inc   (pfblockerng_wizard/*: entirely foreign temp section; bulk installedpackages write: foreign)
 *
 * Test groups:
 *
 * A — LOAD DEFAULT PARITY
 *   Registered keys (pfb_software_check, global_log, suppression, tldexclusion):
 *     Assert PfbConfig::read($key) on an absent section returns the correct default
 *     (parity with prior page behaviour before routing).
 *
 *   Foreign keys (pfblockerngglobal widget-*, pfblockerngsync, pfblockerngipsettings/v4suppression):
 *     Assert registry lookup throws (proving they are NOT in the registry and must
 *     stay on direct config_*_path).
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
	 * pfb_software_check: absent → '' (registry default; page treats absent as enabled
	 * via pfb_software_check_enabled(null)).
	 */
	public function testSoftwareCheckAbsentDefaultIsEmptyString(): void
	{
		$path = 'installedpackages/pfblockerng/config/0/pfb_software_check';

		// Before: key absent.
		$this->assertNull(config_get_path($path), 'pfb_software_check must be absent before read');

		// When: gateway read.
		$result = PfbConfig::read('pfb_software_check');

		// Then: '' — prior page passed null to pfb_software_check_enabled(); '' is equivalent.
		$this->assertSame('', $result, 'pfb_software_check absent -> "" (registry default)');
	}

	/**
	 * pfb_software_check toggle round-trip: write 'on', then 'off', assert both states visible.
	 */
	public function testSoftwareCheckToggleRoundTrips(): void
	{
		// Before: absent → ''.
		$this->assertSame('', PfbConfig::read('pfb_software_check'), 'initial absent -> ""');

		// When: write 'on'.
		PfbConfig::write('pfb_software_check', 'on');

		// Then: read back 'on'.
		$this->assertSame('on', PfbConfig::read('pfb_software_check'), 'after write "on" -> "on"');

		// When: write 'off'.
		PfbConfig::write('pfb_software_check', 'off');

		// Then: read back 'off'.
		$this->assertSame('off', PfbConfig::read('pfb_software_check'), 'after write "off" -> "off"');
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
		$result = PfbConfig::read('global_log');

		// Then: '' — prior page did `config_get_path(...) ?: ''`.
		$this->assertSame('', $result, 'global_log absent -> "" (parity with prior page fallback)');
	}

	/**
	 * global_log round-trip: write a logging mode string, read it back.
	 */
	public function testGlobalLogRoundTrips(): void
	{
		// Before: absent → ''.
		$this->assertSame('', PfbConfig::read('global_log'), 'initial absent -> ""');

		// When: write 'enabled'.
		PfbConfig::write('global_log', 'enabled');

		// Then: read back 'enabled'.
		$this->assertSame('enabled', PfbConfig::read('global_log'), 'after write "enabled" -> "enabled"');

		// When: write 'disabled_log'.
		PfbConfig::write('global_log', 'disabled_log');

		// Then: read back 'disabled_log'.
		$this->assertSame('disabled_log', PfbConfig::read('global_log'), 'after write "disabled_log" -> "disabled_log"');
	}

	/**
	 * suppression: absent → '' (registry default; prior page did `config_get_path(...) ?: ''`).
	 */
	public function testSuppressionAbsentDefaultIsEmptyString(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/suppression';

		// Before: key absent.
		$this->assertNull(config_get_path($path), 'suppression must be absent before read');

		// When: gateway read.
		$result = PfbConfig::read('suppression');

		// Then: '' — parity with prior page coalesce `?: ''`.
		$this->assertSame('', $result, 'suppression absent -> "" (parity with prior page fallback)');
	}

	/**
	 * suppression round-trip: write a base64 blob, read it back byte-identically.
	 */
	public function testSuppressionRoundTrips(): void
	{
		$blob = base64_encode("example.com\r\n.blocked.net\r\n");

		// Before: absent → ''.
		$this->assertSame('', PfbConfig::read('suppression'), 'initial absent -> ""');

		// When: write a base64 blob.
		PfbConfig::write('suppression', $blob);

		// Then: read back byte-identically.
		$this->assertSame($blob, PfbConfig::read('suppression'), 'suppression after write round-trips byte-identically');
	}

	/**
	 * tldexclusion: absent → '' (registry default; prior page did `config_get_path(...) ?: ''`).
	 */
	public function testTldExclusionAbsentDefaultIsEmptyString(): void
	{
		$path = 'installedpackages/pfblockerngdnsblsettings/config/0/tldexclusion';

		// Before: key absent.
		$this->assertNull(config_get_path($path), 'tldexclusion must be absent before read');

		// When: gateway read.
		$result = PfbConfig::read('tldexclusion');

		// Then: '' — parity with prior page coalesce `?: ''`.
		$this->assertSame('', $result, 'tldexclusion absent -> "" (parity with prior page fallback)');
	}

	/**
	 * tldexclusion round-trip: write a base64 blob, read it back byte-identically.
	 */
	public function testTldExclusionRoundTrips(): void
	{
		$blob = base64_encode("example.com\r\n.test.org\r\n");

		// Before: absent → ''.
		$this->assertSame('', PfbConfig::read('tldexclusion'), 'initial absent -> ""');

		// When: write a base64 blob.
		PfbConfig::write('tldexclusion', $blob);

		// Then: read back byte-identically.
		$this->assertSame($blob, PfbConfig::read('tldexclusion'), 'tldexclusion after write round-trips byte-identically');
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
	 * v4suppression is a pfblockerngipsettings key (foreign section) — registry lookup must throw.
	 */
	public function testV4SuppressionIsNotInRegistry(): void
	{
		$this->expectException(InvalidArgumentException::class);
		PfbConfig::read('v4suppression');
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
	 * suppression + tldexclusion together in their section: both registered keys.
	 * Write both via PfbConfig::write(), then read both via PfbConfig::read().
	 */
	public function testSuppressionAndTldExclusionCoexistInSection(): void
	{
		$suppblob = base64_encode("example.com\r\n");
		$tldblob  = base64_encode(".test.org\r\n");

		// When: write both registered keys.
		PfbConfig::write('suppression', $suppblob);
		PfbConfig::write('tldexclusion', $tldblob);

		// Then: each reads back independently and byte-identically.
		$this->assertSame($suppblob, PfbConfig::read('suppression'), 'suppression after write');
		$this->assertSame($tldblob, PfbConfig::read('tldexclusion'), 'tldexclusion after write');
	}
}
