<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #2123 — the 17 PFB_FILTER_ON_OFF toggles whose default used to be declared in
 * the page rather than in pfb_cfg_registry().
 *
 * The claim these tests have to make checkable is a PARITY claim, not a preference:
 * reading each newly registered field through PfbConfig on a configuration that
 * predates the registration must resolve to exactly the value the page produced
 * before. So the deleted page expression is not described here, it is RE-EVALUATED:
 * preRegistrationPageValue() below is a transcription of the two expression shapes
 * the pages carried at b91b95cc, and every row compares the gateway against it.
 *
 * Two shapes, quoted from the pre-#2123 sources:
 *
 *   FALSY_EMPTY (16 fields) — e.g. pfblockerng_ip.php:39
 *       $pconfig['enable_dup'] = $pfb['iconfig']['enable_dup'] ?: '';
 *       ... rendered as pfb_cfg_toggle_read($pconfig['enable_dup']) === PfbToggle::On
 *     so: absent and every falsy token collapse to '' and read Off.
 *
 *   ISSET_ON (1 field) — pfblockerng_alerts.php:41
 *       $alertrefresh = isset($pfb['aglobal']['alertrefresh'])
 *           ? $pfb['aglobal']['alertrefresh'] : 'on';
 *       ... rendered as pfb_cfg_toggle_read($alertrefresh) === PfbToggle::On
 *     so: ONLY a genuinely absent key falls back to 'on'; a stored '' is an operator
 *     uncheck and reads Off. This is the dangerous one — a registered default of ''
 *     would invert it for every install that never touched the checkbox, and a
 *     registry that resolved '' to the default would invert it for every operator
 *     who unchecked it. Both directions are pinned below.
 *
 * The matrix is deliberately wider than the two states pfSense itself writes: the
 * supported producers of a foreign token are an area restore, an XMLRPC HA receive
 * and a hand-edited config.xml (issue #2120's executed evidence), so legacy 'off',
 * case variants and junk all carry a pinned expectation.
 */
final class CfgToggleRegistryPageParityTest extends TestCase
{
	/** $blob[$key] ?: '<default>' — absent and every falsy token collapse to the default. */
	private const SHAPE_FALSY_EMPTY = 'falsy_empty';

	/** isset($blob[$key]) ? $blob[$key] : 'on' — only genuine absence takes the default. */
	private const SHAPE_ISSET_ON = 'isset_on';

	/**
	 * The 17 fields: registry path key => [config.xml section path, pre-#2123 page
	 * expression site, expression shape].
	 *
	 * @var array<string,array{0:string,1:string,2:string}>
	 */
	private const FIELDS = [
		// pfblockerng_ip.php — IP-settings section scalars.
		'ip/enable_dup'   => ['installedpackages/pfblockerngipsettings/config/0', 'pfblockerng_ip.php:39', self::SHAPE_FALSY_EMPTY],
		'ip/enable_agg'   => ['installedpackages/pfblockerngipsettings/config/0', 'pfblockerng_ip.php:40', self::SHAPE_FALSY_EMPTY],
		'ip/enable_log'   => ['installedpackages/pfblockerngipsettings/config/0', 'pfblockerng_ip.php:59', self::SHAPE_FALSY_EMPTY],
		'ip/enable_rdns'  => ['installedpackages/pfblockerngipsettings/config/0', 'pfblockerng_ip.php:60', self::SHAPE_FALSY_EMPTY],
		'ip/database_cc'  => ['installedpackages/pfblockerngipsettings/config/0', 'pfblockerng_ip.php:65', self::SHAPE_FALSY_EMPTY],
		'ip/enable_float' => ['installedpackages/pfblockerngipsettings/config/0', 'pfblockerng_ip.php:75', self::SHAPE_FALSY_EMPTY],
		'ip/killstates'   => ['installedpackages/pfblockerngipsettings/config/0', 'pfblockerng_ip.php:78', self::SHAPE_FALSY_EMPTY],

		// pfblockerng_dnsbl.php — DNSBL-settings section scalars behind the two
		// "Advanced In/Outbound Firewall Rule Settings" panels (:3602, :3611, :3641,
		// :3649 render them with a dynamic field name over a static stored key).
		'dnsbl/autoaddrnot_in'  => ['installedpackages/pfblockerngdnsblsettings/config/0', 'pfblockerng_dnsbl.php:111', self::SHAPE_FALSY_EMPTY],
		'dnsbl/autoports_in'    => ['installedpackages/pfblockerngdnsblsettings/config/0', 'pfblockerng_dnsbl.php:112', self::SHAPE_FALSY_EMPTY],
		'dnsbl/autoaddr_in'     => ['installedpackages/pfblockerngdnsblsettings/config/0', 'pfblockerng_dnsbl.php:114', self::SHAPE_FALSY_EMPTY],
		'dnsbl/autonot_in'      => ['installedpackages/pfblockerngdnsblsettings/config/0', 'pfblockerng_dnsbl.php:115', self::SHAPE_FALSY_EMPTY],
		'dnsbl/autoaddrnot_out' => ['installedpackages/pfblockerngdnsblsettings/config/0', 'pfblockerng_dnsbl.php:120', self::SHAPE_FALSY_EMPTY],
		'dnsbl/autoports_out'   => ['installedpackages/pfblockerngdnsblsettings/config/0', 'pfblockerng_dnsbl.php:121', self::SHAPE_FALSY_EMPTY],
		'dnsbl/autoaddr_out'    => ['installedpackages/pfblockerngdnsblsettings/config/0', 'pfblockerng_dnsbl.php:123', self::SHAPE_FALSY_EMPTY],
		'dnsbl/autonot_out'     => ['installedpackages/pfblockerngdnsblsettings/config/0', 'pfblockerng_dnsbl.php:124', self::SHAPE_FALSY_EMPTY],

		// pfblockerng_sync.php — XMLRPC-sync section scalar.
		'sync/syncinterfaces' => ['installedpackages/pfblockerngsync/config/0', 'pfblockerng_sync.php:35', self::SHAPE_FALSY_EMPTY],

		// pfblockerng_alerts.php — the default-On survivor of the 3.2 arrangement.
		'global/alertrefresh' => ['installedpackages/pfblockerngglobal', 'pfblockerng_alerts.php:41', self::SHAPE_ISSET_ON],
	];

	/**
	 * Raw stored states a pre-registration configuration can present. NULL is the
	 * genuinely absent key; every other row is a value physically present in
	 * config.xml.
	 *
	 * @var array<string,mixed>
	 */
	private const RAW_STATES = [
		'absent'      => NULL,
		'empty'       => '',
		'canonical'   => 'on',
		'legacy_off'  => 'off',
		'case_On'     => 'On',
		'case_OFF'    => 'OFF',
		'junk_yes'    => 'yes',
		'junk_one'    => '1',
		'junk_zero'   => '0',
	];

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
	}

	/**
	 * The pre-#2123 page expression, transcribed. Given the RAW stored value, return
	 * the PfbToggle the page's render comparison saw.
	 */
	private static function preRegistrationPageValue(string $shape, mixed $raw): PfbToggle
	{
		if ($shape === self::SHAPE_ISSET_ON) {
			// isset($blob[$k]) ? $blob[$k] : 'on'  --  a stored '' is set, so it stays ''.
			return pfb_cfg_toggle_read($raw === NULL ? 'on' : $raw);
		}

		// $blob[$k] ?: ''
		return pfb_cfg_toggle_read($raw ?: '');
	}

	/** @return iterable<string,array{0:string,1:string,2:string,3:string,4:mixed}> */
	public static function fieldRawMatrix(): iterable
	{
		foreach (self::FIELDS as $path_key => [$section, $site, $shape]) {
			foreach (self::RAW_STATES as $state => $raw) {
				yield "{$path_key} [{$state}]" => [$path_key, $section, $shape, $site, $raw];
			}
		}
	}

	/**
	 * Scenario:
	 *   Background: a configuration written before #2123 registered these keys.
	 *   Given one of the 17 keys holds raw stored value v (or is absent).
	 *   When PfbConfig::read('<alias>/<key>') resolves it.
	 *   Then the result equals what the page's own pre-registration expression
	 *        produced for the same v — the registry took over the declaration
	 *        without taking over the behaviour.
	 */
	#[DataProvider('fieldRawMatrix')]
	public function testGatewayReadReproducesThePreRegistrationPageValue(
		string $path_key,
		string $section,
		string $shape,
		string $site,
		mixed $raw
	): void {
		$bare = substr($path_key, strpos($path_key, '/') + 1);
		if ($raw !== NULL) {
			config_set_path("{$section}/{$bare}", $raw);
		}

		// Before: the raw state is exactly what a pre-#2123 config presents.
		$this->assertSame($raw, config_get_path("{$section}/{$bare}"),
			"before: {$path_key} raw stored state");

		$expected = self::preRegistrationPageValue($shape, $raw);

		// When/Then.
		$this->assertSame($expected, PfbConfig::read($path_key), sprintf(
			'%s: gateway read must equal the pre-#2123 %s expression (%s) for raw %s',
			$path_key, $shape, $site, var_export($raw, TRUE)
		));
	}

	/**
	 * The Alerts auto-refresh inversion, pinned in both directions.
	 *
	 * Scenario:
	 *   Given the Alerts page defaulted alertrefresh to 'on' via isset() and stored
	 *     '' for an operator's uncheck (pfblockerng_alerts.php:41 and :603).
	 *   When the key is registered.
	 *   Then an install that never touched the checkbox still reads On, and an
	 *     operator who unchecked it still reads Off. A registered default of '',
	 *     or a gateway that resolved a stored '' to the default, flips one of them.
	 */
	public function testAlertRefreshKeepsOnDefaultAndHonoursADeliberateUncheck(): void
	{
		$path = 'installedpackages/pfblockerngglobal/alertrefresh';

		// Never configured -> On (the page's isset() fallback).
		$this->assertNull(config_get_path($path), 'before: alertrefresh absent');
		$this->assertSame(PfbToggle::On, PfbConfig::read('global/alertrefresh'),
			'absent alertrefresh must read On — the registered default carries the '
			. 'page-level default deleted from pfblockerng_alerts.php:41');

		// Operator unchecked the box: PFB_FILTER_ON_OFF stored '' -> Off.
		config_set_path($path, '');
		$this->assertSame(PfbToggle::Off, PfbConfig::read('global/alertrefresh'),
			"stored '' alertrefresh must read Off — an unchecked box is not "
			. 'the default (issue #2120 owner ruling)');

		// And the canonical On token still reads On.
		config_set_path($path, 'on');
		$this->assertSame(PfbToggle::On, PfbConfig::read('global/alertrefresh'),
			"stored 'on' alertrefresh must read On");
	}

	/**
	 * The one runtime consumer that compared the stored token by hand
	 * (pfblockerng.inc's XMLRPC sync section chooser, twice) keeps its verdict.
	 *
	 * Scenario:
	 *   Given the pre-#2123 test was config_get_path(...) != 'on'.
	 *   When the same raw state is read through the gateway as
	 *     PfbConfig::read('sync/syncinterfaces') !== PfbToggle::On.
	 *   Then the boolean matches for every token pfSense or the package writes,
	 *     and differs ONLY for a case variant of 'on' — which #1887 deliberately
	 *     accepts so a hand-edited or HA-synced 'On' cannot silently disable a
	 *     feature the operator enabled.
	 */
	public function testSyncInterfacesGatewayReadMatchesTheHandWrittenTokenTest(): void
	{
		$path = 'installedpackages/pfblockerngsync/config/0/syncinterfaces';

		// [raw, pre-#2123 (raw != 'on'), gateway (read !== On)]
		$rows = [
			['absent',     NULL,  TRUE,  TRUE],
			['empty',      '',    TRUE,  TRUE],
			['canonical',  'on',  FALSE, FALSE],
			['legacy_off', 'off', TRUE,  TRUE],
			['junk',       'yes', TRUE,  TRUE],
		];

		foreach ($rows as [$label, $raw, $legacy, $gateway]) {
			$GLOBALS['config'] = [];
			if ($raw !== NULL) {
				config_set_path($path, $raw);
			}
			$this->assertSame($legacy, config_get_path($path) != 'on',
				"{$label}: pre-#2123 token comparison");
			$this->assertSame($gateway, PfbConfig::read('sync/syncinterfaces') !== PfbToggle::On,
				"{$label}: gateway read must agree with the pre-#2123 comparison");
		}

		// The single deliberate divergence, recorded rather than hidden.
		$GLOBALS['config'] = [];
		config_set_path($path, 'On');
		$this->assertTrue(config_get_path($path) != 'on',
			"pre-#2123: a hand-edited 'On' read as NOT enabled");
		$this->assertSame(PfbToggle::On, PfbConfig::read('sync/syncinterfaces'),
			"'On' now reads On — issue #1887's case-insensitive toggle read reaches "
			. 'this consumer once the key is registered, deliberately');
	}

	/**
	 * Every one of the 17 is registered, adapter-bearing, and classified. Guards the
	 * shape of the entry, not just its presence: a plain-scalar entry would leave a
	 * stored '' resolving to the default, which is the #2120 inversion again.
	 */
	public function testAllSeventeenAreRegisteredAsClassifiedToggles(): void
	{
		$registry = pfb_cfg_registry();

		foreach (array_keys(self::FIELDS) as $path_key) {
			$this->assertArrayHasKey($path_key, $registry,
				"{$path_key} must be registered (issue #2123)");
			$entry = $registry[$path_key];
			$this->assertSame('pfb_cfg_toggle_read', $entry['read_adapter'],
				"{$path_key} must carry the toggle read adapter");
			$this->assertSame('pfb_cfg_toggle_write', $entry['write_adapter'],
				"{$path_key} must carry the toggle write adapter");
			$this->assertArrayNotHasKey('grandfather', $entry,
				"{$path_key} must NOT carry a grandfather map -- the registered default IS "
				. 'the page default it replaced, so there is nothing to map');
			$this->assertArrayHasKey('no_grandfather', $entry,
				"{$path_key} must carry a no_grandfather reason");
			// The reason must identify WHY, not merely be non-empty: a gate that accepts
			// any string lets a wrong reason ship (issue #2123 review finding).
			$expected_marker = $path_key === 'ip/enable_rdns' ? '#336' : '#2123';
			$this->assertStringContainsString($expected_marker, $entry['no_grandfather'],
				"{$path_key}: the no_grandfather reason must cite the decision it records "
				. "({$expected_marker})");
		}
	}

	/**
	 * The registered defaults, spelled out. A silent flip of any of these is the
	 * behaviour change #2123 exists to prevent, so the expected value is written
	 * here as a literal rather than derived from the registry it is checking.
	 */
	public function testRegisteredDefaultsAreThePageDefaultsTheyReplaced(): void
	{
		$expected = [
			'ip/enable_dup'         => '',
			'ip/enable_agg'         => '',
			'ip/enable_log'         => '',
			'ip/enable_rdns'        => '',
			'ip/database_cc'        => '',
			'ip/enable_float'       => '',
			'ip/killstates'         => '',
			'dnsbl/autoaddrnot_in'  => '',
			'dnsbl/autoports_in'    => '',
			'dnsbl/autoaddr_in'     => '',
			'dnsbl/autonot_in'      => '',
			'dnsbl/autoaddrnot_out' => '',
			'dnsbl/autoports_out'   => '',
			'dnsbl/autoaddr_out'    => '',
			'dnsbl/autonot_out'     => '',
			'sync/syncinterfaces'   => '',
			'global/alertrefresh'   => 'on',
		];

		$this->assertSame(array_keys(self::FIELDS), array_keys($expected),
			'the default table must cover exactly the 17 fields under test');

		$registry = pfb_cfg_registry();
		foreach ($expected as $path_key => $default) {
			$this->assertSame($default, $registry[$path_key]['default'] ?? NULL,
				"{$path_key}: registered default must reproduce the deleted page default");
		}
	}
}
