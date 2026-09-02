<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #2994 — registered plain-scalar page/registry default divergences.
 *
 * Each quoted site needs an authority decision before RULE 2 can widen off
 * toggles. The gateway absent-read is the registry side of that agreement;
 * the pre-change page expression is `$blob[$key] ?: '<page default>'`.
 *
 * Decisions (page render of an absent key is the operator-visible contract):
 *
 *   pfb_dnsport / pfb_dnsport_ssl — PAGE. The DNSBL form, the save-site
 *     `?: '8081'`/`?: '8443'`, and the smoke harness all treat those as the
 *     listening ports; registry `''` would empty the inputs and abort DNSBL
 *     (`DNSBL Ports are not defined`) on a never-saved config.
 *   aliaslog — PAGE. The select options are only `enabled`/`disabled`, the
 *     help text says Default Enable, and the save-site falls back to
 *     `enabled`. Registry `''` is not a valid option.
 *   pfb_dnsbl_rule — REGISTRY. The apply path coalesces with `?: 'Disabled'`
 *     and compares `!= 'Disabled'`. The page checkbox runs the value through
 *     `pfb_cfg_toggle_read(...) === PfbToggle::On`, so both `''` and
 *     `Disabled` render unchecked. Routing the page through the gateway keeps
 *     the apply-path Off token.
 *   pfb_dnsvip4 / pfb_dnsvip6 — REGISTRY `''`. Page `'none'` is the Form_Select
 *     empty-option sentinel (save maps `none` → `''` before persist). The
 *     widget mapping stays next to the control; it is not the stored default.
 */
final class CfgScalarRegistryPageParityTest extends TestCase
{
	private const DNSBL = 'installedpackages/pfblockerngdnsblsettings/config/0';

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
	}

	/**
	 * @return iterable<string,array{0:string,1:string,2:string}>
	 */
	public static function absentDefaults(): iterable
	{
		yield 'pfb_dnsport' => ['dnsbl/pfb_dnsport', self::DNSBL . '/pfb_dnsport', '8081'];
		yield 'pfb_dnsport_ssl' => ['dnsbl/pfb_dnsport_ssl', self::DNSBL . '/pfb_dnsport_ssl', '8443'];
		yield 'aliaslog' => ['dnsbl/aliaslog', self::DNSBL . '/aliaslog', 'enabled'];
		yield 'pfb_dnsbl_rule' => ['dnsbl/pfb_dnsbl_rule', self::DNSBL . '/pfb_dnsbl_rule', 'Disabled'];
		yield 'pfb_dnsvip4' => ['dnsbl/pfb_dnsvip4', self::DNSBL . '/pfb_dnsvip4', ''];
		yield 'pfb_dnsvip6' => ['dnsbl/pfb_dnsvip6', self::DNSBL . '/pfb_dnsvip6', ''];
		yield 'dnsbl_interface' => ['dnsbl/dnsbl_interface', self::DNSBL . '/dnsbl_interface', 'lo0'];
		yield 'action' => ['dnsbl/action', self::DNSBL . '/action', 'Disabled'];
	}

	/**
	 * Scenario:
	 *   Given a DNSBL settings key is absent from config.xml.
	 *   When PfbConfig::read() resolves it.
	 *   Then the result is the authoritative default for that site
	 *        (page for ports/aliaslog, registry for vip/rule/interface/action).
	 */
	#[DataProvider('absentDefaults')]
	public function testAbsentKeyReadsTheAuthoritativeDefault(
		string $path_key,
		string $config_path,
		string $expected
	): void {
		$this->assertNull(config_get_path($config_path), "before: {$path_key} must be absent");
		$this->assertSame($expected, PfbConfig::read($path_key), "{$path_key} absent -> {$expected}");
	}

	/**
	 * Scenario:
	 *   Given the DNSBL page save writes '' for an unchecked Permit Firewall
	 *     Rules checkbox (pfb_filter ON_OFF ?: '').
	 *   When PfbConfig::read('dnsbl/pfb_dnsbl_rule') resolves that stored empty.
	 *   Then the checkbox still reads Off — '' and the registry default
	 *        'Disabled' are the same toggle state.
	 */
	public function testDnsblRuleEmptyAndDisabledBothReadOff(): void
	{
		$this->assertSame(PfbToggle::Off, pfb_cfg_toggle_read(''));
		$this->assertSame(PfbToggle::Off, pfb_cfg_toggle_read('Disabled'));

		config_set_path(self::DNSBL . '/pfb_dnsbl_rule', '');
		$this->assertSame(
			PfbToggle::Off,
			pfb_cfg_toggle_read(PfbConfig::read('dnsbl/pfb_dnsbl_rule')),
			'stored empty Off token still renders the checkbox unchecked'
		);
	}

	/**
	 * Scenario:
	 *   Given a stored empty string on a plain-scalar port key (the page
	 *     `?: '8081'` treated '' as missing).
	 *   When PfbConfig::read() resolves it.
	 *   Then the registry default fills it the same way the page did.
	 */
	public function testEmptyPortStringResolvesToThePageDefault(): void
	{
		config_set_path(self::DNSBL . '/pfb_dnsport', '');
		$this->assertSame('8081', PfbConfig::read('dnsbl/pfb_dnsport'));
		config_set_path(self::DNSBL . '/pfb_dnsport_ssl', '');
		$this->assertSame('8443', PfbConfig::read('dnsbl/pfb_dnsport_ssl'));
	}
}
