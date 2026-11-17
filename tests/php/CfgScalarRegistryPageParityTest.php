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
		yield 'aliaslog' => ['dnsbl/aliaslog', self::DNSBL . '/aliaslog', 'enabled'];
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

}
