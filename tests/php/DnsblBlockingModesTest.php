<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Global mode is opt-in; null blocking defaults belong to new DNSBL groups.
 * Install/upgrade and settings saves must preserve supported explicit choices.
 */
final class DnsblBlockingModesTest extends TestCase
{
	private const DNSBL_SECTION   = 'installedpackages/pfblockerngdnsblsettings/config/0';
	private const GLOBAL_LOG_PATH = self::DNSBL_SECTION . '/global_log';

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
	}

	/**
	 * issue #1921 verification 4, scoped to one fixture: apply the pass's own output
	 * back over its input and run again — the second pass must change nothing.
	 *
	 * @param array<string,array<string,mixed>> $sections
	 */
	private function assertSecondPassIsEmpty(array $sections, string $message = ''): void
	{
		$first  = pfb_registry_pass($sections);
		$merged = $sections;
		foreach ($first as $section => $blob) {
			$merged[$section] = $blob;
		}
		$second = pfb_registry_pass($merged);
		$this->assertSame([], $second,
			$message !== '' ? $message : 'a second pass over the first pass\'s own output must change nothing'
		);
	}

	/** @return array<string,array{0:string}> The seven supported concrete mechanisms. */
	public static function recognisedTokenProvider(): array
	{
		$cases = [];
		foreach (['enabled', 'disabled_log', 'disabled', 'nxdomain_log', 'nxdomain', 'nodata_log', 'nodata'] as $token) {
			$cases[$token] = [$token];
		}
		return $cases;
	}


	// -----------------------------------------------------------------------
	// A — pfb_registry_pass(): issue #3288 grandfather map (ABSENT/'' -> 'enabled')
	// -----------------------------------------------------------------------

	/**
	 * A genuinely fresh DNSBL section (NEWCFG) seeds global_log at the registered
	 * default 'disabled_log' (Null Blocking, logging) -- issue #3288's fresh-install
	 * default -- and leaves pfb_hsts at its own already-decided On default: the two
	 * defaults are independent registry rows, and this fix must not regress the other.
	 */
	public function testFreshNewcfgDnsblSectionDefaultsGlobalLogToDisabledLogAndKeepsHstsOn(): void
	{
		$sections = [self::DNSBL_SECTION => []];

		$result = pfb_registry_pass($sections);

		$this->assertSame('disabled_log', $result[self::DNSBL_SECTION]['global_log'] ?? NULL,
			'NEWCFG must seed the registered default "disabled_log" (issue #3288 fresh-install default)'
		);
		$this->assertSame('on', $result[self::DNSBL_SECTION]['pfb_hsts'] ?? NULL,
			'the HSTS On default must be unaffected by the global_log default fix'
		);

		$this->assertSecondPassIsEmpty($sections);
	}

	/**
	 * OLDCFG (a real install), global_log absent entirely: issue #3288's grandfather
	 * map (ABSENT -> 'enabled') fires -- the grandfathered WebServer/VIP mechanism
	 * for an existing install with no prior global override, NOT the fresh
	 * 'disabled_log' default NEWCFG takes.
	 */
	public function testOldcfgAbsentGlobalLogGrandfathersToEnabled(): void
	{
		$sections = [self::DNSBL_SECTION => ['pfb_dnsbl' => 'on']];

		$result = pfb_registry_pass($sections);

		$this->assertSame('enabled', $result[self::DNSBL_SECTION]['global_log'] ?? NULL,
			'an existing install with global_log entirely absent must grandfather to "enabled", never the fresh default'
		);

		$this->assertSecondPassIsEmpty($sections);
	}

	/**
	 * OLDCFG, global_log already an explicit CONCRETE value (NODATA tokens
	 * included, '' excluded -- see testOldcfgExplicitEmptyGrandfathersToEnabled):
	 * every one of them survives the pass untouched -- an already-present concrete
	 * value is never rewritten, and the grandfather map only has ABSENT/'' entries.
	 */
	#[DataProvider('recognisedTokenProvider')]
	public function testOldcfgExplicitRecognisedValuesPreserved(string $token): void
	{
		$sections = [self::DNSBL_SECTION => ['pfb_dnsbl' => 'on', 'global_log' => $token]];

		$result = pfb_registry_pass($sections);
		$stored = $result[self::DNSBL_SECTION]['global_log'] ?? NULL;

		$this->assertSame($token, $stored, "an already-stored '{$token}' must survive the pass unchanged");

		$this->assertSecondPassIsEmpty($sections);
	}

	/**
	 * issue #3288: an explicitly-stored '' (the retired no-override sentinel) is
	 * now grandfathered exactly like ABSENT -- both meant "no override" under the
	 * retired single-field scheme, so both must land on the SAME grandfathered
	 * mechanism.
	 */
	public function testOldcfgExplicitEmptyGrandfathersToEnabled(): void
	{
		$sections = [self::DNSBL_SECTION => ['pfb_dnsbl' => 'on', 'global_log' => '']];

		$result = pfb_registry_pass($sections);

		$this->assertSame('enabled', $result[self::DNSBL_SECTION]['global_log'] ?? NULL,
			'an explicitly-stored "" must grandfather to "enabled", the same as an absent key'
		);

		$this->assertSecondPassIsEmpty($sections);
	}

	// -----------------------------------------------------------------------
	// B — PfbConfig gateway: plain-scalar round trip (no adapter)
	// -----------------------------------------------------------------------

	public function testGlobalLogNotConfiguredDefaultIsDisabledLog(): void
	{
		$this->assertNull(config_get_path(self::GLOBAL_LOG_PATH), 'global_log must be absent before read');

		$this->assertSame('disabled_log', PfbConfig::read('dnsbl/global_log'),
			'a never-configured install must read the registered default "disabled_log" (issue #3288)'
		);
	}

	/** Supported concrete mechanisms round-trip through the gateway. */
	#[DataProvider('recognisedTokenProvider')]
	public function testGlobalLogRecognisedValuesRoundTripThroughTheGateway(string $token): void
	{
		PfbConfig::write('dnsbl/global_log', $token);

		$this->assertSame($token, PfbConfig::read('dnsbl/global_log'),
			"PfbConfig::write/read must round-trip '{$token}' byte-identically"
		);
		$this->assertSame($token, config_get_path(self::GLOBAL_LOG_PATH),
			"'{$token}' must be the exact stored byte — the field carries no adapter"
		);
	}

	// -----------------------------------------------------------------------
	// C — an unrelated field save must never disturb an explicit override choice
	// -----------------------------------------------------------------------

	/**
	 * The read-modify-write shape every settings page save handler uses (readSection ->
	 * change one field -> writeSection) must carry an explicit override choice along
	 * unchanged — a page save touching some OTHER DNSBL field must never silently
	 * reset an explicitly-chosen override back to the "" default.
	 */
	public function testWriteSectionOnAnUnrelatedFieldPreservesAnExplicitOverride(): void
	{
		$data                = PfbConfig::readSection(self::DNSBL_SECTION);
		$data['global_log']  = 'disabled_log';
		$data['pfb_dnsbl']   = 'on';
		PfbConfig::writeSection(self::DNSBL_SECTION, $data);

		$this->assertSame('disabled_log', PfbConfig::read('dnsbl/global_log'),
			'the explicit override choice must survive its own section write'
		);

		$data2                 = PfbConfig::readSection(self::DNSBL_SECTION);
		$data2['top1m_source'] = 'cisco';
		PfbConfig::writeSection(self::DNSBL_SECTION, $data2);

		$this->assertSame('disabled_log', PfbConfig::read('dnsbl/global_log'),
			'an unrelated field save must not disturb the explicit override choice'
		);
	}

	public function testNullPolicyValueDoesNotMakeCurrentConfigurationLegacy(): void
	{
		$policy = pfb_dnsbl_policy_config([
			'global_log_mode' => NULL,
			'global_log' => 'disabled_log',
		], []);

		$this->assertFalse($policy['legacy'], 'a present policy key must not reactivate legacy projection');
		$this->assertSame(PfbDnsblGlobalMode::Default, $policy['mode']);
		$this->assertSame('enabled', pfb_dnsbl_effective_logging(
			'enabled', $policy['mechanism'], $policy['mode'], $policy['legacy']
		), 'invalid current policy must not force an explicit VIP group onto the global null mechanism');
	}

	public function testLegacyZeroStringDoesNotActivateAnOverride(): void
	{
		$policy = pfb_dnsbl_policy_config(['global_log' => '0'], []);

		$this->assertSame(PfbDnsblGlobalMode::Default, $policy['mode']);
		$this->assertSame('nxdomain', pfb_dnsbl_effective_logging(
			'nxdomain', $policy['mechanism'], $policy['mode'], $policy['legacy']
		), 'legacy falsy global values must not mask an explicit group mechanism');
	}
}
