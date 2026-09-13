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

	/** @return array<string,array{0:string}> every recognised storage value: the ''
	 *  no-override sentinel plus the seven concrete mode tokens (NODATA included). */
	public static function recognisedTokenProvider(): array
	{
		$cases = ['no override (empty string)' => ['']];
		foreach (['enabled', 'disabled_log', 'disabled', 'nxdomain_log', 'nxdomain', 'nodata_log', 'nodata'] as $token) {
			$cases[$token] = [$token];
		}
		return $cases;
	}

	// -----------------------------------------------------------------------
	// A — pfb_registry_pass(): no grandfather, no NEWCFG/OLDCFG divergence
	// -----------------------------------------------------------------------

	/**
	 * A genuinely fresh DNSBL section (NEWCFG) seeds global_log at the registered
	 * default '' (No Global mode) — the #3243 mistake is reverted — and leaves
	 * pfb_hsts at its own already-decided On default: the two defaults are
	 * independent registry rows, and this fix must not regress the other.
	 */
	public function testFreshNewcfgDnsblSectionDefaultsGlobalLogToEmptyAndKeepsHstsOn(): void
	{
		$sections = [self::DNSBL_SECTION => []];

		$result = pfb_registry_pass($sections);

		$this->assertSame('', $result[self::DNSBL_SECTION]['global_log'] ?? NULL,
			'NEWCFG must seed the registered default "" (No Global mode) — not the alpha-only disabled_log'
		);
		$this->assertSame('on', $result[self::DNSBL_SECTION]['pfb_hsts'] ?? NULL,
			'the HSTS On default must be unaffected by the global_log default fix'
		);

		$this->assertSecondPassIsEmpty($sections);
	}

	/**
	 * OLDCFG (a real install), global_log absent entirely: seeds the SAME
	 * registered default '' as NEWCFG. There is no grandfather map for this key
	 * (issue #1921 classification 'no_grandfather' — absent-key fallback always
	 * equalled the current default, v3.2.16 through today), so OLDCFG and NEWCFG
	 * behave identically here; #3243's mistaken 'none'/grandfather machinery is
	 * gone, not replaced by another migration.
	 */
	public function testOldcfgAbsentGlobalLogAlsoSeedsEmpty(): void
	{
		$sections = [self::DNSBL_SECTION => ['pfb_dnsbl' => 'on']];

		$result = pfb_registry_pass($sections);

		$this->assertSame('', $result[self::DNSBL_SECTION]['global_log'] ?? NULL,
			'an existing install with global_log entirely absent must seed the same "" default as a fresh install — no grandfather divergence'
		);

		$this->assertSecondPassIsEmpty($sections);
	}

	/**
	 * OLDCFG, global_log already an explicit recognised value (the "" no-override
	 * sentinel included, and both NODATA tokens): every one of them survives the
	 * pass untouched — an already-present value is never rewritten, and there is
	 * no map to canonicalise anything into.
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

	// -----------------------------------------------------------------------
	// B — PfbConfig gateway: plain-scalar round trip (no adapter)
	// -----------------------------------------------------------------------

	public function testGlobalLogNotConfiguredDefaultIsEmptyString(): void
	{
		$this->assertNull(config_get_path(self::GLOBAL_LOG_PATH), 'global_log must be absent before read');

		$this->assertSame('', PfbConfig::read('dnsbl/global_log'),
			'a never-configured install must read the registered default "" (No Global mode)'
		);
	}

	/** Every recognised value (the "" no-override sentinel and both NODATA tokens
	 *  included) round-trips through PfbConfig::write/read byte-identically — the
	 *  field carries no adapter, so nothing besides an explicit write ever changes
	 *  it. */
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
}
