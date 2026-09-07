<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3243 — null blocking (with logging) becomes the DEFAULT DNSBL global mode for
 * NEW configurations; existing installs are grandfathered; NODATA (RFC 2308 Type-2,
 * flags 5/6) joins the logging/blocking vocabulary.
 *
 * Storage-token contract (pinned against the real pfb_registry_pass()/PfbConfig gateway,
 * never source text or a hand-copied mapping):
 *
 *   - dnsbl/global_log's registered default becomes 'disabled_log' (was ''). A genuinely
 *     fresh DNSBL section (NEWCFG) seeds this value on install.
 *   - The historical "no global override" storage byte '' is CANONICALISED to the new
 *     literal token 'none' by pfb_registry_pass()'s OLDCFG grandfather map, for BOTH a
 *     truly-absent key and an explicitly-stored '' — an already-configured install keeps
 *     deferring to each group's own per-list setting, it just spells that choice 'none'
 *     from here on (a '' grandfather-map OUTPUT is otherwise banned by
 *     CfgRegistryGrandfatherGateTest::testGrandfatherMapsAreStringToStringWithCanonicalShapes,
 *     which is why the canonical token cannot itself be the historical empty byte). Every
 *     other explicit token (enabled/disabled_log/disabled/nxdomain_log/nxdomain/
 *     nodata_log/nodata/none-already-stored) passes through OLDCFG unchanged.
 *   - The field stays a plain scalar (no read/write adapter): PfbConfig::read/write round
 *     trip every token, including 'none', byte-identically at runtime; only the ONE-TIME
 *     install/upgrade pass performs the '' -> 'none' canonicalisation.
 *
 * NODATA itself (RFC 2308 Type-2: NOERROR, empty ANSWER, SOA in AUTHORITY, resolver cache
 * disabled, real per-group counters, reusing pfb_unbound.py's DNSBL_NODATA_SOA_RDATA) is a
 * Python-side runtime behaviour outside this file's PHP-gateway scope; here NODATA is
 * covered strictly as two more recognised dnsbl/global_log storage tokens.
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

	/** @return array<string,array{0:string}> every recognised token, 'none' included. */
	public static function explicitTokenProvider(): array
	{
		$cases = [];
		foreach (['none', 'enabled', 'disabled_log', 'disabled', 'nxdomain_log', 'nxdomain', 'nodata_log', 'nodata'] as $token) {
			$cases[$token] = [$token];
		}
		return $cases;
	}

	// -----------------------------------------------------------------------
	// A — pfb_registry_pass(): NEWCFG default + OLDCFG grandfather
	// -----------------------------------------------------------------------

	/**
	 * A genuinely fresh DNSBL section (NEWCFG) seeds global_log at the new default,
	 * disabled_log, and leaves pfb_hsts at its own already-decided On default — the two
	 * defaults are independent registry rows, and this change must not regress the other
	 * (the ticket explicitly keeps HSTS refresh behaviour unchanged).
	 */
	public function testFreshNewcfgDnsblSectionDefaultsGlobalLogToDisabledLogAndKeepsHstsOn(): void
	{
		$sections = [self::DNSBL_SECTION => []];

		$result = pfb_registry_pass($sections);

		$this->assertSame('disabled_log', $result[self::DNSBL_SECTION]['global_log'] ?? NULL,
			'NEWCFG must seed the new default disabled_log (null blocking with logging)'
		);
		$this->assertSame('on', $result[self::DNSBL_SECTION]['pfb_hsts'] ?? NULL,
			'the HSTS On default must be unaffected by the global_log default change'
		);

		$this->assertSecondPassIsEmpty($sections);
	}

	/**
	 * OLDCFG (a real install), global_log absent entirely: grandfathered to the
	 * canonical no-override token 'none' — NOT the new NEWCFG default. This is the
	 * "grandfather existing configurations" half of the issue.
	 */
	public function testOldcfgAbsentGlobalLogGrandfathersToNoneToken(): void
	{
		$sections = [self::DNSBL_SECTION => ['pfb_dnsbl' => 'on']];

		$result = pfb_registry_pass($sections);

		$this->assertSame('none', $result[self::DNSBL_SECTION]['global_log'] ?? NULL,
			'an existing install with global_log entirely absent must grandfather to the '
			. 'no-override token none, not the fresh-install default disabled_log'
		);

		$this->assertSecondPassIsEmpty($sections);
	}

	/**
	 * OLDCFG, global_log explicitly stored as the historical '' no-override byte:
	 * canonicalised to 'none' — same outcome as the absent case, same reason. '' is a
	 * stored value, not absence, but it carries the identical no-override meaning.
	 */
	public function testOldcfgExplicitEmptyGlobalLogCanonicalisesToNoneToken(): void
	{
		$sections = [self::DNSBL_SECTION => ['pfb_dnsbl' => 'on', 'global_log' => '']];

		$result = pfb_registry_pass($sections);

		$this->assertSame('none', $result[self::DNSBL_SECTION]['global_log'] ?? NULL,
			'an explicit stored empty string must canonicalise to none identically to the absent case'
		);

		$this->assertSecondPassIsEmpty($sections);
	}

	/**
	 * OLDCFG, global_log already an explicit recognised token (the canonical 'none'
	 * included, and both new NODATA tokens): every one of them survives the pass
	 * untouched — an already-canonical value is never rewritten.
	 */
	#[DataProvider('explicitTokenProvider')]
	public function testOldcfgExplicitRecognisedTokensPreserved(string $token): void
	{
		$sections = [self::DNSBL_SECTION => ['pfb_dnsbl' => 'on', 'global_log' => $token]];

		$result = pfb_registry_pass($sections);
		$stored = $result[self::DNSBL_SECTION]['global_log'] ?? $token;

		$this->assertSame($token, $stored, "an already-stored '{$token}' must survive the pass unchanged");

		$this->assertSecondPassIsEmpty($sections);
	}

	// -----------------------------------------------------------------------
	// B — PfbConfig gateway: plain-scalar round trip (no adapter)
	// -----------------------------------------------------------------------

	public function testGlobalLogNotConfiguredDefaultIsDisabledLog(): void
	{
		$this->assertNull(config_get_path(self::GLOBAL_LOG_PATH), 'global_log must be absent before read');

		$this->assertSame('disabled_log', PfbConfig::read('dnsbl/global_log'),
			'a never-configured install must read the new default disabled_log'
		);
	}

	/** Every recognised token (the canonical 'none' and both NODATA tokens included)
	 *  round-trips through PfbConfig::write/read byte-identically — the field carries
	 *  no adapter, so nothing besides the ONE-TIME registry pass ever rewrites it. */
	#[DataProvider('explicitTokenProvider')]
	public function testGlobalLogRecognisedTokensRoundTripThroughTheGateway(string $token): void
	{
		PfbConfig::write('dnsbl/global_log', $token);

		$this->assertSame($token, PfbConfig::read('dnsbl/global_log'),
			"PfbConfig::write/read must round-trip '{$token}' byte-identically"
		);
		$this->assertSame($token, config_get_path(self::GLOBAL_LOG_PATH),
			"'{$token}' must be the exact stored byte — the field carries no adapter"
		);
	}

	/**
	 * The canonical no-override token 'none' is a genuinely DIFFERENT runtime state
	 * from "never configured" — an operator who explicitly chooses no override must
	 * read back 'none', never silently promoted to the disabled_log default.
	 */
	public function testGlobalLogExplicitNoneDiffersFromNotConfigured(): void
	{
		$this->assertSame('disabled_log', PfbConfig::read('dnsbl/global_log'), 'before: not configured -> disabled_log');

		PfbConfig::write('dnsbl/global_log', 'none');

		$this->assertSame('none', PfbConfig::read('dnsbl/global_log'),
			'after an explicit none write, the gateway must read none back, not disabled_log'
		);
	}

	// -----------------------------------------------------------------------
	// C — an unrelated field save must never disturb an explicit no-override
	// -----------------------------------------------------------------------

	/**
	 * The read-modify-write shape every settings page save handler uses (readSection ->
	 * change one field -> writeSection) must carry an explicit no-override choice along
	 * unchanged — a page save touching some OTHER DNSBL field must never silently
	 * promote a stored 'none' to the new NEWCFG default.
	 */
	public function testWriteSectionOnAnUnrelatedFieldPreservesExplicitNoOverride(): void
	{
		$data                = PfbConfig::readSection(self::DNSBL_SECTION);
		$data['global_log']  = 'none';
		$data['pfb_dnsbl']   = 'on';
		PfbConfig::writeSection(self::DNSBL_SECTION, $data);

		$this->assertSame('none', PfbConfig::read('dnsbl/global_log'),
			'the explicit no-override choice must survive its own section write'
		);

		$data2                 = PfbConfig::readSection(self::DNSBL_SECTION);
		$data2['top1m_source'] = 'cisco';
		PfbConfig::writeSection(self::DNSBL_SECTION, $data2);

		$this->assertSame('none', PfbConfig::read('dnsbl/global_log'),
			'an unrelated field save must not disturb the explicit no-override choice'
		);
	}
}
