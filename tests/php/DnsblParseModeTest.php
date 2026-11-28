<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #4272: the DNSBL feed-line parsing mode is a three-way setting.
 *  - Strict:      '(<scheme>://)?<domain>/?'.
 *  - Allow Ports: Strict plus an optional ':<1-5 digits>' port (the new-install default, and what a
 *                 stored pre-#4272 strict setting becomes -- that strict already kept 'host:port').
 *  - Lenient:     the permissive host cut ADR-22 introduced.
 * It replaces the ADR-22 'pfb_dnsbl_lenient' checkbox; an upgrade keeps each install's behaviour.
 */
final class DnsblParseModeTest extends TestCase
{
	private const DNSBL_SECTION = 'installedpackages/pfblockerngdnsblsettings/config/0';


	private mixed $savedPfb = NULL;
	private mixed $savedConfig = NULL;

	protected function setUp(): void
	{
		$this->savedPfb = $GLOBALS['pfb'] ?? NULL;
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$GLOBALS['config'] = [];
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb'] = $this->savedPfb;
		$GLOBALS['config'] = $this->savedConfig;
	}

	// -- the setting --------------------------------------------------------------------------

	/** @return array<string, array{string, PfbDnsblParseMode}> stored token => mode */
	public static function storedTokenProvider(): array
	{
		return [
			'strict'                    => ['strict', PfbDnsblParseMode::Strict],
			'allow ports'               => ['ports', PfbDnsblParseMode::Ports],
			'lenient'                   => ['lenient', PfbDnsblParseMode::Lenient],
			'pre-#4272 checked'         => ['on', PfbDnsblParseMode::Lenient],
			'pre-#4272 unchecked'       => ['', PfbDnsblParseMode::Ports],
			'pre-#4272 legacy off'      => ['off', PfbDnsblParseMode::Ports],
			'unknown token'             => ['junk', PfbDnsblParseMode::Ports],
		];
	}

	#[DataProvider('storedTokenProvider')]
	public function testEveryStoredTokenReadsAsItsMode(string $stored, PfbDnsblParseMode $mode): void
	{
		$this->assertSame($mode, pfb_cfg_dnsbl_parse_mode_read($stored));
	}

	public function testEachModeWritesItsCanonicalTokenAndRoundTrips(): void
	{
		foreach (['strict' => PfbDnsblParseMode::Strict, 'ports' => PfbDnsblParseMode::Ports, 'lenient' => PfbDnsblParseMode::Lenient] as $token => $mode) {
			$this->assertSame($token, pfb_cfg_dnsbl_parse_mode_write($mode));
			$this->assertSame($token, pfb_cfg_dnsbl_parse_mode_write(pfb_cfg_dnsbl_parse_mode_read($token)));
		}
	}

	public function testAnAbsentSettingReadsAllowPorts(): void
	{
		$this->assertNull(config_get_path(self::DNSBL_SECTION . '/pfb_dnsbl_parse_mode'));
		$this->assertSame(PfbDnsblParseMode::Ports, PfbConfig::read('dnsbl/pfb_dnsbl_parse_mode'));
	}

	/**
	 * Run the installer's registry writeback over a pre-install DNSBL section and return the
	 * parsing mode it stores.
	 *
	 * @param array<string, string> $section
	 */
	private function installedMode(array $section): ?string
	{
		config_set_path(self::DNSBL_SECTION, $section);
		pfb_install_registry_writeback([self::DNSBL_SECTION => $section], NULL, NULL, NULL, static function (): void {});
		$mode = config_get_path(self::DNSBL_SECTION . '/pfb_dnsbl_parse_mode');
		return is_string($mode) ? $mode : NULL;
	}

	/** @return array<string, array{array<string, string>, string}> pre-upgrade section keys => stored mode after the install */
	public static function upgradeProvider(): array
	{
		return [
			'no setting (pre-ADR-22 install)' => [[], 'lenient'],
			'checked'                         => [['pfb_dnsbl_lenient' => 'on'], 'lenient'],
			'unchecked'                       => [['pfb_dnsbl_lenient' => ''], 'ports'],
			'legacy off'                      => [['pfb_dnsbl_lenient' => 'off'], 'ports'],
		];
	}

	/** @param array<string, string> $keys */
	#[DataProvider('upgradeProvider')]
	public function testAnUpgradeKeepsItsParsingBehaviour(array $keys, string $mode): void
	{
		$this->assertSame($mode, $this->installedMode(['pfb_dnsbl' => 'on'] + $keys));
		$this->assertNull(config_get_path(self::DNSBL_SECTION . '/pfb_dnsbl_lenient'), 'the retired key must be renamed away');
	}

	public function testAFreshInstallDefaultsToAllowPorts(): void
	{
		$this->assertSame('ports', $this->installedMode([]));
	}
}
