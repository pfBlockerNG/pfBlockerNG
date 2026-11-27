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
 * Both strict modes skip, log and count a domain with userinfo or with an empty or invalid port.
 * An Adblock-headed feed collects IPs only from Adblock rule lines.
 */
final class DnsblParseModeTest extends TestCase
{
	private const DNSBL_SECTION = 'installedpackages/pfblockerngdnsblsettings/config/0';

	private static string $region;

	private string $failLog = '';
	private string $mainLog = '';
	private mixed $savedPfb = NULL;
	private mixed $savedConfig = NULL;

	public static function setUpBeforeClass(): void
	{
		$src = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc');
		if ($src === FALSE || !preg_match(
			'/(\t+\$line = pfb_dnsbl_scrub_line\(\$line\);\n.*?\$lite = FALSE;\n.*?@fwrite\(\$dhandle, \$domain_data\);)/s',
			$src,
			$m
		)) {
			throw new RuntimeException('test bootstrap: DNSBL scrub-to-plain-path region not found');
		}
		self::$region = "foreach ([0] as \$pfb_test_iter) {\n{$m[1]}\n}\n";
	}

	protected function setUp(): void
	{
		$this->failLog = (string) tempnam(sys_get_temp_dir(), 'pfb_mode_fail_');
		$this->mainLog = (string) tempnam(sys_get_temp_dir(), 'pfb_mode_log_');
		$this->savedPfb = $GLOBALS['pfb'] ?? NULL;
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$GLOBALS['config'] = [];
	}

	protected function tearDown(): void
	{
		@unlink($this->failLog);
		@unlink($this->mainLog);
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

	// -- the host grammar ---------------------------------------------------------------------

	private function extract(string $line, bool $strict, bool $allowPort, int &$skipped): string|false
	{
		$skipped = 0;
		return pfb_dnsbl_extract_host($line, $strict, 'hdr', $line, 3, $this->failLog, $skipped, $allowPort);
	}

	/** @return array<string, array{string, string}> line => host Allow Ports keeps */
	public static function allowPortsKeptProvider(): array
	{
		return [
			'STUN feed line'           => ['stun.example.com:3478', 'stun.example.com'],
			'port and root path'       => ['example.com:8080/', 'example.com'],
			'scheme and port'          => ['http://example.com:8080', 'example.com'],
			'scheme, port, root path'  => ['https://example.com:443/', 'example.com'],
			'no port'                  => ['example.com', 'example.com'],
			'IDN with root path'       => ['bücher.de/', 'bücher.de'],
		];
	}

	#[DataProvider('allowPortsKeptProvider')]
	public function testAllowPortsKeepsADomainWithAPort(string $line, string $host): void
	{
		$skipped = 0;
		$this->assertSame($host, $this->extract($line, TRUE, TRUE, $skipped), "Allow Ports [{$line}]");
		$this->assertSame(0, $skipped);
	}

	public function testStrictStillSkipsAPort(): void
	{
		$skipped = 0;
		$this->assertFalse($this->extract('stun.example.com:3478', TRUE, FALSE, $skipped));
		$this->assertSame(1, $skipped);
	}

	/** @return array<string, array{string}> */
	public static function strictModesRejectProvider(): array
	{
		return [
			'scheme-less userinfo'        => ['user@example.com'],
			'scheme-less userinfo, port'  => ['user@example.com:80'],
			'scheme userinfo and port'    => ['http://user@example.com:80/'],
			'empty port'                  => ['example.com:'],
			'non-numeric port'            => ['example.com:abc'],
			'six-digit port'              => ['example.com:123456'],
			'port then path'              => ['example.com:8080/x'],
			'IDN with a path'             => ['bücher.de/x'],
			'empty scheme, domain'        => ['://example.com'],
		];
	}

	#[DataProvider('strictModesRejectProvider')]
	public function testBothStrictModesSkipLogAndCountTheLine(string $line): void
	{
		foreach ([FALSE, TRUE] as $allowPort) {
			@unlink($this->failLog);
			$skipped = 0;
			$this->assertFalse($this->extract($line, TRUE, $allowPort, $skipped), "[{$line}] allow_port=" . var_export($allowPort, TRUE));
			$this->assertSame(1, $skipped, "[{$line}] must be counted for the strict-skip warning");
			$this->assertStringContainsString($line, (string) file_get_contents($this->failLog));
		}
	}

	// -- the parse loop -----------------------------------------------------------------------

	/** @return array{rows: list<array{0: string, 1: string}>, ip4: list<string>, skipped: int} */
	private function parseLine(string $feedLine, PfbDnsblParseMode $mode, bool $abpFeed = FALSE): array
	{
		$pfb = [
			'dnsbl_parse_mode' => $mode,
			'dnsbl_parse_err'  => $this->failLog,
			'dnsbl_ip'         => 'Deny_Both',
			'supp'             => PfbToggle::Off,
			'log'              => $this->mainLog,
		];
		$GLOBALS['pfb'] = $pfb;
		$line = $feedLine;
		$oline = $feedLine;
		$header = 'testfeed';
		$dnsbl_lineno = 1;
		$pfb_scheme_skipped = 0;
		$abp_feed = $abpFeed;
		$domain_data_ip = [];
		$domain_data_ip6 = [];
		$ipcount = 0;
		$dnsbl_skip = [];
		$custom = TRUE;
		$csv_parser = FALSE;
		$run_once = TRUE;
		$csv_type = '';
		$rev_format = FALSE;
		$alienvault_types = [];
		$dhandle = fopen('php://memory', 'w+');
		eval(self::$region);
		rewind($dhandle);
		$rows = [];
		while (($row = fgets($dhandle)) !== FALSE) {
			$rows[] = json_decode($row, TRUE, 512, JSON_THROW_ON_ERROR);
		}
		fclose($dhandle);
		return ['rows' => $rows, 'ip4' => $domain_data_ip, 'skipped' => $pfb_scheme_skipped];
	}

	public function testTheConfiguredModeDecidesWhatTheLoopKeeps(): void
	{
		$port = 'stun.example.com:3478';
		$path = 'example.com/x';
		$this->assertSame([[['d', 'stun.example.com']], 0], array_values(array_intersect_key($this->parseLine($port, PfbDnsblParseMode::Ports), ['rows' => 1, 'skipped' => 1])));
		$this->assertSame([[], 1], array_values(array_intersect_key($this->parseLine($port, PfbDnsblParseMode::Strict), ['rows' => 1, 'skipped' => 1])));
		$this->assertSame([[['d', 'stun.example.com']], 0], array_values(array_intersect_key($this->parseLine($port, PfbDnsblParseMode::Lenient), ['rows' => 1, 'skipped' => 1])));
		$this->assertSame([], $this->parseLine($path, PfbDnsblParseMode::Ports)['rows']);
		$this->assertSame([['d', 'example.com']], $this->parseLine($path, PfbDnsblParseMode::Lenient)['rows']);
	}

	public function testAnAdblockFeedCollectsIpsOnlyFromAdblockRules(): void
	{
		$hosts = $this->parseLine('0.0.0.0 1.2.3.4', PfbDnsblParseMode::Lenient, TRUE);
		$this->assertSame([[], []], [$hosts['rows'], $hosts['ip4']], 'a hosts line in an Adblock feed is no Adblock rule');

		$anchor = $this->parseLine('||1.2.3.4^', PfbDnsblParseMode::Lenient, TRUE);
		$this->assertSame(['1.2.3.4'], $anchor['ip4'], 'an anchored IP rule still feeds the IP table');

		$control = $this->parseLine('0.0.0.0 1.2.3.4', PfbDnsblParseMode::Lenient, FALSE);
		$this->assertSame(['1.2.3.4'], $control['ip4'], 'control: a hosts feed still collects the IP');
	}
}
