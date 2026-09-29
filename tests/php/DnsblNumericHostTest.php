<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * DNSBL feeds: a host a client reads as an IPv4 literal is an IP, never a domain rule.
 *
 * '0xc0.0xa8.0x1.0x64', '192.168.356', '3232235876' and friends all reach 192.168.1.100 in a
 * browser or libcurl, and no client ever sends a DNS query for them. The download loop used to
 * write six such dotted forms as domain rows (dead rules that block nothing) and reject the
 * dotless ones, so the address the feed listed was never blocked. They are now decoded with the
 * WHATWG rules (pfb_ipv4_numeric_host()) and collected through pfb_dnsbl_collect_feed_ip(), so
 * suppression still applies; numeric-but-invalid hosts go to the parse-error log. A URL's
 * userinfo ('http://decoy@host/') is removed so the real host is what gets classified.
 *
 * The plain-line step and the ABP-anchor step live inside sync_package_pfblockerng()'s feed loop
 * and are not unit-reachable, so both regions are eval-extracted verbatim from the REAL source
 * (house precedent: tests/php/DnsblFeedIdnWildcardTest.php).
 */
#[CoversFunction('pfb_dnsbl_abp_extract_ip')]
#[CoversFunction('pfb_dnsbl_extract_host')]
final class DnsblNumericHostTest extends TestCase
{
	private static string $plainRegion;
	private static string $abpRegion;
	private static string $hostsRegion;

	private string $failLog = '';
	private string $mainLog = '';
	private mixed $savedPfb = NULL;

	public static function setUpBeforeClass(): void
	{
		$src = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc');
		if ($src === FALSE) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_apply.inc');
		}
		if (!preg_match('/(\t+\$lite = FALSE;\n.*?@fwrite\(\$dhandle, \$domain_data\);)/s', $src, $plain)) {
			throw new RuntimeException('test bootstrap: DNSBL plain-line region not found');
		}
		if (!preg_match(
			'/(\t+if \(\$pfb\[\'dnsbl_ip\'\] != \'Disabled\'\) \{\n\t+\$abp_ip = pfb_dnsbl_abp_extract_ip\(\$line\);' .
			'.*?PfbDnsblRowKind::Abp, \$line\);\n\t+@fwrite\(\$dhandle, \$domain_data\);\n\t+continue;\n\t+\})/s',
			$src,
			$abp
		)) {
			throw new RuntimeException('test bootstrap: DNSBL ABP-anchor region not found');
		}
		// The hosts-line space split runs before the plain region; start there to reach it.
		if (!preg_match('/(\t+\/\/ Typical Host Feed format.*?@fwrite\(\$dhandle, \$domain_data\);)/s', $src, $hosts)) {
			throw new RuntimeException('test bootstrap: DNSBL hosts-line region not found');
		}
		self::$hostsRegion = "\$rev_format = FALSE;\nforeach ([0] as \$pfb_test_iter) {\n{$hosts[1]}\n}\n";
		// Both regions drop a line with `continue`; give them a loop of their own inside eval().
		self::$plainRegion = "foreach ([0] as \$pfb_test_iter) {\n{$plain[1]}\n}\n";
		self::$abpRegion = "foreach ([0] as \$pfb_test_iter) {\n{$abp[1]}\n}\n";
	}

	protected function setUp(): void
	{
		$this->failLog = (string) tempnam(sys_get_temp_dir(), 'pfb_num_fail_');
		$this->mainLog = (string) tempnam(sys_get_temp_dir(), 'pfb_num_log_');
		$this->savedPfb = $GLOBALS['pfb'] ?? NULL;
	}

	protected function tearDown(): void
	{
		@unlink($this->failLog);
		@unlink($this->mainLog);
		$GLOBALS['pfb'] = $this->savedPfb;
	}

	public function testRegionsStartAtExecutableCode(): void
	{
		$this->assertStringContainsString('$lite = FALSE;', self::$plainRegion);
		$this->assertStringContainsString('PFB_FILTER_DOMAIN', self::$plainRegion);
		$this->assertStringContainsString('pfb_dnsbl_abp_extract_ip($line)', self::$abpRegion);
		$this->assertStringContainsString('pfb_dnsbl_is_abp_rule_line($line)', self::$abpRegion);
	}

	/**
	 * Run one extracted region over one feed line.
	 *
	 * @return array{rows: list<array{0: string, 1: string}>, ip4: list<string>, ip6: list<string>, fail: string, log: string}
	 */
	private function runRegion(string $region, string $feedLine, bool $lenient = TRUE, bool $custom = TRUE,
		PfbToggle $supp = PfbToggle::Off, string $dnsblIp = 'Deny_Both'): array
	{
		$pfb = [
			'dnsbl_lenient'   => $lenient ? PfbToggle::On : PfbToggle::Off,
			'dnsbl_parse_err' => $this->failLog,
			'dnsbl_ip'        => $dnsblIp,
			'supp'            => $supp,
			'log'             => $this->mainLog,
		];
		$GLOBALS['pfb'] = $pfb;
		$line = $feedLine;
		$oline = $feedLine;
		$header = 'testfeed';
		$dnsbl_lineno = 1;
		$pfb_scheme_skipped = 0;
		$domain_data_ip = [];
		$domain_data_ip6 = [];
		$ipcount = 0;
		$dnsbl_skip = [];
		$dhandle = fopen('php://memory', 'w+');
		eval($region);
		rewind($dhandle);
		$rows = [];
		while (($row = fgets($dhandle)) !== FALSE) {
			$rows[] = json_decode($row, TRUE, 512, JSON_THROW_ON_ERROR);
		}
		fclose($dhandle);
		return [
			'rows' => $rows,
			'ip4'  => $domain_data_ip,
			'ip6'  => $domain_data_ip6,
			'fail' => (string) file_get_contents($this->failLog),
			'log'  => (string) file_get_contents($this->mainLog),
		];
	}

	/** @return array<string, array{string}> */
	public static function decodedPlainLineProvider(): array
	{
		return [
			'dotted hex'        => ['0xc0.0xa8.0x1.0x64'],
			'dotted octal'      => ['0300.0250.01.0144'],
			'mixed bases'       => ['192.0xa8.01.100'],
			'class B short'     => ['192.11010404'],
			'class C short'     => ['192.168.356'],
			'leading-zero quad' => ['192.168.01.100'],
			'dword'             => ['3232235876'],
			'hex dword'         => ['0xC0A80164'],
			'octal dword'       => ['030052000544'],
			'dword url'         => ['http://3232235876/login'],
			'userinfo decoy url' => ['http://secure.bank.com@3232235876/'],
		];
	}

	#[DataProvider('decodedPlainLineProvider')]
	public function testPlainNumericHostIsCollectedAsItsIpv4AndNeverADomain(string $feedLine): void
	{
		$out = $this->runRegion(self::$plainRegion, $feedLine);
		$this->assertSame(
			[[], ['192.168.1.100'], [], ''],
			[$out['rows'], $out['ip4'], $out['ip6'], $out['fail']],
			"line {$feedLine}: rows=" . json_encode($out['rows']) . ' ip4=' . json_encode($out['ip4']) . " fail={$out['fail']}"
		);
		$this->assertStringContainsString("IP literal decoded: [ {$this->hostOf($feedLine)} ] -> [ 192.168.1.100 ]", $out['log']);
	}

	private function hostOf(string $feedLine): string
	{
		return match ($feedLine) {
			'http://3232235876/login', 'http://secure.bank.com@3232235876/' => '3232235876',
			default => $feedLine,
		};
	}

	public function testCanonicalQuadWithTrailingDotIsCollected(): void
	{
		$out = $this->runRegion(self::$plainRegion, '8.8.8.8.');
		$this->assertSame([[], ['8.8.8.8']], [$out['rows'], $out['ip4']]);
	}

	/** @return array<string, array{string}> */
	public static function invalidPlainLineProvider(): array
	{
		return [
			'invalid octal digit' => ['08.08.08.08'],
			'non-number part'     => ['a.0x1'],
			'five parts'          => ['1.2.3.4.5'],
			'NUL in a label'      => ["1.2\x00.3.4"],
		];
	}

	#[DataProvider('invalidPlainLineProvider')]
	public function testPlainNumericButInvalidHostIsLoggedNotEmitted(string $feedLine): void
	{
		$out = $this->runRegion(self::$plainRegion, $feedLine);
		$this->assertSame([[], [], []], [$out['rows'], $out['ip4'], $out['ip6']], "line {$feedLine}: rows=" . json_encode($out['rows']));
		$this->assertStringContainsString($feedLine, $out['fail'], "line {$feedLine} missing from the parse-error log");
	}

	/** @return array<string, array{string, string}> */
	public static function hostsLineProvider(): array
	{
		return [
			'hex target'     => ['0.0.0.0 0xC0A80164', '0xC0A80164'],
			'dword target'   => ['127.0.0.1 3232235876', '3232235876'],
			'tab separated'  => ["0.0.0.0 \t0xC0A80164", '0xC0A80164'],
		];
	}

	#[DataProvider('hostsLineProvider')]
	public function testHostsLineNumericTargetIsDecodedOnThePlainPath(string $feedLine, string $target): void
	{
		$out = $this->runRegion(self::$hostsRegion, $feedLine);
		$this->assertSame([[], ['192.168.1.100'], [], ''], [$out['rows'], $out['ip4'], $out['ip6'], $out['fail']]);
		$this->assertStringContainsString("IP literal decoded: [ {$target} ] -> [ 192.168.1.100 ]", $out['log']);
	}

	public function testHostsLineInvalidNumericTargetIsLoggedNotEmitted(): void
	{
		$out = $this->runRegion(self::$hostsRegion, '0.0.0.0 08.08.08.08');
		$this->assertSame([[], [], []], [$out['rows'], $out['ip4'], $out['ip6']]);
		$this->assertStringContainsString('08.08.08.08', $out['fail']);
	}

	public function testUserinfoIsRemovedSoTheRealDomainIsBlocked(): void
	{
		$out = $this->runRegion(self::$plainRegion, 'http://user@evil.com/');
		$this->assertSame([[['d', 'evil.com']], '', ], [$out['rows'], $out['fail']]);
	}

	public function testStrictModeAlsoResolvesUserinfo(): void
	{
		$decoy = $this->runRegion(self::$plainRegion, 'http://secure.bank.com@3232235876/', lenient: FALSE);
		$this->assertSame([[], ['192.168.1.100']], [$decoy['rows'], $decoy['ip4']]);
		$domain = $this->runRegion(self::$plainRegion, 'http://user@evil.com/', lenient: FALSE);
		$this->assertSame([['d', 'evil.com']], $domain['rows']);
	}

	public function testSuppressionStillAppliesToADecodedAddress(): void
	{
		$control = $this->runRegion(self::$plainRegion, '0xC0A80164', custom: FALSE, supp: PfbToggle::Off);
		$this->assertContains('192.168.1.100', $control['ip4'], 'control: without suppression the decode collects the address');
		$out = $this->runRegion(self::$plainRegion, '0xC0A80164', custom: FALSE, supp: PfbToggle::On);
		$this->assertSame([[], []], [$out['rows'], $out['ip4']], 'a suppressed RFC1918 decode must not be collected or become a domain');
	}

	/** @return array<string, array{string, list<array{0: string, 1: string}>, list<string>, list<string>, bool}> */
	public static function unchangedPlainLineProvider(): array
	{
		return [
			'plain domain'              => ['example.com', [['d', 'example.com']], [], [], FALSE],
			'digit labels, alpha tld'   => ['1.2.example.com', [['d', '1.2.example.com']], [], [], FALSE],
			'canonical quad'            => ['192.168.1.100', [], ['192.168.1.100'], [], FALSE],
			'ipv6'                      => ['2001:db8::1', [], [], ['2001:db8::1'], FALSE],
			'bare userinfo (no scheme)' => ['secure.bank.com@3232235876', [], [], [], TRUE],
		];
	}

	/**
	 * @param list<array{0: string, 1: string}> $rows
	 * @param list<string> $ip4
	 * @param list<string> $ip6
	 */
	#[DataProvider('unchangedPlainLineProvider')]
	public function testNamesAndCanonicalAddressesKeepTheirPath(string $feedLine, array $rows, array $ip4, array $ip6, bool $logged): void
	{
		$out = $this->runRegion(self::$plainRegion, $feedLine);
		$this->assertSame([$rows, $ip4, $ip6, $logged], [$out['rows'], $out['ip4'], $out['ip6'], $out['fail'] !== ''], "line {$feedLine}");
	}

	/** @return array<string, array{string, string}> */
	public static function abpDecodedProvider(): array
	{
		return [
			'hex dword anchor'           => ['||0xC0A80164^', '192.168.1.100'],
			'dotted hex anchor + option' => ['||0xc0.0xa8.0x1.0x64^$important', '192.168.1.100'],
			'short form anchor'          => ['||192.168.356^', '192.168.1.100'],
			'quad trailing dot anchor'   => ['||8.8.8.8.^', '8.8.8.8'],
		];
	}

	#[DataProvider('abpDecodedProvider')]
	public function testAbpNumericAnchorIsExtractedAsItsIpv4(string $feedLine, string $ip): void
	{
		$this->assertSame($ip, pfb_dnsbl_abp_extract_ip($feedLine));
		$out = $this->runRegion(self::$abpRegion, $feedLine);
		$this->assertSame([[], [$ip]], [$out['rows'], $out['ip4']], "line {$feedLine}: rows=" . json_encode($out['rows']));
	}

	/** @return array<string, array{string}> */
	public static function abpInvalidProvider(): array
	{
		return [
			'invalid octal anchor' => ['||08.08.08.08^'],
			'non-number anchor'    => ['||a.0x1^'],
		];
	}

	#[DataProvider('abpInvalidProvider')]
	public function testAbpNumericButInvalidAnchorIsLoggedNotPassedToPython(string $feedLine): void
	{
		$this->assertFalse(pfb_dnsbl_abp_extract_ip($feedLine));
		$out = $this->runRegion(self::$abpRegion, $feedLine);
		$this->assertSame([[], []], [$out['rows'], $out['ip4']], "line {$feedLine}: rows=" . json_encode($out['rows']));
		$this->assertStringContainsString($feedLine, $out['fail']);
	}

	public function testAbpDomainAnchorAndHostsLineAreUnchanged(): void
	{
		$this->assertSame('', pfb_dnsbl_abp_extract_ip('||example.com^'));
		$this->assertSame('', pfb_dnsbl_abp_extract_ip('||1.2.example.com^'));
		$this->assertSame('', pfb_dnsbl_abp_extract_ip('0.0.0.0 0xC0A80164'), 'hosts targets stay on the plain path');
		$out = $this->runRegion(self::$abpRegion, '||example.com^');
		$this->assertSame([['a', '||example.com^']], $out['rows']);
	}

	public function testAbpNumericAnchorWithDnsblIpDisabledStillGoesToPython(): void
	{
		// The extract block is skipped when DNSBL IP is off; Python then skips the anchor, the same
		// outcome as a dotted-quad anchor with the feature off.
		$out = $this->runRegion(self::$abpRegion, '||0xC0A80164^', dnsblIp: 'Disabled');
		$this->assertSame([[['a', '||0xC0A80164^']], []], [$out['rows'], $out['ip4']]);
	}

	/** @return array<string, array{string, bool, string|false}> */
	public static function extractHostProvider(): array
	{
		return [
			'userinfo domain lenient'   => ['http://user@evil.com/', FALSE, 'evil.com'],
			'userinfo domain strict'    => ['http://user@evil.com/', TRUE, 'evil.com'],
			'userinfo decoy lenient'    => ['http://secure.bank.com@3232235876/', FALSE, '3232235876'],
			'user:pass, port'           => ['https://u:p@evil.com:8443/x', FALSE, 'evil.com'],
			'last @ wins'               => ['http://a@b@evil.com/', FALSE, 'evil.com'],
			'@ in the path only'        => ['http://evil.com/p@th', FALSE, 'evil.com'],
			'@ in the query only'       => ['http://evil.com?x=a@b', FALSE, 'evil.com'],
			'no scheme keeps userinfo'  => ['secure.bank.com@3232235876', FALSE, 'secure.bank.com@3232235876'],
			'numeric host + path lenient' => ['http://3232235876/login', FALSE, '3232235876'],
			'numeric host + path strict'  => ['http://3232235876/login', TRUE, '3232235876'],
			'decoy + path strict'       => ['http://secure.bank.com@3232235876/login', TRUE, '3232235876'],
			'numeric host + port + path strict' => ['http://3232235876:8080/login', TRUE, '3232235876'],
			'upper-case scheme strict'  => ['HTTP://3232235876/login', TRUE, '3232235876'],
			'@ in the query strict'     => ['http://3232235876?x=a@b', TRUE, '3232235876'],
			'@ in the fragment strict'  => ['http://3232235876#a@b/', TRUE, '3232235876'],
			'several @ strict'          => ['http://a@b@c@192.168.010.100/x', TRUE, '192.168.010.100'],
			'canonical quad + path strict' => ['http://192.168.1.100/login', TRUE, '192.168.1.100'],
			'name host + path strict'   => ['http://evil.com/login', TRUE, FALSE],
			'userinfo name + path strict' => ['http://user@evil.com/login', TRUE, FALSE],
			'empty port + path strict'  => ['http://0x7f000001:/x', TRUE, FALSE],
			'empty host + path strict'  => ['http:///login', TRUE, FALSE],
		];
	}

	#[DataProvider('extractHostProvider')]
	public function testExtractHostDropsUrlUserinfo(string $feedLine, bool $strict, string|false $host): void
	{
		$skipped = 0;
		$this->assertSame($host, pfb_dnsbl_extract_host($feedLine, $strict, 'testfeed', $feedLine, 1, $this->failLog, $skipped));
	}

	/** @return array<string, array{string}> */
	public static function strictNumericHostWithPathProvider(): array
	{
		return [
			'dword url'          => ['http://3232235876/login'],
			'userinfo decoy url' => ['http://secure.bank.com@3232235876/login'],
			'dword + port'       => ['http://3232235876:8080/login'],
		];
	}

	#[DataProvider('strictNumericHostWithPathProvider')]
	public function testStrictModeDecodesANumericHostWhateverThePath(string $feedLine): void
	{
		$out = $this->runRegion(self::$plainRegion, $feedLine, lenient: FALSE);
		$this->assertSame([[], ['192.168.1.100'], [], ''], [$out['rows'], $out['ip4'], $out['ip6'], $out['fail']], "line {$feedLine}");
		$this->assertStringContainsString('IP literal decoded: [ 3232235876 ] -> [ 192.168.1.100 ]', $out['log']);
	}

	public function testStrictModeDecodesTheHostAfterTheLastAt(): void
	{
		$out = $this->runRegion(self::$plainRegion, 'http://a@b@c@192.168.010.100/x', lenient: FALSE);
		$this->assertSame([[], ['192.168.8.100']], [$out['rows'], $out['ip4']]);
	}

	/** @return array<string, array{string}> */
	public static function strictRejectedProvider(): array
	{
		return [
			'invalid numeric host + path'    => ['http://08.08.08.08/login'],
			'invalid numeric host + userinfo' => ['http://user:p@ss@08.08.08.08/login'],
			'name host + path (control)'     => ['http://evil.com/login'],
			'userinfo name + path (control)' => ['http://user@evil.com/login'],
		];
	}

	#[DataProvider('strictRejectedProvider')]
	public function testStrictModeStillRejectsWhatIsNotANumericHost(string $feedLine): void
	{
		$out = $this->runRegion(self::$plainRegion, $feedLine, lenient: FALSE);
		$this->assertSame([[], [], []], [$out['rows'], $out['ip4'], $out['ip6']], "line {$feedLine}: rows=" . json_encode($out['rows']));
		$this->assertStringContainsString($feedLine, $out['fail'], "line {$feedLine} missing from the parse-error log");
	}
}
