<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/PfbNoPhpWarningTrait.php';

/**
 * Issue #3434: an ABP block regex rule that names an IPv4 address octet by octet adds exactly the addresses
 * it matches to the DNSBL IP table, as merged CIDRs (no wider than /16, at most 256 per rule). The rule is
 * still staged for Python byte-identical.
 *
 * The helper rows call pfb_dnsbl_abp_regex_ip4_cidrs() directly; the parse-loop rows run the ABP region
 * eval-extracted verbatim from the REAL pfblockerng_apply.inc (house precedent:
 * tests/php/DnsblNumericHostTest.php) and never name the helper, so they pin the wiring by behaviour.
 *
 * The oracle rows are the 51 IPv4-shaped regex lines of DandelionSprout's Anti-Malware List for AdGuard Home,
 * version 19September2026v1 (the provider key is the list line number): 50 qualify, line 13150 does not.
 */
#[CoversFunction('pfb_dnsbl_abp_regex_ip4_cidrs')]
final class DnsblAbpRegexIp4CidrsTest extends TestCase
{
	use PfbNoPhpWarningTrait;

	private static string $abpRegion;

	private string $failLog = '';
	private string $mainLog = '';
	private mixed $savedPfb = NULL;
	private string|false $savedLimit = FALSE;

	public static function setUpBeforeClass(): void
	{
		$src = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc');
		if ($src === FALSE) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_apply.inc');
		}
		if (!preg_match(
			'/(\t+if \(\$pfb\[\'dnsbl_ip\'\] != \'Disabled\'\) \{\n\t+\$abp_ip = pfb_dnsbl_abp_extract_ip\(\$line\);' .
			'.*?PfbDnsblRowKind::Abp, \$line\);\n\t+@fwrite\(\$dhandle, \$domain_data\);\n\t+continue;\n\t+\})/s',
			$src,
			$abp
		)) {
			throw new RuntimeException('test bootstrap: DNSBL ABP-anchor region not found');
		}
		self::$abpRegion = "foreach ([0] as \$pfb_test_iter) {\n{$abp[1]}\n}\n";
	}

	protected function setUp(): void
	{
		$this->failLog = (string) tempnam(sys_get_temp_dir(), 'pfb_r24_fail_');
		$this->mainLog = (string) tempnam(sys_get_temp_dir(), 'pfb_r24_log_');
		$this->savedPfb = $GLOBALS['pfb'] ?? NULL;
		$GLOBALS['pfb'] = ['log' => $this->mainLog];
		$this->savedLimit = ini_set('pcre.backtrack_limit', '123456');
	}

	protected function tearDown(): void
	{
		unset($GLOBALS['pfb_test_abp_regex_fault']);
		ini_set('pcre.backtrack_limit', (string) $this->savedLimit);
		@unlink($this->failLog);
		@unlink($this->mainLog);
		$GLOBALS['pfb'] = $this->savedPfb;
	}

	/**
	 * Run the extracted ABP region over one (already scrubbed) feed line.
	 *
	 * @return array{rows: list<array{0: string, 1: string}>, ip4: list<string>, ip6: list<string>, ipcount: int, updateip: mixed, warnings: list<string>}
	 */
	private function runRegion(string $feedLine, bool $custom = TRUE, PfbToggle $supp = PfbToggle::Off,
		string $dnsblIp = 'Deny_Both'): array
	{
		$pfb = [
			'dnsbl_lenient'   => PfbToggle::On,
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
		$domain_data_ip = [];
		$domain_data_ip6 = [];
		$ipcount = 0;
		$dhandle = fopen('php://memory', 'w+');
		$warnings = [];
		set_error_handler(static function (int $no, string $str) use (&$warnings): bool {
			$warnings[] = $str;
			return TRUE;
		});
		try {
			eval(self::$abpRegion);
		} finally {
			restore_error_handler();
		}
		rewind($dhandle);
		$rows = [];
		while (($row = fgets($dhandle)) !== FALSE) {
			$rows[] = json_decode($row, TRUE, 512, JSON_THROW_ON_ERROR);
		}
		fclose($dhandle);
		return [
			'rows'     => $rows,
			'ip4'      => $domain_data_ip,
			'ip6'      => $domain_data_ip6,
			'ipcount'  => $ipcount,
			'updateip' => $pfb['updateip'] ?? FALSE,
			'warnings' => $warnings,
		];
	}

	/** @return list<string> */
	private function helper(string $line): array
	{
		return $this->assertNoPhpWarning(static fn(): array => pfb_dnsbl_abp_regex_ip4_cidrs($line, 'testfeed'));
	}

	/**
	 * Call the helper under a caller-owned error handler; assert it is active again, saw no warning, and the backtrack limit is back.
	 *
	 * @return list<string>
	 */
	private function callAndAssertStateRestored(string $rule): array
	{
		$seen = [];
		$mine = static function (int $no, string $str) use (&$seen): bool {
			$seen[] = $str;
			return TRUE;
		};
		set_error_handler($mine);
		try {
			$result = pfb_dnsbl_abp_regex_ip4_cidrs($rule, 'testfeed');
			$active = set_error_handler(static fn(): bool => FALSE);
			restore_error_handler();
		} finally {
			restore_error_handler();
		}
		$this->assertSame($mine, $active, "the caller's error handler is active again after $rule");
		$this->assertSame([], $seen, "no warning reaches the caller's handler for $rule");
		$this->assertSame('123456', ini_get('pcre.backtrack_limit'), "pcre.backtrack_limit restored after $rule");
		return $result;
	}

	/** @return list<string> the non-empty lines of the main log */
	private function logLines(): array
	{
		return array_values(array_filter(explode("\n", (string) file_get_contents($this->mainLog)), static fn(string $l): bool => $l !== ''));
	}

	/** An eligible rule that is exactly $bytes long: '/^5\.8\.44\.' + a /24 tail + '()' padding + '$/'. */
	private static function paddedRule(int $bytes): string
	{
		$head = '/^5\.8\.44\.';
		$tail = (($bytes - strlen($head . '\d+$/')) % 2 === 0) ? '\d+' : '[12]?\d?\d';
		return $head . $tail . str_repeat('()', intdiv($bytes - strlen($head . $tail . '$/'), 2)) . '$/';
	}

	/** The part 'matches 0..255 under the default backtrack limit, but exceeds 10000 steps' (see the cost test). */
	private static function backtrackHeavyPart(): string
	{
		return '(' . str_repeat('(\d|\d)*', 15) . '-|\d{1,3})';
	}

	/** @return list<string> */
	private static function octetStrings(): array
	{
		return array_map('strval', range(0, 255));
	}

	/**
	 * What the IP table holds after the sanitizer: a /32 is stored bare, 0.x.x.x is dropped.
	 *
	 * @param list<string> $cidrs
	 * @return list<string>
	 */
	private static function collected(array $cidrs): array
	{
		$out = [];
		foreach ($cidrs as $cidr) {
			if (!str_starts_with($cidr, '0.')) {
				$out[] = str_ends_with($cidr, '/32') ? substr($cidr, 0, -3) : $cidr;
			}
		}
		return $out;
	}

	/**
	 * Every shape the helper decides on: [rule line, expected CIDRs, parse-loop options].
	 *
	 * @return array<string, array{string, list<string>, array{custom?: bool, supp?: PfbToggle, ip4?: list<string>}}>
	 */
	public static function ruleProvider(): array
	{
		$hosts256 = array_map(static fn(int $i): string => "5.$i.1.1/32", range(0, 255));
		// Third-octet values 0..127 each give '.0/31' + '.2/32': 256 CIDRs from 128 intervals, so only the CIDR count decides.
		$cap256 = [];
		foreach (range(0, 127) as $c) {
			$cap256[] = "5.8.$c.0/31";
			$cap256[] = "5.8.$c.2/32";
		}
		$rows = [
			'full last octet'               => ['/^142\.91\.159\.[12]?\d?\d$/', ['142.91.159.0/24']],
			'\d{1,3} last octet'            => ['/^5\.8\.44\.\d{1,3}$/', ['5.8.44.0/24']],
			'class in third octet'          => ['/^5\.8\.4[4-7]\.\d{1,3}$/', ['5.8.44.0/22']],
			'class with gaps'               => ['/^178\.253\.3[04-7]\.[12]?\d?\d$/', ['178.253.30.0/24', '178.253.34.0/23', '178.253.36.0/23']],
			'wide class in third octet'     => ['/^178\.253\.[0-7]\.[12]?\d?\d$/', ['178.253.0.0/21']],
			'full third and fourth octet'   => ['/^5\.8\.\d{1,3}\.\d{1,3}$/', ['5.8.0.0/16']],
			'partial last octet'            => ['/^172\.255\.6\.(\d\d?|(17?|2)[0-689]\d)$/', [
				'172.255.6.0/25', '172.255.6.128/27', '172.255.6.160/29', '172.255.6.168/31',
				'172.255.6.180/30', '172.255.6.184/29', '172.255.6.192/26',
			]],
			'literal fourth octet'          => ['/^5\.8\.44\.1$/', ['5.8.44.1/32']],
			'exactly 256 CIDRs'             => ['/^5\.\d+\.1\.1$/', $hosts256],
			'one CIDR wider than /16'       => ['/^5\.[0-1]\.\d{1,3}\.\d{1,3}$/', []],
			'four wildcard octets'          => ['/^\d+\.\d+\.\d+\.\d+$/', []],
			'0.x network is sanitized away' => ['/^0\.1\.2\.\d{1,3}$/', ['0.1.2.0/24']],
			'reserved inside a /16'         => ['/^192\.0\.\d{1,3}\.\d{1,3}$/', ['192.0.0.0/16'],
				['custom' => FALSE, 'supp' => PfbToggle::On, 'ip4' => ['192.0.0.0/16']]],
			'one private, one public'       => ['/^(5|192)\.168\.0\.\d{1,3}$/', ['5.168.0.0/24', '192.168.0.0/24'],
				['custom' => FALSE, 'supp' => PfbToggle::On, 'ip4' => ['5.168.0.0/24']]],
			'brace bound 65536'             => ['/^5\.8\.44\.\d{0,65536}$/', []],
			'brace over the octet limit'    => ['/^5\.8\.44\.\d{1,4}$/', []],
			'brace bound 10'                => ['/^5\.8\.44\.\d{10}$/', []],
			'brace at the octet limit'      => ['/^5\.8\.44\.\d{0,3}$/', ['5.8.44.0/24']],
			'514-byte line'                 => [self::paddedRule(514), ['5.8.44.0/24']],
			'515-byte line'                 => [self::paddedRule(515), []],
			'wider than /16'                => ['/^5\.\d+\.\d+\.\d+$/', []],
			'class in first octet'          => ['/^(5|6)\.8\.44\.\d+$/', ['5.8.44.0/24', '6.8.44.0/24']],
			'256 CIDRs from 128 intervals'  => ['/^5\.8\.(\d{1,2}|1[01]\d|12[0-7])\.[0-2]$/', $cap256],
			'258 CIDRs from 129 intervals'  => ['/^5\.8\.(\d{1,2}|1[01]\d|12[0-8])\.[0-2]$/', []],
			'over the 256-CIDR cap'         => ['/^5\.8\.\d+\.(1|3)$/', []],
			'. in a part'                   => ['/^5\.8\.44\..*$/', []],
			'. in a part, lazy'             => ['/^5\.8\.44\..*?$/', []],
			'top-level |'                   => ['/^1\.2\.3\.4|\d$/', []],
			'\. inside a group'             => ['/^5\.8\.(44\.\d+)$/', []],
			'three parts only'              => ['/^5\.8\.44$/', []],
			'five parts'                    => ['/^5\.8\.44\.1\.\d+$/', []],
			'POSIX class part'              => ['/^5\.8\.44\.[[:digit:]]+$/', []],
			'unicode property part'         => ['/^5\.8\.44\.\p{Nd}+$/', []],
			'recursion (?1) part'           => ['/^5\.8\.44\.(\d+)(?1)?$/', []],
			'inline flag (?i) part'         => ['/^5\.8\.44\.(?i)\d+$/', []],
			'(? in a |-split rule'          => ['/^1\.2\.3\.(\d{1,3})|(?1)$/', []],
			'{,} after |'                   => ['/^1\.2\.3\.\d+|{,}$/', []],
			'{,} after ? then |'            => ['/^1\.2\.3\.\d?{,}|\d+$/', []],
			'{,} inside a group'            => ['/^1\.2\.3\.(\d+|{,})$/', []],
			'empty value set'               => ['/^5\.8\.300\.\d$/', []],
			'padded octet'                  => ['/^05\.8\.44\.\d+$/', []],
			'octet over 255'                => ['/^5\.256\.44\.\d+$/', []],
			'octet 255 is fine'             => ['/^255\.255\.255\.\d+$/', ['255.255.255.0/24']],
			'octet 0 is fine'               => ['/^1\.0\.0\.\d+$/', ['1.0.0.0/24']],
			'class holding |'               => ['/^5\.8\.4[4|5]\.\d+$/', []],
			'( inside a class'              => ['/^5\.8\.4[(4]\.\d+$/', []],
			') inside a class'              => ['/^5\.8\.4[)4]\.\d+$/', []],
			'\. inside a class'             => ['/^5\.8\.[\.]44\.\d+$/', []],
			'[]-led class'                  => ['/^5\.8\.44\.([](]|\d)\d*$/', []],
			'escaped bracket'               => ['/^5\.8\.44\.\[\d+$/', []],
			'$options suffix'               => ['/^5\.8\.44\.\d{1,3}$/$important', []],
			'allow rule'                    => ['@@/^5\.8\.44\.\d{1,3}$/', []],
			'no ^ and no $'                 => ['/5\.8\.44\.\d+/', []],
			'no $'                          => ['/^5\.8\.44\.\d+/', []],
			'suppression off, RFC 1918'     => ['/^192\.168\.0\.\d{1,3}$/', ['192.168.0.0/24'], ['custom' => FALSE]],
			'suppression on, RFC 1918'      => ['/^192\.168\.0\.\d{1,3}$/', ['192.168.0.0/24'], ['custom' => FALSE, 'supp' => PfbToggle::On, 'ip4' => []]],
			'domain regex'                  => ['/^ads\d+\.example\.com$/', []],
			'scheme and path wrappers'      => ['/^(.*://)?204\.11\.56\.\d{1,3}(/.*)?$/', ['204.11.56.0/24']],
			'scheme group, no ^, 3-digit'   => ['/((https?|tcp|iquic)://)?204\.194\.54\.\d{1,3}([:/].*)?$/', ['204.194.54.0/24']],
			'escaped-slash path wrapper'    => ['/^5\.8\.44\.\d{1,3}(\/.*)?$/', ['5.8.44.0/24']],
			'no ^, short first octet'       => ['/5\.8\.44\.\d+$/', []],
			'no ^, group first octet'       => ['/(200|201)\.8\.44\.\d+$/', []],
			'wrapper, no ^, short first'    => ['/(.*://)?5\.8\.44\.\d+$/', []],
			'wrapper with ^, short first'   => ['/^(.*://)?5\.8\.44\.\d+$/', ['5.8.44.0/24']],
			'non-optional URL wrapper'      => ['/^(.*://)5\.8\.44\.\d+$/', []],
			'non-URL wrapper'               => ['/^(evil\.com/)?5\.8\.44\.\d+$/', []],
			'colon in the scheme group'     => ['/^(a:b://)?5\.8\.44\.\d+$/', []],
			'two scheme groups'             => ['/^(.*://)?(.*://)?5\.8\.44\.\d+$/', []],
			'| in the scheme group'         => ['/^(1|x://)?2\.3\.4\.\d+$/', []],
			'(*://) scheme group'           => ['/^(*://)?5\.8\.44\.\d+$/', []],
			'(+://) scheme group'           => ['/^(+://)?5\.8\.44\.\d+$/', []],
			'(?+://) scheme group'          => ['/^(?+://)?5\.8\.44\.\d+$/', []],
			'(??://) scheme group'          => ['/^(??://)?5\.8\.44\.\d+$/', []],
			'((?x)://) scheme group'        => ['/^((?x)://)?5\.8\.44\.\d+$/', []],
			'(123://) scheme group'         => ['/^(123://)?5\.8\.44\.\d+$/', []],
			'digit in a nested scheme word' => ['/^((http2|tcp)://)?5\.8\.44\.\d+$/', []],
			'possessive class holding ('    => ['/^5\.8\.4[(-9]++\.\d+$/', []],
			'class holding , and a bound'   => ['/^5\.8\.4[,-9]{1,2}+\.\d+$/', []],
			'class range from -'            => ['/^5\.8\.4[--9]\.\d+$/', []],
			'empty inner //$'               => ['/$/', []],
			'empty inner after ^'           => ['/^$/', []],
			'single slash'                  => ['/', []],
			'space in a part'               => ['/^5\.8\.44\. \d+$/', []],
			'tab in a part'                 => ["/^5\\.8\\.44\\.\t\\d+$/", []],
			'# in a part'                   => ['/^5\.8\.44\.#\d+$/', []],
			'~ in a part'                   => ['/^5\.8\.44\.~\d+$/', []],
			'/ in a part'                   => ['/^5\.8\.44\.\d+\/24$/', []],
			'empty group part'              => ['/^5\.8\.44\.()$/', []],
			'zero-repeat part'              => ['/^5\.8\.44\.\d{0}$/', []],
			'empty alternative (|\d+)'      => ['/^5\.8\.44\.(|\d+)$/', ['5.8.44.0/24']],
			'nested quantifier (\d+)+'      => ['/^5\.8\.44\.(\d+)+$/', ['5.8.44.0/24']],
			'nested quantifier (\d*)*\d*'   => ['/^5\.8\.44\.(\d*)*\d*$/', ['5.8.44.0/24']],
			'\d* part'                      => ['/^5\.8\.44\.\d*$/', ['5.8.44.0/24']],
			'lazy \d*? part'                => ['/^5\.8\.44\.\d*?$/', ['5.8.44.0/24']],
			'unbalanced ) across parts'     => ['/^5)\.(8\.44\.\d$/', []],
			'unbalanced ( in the last part' => ['/^5\.8\.44\.(\d+$/', []],
			'unterminated class'            => ['/^5\.8\.44\.[\d$/', []],
			'inverted quantifier'           => ['/^5\.8\.44\.\d{3,1}$/', []],
			'non-ASCII digit, first octet'  => ['/^٥\.8\.44\.\d+$/', []],
			'non-ASCII digit, last octet'   => ['/^5\.8\.44\.٥$/', []],
			'non-ASCII digit, third octet'  => ['/^5\.8\.٤٤\.\d+$/', []],
			'uppercase \D part'             => ['/^5\.8\.44\.\D*$/', []],
			'backreference part'            => ['/^5\.8\.44\.(\d+)\1?$/', []],
			'escaped $ at the end'          => ['/^5\.8\.44\.\d+\$/', []],
			'trailing LF'                   => ["/^5\\.8\\.44\\.\\d+$/\n", []],
			'trailing CRLF'                 => ["/^5\\.8\\.44\\.\\d+$/\r\n", []],
			'100 KB inner'                  => ['/^5\.8\.44\.' . str_repeat('()', 51200) . '\d+$/', []],
			'backtrack-heavy part'          => ['/^5\.8\.44\.' . self::backtrackHeavyPart() . '$/', []],
			'empty line'                    => ['', []],
			'bare IP'                       => ['1.2.3.4', []],
		];
		foreach (self::oracle() as $lineno => [$rule, $cidrs]) {
			$rows["oracle $lineno"] = [$rule, $cidrs];
		}
		return $rows;
	}

	/**
	 * The 51 IPv4-shaped regex lines of the DandelionSprout list: list line number => [rule, expected CIDRs].
	 *
	 * @return array<int, array{string, list<string>}>
	 */
	private static function oracle(): array
	{
		return [
			221 => ['/^142\.91\.159\.[12]?\d?\d$/', ['142.91.159.0/24']],
			222 => ['/^23\.109\.150\.[12]?\d?\d$/', ['23.109.150.0/24']],
			223 => ['/^23\.109\.248\.[12]?\d?\d$/', ['23.109.248.0/24']],
			248 => ['/^172\.255\.6\.(\d\d?|(17?|2)[0-689]\d)$/', ['172.255.6.0/25', '172.255.6.128/27', '172.255.6.160/29', '172.255.6.168/31', '172.255.6.180/30', '172.255.6.184/29', '172.255.6.192/26']],
			534 => ['/^173\.233\.137\.[12]?\d?\d$/', ['173.233.137.0/24']],
			535 => ['/^173\.233\.139\.[12]?\d?\d$/', ['173.233.139.0/24']],
			536 => ['/^192\.243\.59\.[12]?\d?\d$/', ['192.243.59.0/24']],
			537 => ['/^192\.243\.61\.[12]?\d?\d$/', ['192.243.61.0/24']],
			1133 => ['/^46\.161\.27\.[12]?\d?\d$/', ['46.161.27.0/24']],
			1134 => ['/^78\.128\.112\.[12]?\d?\d$/', ['78.128.112.0/24']],
			1135 => ['/^179\.60\.146\.[12]?\d?\d$/', ['179.60.146.0/24']],
			1254 => ['/^178\.253\.[0-7]\.[12]?\d?\d$/', ['178.253.0.0/21']],
			1255 => ['/^178\.253\.14\.[12]?\d?\d$/', ['178.253.14.0/24']],
			1256 => ['/^178\.253\.15\.[12]?\d?\d$/', ['178.253.15.0/24']],
			1257 => ['/^178\.253\.2[0145]\.[12]?\d?\d$/', ['178.253.20.0/23', '178.253.24.0/23']],
			1258 => ['/^178\.253\.3[04-7]\.[12]?\d?\d$/', ['178.253.30.0/24', '178.253.34.0/23', '178.253.36.0/23']],
			1259 => ['/^178\.253\.46\.[12]?\d?\d$/', ['178.253.46.0/24']],
			1260 => ['/^178\.253\.47\.[12]?\d?\d$/', ['178.253.47.0/24']],
			1261 => ['/^178\.253\.54\.[12]?\d?\d$/', ['178.253.54.0/24']],
			1268 => ['/^162\.241\.115\.[12]?\d?\d$/', ['162.241.115.0/24']],
			2717 => ['/^104\.160\.10\.[12]?\d?\d$/', ['104.160.10.0/24']],
			2718 => ['/^165\.231\.154\.[12]?\d?\d$/', ['165.231.154.0/24']],
			2850 => ['/^165\.231\.10\.[12]?\d?\d$/', ['165.231.10.0/24']],
			2851 => ['/^165\.231\.152\.[12]?\d?\d$/', ['165.231.152.0/24']],
			2852 => ['/^196\.196\.52\.[12]?\d?\d$/', ['196.196.52.0/24']],
			2853 => ['/^196\.196\.155\.[12]?\d?\d$/', ['196.196.155.0/24']],
			2854 => ['/^196\.240\.121\.[12]?\d?\d$/', ['196.240.121.0/24']],
			2855 => ['/^196\.242\.179\.[12]?\d?\d$/', ['196.242.179.0/24']],
			2856 => ['/^196\.245\.52\.[12]?\d?\d$/', ['196.245.52.0/24']],
			2857 => ['/^196\.245\.56\.[12]?\d?\d$/', ['196.245.56.0/24']],
			2897 => ['/^139\.45\.197\.[12]?\d?\d$/', ['139.45.197.0/24']],
			3163 => ['/^5\.61\.60\.[12]?\d?\d$/', ['5.61.60.0/24']],
			3209 => ['/^103\.224\.182\.[12]?\d?\d$/', ['103.224.182.0/24']],
			3274 => ['/^192\.243\.58\.[12]?\d?\d$/', ['192.243.58.0/24']],
			3959 => ['/^45\.141\.59\.[12]?\d?\d$/', ['45.141.59.0/24']],
			10483 => ['/^194\.226\.139\.[12]?\d?\d$/', ['194.226.139.0/24']],
			10496 => ['/^5\.8\.4[4-7]\.\d{1,3}$/', ['5.8.44.0/22']],
			10497 => ['/^5\.101\.4[67]\.\d{1,3}$/', ['5.101.46.0/23']],
			10498 => ['/^5\.188\.5[01]\.\d{1,3}$/', ['5.188.50.0/23']],
			10499 => ['/^5\.188\.17[67]\.\d{1,3}$/', ['5.188.176.0/23']],
			10500 => ['/^5\.188\.19[45]\.\d{1,3}$/', ['5.188.194.0/23']],
			10501 => ['/^5\.189\.21[89]\.\d{1,3}$/', ['5.189.218.0/23']],
			10502 => ['/^31\.184\.20[0-3]\.\d{1,3}$/', ['31.184.200.0/22']],
			10503 => ['/^185\.238\.15[2-5]\.\d{1,3}$/', ['185.238.152.0/22']],
			10687 => ['/^188\.42\.84\.[12]?\d?\d$/', ['188.42.84.0/24']],
			10688 => ['/^203\.195\.121\.[12]?\d?\d$/', ['203.195.121.0/24']],
			13150 => ['/^172\.255\.6\.(\d\d?|2.*|1[0-689].*|17[0-689])$/', []],
			10010 => ['/((https?|tcp|iquic)://)?204\.194\.54\.\d{1,3}([:/].*)?$/', ['204.194.54.0/24']],
			10462 => ['/^((https?|tcp|iquic)://)?192\.243\.59\.\d{1,3}(/.*)?$/', ['192.243.59.0/24']],
			12490 => ['/^(.*://)?204\.11\.56\.\d{1,3}(/.*)?$/', ['204.11.56.0/24']],
			12491 => ['/^(.*://)?208\.91\.197\.\d{1,3}(/.*)?$/', ['208.91.197.0/24']],
		];
	}

	/**
	 * @param list<string> $cidrs
	 * @param array<string, mixed> $opts
	 */
	#[DataProvider('ruleProvider')]
	public function testHelperReturnsTheMergedCidrs(string $line, array $cidrs, array $opts = []): void
	{
		$this->assertSame($cidrs, $this->helper($line));
	}

	public function testOracleHasFiftyOneLinesAndFiftyQualify(): void
	{
		$this->assertCount(51, self::oracle());
		$this->assertCount(50, array_filter(self::oracle(), static fn(array $r): bool => $r[1] !== []));
		$this->assertSame([], self::oracle()[13150][1]);
	}

	/**
	 * @param array<int, TRUE> $set
	 * @return array{0: array<int, TRUE>, 1: array<int, TRUE>, 2: array<int, TRUE>, 3: array<int, TRUE>}
	 */
	private static function projections(array $set): array
	{
		$p = [[], [], [], []];
		foreach (array_keys($set) as $a) {
			$p[0][($a >> 24) & 255] = TRUE;
			$p[1][($a >> 16) & 255] = TRUE;
			$p[2][($a >> 8) & 255] = TRUE;
			$p[3][$a & 255] = TRUE;
		}
		return $p;
	}

	/**
	 * @param list<string> $cidrs
	 * @return array<int, TRUE>
	 */
	private static function addresses(array $cidrs): array
	{
		$set = [];
		foreach ($cidrs as $cidr) {
			[$ip, $bits] = explode('/', $cidr, 2);
			$start = (int) ip2long($ip);
			$end = $start + (1 << (32 - (int) $bits)) - 1;
			for ($a = $start; $a <= $end; $a++) {
				$set[$a] = TRUE;
			}
		}
		return $set;
	}

	/** The rule as pfb_unbound.py applies it: the whole '/…/' body, case-insensitive, unanchored search. */
	private static function fullPatternMatches(string $line, string $address): bool
	{
		return preg_match("\x01" . substr($line, 1, -1) . "\x01i", $address) === 1;
	}

	/**
	 * The CIDRs are the exact product of the four octet sets, and each address in them (and no probed
	 * address outside them) matches the full pattern.
	 *
	 * @param list<string> $cidrs
	 * @param array<string, mixed> $opts
	 */
	#[DataProvider('ruleProvider')]
	public function testCollectedAddressesAreExactlyTheAddressesThePatternMatches(string $line, array $cidrs, array $opts = []): void
	{
		$set = self::addresses($this->helper($line));
		$this->assertSame($cidrs === [], $set === []);
		$bad = [];
		foreach (array_keys($set) as $a) {
			if (!self::fullPatternMatches($line, long2ip($a))) {
				$bad[] = long2ip($a);
			}
		}
		$this->assertSame([], array_slice($bad, 0, 5), 'collected addresses the full pattern does not match');
		if ($set === []) {
			return;
		}
		$p = self::projections($set);
		$this->assertSame(count($p[0]) * count($p[1]) * count($p[2]) * count($p[3]), count($set), 'the set is the Cartesian product of its octet sets');
		$first = explode('.', long2ip(min(array_keys($set))));
		$leaks = [];
		foreach ($p as $i => $inSet) {
			for ($v = 0; $v < 256; $v++) {
				$probe = $first;
				$probe[$i] = (string) $v;
				if (!isset($inSet[$v]) && self::fullPatternMatches($line, implode('.', $probe))) {
					$leaks[] = implode('.', $probe);
				}
			}
		}
		$this->assertSame([], array_slice($leaks, 0, 5), 'addresses outside the octet sets that the full pattern matches');
	}

	public function testLineLengthBoundaryIs514Bytes(): void
	{
		$this->assertSame(514, strlen(self::paddedRule(514)));
		$this->assertSame(515, strlen(self::paddedRule(515)));
		$this->assertSame(['5.8.44.0/24'], $this->helper(self::paddedRule(514)));
		$this->assertSame([], $this->helper(self::paddedRule(515)));
		// The refused rule is a valid, qualifying pattern: only its length disqualifies it.
		$this->assertCount(256, preg_grep('~' . substr(self::paddedRule(515), 1, -1) . '~', array_map(static fn(string $o): string => "5.8.44.$o", self::octetStrings())));
	}

	public function testBacktrackHeavyPartIsRefusedOnlyForItsCost(): void
	{
		$re = '/^(?:' . self::backtrackHeavyPart() . ')$/';
		$this->assertLessThanOrEqual(514, strlen('/^5\.8\.44\.' . self::backtrackHeavyPart() . '$/'));
		ini_set('pcre.backtrack_limit', '1000000');
		$this->assertCount(256, preg_grep($re, self::octetStrings()), 'under the default limit it matches every value');
		$this->assertSame(PREG_NO_ERROR, preg_last_error());
		ini_set('pcre.backtrack_limit', '10000');
		preg_grep($re, self::octetStrings());
		$this->assertSame(PREG_BACKTRACK_LIMIT_ERROR, preg_last_error(), 'under the helper limit it exhausts the budget');
	}

	/**
	 * @param list<string> $cidrs
	 * @param array{custom?: bool, supp?: PfbToggle, ip4?: list<string>} $opts
	 */
	#[DataProvider('ruleProvider')]
	public function testParseLoopCollectsTheCidrsAndStagesTheLineUnchanged(string $line, array $cidrs, array $opts = []): void
	{
		$custom = $opts['custom'] ?? TRUE;
		$supp = $opts['supp'] ?? PfbToggle::Off;
		$expected = $opts['ip4'] ?? self::collected($cidrs);
		$out = $this->runRegion($line, $custom, $supp);
		$this->assertSame([], $out['warnings']);
		$this->assertSame([], $out['ip6']);
		$this->assertSame($expected, $out['ip4']);
		$this->assertSame(count($expected), $out['ipcount']);
		$this->assertSame($expected !== [], $out['updateip'] === TRUE);
		// Staged exactly as with DNSBL IP disabled (today's behaviour): the new step never drops or edits a line.
		$this->assertSame($this->runRegion($line, $custom, $supp, 'Disabled')['rows'], $out['rows']);
		if ($cidrs !== []) {
			$this->assertSame([['a', $line]], $out['rows'], 'an eligible rule is staged for Python byte-identical');
		}
	}

	public function testParseLoopWithDnsblIpDisabledCollectsNothingAndStillStages(): void
	{
		$line = '/^5\.8\.4[4-7]\.\d{1,3}$/';
		$out = $this->runRegion($line, dnsblIp: 'Disabled');
		$this->assertSame([[], [], 0, FALSE], [$out['ip4'], $out['ip6'], $out['ipcount'], $out['updateip']]);
		$this->assertSame([['a', $line]], $out['rows']);
	}

	public function testParseLoopStillTreatsAnAnchorAsAnIpAndNotAsARegex(): void
	{
		$out = $this->runRegion('||5.8.44.1^');
		$this->assertSame([['5.8.44.1'], 1, []], [$out['ip4'], $out['ipcount'], $out['rows']]);
	}

	public function testHelperLeavesTheBacktrackLimitAndErrorHandlerAsItFoundThem(): void
	{
		$rules = ['/^5\.8\.44\.\d{1,3}$/', '/^5\.8\.44\.\d{3,1}$/', '/^5\.8\.44\.' . self::backtrackHeavyPart() . '$/',
			'/^5\.8\.44\.\p{Nd}+$/', '@@/^5\.8\.44\.\d{1,3}$/', '/^5\.8\.44\.\d{1,3}$/$important'];
		foreach ($rules as $rule) {
			$this->callAndAssertStateRestored($rule);
		}
	}

	public function testRefusalsWriteNothingToTheLog(): void
	{
		foreach (['/^5\.8\.44\.\p{Nd}+$/', '/^5\.8\.44\.\d{3,1}$/', '/^5\.8\.44\.' . self::backtrackHeavyPart() . '$/', '/^\d+\.\d+\.\d+\.\d+$/'] as $rule) {
			$this->assertSame([], $this->helper($rule));
		}
		$this->assertSame([], $this->logLines());
	}

	/** @return array<string, array{\Throwable}> an Exception and an Error, since the catch must hold both */
	public static function faultProvider(): array
	{
		return ['RuntimeException' => [new RuntimeException('x')], 'Error' => [new Error('x')]];
	}

	#[DataProvider('faultProvider')]
	public function testForcedInternalFailureIsContainedLoggedOnceAndRestoresState(\Throwable $fault): void
	{
		$rule = '/^5\.8\.44\.\d{1,3}$/';
		$this->assertSame(['5.8.44.0/24'], $this->helper($rule), 'control: without the fault the rule collects');
		$GLOBALS['pfb_test_abp_regex_fault'] = $fault;
		$this->assertSame([], $this->callAndAssertStateRestored($rule));
		$lines = $this->logLines();
		$this->assertCount(1, $lines);
		$this->assertStringContainsString('testfeed', $lines[0]);
		$this->assertStringContainsString($rule, $lines[0]);
	}

	public function testForcedFailureLogsAtMostTheFirst128BytesOfTheRule(): void
	{
		$GLOBALS['pfb_test_abp_regex_fault'] = new RuntimeException('x');
		$rule = self::paddedRule(400);
		$this->assertSame([], $this->helper($rule));
		$lines = $this->logLines();
		$this->assertCount(1, $lines);
		$this->assertStringContainsString(substr($rule, 0, 128), $lines[0]);
		$this->assertStringNotContainsString(substr($rule, 0, 129), $lines[0]);
	}

	public function testFailureSeamIsUnreachableForRulesRefusedEarlier(): void
	{
		$GLOBALS['pfb_test_abp_regex_fault'] = new RuntimeException('x');
		foreach (['/^5\.8\.44\.\p{Nd}+$/', '@@/^5\.8\.44\.\d{1,3}$/', '/^ads\d+\.example\.com$/', '||5.8.44.1^', ''] as $line) {
			$this->assertSame([], $this->helper($line));
		}
		$this->assertSame([], $this->logLines());
	}

	public function testForcedFailureThroughTheParseLoopStagesTheLineAndKeepsParsing(): void
	{
		$line = '/^5\.8\.44\.\d{1,3}$/';
		$GLOBALS['pfb_test_abp_regex_fault'] = new RuntimeException('x');
		$out = $this->runRegion($line);
		$this->assertSame([], $out['warnings']);
		$this->assertSame([[], 0, FALSE, [['a', $line]]], [$out['ip4'], $out['ipcount'], $out['updateip'], $out['rows']]);
		$lines = $this->logLines();
		$this->assertCount(1, $lines);
		$this->assertStringContainsString('testfeed', $lines[0]);
		$this->assertStringContainsString($line, $lines[0]);
		$next = $this->runRegion('||1.2.3.4^');
		$this->assertSame([['1.2.3.4'], 1, []], [$next['ip4'], $next['ipcount'], $next['rows']]);
		unset($GLOBALS['pfb_test_abp_regex_fault']);
		$after = $this->runRegion($line);
		$this->assertSame([['5.8.44.0/24'], 1], [$after['ip4'], $after['ipcount']]);
	}
}
