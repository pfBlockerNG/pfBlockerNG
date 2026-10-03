<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3434: an ABP block regex rule '/^A\.B\.C\.<tail>$/' whose pattern matches all 256 strings
 * A.B.C.0..A.B.C.255 also puts 'A.B.C.0/24' into the DNSBL IP table. The rule is still staged for
 * Python byte-identical (Python skips nothing here: the line keeps flowing as an ABP row).
 *
 * The helper rows call pfb_dnsbl_abp_regex_ip4_24() directly; the parse-loop rows run the ABP region
 * eval-extracted verbatim from the REAL pfblockerng_apply.inc (house precedent:
 * tests/php/DnsblNumericHostTest.php) and never name the helper, so they pin the wiring by behaviour.
 */
#[CoversFunction('pfb_dnsbl_abp_regex_ip4_24')]
final class DnsblAbpRegexIp4SlashTwentyFourTest extends TestCase
{
	private const FIXTURE = __DIR__ . '/fixtures/dnsbl_abp_regex_ipv4_24_oracle.txt';

	private static string $abpRegion;

	private string $failLog = '';
	private string $mainLog = '';
	private mixed $savedPfb = NULL;

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
	}

	protected function tearDown(): void
	{
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

	/** Call the helper with warnings/notices captured; returns [result, warnings]. */
	private function callHelper(string $line): array
	{
		$warnings = [];
		set_error_handler(static function (int $no, string $str) use (&$warnings): bool {
			$warnings[] = $str;
			return TRUE;
		});
		try {
			$result = pfb_dnsbl_abp_regex_ip4_24($line);
		} finally {
			restore_error_handler();
		}
		return [$result, $warnings];
	}

	/** An eligible rule whose inner is exactly $bytes long: '^5\.8\.44\.' + '.*' + '()' padding + '$'. */
	private static function paddedRule(int $bytes, string $star = '.*'): string
	{
		$fixed = strlen('^5\.8\.44\.' . $star . '$');
		return '/^5\.8\.44\.' . $star . str_repeat('()', intdiv($bytes - $fixed, 2)) . '$/';
	}

	/** Matches all of 5.8.44.0-255, but only after a failing branch of nested alternations backtracks far past 10000 steps. */
	private static function backtrackHeavyRule(): string
	{
		return '/^5\.8\.44\.(' . str_repeat('(\d|\d)*', 15) . '-|\d{1,3})$/';
	}

	/**
	 * Every shape the helper decides on: [rule line, expected 'A.B.C.0/24' or ''].
	 *
	 * @return array<string, array{string, string}>
	 */
	public static function ruleProvider(): array
	{
		$rows = [
			'[12]?\d?\d tail'              => ['/^142\.91\.159\.[12]?\d?\d$/', '142.91.159.0/24'],
			'\d{1,3} tail'                 => ['/^5\.8\.44\.\d{1,3}$/', '5.8.44.0/24'],
			'.* tail'                      => ['/^5\.8\.44\..*$/', '5.8.44.0/24'],
			'\d* tail matches 0-255'       => ['/^5\.8\.44\.\d*$/', '5.8.44.0/24'],
			'lazy .*? tail'                => ['/^5\.8\.44\..*?$/', '5.8.44.0/24'],
			'partial tail'                 => ['/^172\.255\.6\.(\d\d?|(17?|2)[0-689]\d)$/', ''],
			'near-full tail 255/256'       => ['/^172\.255\.6\.(\d\d?|2.*|1[0-689].*|17[0-689])$/', ''],
			'class in third octet'         => ['/^5\.8\.4[4-7]\.\d{1,3}$/', ''],
			'literal fourth octet'         => ['/^5\.8\.44\.1$/', ''],
			'posix class tail'             => ['/^5\.8\.44\.[[:digit:]]+$/', ''],
			'unicode property tail'        => ['/^5\.8\.44\.\p{Nd}+$/', ''],
			'recursion (?1) tail'          => ['/^5\.8\.44\.(\d+)(?1)?$/', ''],
			'inline flag (?i) tail'        => ['/^5\.8\.44\.(?i)\d+$/', ''],
			'(? inside an allowed tail'    => ['/^1\.2\.3\.(\d{1,3})|(?1)$/', ''],
			'$options suffix'              => ['/^5\.8\.44\.\d{1,3}$/$important', ''],
			'allow rule'                   => ['@@/^5\.8\.44\.\d{1,3}$/', ''],
			'no ^ and no $'                => ['/5\.8\.44\.\d+/', ''],
			'no ^'                         => ['/5\.8\.44\.\d+$/', ''],
			'no $'                         => ['/^5\.8\.44\.\d+/', ''],
			'padded octet'                 => ['/^05\.8\.44\.\d+$/', ''],
			'octet over 255'               => ['/^5\.256\.44\.\d+$/', ''],
			'octet 255 is fine'            => ['/^255\.255\.255\.\d+$/', '255.255.255.0/24'],
			'octet 0 is fine'              => ['/^1\.0\.0\.\d+$/', '1.0.0.0/24'],
			'inner contains a slash'       => ['/^5\.8\.44\.\d+\/24$/', ''],
			'domain regex'                 => ['/^ads\d+\.example\.com$/', ''],
			'empty inner'                  => ['//', ''],
			'single slash'                 => ['/', ''],
			'space inner'                  => ['/ /', ''],
			'space in tail'                => ['/^5\.8\.44\. \d+$/', ''],
			'tab in tail'                  => ['/^5\.8\.44\.' . "\t" . '\d+$/', ''],
			'# in tail'                    => ['/^5\.8\.44\.#\d+$/', ''],
			'~ in tail'                    => ['/^5\.8\.44\.~\d+$/', ''],
			'trailing ~'                   => ['/^5\.8\.44\.\d+~$/', ''],
			'nested quantifier (\d+)+'     => ['/^5\.8\.44\.(\d+)+$/', '5.8.44.0/24'],
			'nested quantifier (\d*)*\d*'  => ['/^5\.8\.44\.(\d*)*\d*$/', '5.8.44.0/24'],
			'unbalanced group'             => ['/^5\.8\.44\.(\d+$/', ''],
			'unterminated class'           => ['/^5\.8\.44\.[\d$/', ''],
			'inverted quantifier'          => ['/^5\.8\.44\.\d{3,1}$/', ''],
			'non-ASCII digit octet'        => ['/^٥\.8\.44\.\d+$/', ''],
			'non-ASCII digit tail'         => ['/^5\.8\.44\.٥$/', ''],
			'uppercase \D in tail'         => ['/^5\.8\.44\.\D*$/', ''],
			'backreference in tail'        => ['/^5\.8\.44\.(\d+)\1?$/', ''],
			'trailing newline'             => ["/^5\\.8\\.44\\.\\d+$/\n", ''],
			'512-byte inner qualifies'     => [self::paddedRule(512), '5.8.44.0/24'],
			'513-byte inner is refused'    => [self::paddedRule(513, '.*+'), ''],
			'100 KB inner'                 => ['/^5\.8\.44\.' . str_repeat('()', 51200) . '\d+$/', ''],
			'empty group tail ()'          => ['/^5\.8\.44\.()$/', ''],
			'zero-repeat tail \d{0}'       => ['/^5\.8\.44\.\d{0}$/', ''],
			'empty alternative (|\d+)'     => ['/^5\.8\.44\.(|\d+)$/', '5.8.44.0/24'],
			'{,} after |'                  => ['/^1\.2\.3\.\d+|{,}$/', ''],
			'{,} after ? then |'           => ['/^1\.2\.3\.\d?{,}|\d+$/', ''],
			'{,} inside a group'           => ['/^1\.2\.3\.(\d+|{,})$/', ''],
			'backtrack-heavy tail'         => [self::backtrackHeavyRule(), ''],
		];
		return $rows;
	}

	#[DataProvider('ruleProvider')]
	public function testHelperDecidesPerRule(string $line, string $expected): void
	{
		[$result, $warnings] = $this->callHelper($line);
		$this->assertSame($expected, $result);
		$this->assertSame([], $warnings, 'no warning or notice may escape the helper');
	}

	public function testHelperInnerLengthBoundaryIs512Bytes(): void
	{
		$at = self::paddedRule(512);
		$over = self::paddedRule(513, '.*+');
		$this->assertSame(512, strlen($at) - 2);
		$this->assertSame(513, strlen($over) - 2);
		$this->assertSame('5.8.44.0/24', pfb_dnsbl_abp_regex_ip4_24($at));
		$this->assertSame('', pfb_dnsbl_abp_regex_ip4_24($over));
		// The refused rule is a valid, qualifying pattern: only its length disqualifies it.
		$this->assertSame(256, count(preg_grep('~' . substr($over, 1, -1) . '~', array_map(static fn(int $n): string => "5.8.44.$n", range(0, 255)))));
	}

	public function testBacktrackHeavyRuleIsRefusedOnlyForItsCost(): void
	{
		$rule = self::backtrackHeavyRule();
		$this->assertLessThanOrEqual(512, strlen($rule) - 2);
		$hosts = array_map(static fn(int $n): string => "5.8.44.$n", range(0, 255));
		$this->assertCount(256, preg_grep('~' . substr($rule, 1, -1) . '~', $hosts), 'under the default limit it matches every address');
		$this->assertSame(PREG_NO_ERROR, preg_last_error());
	}

	public function testHelperDoesNotSelfStripAnEndOfLine(): void
	{
		$this->assertSame('5.8.44.0/24', pfb_dnsbl_abp_regex_ip4_24('/^5\.8\.44\.\d+$/'));
		$this->assertSame('', pfb_dnsbl_abp_regex_ip4_24("/^5\\.8\\.44\\.\\d+$/\n"));
		$this->assertSame('', pfb_dnsbl_abp_regex_ip4_24("/^5\\.8\\.44\\.\\d+$/\r\n"));
	}

	public function testHelperLeavesPcreStateAndReturnTypeAlone(): void
	{
		$this->assertSame('', pfb_dnsbl_abp_regex_ip4_24('/^5\.8\.44\.\d{3,1}$/'));
		$this->assertSame('', pfb_dnsbl_abp_regex_ip4_24(''));
		$this->assertSame('', pfb_dnsbl_abp_regex_ip4_24('||5.8.44.1^'));
		$this->assertSame('', pfb_dnsbl_abp_regex_ip4_24('1.2.3.4'));
	}

	/** Parse-loop wiring: the collected /24 (or nothing) and the staged rows, for every rule shape. */
	#[DataProvider('ruleProvider')]
	public function testParseLoopCollectsTheSlash24AndStagesTheLineUnchanged(string $line, string $expected): void
	{
		$out = $this->runRegion($line);
		$this->assertSame([], $out['warnings']);
		$this->assertSame([], $out['ip6']);
		$this->assertSame($expected === '' ? [] : [$expected], $out['ip4']);
		$this->assertSame($expected === '' ? 0 : 1, $out['ipcount']);
		$this->assertSame($expected !== '', $out['updateip'] === TRUE);
		// Staged exactly as with DNSBL IP disabled (today's behaviour): the new step never drops or edits a line.
		$this->assertSame($this->runRegion($line, dnsblIp: 'Disabled')['rows'], $out['rows']);
		if ($expected !== '') {
			$this->assertSame([['a', $line]], $out['rows'], 'a qualifying rule is staged for Python byte-identical');
		}
	}

	public function testParseLoopSuppressionDropsAnRfc1918Slash24ButStillStagesTheLine(): void
	{
		$line = '/^192\.168\.0\.\d{1,3}$/';
		$control = $this->runRegion($line, custom: FALSE, supp: PfbToggle::Off);
		$this->assertSame(['192.168.0.0/24'], $control['ip4'], 'control: without suppression the /24 is collected');
		$out = $this->runRegion($line, custom: FALSE, supp: PfbToggle::On);
		$this->assertSame([], $out['ip4']);
		$this->assertSame(0, $out['ipcount']);
		$this->assertFalse($out['updateip']);
		$this->assertSame([['a', $line]], $out['rows']);
	}

	public function testParseLoopWithDnsblIpDisabledCollectsNothingAndStillStages(): void
	{
		$line = '/^142\.91\.159\.[12]?\d?\d$/';
		$out = $this->runRegion($line, dnsblIp: 'Disabled');
		$this->assertSame([[], [], 0, FALSE], [$out['ip4'], $out['ip6'], $out['ipcount'], $out['updateip']]);
		$this->assertSame([['a', $line]], $out['rows']);
	}

	public function testParseLoopStillTreatsAnAnchorAsAnIpAndNotAsARegex(): void
	{
		$out = $this->runRegion('||5.8.44.1^');
		$this->assertSame([['5.8.44.1'], 1, []], [$out['ip4'], $out['ipcount'], $out['rows']]);
	}

	public function testFixtureIsTheFortySevenLinesTheOracleMapNames(): void
	{
		$lines = file(self::FIXTURE, FILE_IGNORE_NEW_LINES);
		$this->assertIsArray($lines);
		$this->assertSame(array_keys(self::oracle()), $lines);
		$this->assertCount(47, $lines);
		$this->assertCount(34, array_filter(self::oracle(), static fn(string $cidr): bool => $cidr !== ''));
	}

	/** @return array<string, array{string, string}> */
	public static function oracleProvider(): array
	{
		$rows = [];
		foreach (self::oracle() as $line => $cidr) {
			$rows[$line] = [(string) $line, $cidr];
		}
		return $rows;
	}

	#[DataProvider('oracleProvider')]
	public function testOracleLineThroughHelper(string $line, string $cidr): void
	{
		$this->assertSame($cidr, pfb_dnsbl_abp_regex_ip4_24($line));
	}

	#[DataProvider('oracleProvider')]
	public function testOracleLineThroughParseLoop(string $line, string $cidr): void
	{
		$out = $this->runRegion($line);
		$this->assertSame($cidr === '' ? [] : [$cidr], $out['ip4']);
		$this->assertSame([['a', $line]], $out['rows']);
	}

	/**
	 * line => expected collected /24 ('' = nothing): 34 qualify, 13 do not (partial or non-/24 coverage).
	 *
	 * @return array<string, string>
	 */
	private static function oracle(): array
	{
		return [
			'/^142\.91\.159\.[12]?\d?\d$/' => '142.91.159.0/24',
			'/^23\.109\.150\.[12]?\d?\d$/' => '23.109.150.0/24',
			'/^23\.109\.248\.[12]?\d?\d$/' => '23.109.248.0/24',
			'/^172\.255\.6\.(\d\d?|(17?|2)[0-689]\d)$/' => '',
			'/^173\.233\.137\.[12]?\d?\d$/' => '173.233.137.0/24',
			'/^173\.233\.139\.[12]?\d?\d$/' => '173.233.139.0/24',
			'/^192\.243\.59\.[12]?\d?\d$/' => '192.243.59.0/24',
			'/^192\.243\.61\.[12]?\d?\d$/' => '192.243.61.0/24',
			'/^46\.161\.27\.[12]?\d?\d$/' => '46.161.27.0/24',
			'/^78\.128\.112\.[12]?\d?\d$/' => '78.128.112.0/24',
			'/^179\.60\.146\.[12]?\d?\d$/' => '179.60.146.0/24',
			'/^178\.253\.[0-7]\.[12]?\d?\d$/' => '',
			'/^178\.253\.14\.[12]?\d?\d$/' => '178.253.14.0/24',
			'/^178\.253\.15\.[12]?\d?\d$/' => '178.253.15.0/24',
			'/^178\.253\.2[0145]\.[12]?\d?\d$/' => '',
			'/^178\.253\.3[04-7]\.[12]?\d?\d$/' => '',
			'/^178\.253\.46\.[12]?\d?\d$/' => '178.253.46.0/24',
			'/^178\.253\.47\.[12]?\d?\d$/' => '178.253.47.0/24',
			'/^178\.253\.54\.[12]?\d?\d$/' => '178.253.54.0/24',
			'/^162\.241\.115\.[12]?\d?\d$/' => '162.241.115.0/24',
			'/^104\.160\.10\.[12]?\d?\d$/' => '104.160.10.0/24',
			'/^165\.231\.154\.[12]?\d?\d$/' => '165.231.154.0/24',
			'/^165\.231\.10\.[12]?\d?\d$/' => '165.231.10.0/24',
			'/^165\.231\.152\.[12]?\d?\d$/' => '165.231.152.0/24',
			'/^196\.196\.52\.[12]?\d?\d$/' => '196.196.52.0/24',
			'/^196\.196\.155\.[12]?\d?\d$/' => '196.196.155.0/24',
			'/^196\.240\.121\.[12]?\d?\d$/' => '196.240.121.0/24',
			'/^196\.242\.179\.[12]?\d?\d$/' => '196.242.179.0/24',
			'/^196\.245\.52\.[12]?\d?\d$/' => '196.245.52.0/24',
			'/^196\.245\.56\.[12]?\d?\d$/' => '196.245.56.0/24',
			'/^139\.45\.197\.[12]?\d?\d$/' => '139.45.197.0/24',
			'/^5\.61\.60\.[12]?\d?\d$/' => '5.61.60.0/24',
			'/^103\.224\.182\.[12]?\d?\d$/' => '103.224.182.0/24',
			'/^192\.243\.58\.[12]?\d?\d$/' => '192.243.58.0/24',
			'/^45\.141\.59\.[12]?\d?\d$/' => '45.141.59.0/24',
			'/^194\.226\.139\.[12]?\d?\d$/' => '194.226.139.0/24',
			'/^5\.8\.4[4-7]\.\d{1,3}$/' => '',
			'/^5\.101\.4[67]\.\d{1,3}$/' => '',
			'/^5\.188\.5[01]\.\d{1,3}$/' => '',
			'/^5\.188\.17[67]\.\d{1,3}$/' => '',
			'/^5\.188\.19[45]\.\d{1,3}$/' => '',
			'/^5\.189\.21[89]\.\d{1,3}$/' => '',
			'/^31\.184\.20[0-3]\.\d{1,3}$/' => '',
			'/^185\.238\.15[2-5]\.\d{1,3}$/' => '',
			'/^188\.42\.84\.[12]?\d?\d$/' => '188.42.84.0/24',
			'/^203\.195\.121\.[12]?\d?\d$/' => '203.195.121.0/24',
			'/^172\.255\.6\.(\d\d?|2.*|1[0-689].*|17[0-689])$/' => '',
		];
	}
}
