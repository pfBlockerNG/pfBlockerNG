<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #4272, at the DNSBL parse loop itself:
 *  - in an Adblock feed a line takes the ABP path, is kept as a hostname, hosts line or hostname mask,
 *    or is dropped, so a path rule never becomes a domain block;
 *  - in strict mode a domain line is kept only as '(<scheme>://)?<domain>/?', optionally followed by
 *    a space and a '#' comment.
 *
 * The loop lives inside sync_package_pfblockerng() and is not unit-reachable, so the region from the
 * per-line scrub through the plain-path domain write is eval-extracted verbatim from the REAL source
 * (house precedent: DnsblSchemeSeparatorTest, DnsblNumericHostTest).
 */
final class DnsblFeedLineRoutingTest extends TestCase
{
	private static string $region;

	private string $failLog = '';
	private string $mainLog = '';
	private mixed $savedPfb = NULL;
	private string $lastDomainData = '';

	public static function setUpBeforeClass(): void
	{
		$src = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc');
		if ($src === FALSE) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_apply.inc');
		}
		if (!preg_match(
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
		$this->failLog = (string) tempnam(sys_get_temp_dir(), 'pfb_route_fail_');
		$this->mainLog = (string) tempnam(sys_get_temp_dir(), 'pfb_route_log_');
		$this->savedPfb = $GLOBALS['pfb'] ?? NULL;
	}

	protected function tearDown(): void
	{
		@unlink($this->failLog);
		@unlink($this->mainLog);
		$GLOBALS['pfb'] = $this->savedPfb;
	}

	/** @return list<array{0: string, 1: string}> the staged rows: ['a', rule] or ['d', domain] */
	private function parseLine(string $feedLine, bool $abpFeed, bool $lenient): array
	{
		$pfb = [
			'dnsbl_parse_mode' => $lenient ? PfbDnsblParseMode::Lenient : PfbDnsblParseMode::Strict,
			'dnsbl_parse_err' => $this->failLog,
			'dnsbl_ip'        => 'Deny_Both',
			'supp'            => PfbToggle::Off,
			'log'             => $this->mainLog,
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
		$custom = FALSE;
		$csv_parser = FALSE;
		$run_once = TRUE;
		$csv_type = '';
		$rev_format = FALSE;
		$alienvault_types = [];
		$dhandle = fopen('php://memory', 'w+');
		$domain_data = '';
		eval(self::$region);
		$this->lastDomainData = $domain_data;
		rewind($dhandle);
		$rows = [];
		while (($row = fgets($dhandle)) !== FALSE) {
			$rows[] = json_decode($row, TRUE, 512, JSON_THROW_ON_ERROR);
		}
		fclose($dhandle);
		return $rows;
	}

	/** @return array<string, array{string, list<array{0: string, 1: string}>}> line => rows in an Adblock feed */
	public static function adblockFeedLineProvider(): array
	{
		return [
			'EasyPrivacy path rule'  => ['.imgur.com/lumbar.gif', []],
			'path rule with options' => ['.facebook.com/tr/$image', []],
			'file-name rule'         => ['-geoIP.js', []],
			// uBO reads these as ||host^, AdGuard DNS blocks the host (owner decision, #4272).
			'bare domain'            => ['imgur.com', [['d', 'imgur.com']]],
			'hosts line'             => ['0.0.0.0 imgur.com', [['d', 'imgur.com']]],
			'filename fragment'      => ['_chartbeat.js', []],
			'header'                 => ['[Adblock Plus 2.0]', []],
			'comment'                => ['! Title: EasyPrivacy', []],
			'anchored rule'          => ['||mp.imgur.com^', [['a', '||mp.imgur.com^']]],
			'anchored path rule'     => ['||imgur.com/albumview.gif?', [['a', '||imgur.com/albumview.gif?']]],
			'exception rule'         => ['@@||imgur.com/min/px.js$~third-party', [['a', '@@||imgur.com/min/px.js$~third-party']]],
			'cosmetic rule'          => ['imgur.com##.Top300x600', [['a', 'imgur.com##.Top300x600']]],
			// owner decisions, second round: Allow Ports-compatible hostnames, hosts lines, AdGuard DNS masks.
			'hostname with port'     => ['imgur.com:8080', [['d', 'imgur.com']]],
			'hostname, port, slash'  => ['imgur.com:443/', [['d', 'imgur.com']]],
			'hostname with slash'    => ['imgur.com/', [['d', 'imgur.com']]],
			'hosts line, aliases'    => ['0.0.0.0 imgur.com i.imgur.com # ads', [['d', 'imgur.com']]],
			'exact mask'             => ['|imgur.com^', [['d', 'imgur.com']]],
			'scheme mask'            => ['://imgur.com^', [['d', 'imgur.com']]],
			'end-anchored mask'      => ['imgur.com^', [['a', '||imgur.com^']]],
			'important mask'         => ['imgur.com^$important', [['a', '||imgur.com^$important']]],
			'subdomain-only mask'    => ['.imgur.com^', []],
			'wildcard mask'          => ['*.imgur.com^', []],
			'badfilter mask'         => ['imgur.com^$badfilter', [['a', '||imgur.com^$badfilter']]],
			'AdGuard extended CSS'   => ['eksisozluk.com#$?#.ads', [['a', 'eksisozluk.com#$?#.ads']]],
			'AdGuard HTML filter'    => ['imgur.com$$script[data-src]', []],
			'hosts line, IP target'  => ['0.0.0.0 1.2.3.4', []],
		];
	}

	/** A mask row counts as feed output: a feed of masks alone must not be taken for an empty one ('No Domains Found'). */
	public function testAMaskRowIsFeedOutput(): void
	{
		$this->assertSame([['a', '||imgur.com^']], $this->parseLine('imgur.com^', TRUE, FALSE));
		$this->assertNotSame('', $this->lastDomainData);
	}

	/** An AdGuard extended cosmetic rule takes the ABP path in any feed, so Lenient never cuts its site out. */
	public function testAnAdGuardExtendedCosmeticRuleIsNeverADomainBlock(): void
	{
		foreach ([TRUE, FALSE] as $lenient) {
			$this->assertSame([['a', 'eksisozluk.com#$?#.ads']], $this->parseLine('eksisozluk.com#$?#.ads', FALSE, $lenient));
		}
	}

	/** @param list<array{0: string, 1: string}> $rows */
	#[DataProvider('adblockFeedLineProvider')]
	public function testAnAdblockFeedLineTakesTheAbpPathOrIsDropped(string $feedLine, array $rows): void
	{
		foreach ([TRUE, FALSE] as $lenient) {
			$this->assertSame($rows, $this->parseLine($feedLine, TRUE, $lenient), "[{$feedLine}] lenient=" . var_export($lenient, TRUE));
		}
	}

	/** Control: without the header the same plain lines keep today's routing. */
	public function testTheSameLinesInAFeedWithoutTheHeaderKeepPerLineRouting(): void
	{
		$this->assertSame([['d', 'imgur.com']], $this->parseLine('imgur.com', FALSE, FALSE));
		$this->assertSame([['d', 'imgur.com']], $this->parseLine('0.0.0.0 imgur.com', FALSE, FALSE));
		$this->assertSame([['a', '||mp.imgur.com^']], $this->parseLine('||mp.imgur.com^', FALSE, FALSE));
		$this->assertSame([['d', 'imgur.com']], $this->parseLine('.imgur.com/lumbar.gif', FALSE, TRUE), 'lenient still cuts the host');
	}

	/** Any bracketed first line naming an Adblock-family product heads an Adblock-syntax list (owner ruling, #4272). */
	public function testEveryAdblockFamilyBracketHeaderMarksTheFeedAsAdblock(): void
	{
		$path = (string) tempnam(sys_get_temp_dir(), 'pfb_route_hdr_');
		try {
			foreach (['[Adblock Plus 2.0]', '[Adblocker list]', '[AdGuardHome blocklist]', '[uBlock-mirror hosts]', '[ uBlock ]'] as $first) {
				file_put_contents($path, "{$first}\n");
				$this->assertTrue(pfb_dnsbl_feed_has_abp_header($path), "{$first} heads an Adblock-syntax list");
			}
		} finally {
			@unlink($path);
		}
	}

	/** @return array<string, array{string, list<array{0: string, 1: string}>}> line => rows in strict mode */
	public static function strictCommentProvider(): array
	{
		return [
			'comment after the domain'       => ['example.com # blocked', [['d', 'example.com']]],
			'comment after the slash'        => ['example.com/ # blocked', [['d', 'example.com']]],
			'tab before the comment'         => ["example.com/\t# blocked", [['d', 'example.com']]],
			'scheme, slash and comment'      => ['https://example.com/ # blocked', [['d', 'example.com']]],
			'fragment glued to the domain'   => ['example.com#blocked', []],
			'fragment glued to the slash'    => ['example.com/#blocked', []],
		];
	}

	/** @param list<array{0: string, 1: string}> $rows */
	#[DataProvider('strictCommentProvider')]
	public function testStrictModeAllowsASpaceSeparatedCommentOnly(string $feedLine, array $rows): void
	{
		$this->assertSame($rows, $this->parseLine($feedLine, FALSE, FALSE), "strict [{$feedLine}]");
	}
}
