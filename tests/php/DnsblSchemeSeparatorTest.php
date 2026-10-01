<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * DNSBL plain lines: what counts as a scheme separator, and the empty-scheme IP shape.
 *
 * Intent pinned here:
 *  - '://<ip>', '://<ip>^' and '://<ip>^$options' (IPv4 bare, IPv6 bracketed only) list that IP in
 *    lenient AND strict mode; the options are dropped, never scanned.
 *  - A '://' that follows a '/', '?' or '#' is part of the path/query/fragment, never a scheme
 *    separator: an embedded redirector URL ('evil.com/x?u=http://8.8.8.8/') cannot supply the IP
 *    the firewall blocks.
 *  - Every other shape keeps its previous lenient/strict outcome (controls).
 *
 * The expectation string is: 'ip4=<a>,<b>', 'ip6=...', 'd=<domain>' (domain rows), 'pe' (the line
 * went to the parse-error log), or 'none'; parts are joined by a space. Each row names the
 * lenient and the strict outcome. Rows marked RED fail on the code before the scheme-separator
 * rule; the rest are controls that must not move.
 *
 * The parse loop lives inside sync_package_pfblockerng() and is not unit-reachable, so the region
 * from the per-line scrub through the first plain-path domain write is eval-extracted verbatim
 * from the REAL source (house precedent: DnsblNumericHostTest).
 */
#[CoversFunction('pfb_dnsbl_extract_host')]
#[CoversFunction('pfb_dnsbl_strip_scheme')]
#[CoversFunction('pfb_dnsbl_scheme_pos')]
final class DnsblSchemeSeparatorTest extends TestCase
{
	private static string $region;

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
			'/(\t+\$line = pfb_dnsbl_scrub_line\(\$line\);\n.*?\$lite = FALSE;\n.*?@fwrite\(\$dhandle, \$domain_data\);)/s',
			$src,
			$m
		)) {
			throw new RuntimeException('test bootstrap: DNSBL scrub-to-plain-path region not found');
		}
		// The region drops a line with `continue`; give it a loop of its own inside eval().
		self::$region = "foreach ([0] as \$pfb_test_iter) {\n{$m[1]}\n}\n";
	}

	protected function setUp(): void
	{
		$this->failLog = (string) tempnam(sys_get_temp_dir(), 'pfb_sep_fail_');
		$this->mainLog = (string) tempnam(sys_get_temp_dir(), 'pfb_sep_log_');
		$this->savedPfb = $GLOBALS['pfb'] ?? NULL;
	}

	protected function tearDown(): void
	{
		@unlink($this->failLog);
		@unlink($this->mainLog);
		$GLOBALS['pfb'] = $this->savedPfb;
	}

	/**
	 * Run the extracted loop body over one feed line.
	 *
	 * @return array{ip4: list<string>, ip6: list<string>, domains: list<string>, pe: bool}
	 */
	private function parseLine(string $feedLine, bool $lenient, PfbToggle $supp = PfbToggle::Off,
		string $dnsblIp = 'Deny_Both', bool $custom = TRUE): array
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
		$csv_parser = FALSE;
		$run_once = TRUE;
		$csv_type = '';
		$rev_format = FALSE;
		$alienvault_types = [];
		$dhandle = fopen('php://memory', 'w+');
		eval(self::$region);
		rewind($dhandle);
		$domains = [];
		while (($row = fgets($dhandle)) !== FALSE) {
			$domains[] = json_decode($row, TRUE, 512, JSON_THROW_ON_ERROR)[1];
		}
		fclose($dhandle);
		return [
			'ip4'     => $domain_data_ip,
			'ip6'     => $domain_data_ip6,
			'domains' => $domains,
			'pe'      => filesize($this->failLog) > 0,
		];
	}

	/** @param array{ip4: list<string>, ip6: list<string>, domains: list<string>, pe: bool} $r */
	private static function summarize(array $r): string
	{
		$parts = [];
		if ($r['ip4'] !== []) {
			$parts[] = 'ip4=' . implode(',', $r['ip4']);
		}
		if ($r['ip6'] !== []) {
			$parts[] = 'ip6=' . implode(',', $r['ip6']);
		}
		if ($r['domains'] !== []) {
			$parts[] = 'd=' . implode(',', $r['domains']);
		}
		if ($r['pe']) {
			$parts[] = 'pe';
		}
		return $parts === [] ? 'none' : implode(' ', $parts);
	}

	#[DataProvider('lineProvider')]
	public function testLenientOutcome(string $line, string $lenient, string $strict, string $status): void
	{
		$this->assertSame($lenient, self::summarize($this->parseLine($line, TRUE)), "lenient [{$status}] {$line}");
	}

	#[DataProvider('lineProvider')]
	public function testStrictOutcome(string $line, string $lenient, string $strict, string $status): void
	{
		$this->assertSame($strict, self::summarize($this->parseLine($line, FALSE)), "strict [{$status}] {$line}");
	}

	/** @return array<string, array{string, string, string, string}> line, lenient, strict, RED|control */
	public static function lineProvider(): array
	{
		$rows = [
			// RED: empty-scheme IP shapes are listed in both modes, options dropped.
			['://1.2.3.4', 'ip4=1.2.3.4', 'ip4=1.2.3.4', 'RED'],
			['://1.2.3.4^', 'ip4=1.2.3.4', 'ip4=1.2.3.4', 'RED'],
			['://1.2.3.4^$third-party', 'ip4=1.2.3.4', 'ip4=1.2.3.4', 'RED'],
			['://[2001:db8::1]^', 'ip6=2001:db8::1', 'ip6=2001:db8::1', 'RED'],
			['://[2001:db8::1]^$important,dnstype=A', 'ip6=2001:db8::1', 'ip6=2001:db8::1', 'RED'],
			['://[::ffff:192.0.2.1]^', 'ip4=192.0.2.1', 'ip4=192.0.2.1', 'RED'],
			['://user:pass@1.2.3.4^', 'ip4=1.2.3.4', 'ip4=1.2.3.4', 'RED'],
			['://1.2.3.4^$', 'ip4=1.2.3.4', 'ip4=1.2.3.4', 'RED'],
			['://[2001:db8::1]^$/http://9.9.9.9', 'ip6=2001:db8::1', 'ip6=2001:db8::1', 'RED'],

			// RED: an '@' in the '^$options' tail is option text, not userinfo.
			['://1.2.3.4^$domain=a@9.9.9.9', 'ip4=1.2.3.4', 'ip4=1.2.3.4', 'RED'],
			['://[2001:db8::1]^$domain=a@9.9.9.9', 'ip6=2001:db8::1', 'ip6=2001:db8::1', 'RED'],
			['://[2001:db8::1]^$x@[2001:db8::2]^', 'ip6=2001:db8::1', 'ip6=2001:db8::1', 'RED'],
			['://1.2.3.4^$domain=a@evil.com', 'ip4=1.2.3.4', 'ip4=1.2.3.4', 'RED'],
			['://1.2.3.4^$csp=x@[2001:db8::99]', 'ip4=1.2.3.4', 'ip4=1.2.3.4', 'RED'],
			['http://evil.com^$x@9.9.9.9', 'pe', 'pe', 'RED'],
			// A bare '^' (no '$' after it) also ends the userinfo search.
			['://1.2.3.4^@evil.com', 'pe', 'pe', 'RED'],
			['://1.2.3.4^x@9.9.9.9', 'pe', 'pe', 'RED'],

			// RED: path or trailing text after an empty-scheme IPv4.
			['://1.2.3.4/path^', 'ip4=1.2.3.4', 'ip4=1.2.3.4', 'RED'],
			['://1.2.3.4^ #c', 'ip4=1.2.3.4', 'ip4=1.2.3.4', 'RED'],

			// RED: a '://' after '/', '?' or '#' is not a scheme separator.
			['evil.com/x?u=http://8.8.8.8/', 'd=evil.com', 'd=evil.com', 'RED'],
			['evil.com/r#http://8.8.8.8', 'd=evil.com', 'd=evil.com', 'RED'],
			['evil.com?u=http://8.8.8.8', 'd=evil.com', 'd=evil.com', 'RED'],
			['evil.com/r?u=://8.8.8.8', 'd=evil.com', 'd=evil.com', 'RED'],
			['evil.com/x?u=http://[2001:db8::1]/', 'd=evil.com', 'd=evil.com', 'RED'],
			['8.8.8.8/http://9.9.9.9', 'ip4=8.8.8.8', 'ip4=8.8.8.8', 'RED'],
			['1.2.3.4?u=http://9.9.9.9', 'ip4=1.2.3.4', 'ip4=1.2.3.4', 'RED'],
			['a/b://8.8.8.8', 'pe', 'pe', 'RED'],
			['a/b://evil.com', 'pe', 'pe', 'RED'],
			['?u=http://8.8.8.8', 'pe', 'pe', 'RED'],
			['://user:pass@1.2.3.4^$third-party', 'ip4=1.2.3.4', 'ip4=1.2.3.4', 'RED'],

			// RED: an empty-scheme IP anchor drops the port, honours a CIDR and reads padded octets as
			// decimal, as the plain path and the '||' anchor do; a bad mask is a parse error.
			['://1.2.3.4:443^', 'ip4=1.2.3.4', 'ip4=1.2.3.4', 'RED'],
			['://[2001:db8::1]:443^', 'ip6=2001:db8::1', 'ip6=2001:db8::1', 'RED'],
			['://2001:db8::1^', 'ip6=2001:db8::1', 'ip6=2001:db8::1', 'RED'],
			['://2001:db8::1', 'ip6=2001:db8::1', 'ip6=2001:db8::1', 'RED'],
			['://0xC0A80164^', 'ip4=192.168.1.100', 'ip4=192.168.1.100', 'RED'],
			['://1.2.3.4:80', 'ip4=1.2.3.4', 'ip4=1.2.3.4', 'RED'],
			['://10.0.0.0/8^', 'ip4=10.0.0.0/8', 'ip4=10.0.0.0/8', 'RED'],
			['://192.168.010.1^', 'ip4=192.168.10.1', 'ip4=192.168.10.1', 'RED'],
			['://10.0.0.0/33^', 'pe', 'pe', 'RED'],
			['://192.168.1/24^', 'pe', 'pe', 'RED'],
			['://1.2.3.4/' . str_repeat('9', 5000) . '^', 'pe', 'pe', 'RED'],

			// Controls: outcome identical before and after the separator rule.
			['http://user@1.2.3.4/', 'ip4=1.2.3.4', 'ip4=1.2.3.4', 'control'],
			['://[2001:db8::1]', 'ip6=2001:db8::1', 'ip6=2001:db8::1', 'control'],
			['://1.2.3.4$third-party', 'pe', 'pe', 'control'],
			['://[2001:db8::1]^^', 'pe', 'pe', 'control'],
			['://[2001:db8::1]^x', 'pe', 'pe', 'control'],
			['://[not-an-ip]^', 'pe', 'pe', 'control'],
			['://[192.0.2.1]^', 'pe', 'pe', 'control'],
			['://[192.0.2.1]', 'pe', 'pe', 'control'],
			['://[2001:db8::1]/path^', 'ip6=2001:db8::1', 'pe', 'control'],
			['http://1.2.3.4^', 'pe', 'pe', 'control'],
			['http://[2001:db8::1]^', 'pe', 'pe', 'control'],
			['http://[2001:db8::1]', 'ip6=2001:db8::1', 'ip6=2001:db8::1', 'control'],
			['1.2.3.4^', 'pe', 'pe', 'control'],
			['[2001:db8::1]^', 'pe', 'pe', 'control'],
			['evil.com;url=http://8.8.8.8', 'ip4=8.8.8.8', 'pe', 'control'],
			['note http://8.8.8.8', 'ip4=8.8.8.8', 'ip4=8.8.8.8', 'control'],
			['http://evil.com/x?u=http://8.8.8.8/', 'd=evil.com', 'pe', 'control'],
			['123://evil.com', 'd=evil.com', 'pe', 'control'],
			['!!bad://evil.com', 'none', 'none', 'control'],
			['evil.com://junk', 'pe', 'pe', 'control'],
			['://evil.com', 'd=evil.com', 'pe', 'control'],
			['http://evil.com', 'd=evil.com', 'd=evil.com', 'control'],
			['https://evil.com/', 'd=evil.com', 'd=evil.com', 'control'],

			// Hostile input: none of it may list an address or a domain.
			['://', 'pe', 'pe', 'control'],
			['://^', 'pe', 'pe', 'control'],
			['://^$x', 'pe', 'pe', 'control'],
			['://[]^', 'pe', 'pe', 'control'],
			['://[', 'pe', 'pe', 'control'],
			['://]^', 'pe', 'pe', 'control'],
			['://[2001:db8::1', 'pe', 'pe', 'control'],
			["://1.2.3.4\t^", 'pe', 'pe', 'control'],
			['://' . str_repeat('a', 5000), 'pe', 'pe', 'control'],
			['://[ｆｅ80::1]^', 'pe', 'pe', 'control'],
			['://:80^', 'pe', 'pe', 'control'],
			['://[2001:db8::1]:^', 'pe', 'pe', 'control'],
		];
		$out = [];
		foreach ($rows as [$line, $l, $s, $status]) {
			if (isset($out[$status . ' ' . $line])) {
				throw new \LogicException('duplicate provider row: ' . $line);
			}
			$out[$status . ' ' . $line] = [$line, $l, $s, $status];
		}
		return $out;
	}

	public function testDisabledDnsblIpCollectsNothingAndWritesNoDomainRow(): void
	{
		foreach ([TRUE, FALSE] as $lenient) {
			$r = $this->parseLine('://1.2.3.4^', $lenient, PfbToggle::Off, 'Disabled');
			$this->assertSame([], $r['ip4'], 'IP collected while DNSBL IP is Disabled');
			$this->assertSame([], $r['domains'], 'domain row written for an IP line while Disabled');
		}
	}

	public function testSuppressedPrivateAddressIsNotCollectedFromEmptySchemeLine(): void
	{
		// Before-state: suppression off lists it, so suppression on is what drops it.
		$this->assertSame('ip4=192.168.1.100',
			self::summarize($this->parseLine('://192.168.1.100^', TRUE, PfbToggle::Off, 'Deny_Both', FALSE)));
		foreach ([TRUE, FALSE] as $lenient) {
			$r = $this->parseLine('://192.168.1.100^', $lenient, PfbToggle::On, 'Deny_Both', FALSE);
			$this->assertSame([], $r['ip4'], 'RFC1918 address collected with suppression on');
			$this->assertSame([], $r['domains']);
		}
	}
}
