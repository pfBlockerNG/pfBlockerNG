<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * IP feeds: numeric URL hosts and IPv4-mapped IPv6, read the way a client reads them.
 *
 * A line starting with 'scheme://' whose host is a non-canonical IPv4 spelling is decoded with
 * the WHATWG rules (pfb_ipv4_numeric_host()): 'http://010.010.010.010/' reaches 8.8.8.8, not the
 * decimal 10.10.10.10 the regex used to produce, and 'http://0xC0A80164/' reaches 192.168.1.100
 * instead of being dropped without a log line. The rest of the line is still scanned for other
 * addresses; the host and its userinfo are not. A whole-line '::ffff:' address on a v4 list
 * yields the embedded IPv4; on a v6 list it is dropped and counted (it never matches a packet).
 * Bare zero-padded quads keep today's decimal reading: a bare feed line is the author's
 * notation, not a client URL.
 */
#[CoversFunction('pfb_ip_parse_line')]
#[CoversFunction('pfb_ip_parse_line_replay')]
final class IpParseLineNumericHostTest extends TestCase
{
	/** @return array<string, mixed> */
	private static function config(string $vtype, string $pftype, bool $custom = TRUE, string $suppression = 'off'): array
	{
		return pfb_ip_regex_config() + [
			'vtype'         => $vtype,
			'pftype'        => $pftype,
			'custom'        => $custom,
			'cidr_floor_v4' => 'Disabled',
			'cidr_floor_v6' => 'Disabled',
			'suppression'   => $suppression,
		];
	}

	/**
	 * [line, entries, detailed parse failure], run under both auto and regex pftype.
	 *
	 * @return array<string, array{string, string, list<string>, bool}>
	 */
	public static function v4LineProvider(): array
	{
		$rows = [
			// URL-context numeric host: decoded, rest of the line still scanned.
			'octal url host'             => ['http://010.010.010.010/x', ['8.8.8.8'], FALSE],
			'hex url host'               => ['http://0xC0A80164/x', ['192.168.1.100'], FALSE],
			'dword url host'             => ['http://3232235876/x', ['192.168.1.100'], FALSE],
			'upper-case scheme'          => ['HTTP://0xC0A80164/', ['192.168.1.100'], FALSE],
			'octal host + query quad'    => ['http://010.010.010.010/?to=1.2.3.4', ['8.8.8.8', '1.2.3.4'], FALSE],
			'hex host + query quad'      => ['http://0x7f000001/?to=1.2.3.4', ['127.0.0.1', '1.2.3.4'], FALSE],
			'hex host alone'             => ['http://0x7f000001/x', ['127.0.0.1'], FALSE],
			'userinfo decoy'             => ['http://1.2.3.4@0x7f000001/', ['127.0.0.1'], FALSE],
			'user:pass and port'         => ['http://u:p@0x7f000001:80/', ['127.0.0.1'], FALSE],
			'empty port after colon'    => ['http://0x7f000001:/x', ['127.0.0.1'], FALSE],
			'port then query quad'       => ['http://0x7f000001:8080/?to=1.2.3.4', ['127.0.0.1', '1.2.3.4'], FALSE],
			'space ends the authority'   => ['http://0x7f000001 1.2.3.4', ['127.0.0.1', '1.2.3.4'], FALSE],
			'space after octal host'     => ['http://010.010.010.010 1.2.3.4', ['8.8.8.8', '1.2.3.4'], FALSE],
			'path copy stays bare quad'  => ['http://010.010.010.010/goto/010.010.010.010', ['8.8.8.8', '10.10.10.10'], FALSE],
			'invalid host + query quad'  => ['http://08.08.08.08/?to=9.9.9.9', ['9.9.9.9'], TRUE],
			'url host with NUL label'   => ["http://1.2\x00.3.4/x", [], TRUE],
			'invalid host alone'         => ['http://08.08.08.08/x', [], TRUE],
			// Unchanged: canonical host keeps the regex path; a mid-line URL is not decoded.
			'canonical host + query quad' => ['http://1.2.3.4/?to=5.6.7.8', ['1.2.3.4', '5.6.7.8'], FALSE],
			'mid-line url'               => ['see http://0x7f000001/ in text 9.9.9.9', ['9.9.9.9'], FALSE],
			// Whole-line IPv4-mapped IPv6 on a v4 list.
			'mapped hex tail'            => ['::ffff:c0a8:164', ['192.168.1.100'], FALSE],
			'mapped dotted tail'         => ['::ffff:192.168.1.100', ['192.168.1.100'], FALSE],
			'mapped + another quad'      => ['::ffff:c0a8:164 1.2.3.4', ['1.2.3.4'], FALSE],
			'mapped dotted + quad'       => ['::ffff:192.168.1.100 9.9.9.9', ['192.168.1.100', '9.9.9.9'], FALSE],
			'mapped + comment'           => ['::ffff:c0a8:164 # comment', [], FALSE],
			// Bare numeric tokens: counted and logged, never decoded.
			'bare hex dword'             => ['0xC0A80164', [], TRUE],
			'bare dotted hex'            => ['0xc0.0xa8.0x1.0x64', [], TRUE],
			'bare dword'                 => ['3232235876', [], TRUE],
			'bare short form'            => ['192.168.356', [], TRUE],
			'bare hex with prefix len'  => ['0xC0A80164/32', [], TRUE],
			'text ending in a number'    => ['version 1.2.3', [], FALSE],
			'tabbed text ending in number' => ["version\t1.2.3", [], FALSE],
			// Text whose last dot-label is numeric is not an address token: uncounted, as before.
			'text token Mozilla/5.0' => ['Mozilla/5.0', [], FALSE],
			'text token apache/2.4' => ['apache/2.4', [], FALSE],
			'text token v1.2.3' => ['v1.2.3', [], FALSE],
			'text token v1.2.3.4' => ['v1.2.3.4', [], FALSE],
			'text token Section2.5' => ['Section2.5', [], FALSE],
			'text token release-2.10' => ['release-2.10', [], FALSE],
			'text token foo.123' => ['foo.123', [], FALSE],
			'text token x.0x1f' => ['x.0x1f', [], FALSE],
			'text token Generated-2024.09.29' => ['Generated-2024.09.29', [], FALSE],
			'text token build.0x1f' => ['build.0x1f', [], FALSE],
			'text token x.1' => ['x.1', [], FALSE],
			'ipv6 literal host' => ['http://[::1]:80/x', [], FALSE],
			'ipv6 literal hex host' => ['http://[0x7f000001]/', [], FALSE],
			// Text with a numeric last label only (round 5): uncounted, as on base.
			'text example.com.1'         => ['example.com.1', [], FALSE],
			'text path x.1'              => ['/var/lib/x.1', [], FALSE],
			'text key=value'             => ['version=0.9.70', [], FALSE],
			'text quote-prefixed'        => ["'3.3.2", [], FALSE],
			// Pins for the URL-host parser.
			'userinfo with two @'        => ['http://u:p@ss@0x7f000001/', ['127.0.0.1'], FALSE],
			'canonical host + userinfo'  => ['http://1.2.3.4@5.6.7.8/', ['1.2.3.4', '5.6.7.8'], FALSE],
			'trailing NUL after path'    => ["http://0x7f000001/\x00", ['127.0.0.1'], FALSE],
			'query ends the authority'   => ['http://0x7f000001?to=1.2.3.4', ['127.0.0.1', '1.2.3.4'], FALSE],
			'fragment ends the authority' => ['http://0x7f000001#1.2.3.4', ['127.0.0.1', '1.2.3.4'], FALSE],
			'vertical tab ends the authority' => ["http://0x7f000001\v1.2.3.4", ['127.0.0.1', '1.2.3.4'], FALSE],
			'carriage return ends the authority' => ["http://0x7f000001\r1.2.3.4", ['127.0.0.1', '1.2.3.4'], FALSE],
			'form feed ends the authority' => ["http://0x7f000001\f1.2.3.4", ['127.0.0.1', '1.2.3.4'], FALSE],
			'newline ends the authority' => ["http://0x7f000001\n1.2.3.4", ['127.0.0.1', '1.2.3.4'], FALSE],
			'fragment after port'        => ['http://0x7f000001:80#f', ['127.0.0.1'], FALSE],
			'scheme starts with a digit' => ['1http://0x7f000001/x', [], FALSE],
			'bare hex + quad (ceiling)'  => ['0xC0A80164 1.2.3.4', ['1.2.3.4'], FALSE],
			// An interior NUL byte is a parse failure, never an exception.
			'bare quad with NUL'         => ["1.2\x00.3.4", [], TRUE],
			'NUL with colon and percent'   => ["ab\x00\x01:%\x02z", [], FALSE],
			'NUL with v6-shaped text'    => ["fe80::\x00a%eth0", [], FALSE],
			'bare hex with NUL'          => ["0xC0A8\x00164", [], FALSE],
			// Bare zero-padded quads keep the decimal reading.
			'padded 08'                  => ['08.08.08.08', ['8.8.8.8'], FALSE],
			'padded 010 octet'           => ['192.168.010.100', ['192.168.10.100'], FALSE],
			'padded 010 quad'            => ['010.010.010.010', ['10.10.10.10'], FALSE],
			'padded quad cidr'           => ['010.010.010.010/24', ['10.10.10.0/24'], FALSE],
		];
		$cases = [];
		foreach (['auto', 'regex'] as $pftype) {
			foreach ($rows as $name => [$line, $entries, $detail]) {
				$cases["{$pftype}: {$name}"] = [$pftype, $line, $entries, $detail];
			}
		}
		return $cases;
	}

	/** @param list<string> $entries */
	#[DataProvider('v4LineProvider')]
	public function testV4Line(string $pftype, string $line, array $entries, bool $detail): void
	{
		$result = pfb_ip_parse_line($line, self::config('_v4', $pftype));
		$this->assertSame(
			[$entries, $detail, $detail ? 1 : 0],
			[$result['entries'], $result['detailed_parse_fail'], $result['parse_fail_delta']],
			"{$pftype} line {$line}: entries=" . json_encode($result['entries']) .
			' detail=' . var_export($result['detailed_parse_fail'], TRUE) . " delta={$result['parse_fail_delta']}"
		);
	}

	public function testDecodedUrlHostStillHonoursSuppression(): void
	{
		$result = pfb_ip_parse_line('http://0x7f000001/x', self::config('_v4', 'auto', custom: FALSE, suppression: 'on'));
		$this->assertSame([], $result['entries'], 'loopback decoded from a URL must still be suppressed');
	}

	public function testMappedLineStillHonoursSuppression(): void
	{
		$control = pfb_ip_parse_line('::ffff:7f00:1', self::config('_v4', 'auto', custom: FALSE, suppression: 'off'));
		$this->assertSame(['127.0.0.1'], $control['entries'], 'control: with suppression off the mapped loopback is unwrapped');
		$result = pfb_ip_parse_line('::ffff:7f00:1', self::config('_v4', 'auto', custom: FALSE, suppression: 'on'));
		$this->assertSame([], $result['entries'], 'mapped loopback must still be suppressed');
	}

	/**
	 * A huge dot-separated URL host or bare token is rejected before it is split into labels.
	 * ponytail: a bare token in auto mode costs ~49 MB on base already (unrelated to the numeric
	 * host path), so its memory is not bounded here; only its result is.
	 */
	public function testHugeTokenIsRejectedCheaply(): void
	{
		$dots = str_repeat('1.', 1_000_000) . '1';
		foreach (['auto', 'regex'] as $pftype) {
			foreach (['bare' => $dots, 'url' => "http://{$dots}/x", 'hex url' => "http://0x{$dots}/x"] as $kind => $line) {
				memory_reset_peak_usage();
				$before = memory_get_peak_usage();
				$result = pfb_ip_parse_line($line, self::config('_v4', $pftype));
				$this->assertSame([], $result['entries'], "{$pftype} {$kind}: huge line yields no entry");
				if ($kind !== 'bare' || $pftype === 'regex') {
					$this->assertLessThan(12 * 1024 * 1024, memory_get_peak_usage() - $before, "{$pftype} {$kind}: peak memory while parsing a huge line");
				}
			}
		}
	}

	/** A binary blob is not a feed of addresses: its NUL-bearing lines are not counted as parse failures. */
	public function testBinaryFixtureLinesAreNotCounted(): void
	{
		$counted = [];
		foreach (['auto', 'regex'] as $pftype) {
			foreach (explode("\n", (string) file_get_contents(__DIR__ . '/../fixtures/pkg-signing/pfblockerng-repo.pub.der')) as $no => $line) {
				if (pfb_ip_parse_line($line, self::config('_v4', $pftype))['parse_fail_delta'] !== 0) {
					$counted[] = "{$pftype}:" . ($no + 1);
				}
			}
		}
		$this->assertSame([], $counted);
	}

	/** @return array<string, array{string, string}> */
	public static function v6NulLineProvider(): array
	{
		$cases = [];
		foreach (['auto', 'regex'] as $pftype) {
			foreach (["fe80::\x00a%eth0", "2001:db8::1\x00junk", "2001:db8::\x00a", "fe80::\x00a%eth0 -x", "fe80::\x00a\tfoo", "fe80::\x00a-eth0", "fe80::1\x00x-fe80::2", "fe80::1-fe80::\x002"] as $line) {
				$cases["{$pftype}: " . bin2hex($line)] = [$pftype, $line];
			}
		}
		return $cases;
	}

	/** An address cut at a NUL byte (text continues past it within a token or range endpoint) is not collected. */
	#[DataProvider('v6NulLineProvider')]
	public function testV6NulCutAddressIsAParseFailure(string $pftype, string $line): void
	{
		$result = pfb_ip_parse_line($line, self::config('_v6', $pftype));
		$this->assertSame([[], TRUE, 1], [$result['entries'], $result['detailed_parse_fail'], $result['parse_fail_delta']]);
	}

	/** @return array<string, array{string, string}> */
	public static function corpusPftypeProvider(): array
	{
		$cases = [];
		foreach (['_v4', '_v6'] as $vtype) {
			foreach (['auto', 'regex'] as $pftype) {
				$cases["{$vtype} {$pftype}"] = [$vtype, $pftype];
			}
		}
		return $cases;
	}

	/** Every line of every binary corpus sample must parse or fail cleanly, never throw. */
	#[DataProvider('corpusPftypeProvider')]
	public function testNoCorpusLineThrows(string $vtype, string $pftype): void
	{
		$files = glob(__DIR__ . '/../fixtures/feed_corpus/samples/*.bin') ?: [];
		$this->assertNotSame([], $files, 'corpus samples missing');
		$thrown = [];
		foreach ($files as $file) {
			foreach (explode("\n", (string) file_get_contents($file)) as $no => $line) {
				try {
					pfb_ip_parse_line($line, self::config($vtype, $pftype));
				} catch (\Throwable $e) {
					$thrown[] = basename($file) . ':' . ($no + 1) . ' ' . get_class($e);
				}
			}
		}
		$this->assertSame([], $thrown, "{$vtype} {$pftype}: lines that throw");
	}

	/** @return array<string, array{string, string, bool}> */
	public static function v6LineProvider(): array
	{
		return [
			'mapped dotted tail' => ['::ffff:192.168.1.100', '', TRUE],
			'mapped hex tail'    => ['::ffff:c0a8:164', '', TRUE],
			'mapped with prefix len' => ['::ffff:1.2.3.4/128', '', TRUE],
			'bare hex on a v6 list' => ['0xC0A80164', '', FALSE],
			'plain v6'           => ['2001:db8::1', "2001:db8::1\n", FALSE],
			'compatible v6'      => ['::192.168.1.100', "::192.168.1.100\n", FALSE],
		];
	}

	#[DataProvider('v6LineProvider')]
	public function testV6ListDropsMappedEntries(string $line, string $ipData, bool $detail): void
	{
		$data = '';
		$result = pfb_ip_parse_line_replay($line, self::config('_v6', 'auto'), 0, $data, FALSE, 0);
		$this->assertSame(
			[$ipData, $detail, $detail ? 1 : 0],
			[$data, $result['detailed_parse_fail'], $result['parse_fail']],
			"v6 line {$line}: data=" . json_encode($data)
		);
	}
}
