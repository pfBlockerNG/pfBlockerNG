<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Boundary + mask guards on the production IP extraction regexes (issue #1922),
 * exercised through the production regex configuration seam.
 *
 * The defect class is silent address fabrication: a valid-looking address that
 * appears nowhere in the input is extracted and blocked (v4.1.2.3.4 -> 4.1.2.3),
 * and a URL path segment parses as a CIDR prefix length, so a feed line like
 * 84.38.133.113/1/webpanel/login.php yields 0.0.0.0/1 after aggregation — two
 * such lines collapse a whole feed to 0.0.0.0/0 (the issue #1922 outage).
 *
 * The rule: the boundary class is word characters plus every character that can
 * appear inside that family's address text — '.' for IPv4; ':' AND '.' for IPv6
 * (IPv6 embeds IPv4). The mask guard (?![\w./]) sits INSIDE the optional mask
 * group so IP/path recovers the bare host while genuine CIDR masks and the
 * pinned parity shapes (1.2.3.4/bla, 1.2.3.4:8080, ...) stay byte-identical.
 * \b must NOT be used: it accepts foo.1.2.3.4 on v4 and breaks every
 * ::-leading address on v6 (re-anchoring x2001:db8::1 to the WRONG db8::1).
 */
#[CoversFunction('pfb_ip_parse_line')]
final class IpRegexBoundaryGuardTest extends TestCase
{
	private static string $reV4;
	private static string $reV6;
	private static string $reRange;

	public static function setUpBeforeClass(): void
	{
		$config = pfb_ip_regex_config();
		self::$reV4    = $config['ipv4'];
		self::$reV6    = $config['ipv6'];
		self::$reRange = $config['range'];
	}

	/** @return array{vtype:string,pftype:string,custom:bool,cidr_floor_v4:int|string,cidr_floor_v6:int|string,suppression:string,range:string,ipv4:string,ipv6:string} */
	private function config(string $vtype): array
	{
		return [
			'vtype'         => $vtype,
			'pftype'        => 'regex',
			'custom'        => TRUE,
			'cidr_floor_v4' => 'Disabled',
			'cidr_floor_v6' => 'Disabled',
			'suppression'   => 'off',
			'range'         => self::$reRange,
			'ipv4'          => self::$reV4,
			'ipv6'          => self::$reV6,
		];
	}

	/** Extraction at the regex level: the raw production-literal match set. */
	private function extract(string $re, string $line): array
	{
		return preg_match_all($re, $line, $m) ? $m[0] : [];
	}

	/** Range extraction: the [start, end] capture pair, or the empty set. */
	private function extractRange(string $line): array
	{
		return preg_match(self::$reRange, $line, $m) ? [$m[1], $m[2]] : [];
	}

	/**
	 * The issue #1922 spec table for IPv4: line => [regex match set, parser entries].
	 * A '-' spec row is the empty set. Parity rows pin today's behaviour as the
	 * oracle; CHANGED rows are the defect class (fabricated addresses, path-as-mask).
	 */
	public static function ipv4Rows(): array
	{
		return [
			// CHANGED: glued-on neighbours and malformed octets no longer fabricate an address
			'glued label foo.'          => ['foo.1.2.3.4', [], []],
			'malformed octet 999.'      => ['999.1.2.3.4', [], []],
			'version label v4.'         => ['v4.1.2.3.4', [], []],
			'five octets'               => ['1.2.3.4.5', [], []],
			'six octets'                => ['1.2.3.4.5.6', [], []],
			'leading zeros octet'       => ['0001.2.3.4', [], []],
			'label both sides'          => ['ver1.2.3.4beta', [], []],
			'glued letter'              => ['x1.2.3.4', [], []],
			'upstream typo C91'         => ['C91.196.152.28', [], []],
			// CHANGED: a URL path segment is not a prefix length (the outage lines)
			'path segment /1'           => ['84.38.133.113/1/webpanel/login.php', ['84.38.133.113'], ['84.38.133.113']],
			'path segment /0'           => ['104.233.105.159/0/aa-00/panel/admin.php', ['104.233.105.159'], ['104.233.105.159']],
			// Parity (owner constraint): byte-identical extraction to today
			'hyphenated host'           => ['host-1.2.3.4', ['1.2.3.4'], ['1.2.3.4']],
			'slash text'                => ['1.2.3.4/bla', ['1.2.3.4'], ['1.2.3.4']],
			'port'                      => ['1.2.3.4:8080', ['1.2.3.4'], ['1.2.3.4']],
			'port and path'             => ['1.2.3.4:8080/bla', ['1.2.3.4'], ['1.2.3.4']],
			'two path segments'         => ['1.2.3.4/bla/more', ['1.2.3.4'], ['1.2.3.4']],
			'full url'                  => ['http://1.2.3.4:8080/a/1', ['1.2.3.4'], ['1.2.3.4']],
			'alpha path'                => ['5.182.86.32/auth/login', ['5.182.86.32'], ['5.182.86.32']],
			'cidr /8'                   => ['10.0.0.0/8', ['10.0.0.0/8'], ['10.0.0.0/8']],
			'cidr /24'                  => ['192.168.1.0/24', ['192.168.1.0/24'], ['192.168.1.0/24']],
			'cidr /32'                  => ['1.2.3.4/32', ['1.2.3.4/32'], ['1.2.3.4']],
			'mask out of range /33'     => ['1.2.3.4/33', ['1.2.3.4'], ['1.2.3.4']],
			'cidr then comma'           => ['1.2.3.4/8,x', ['1.2.3.4/8'], ['1.2.3.4/8']],
			'cidr then comment'         => ['1.2.3.4/24 # comment', ['1.2.3.4/24'], ['1.2.3.0/24']],
			'html cell'                 => ['<td>8.8.8.8</td>', ['8.8.8.8'], ['8.8.8.8']],
		];
	}

	/**
	 * The issue #1922 spec table for IPv6. The boundary class is [\w:.] — never
	 * \b (an address may start with ':'). Adding '.' also stops the v4-mapped
	 * truncation that turned a correctly-rejected ::ffff:1.2.3.4 into the
	 * accepted junk remnant ::ffff:1.
	 */
	public static function ipv6Rows(): array
	{
		return [
			// Parity: every ::-leading and pinned shape identical to today
			'loopback'                  => ['::1', ['::1'], ['::1']],
			'all zeros'                 => ['::', ['::'], []],
			'all zeros slash zero'      => ['::/0', ['::/0'], []],
			'plain'                     => ['2001:db8::1', ['2001:db8::1'], ['2001:db8::1']],
			'cidr'                      => ['2001:db8::/32', ['2001:db8::/32'], ['2001:db8::/32']],
			'zone index'                => ['fe80::1%em0', ['fe80::1%em0'], []],
			'bracketed with port'       => ['[2001:db8::1]:443', ['2001:db8::1'], ['2001:db8::1']],
			'full mask'                 => ['2001:db8::1/128', ['2001:db8::1/128'], ['2001:db8::1/128']],
			'trailing hex group'        => ['2001:db8::1abc', ['2001:db8::1abc'], ['2001:db8::1abc']],
			// CHANGED: glued-on prefixes no longer re-anchor to a wrong address
			'glued letter'              => ['x2001:db8::1', [], []],
			'glued hex word'            => ['deadbeef2001:db8::1', [], []],
			// CHANGED: a URL path segment is not a prefix length (the v6 outage shape)
			'path segment /1'           => ['2001:db8::1/1/path', ['2001:db8::1'], ['2001:db8::1']],
			// CHANGED: v4-mapped forms parse whole instead of truncating mid-address
			'v4-mapped'                 => ['::ffff:1.2.3.4', ['::ffff:1.2.3.4'], ['::ffff:1.2.3.4']],
			'v4-mapped with mask'       => ['::ffff:192.168.1.1/96', ['::ffff:192.168.1.1/96'], ['::ffff:192.168.1.1/96']],
			'v4-mapped in text'         => ['text ::ffff:1.2.3.4', ['::ffff:1.2.3.4'], ['::ffff:1.2.3.4']],
			// CHANGED (accepted cost): a sentence-ending period drops the address
			// rather than risking a wrong extraction from comment text
			'trailing period'           => ['2001:db8::1.', [], []],
		];
	}

	/**
	 * The issue #1934 spec table for the v4 range regex: line => [[start, end]
	 * capture pair, parser entries]. Same boundary rule as ipv4: a quad glued to
	 * word chars or extra octets is not a range endpoint, so a malformed line
	 * drops the range instead of expanding fabricated endpoints into a subnet
	 * span; the ipv4 fallback still recovers any genuinely present address.
	 */
	public static function rangeRows(): array
	{
		return [
			// CHANGED: garbage-adjacent endpoints no longer slice a range out of the line
			'malformed octet 999.'      => ['999.1.2.3.4-5.6.7.8', [], ['5.6.7.8']],
			'version label v4.'         => ['v4.1.2.3.4-5.6.7.8', [], ['5.6.7.8']],
			'glued label foo.'          => ['foo.1.2.3.4-5.6.7.8', [], ['5.6.7.8']],
			'glued letter start'        => ['x1.2.3.4-5.6.7.8', [], ['5.6.7.8']],
			'five-octet end'            => ['1.2.3.4-5.6.7.8.9', [], ['1.2.3.4']],
			'glued letter end'          => ['1.2.3.4-5.6.7.8beta', [], ['1.2.3.4']],
			// Parity: genuine quad-quad ranges expand exactly as today
			'plain range'               => ['10.0.0.0-10.0.0.3', ['10.0.0.0', '10.0.0.3'], ['10.0.0.0/30']],
			'single-address range'      => ['10.0.0.1-10.0.0.1', ['10.0.0.1', '10.0.0.1'], ['10.0.0.1']],
			'iblocklist range'          => ['4.53.2.12-4.53.2.15', ['4.53.2.12', '4.53.2.15'], ['4.53.2.12/30']],
			'range then comment'        => ['10.0.0.0-10.0.0.3 # comment', ['10.0.0.0', '10.0.0.3'], ['10.0.0.0/30']],
		];
	}

	#[DataProvider('rangeRows')]
	public function testRangeRegexExtractionMatchesSpec(string $line, array $matches, array $entries): void
	{
		$this->assertSame($matches, $this->extractRange($line),
			"range regex extraction differs from the issue #1934 spec for: {$line}");
	}

	#[DataProvider('rangeRows')]
	public function testRangeParserEntriesMatchSpec(string $line, array $matches, array $entries): void
	{
		$result = pfb_ip_parse_line($line, $this->config('_v4'));
		$this->assertSame($entries, $result['entries'],
			"pfb_ip_parse_line() entries differ from the issue #1934 spec for: {$line}");
	}

	#[DataProvider('ipv4Rows')]
	public function testIpv4RegexExtractionMatchesSpec(string $line, array $matches, array $entries): void
	{
		$this->assertSame($matches, $this->extract(self::$reV4, $line),
			"IPv4 regex extraction differs from the issue #1922 spec for: {$line}");
	}

	#[DataProvider('ipv4Rows')]
	public function testIpv4ParserEntriesMatchSpec(string $line, array $matches, array $entries): void
	{
		$result = pfb_ip_parse_line($line, $this->config('_v4'));
		$this->assertSame($entries, $result['entries'],
			"pfb_ip_parse_line() entries differ from the issue #1922 spec for: {$line}");
	}

	#[DataProvider('ipv6Rows')]
	public function testIpv6RegexExtractionMatchesSpec(string $line, array $matches, array $entries): void
	{
		$this->assertSame($matches, $this->extract(self::$reV6, $line),
			"IPv6 regex extraction differs from the issue #1922 spec for: {$line}");
	}

	#[DataProvider('ipv6Rows')]
	public function testIpv6ParserEntriesMatchSpec(string $line, array $matches, array $entries): void
	{
		$result = pfb_ip_parse_line($line, $this->config('_v6'));
		$this->assertSame($entries, $result['entries'],
			"pfb_ip_parse_line() entries differ from the issue #1922 spec for: {$line}");
	}

	/**
	 * Scenario: the outage line pair no longer yields both halves of the space.
	 *   Given the two CCT_IP lines whose /1 "masks" aggregated to 0.0.0.0/0
	 *   When both are parsed with the production regexes
	 *   Then each recovers its bare host and neither carries a prefix length,
	 *        so no later aggregation step can collapse them to 0.0.0.0/0.
	 */
	public function testOutageLinePairRecoversBareHostsWithNoMask(): void
	{
		$config = $this->config('_v4');
		$low  = pfb_ip_parse_line('84.38.133.113/1/webpanel/login.php', $config);
		$high = pfb_ip_parse_line('185.162.10.145/1/PvqDq929BSx_A_D_M1n_a.php', $config);

		$this->assertSame(['84.38.133.113'], $low['entries']);
		$this->assertSame(['185.162.10.145'], $high['entries']);
		foreach (array_merge($low['entries'], $high['entries']) as $entry) {
			$this->assertStringNotContainsString('/', $entry,
				'no outage-line entry may carry a prefix length');
		}
	}

	/**
	 * Numeric fabricated-address lines now count as parse failures instead of
	 * silently blocking an address absent from the input (silent extraction is
	 * the defect class; a failure count is the visible alternative).
	 */
	public function testNumericFabricationLinesCountAsDetailedParseFailures(): void
	{
		$config = $this->config('_v4');
		foreach (['999.1.2.3.4', '1.2.3.4.5', '0001.2.3.4'] as $line) {
			$result = pfb_ip_parse_line($line, $config);
			$this->assertSame([], $result['entries'], "no entry may be fabricated from: {$line}");
			$this->assertSame(1, $result['parse_fail_delta'], "a parse failure must be counted for: {$line}");
			$this->assertTrue($result['detailed_parse_fail'], "the failure must be detailed for: {$line}");
		}
	}
}
