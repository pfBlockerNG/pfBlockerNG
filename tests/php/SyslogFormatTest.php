<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-38 Phase 1 — Pure IP syslog event formatter.
 *
 * Pins the behaviour of:
 *   pfb_syslog_format_ip(array $fields): string
 *
 * The function is PURE (no I/O, no globals) and DORMANT this phase (uncalled
 * from production code).  These tests are the only callers.
 *
 * Coverage mandate (CLAUDE.md):
 *   - Every event class: Block, Permit, Match.
 *   - Both IP versions: IPv4, IPv6.
 *   - Required fields always present; optional fields present vs absent.
 *   - Known absent-sentinels ('Unknown', 'Unk', 'null', '') are omitted.
 *   - Values containing space, '=', or '"' are double-quoted; '"' is \.
 *   - Newlines in values are stripped (single-line guarantee).
 *
 * All assertions are against EXACT golden strings (the mapping is pinned).
 */
final class SyslogFormatTest extends TestCase
{
	// -----------------------------------------------------------------------
	// Helpers
	// -----------------------------------------------------------------------

	/**
	 * Build a complete, fully-populated IPv4 Block event field array.
	 *
	 * @return array<string,string>
	 */
	private function ipv4BlockFields(): array
	{
		return [
			'act'   => 'block',
			'dir'   => 'in',
			'if'    => 'em0',
			'proto' => 'TCP-SA',
			'src'   => '203.0.113.42',
			'dst'   => '192.168.1.10',
			'sport' => '54321',
			'dport' => '443',
			'ipver' => '4',
			'geoip' => 'CN',
			'alias' => 'pfB_DNSBL_v4',
			'feed'  => 'EasyList',
			'host'  => 'malware.example.com',
			'asn'   => '|AS4134:CHINANET-BACKBONE|',
		];
	}

	/**
	 * Build a complete, fully-populated IPv6 Permit event field array.
	 *
	 * @return array<string,string>
	 */
	private function ipv6PermitFields(): array
	{
		return [
			'act'   => 'pass',
			'dir'   => 'out',
			'if'    => 'igb1',
			'proto' => 'UDP',
			'src'   => '2001:db8::1',
			'dst'   => '2001:db8::2',
			'sport' => '1024',
			'dport' => '53',
			'ipver' => '6',
			'geoip' => 'US',
			'alias' => 'pfB_Permit_v6',
			'feed'  => 'Whitelist',
			'host'  => 'resolver.example.net',
			'asn'   => '|AS15169:GOOGLE|',
		];
	}

	// -----------------------------------------------------------------------
	// Block event — IPv4, all fields populated
	// -----------------------------------------------------------------------

	/**
	 * IPv4 Block event with all optional fields present produces the exact
	 * key=value string in fixed documented order.
	 *
	 * Scenario:
	 *   Given a fully-populated IPv4 Block event field array.
	 *   When  pfb_syslog_format_ip($fields).
	 *   Then  returns the exact golden string with all 14 key=value pairs.
	 */
	public function testIpv4BlockAllFieldsProducesExactString(): void
	{
		$result = pfb_syslog_format_ip($this->ipv4BlockFields());

		$this->assertSame(
			'act=block dir=in if=em0 proto=TCP-SA src=203.0.113.42 dst=192.168.1.10'
			. ' sport=54321 dport=443 ipver=4 geoip=CN alias=pfB_DNSBL_v4'
			. ' feed=EasyList host=malware.example.com asn=|AS4134:CHINANET-BACKBONE|',
			$result,
			'IPv4 Block: all fields in documented order'
		);
	}

	// -----------------------------------------------------------------------
	// Permit event — IPv6, all fields populated
	// -----------------------------------------------------------------------

	/**
	 * IPv6 Permit event with all optional fields present.
	 *
	 * Scenario:
	 *   Given a fully-populated IPv6 Permit event field array.
	 *   When  pfb_syslog_format_ip($fields).
	 *   Then  returns the exact golden string with act=pass.
	 */
	public function testIpv6PermitAllFieldsProducesExactString(): void
	{
		$result = pfb_syslog_format_ip($this->ipv6PermitFields());

		$this->assertSame(
			'act=pass dir=out if=igb1 proto=UDP src=2001:db8::1 dst=2001:db8::2'
			. ' sport=1024 dport=53 ipver=6 geoip=US alias=pfB_Permit_v6'
			. ' feed=Whitelist host=resolver.example.net asn=|AS15169:GOOGLE|',
			$result,
			'IPv6 Permit: all fields in documented order'
		);
	}

	// -----------------------------------------------------------------------
	// Match event — IPv4, no optional fields
	// -----------------------------------------------------------------------

	/**
	 * IPv4 Match event with only required fields produces the minimal string.
	 *
	 * Scenario:
	 *   Given a field array with required fields only; all optional fields
	 *   set to absent-sentinels ('Unknown', 'Unk', 'null', '').
	 *   When  pfb_syslog_format_ip($fields).
	 *   Then  returns only the required key=value pairs (no optional keys).
	 */
	public function testIpv4MatchRequiredFieldsOnlyProducesMinimalString(): void
	{
		$fields = [
			'act'   => 'match',
			'dir'   => 'in',
			'if'    => 'em0',
			'proto' => 'TCP',
			'src'   => '198.51.100.5',
			'dst'   => '10.0.0.1',
			'sport' => '',        // omitted — empty
			'dport' => '',        // omitted — empty
			'ipver' => '4',
			'geoip' => 'Unk',     // omitted — known absent sentinel
			'alias' => 'Unknown', // omitted — known absent sentinel
			'feed'  => 'Unknown', // omitted — known absent sentinel
			'host'  => 'Unknown', // omitted — known absent sentinel
			'asn'   => 'null',    // omitted — known absent sentinel
		];

		$result = pfb_syslog_format_ip($fields);

		$this->assertSame(
			'act=match dir=in if=em0 proto=TCP src=198.51.100.5 dst=10.0.0.1 ipver=4',
			$result,
			'Match: required fields only; absent-sentinels omitted'
		);
	}

	// -----------------------------------------------------------------------
	// Optional field presence vs absence (before-and-after)
	// -----------------------------------------------------------------------

	/**
	 * 'Unknown' sentinel is omitted; a real value is included — before/after.
	 *
	 * Scenario:
	 *   Before: geoip='Unknown' -> key absent from output.
	 *   After:  geoip='DE'      -> key present in output.
	 */
	public function testGeoipUnknownSentinelOmittedRealValueIncluded(): void
	{
		$base = [
			'act' => 'block', 'dir' => 'in', 'if' => 'em0', 'proto' => 'TCP',
			'src' => '198.51.100.1', 'dst' => '10.0.0.1', 'ipver' => '4',
		];

		// Before: sentinel -> absent.
		$before = pfb_syslog_format_ip(array_merge($base, ['geoip' => 'Unknown']));
		$this->assertStringNotContainsString('geoip=', $before, 'geoip=Unknown must be absent');

		// After: real value -> present.
		$after = pfb_syslog_format_ip(array_merge($base, ['geoip' => 'DE']));
		$this->assertStringContainsString('geoip=DE', $after, 'geoip=DE must be present');
	}

	/**
	 * 'Unk' sentinel is omitted; a real two-letter code is included — before/after.
	 *
	 * Scenario:
	 *   Before: geoip='Unk' -> key absent.
	 *   After:  geoip='JP'  -> key present.
	 */
	public function testGeoipUnkSentinelOmitted(): void
	{
		$base = [
			'act' => 'block', 'dir' => 'in', 'if' => 'em0', 'proto' => 'UDP',
			'src' => '198.51.100.2', 'dst' => '10.0.0.2', 'ipver' => '4',
		];

		// Before: 'Unk' -> absent.
		$before = pfb_syslog_format_ip(array_merge($base, ['geoip' => 'Unk']));
		$this->assertStringNotContainsString('geoip=', $before, "'Unk' must be omitted");

		// After: real code -> present.
		$after = pfb_syslog_format_ip(array_merge($base, ['geoip' => 'JP']));
		$this->assertStringContainsString('geoip=JP', $after, "real code must appear");
	}

	/**
	 * 'null' string is omitted for asn; a real ASN value is included.
	 *
	 * Scenario:
	 *   Before: asn='null' -> key absent.
	 *   After:  asn='|AS1234:ORG|' -> key present (and quoted due to '|').
	 *   Note: '|' does not trigger quoting; only space, '=', '"' do.
	 */
	public function testAsnNullSentinelOmittedRealAsnIncluded(): void
	{
		$base = [
			'act' => 'block', 'dir' => 'in', 'if' => 'em0', 'proto' => 'TCP',
			'src' => '198.51.100.3', 'dst' => '10.0.0.3', 'ipver' => '4',
		];

		// Before: 'null' -> absent.
		$before = pfb_syslog_format_ip(array_merge($base, ['asn' => 'null']));
		$this->assertStringNotContainsString('asn=', $before, "'null' asn must be omitted");

		// After: real value with spaces -> present and quoted.
		$after = pfb_syslog_format_ip(array_merge($base, ['asn' => '|AS1234:TEST ORG|']));
		$this->assertStringContainsString('asn="|AS1234:TEST ORG|"', $after, "real asn with space must be quoted");
	}

	// -----------------------------------------------------------------------
	// IPv6 Match event — minimal fields
	// -----------------------------------------------------------------------

	/**
	 * IPv6 Match event with required fields only.
	 *
	 * Scenario:
	 *   Given a minimal IPv6 Match field array (required fields only, all
	 *   optional fields absent or set to sentinels).
	 *   When  pfb_syslog_format_ip($fields).
	 *   Then  returns only required key=value pairs with ipver=6.
	 */
	public function testIpv6MatchRequiredFieldsOnlyProducesMinimalString(): void
	{
		$fields = [
			'act'   => 'match',
			'dir'   => 'out',
			'if'    => 'vtnet0',
			'proto' => 'ICMPv6',
			'src'   => '2001:db8::10',
			'dst'   => '2001:db8::20',
			'ipver' => '6',
			'geoip' => '',
			'alias' => '',
			'feed'  => '',
			'host'  => '',
			'asn'   => '',
		];

		$result = pfb_syslog_format_ip($fields);

		$this->assertSame(
			'act=match dir=out if=vtnet0 proto=ICMPv6 src=2001:db8::10 dst=2001:db8::20 ipver=6',
			$result,
			'IPv6 Match: required fields only'
		);
	}

	// -----------------------------------------------------------------------
	// Escaping — space, '=', and '"' in values
	// -----------------------------------------------------------------------

	/**
	 * A value containing a space is double-quoted.
	 *
	 * Scenario:
	 *   Given a field where proto = 'TCP FLAGS' (contains a space).
	 *   When  pfb_syslog_format_ip($fields).
	 *   Then  proto="TCP FLAGS" appears quoted in output.
	 */
	public function testValueWithSpaceIsDoubleQuoted(): void
	{
		$fields = [
			'act'   => 'block',
			'dir'   => 'in',
			'if'    => 'em0',
			'proto' => 'TCP FLAGS',
			'src'   => '198.51.100.10',
			'dst'   => '10.0.0.10',
			'ipver' => '4',
		];

		$result = pfb_syslog_format_ip($fields);

		$this->assertStringContainsString('proto="TCP FLAGS"', $result, 'proto with space must be quoted');
	}

	/**
	 * A value containing '=' is double-quoted.
	 *
	 * Scenario:
	 *   Given alias = 'pfB_Deny=v4' (contains '=').
	 *   When  pfb_syslog_format_ip($fields).
	 *   Then  alias="pfB_Deny=v4" appears quoted in output.
	 */
	public function testValueWithEqualsIsDoubleQuoted(): void
	{
		$fields = [
			'act'   => 'block',
			'dir'   => 'in',
			'if'    => 'em0',
			'proto' => 'TCP',
			'src'   => '198.51.100.11',
			'dst'   => '10.0.0.11',
			'ipver' => '4',
			'alias' => 'pfB_Deny=v4',
		];

		$result = pfb_syslog_format_ip($fields);

		$this->assertStringContainsString('alias="pfB_Deny=v4"', $result, 'alias with = must be quoted');
	}

	/**
	 * A value containing a double-quote is quoted and the inner quote escaped.
	 *
	 * Scenario:
	 *   Given host = 'bad"host.example.com' (contains '"').
	 *   When  pfb_syslog_format_ip($fields).
	 *   Then  host="bad\"host.example.com" appears in output.
	 */
	public function testValueWithDoubleQuoteIsEscaped(): void
	{
		$fields = [
			'act'   => 'block',
			'dir'   => 'in',
			'if'    => 'em0',
			'proto' => 'TCP',
			'src'   => '198.51.100.12',
			'dst'   => '10.0.0.12',
			'ipver' => '4',
			'host'  => 'bad"host.example.com',
		];

		$result = pfb_syslog_format_ip($fields);

		$this->assertStringContainsString('host="bad\\"host.example.com"', $result, 'inner " must be \\"-escaped');
	}

	/**
	 * Newlines embedded in a value are stripped (single-line guarantee).
	 *
	 * Scenario:
	 *   Given host = "multi\nline" (contains \n).
	 *   When  pfb_syslog_format_ip($fields).
	 *   Then  the output contains no newline character.
	 *   And   the \n is replaced with a space (preserved as content).
	 */
	public function testNewlineInValueIsStripped(): void
	{
		$fields = [
			'act'   => 'block',
			'dir'   => 'in',
			'if'    => 'em0',
			'proto' => 'TCP',
			'src'   => '198.51.100.13',
			'dst'   => '10.0.0.13',
			'ipver' => '4',
			'host'  => "multi\nline",
		];

		$result = pfb_syslog_format_ip($fields);

		$this->assertStringNotContainsString("\n", $result, 'output must be single-line');
		$this->assertStringContainsString('host="multi line"', $result, 'newline replaced with space, then quoted');
	}

	// -----------------------------------------------------------------------
	// Key order is fixed
	// -----------------------------------------------------------------------

	/**
	 * Required keys appear in the documented fixed order: act dir if proto src dst ipver.
	 *
	 * Scenario:
	 *   Given any valid field array with required keys only.
	 *   When  pfb_syslog_format_ip($fields).
	 *   Then  the keys appear in the fixed documented order.
	 */
	public function testKeyOrderIsFixed(): void
	{
		$fields = [
			'act'   => 'block',
			'dir'   => 'in',
			'if'    => 'em0',
			'proto' => 'TCP',
			'src'   => '198.51.100.20',
			'dst'   => '10.0.0.20',
			'ipver' => '4',
		];

		$result = pfb_syslog_format_ip($fields);

		// Parse the key positions and assert their relative order.
		$pos_act   = strpos($result, 'act=');
		$pos_dir   = strpos($result, 'dir=');
		$pos_if    = strpos($result, 'if=');
		$pos_proto = strpos($result, 'proto=');
		$pos_src   = strpos($result, 'src=');
		$pos_dst   = strpos($result, 'dst=');
		$pos_ipver = strpos($result, 'ipver=');

		$this->assertLessThan($pos_dir,   $pos_act,   'act before dir');
		$this->assertLessThan($pos_if,    $pos_dir,   'dir before if');
		$this->assertLessThan($pos_proto, $pos_if,    'if before proto');
		$this->assertLessThan($pos_src,   $pos_proto, 'proto before src');
		$this->assertLessThan($pos_dst,   $pos_src,   'src before dst');
		$this->assertLessThan($pos_ipver, $pos_dst,   'dst before ipver');
	}

	/**
	 * Optional enrichment keys (geoip/alias/feed/host/asn) appear after ipver
	 * when present, in the documented fixed order.
	 *
	 * Scenario:
	 *   Given all optional fields present with non-sentinel values.
	 *   When  pfb_syslog_format_ip($fields).
	 *   Then  geoip < alias < feed < host < asn in the output.
	 */
	public function testOptionalKeyOrderAfterIpver(): void
	{
		$fields = [
			'act'   => 'block',
			'dir'   => 'in',
			'if'    => 'em0',
			'proto' => 'TCP',
			'src'   => '198.51.100.21',
			'dst'   => '10.0.0.21',
			'ipver' => '4',
			'geoip' => 'US',
			'alias' => 'pfB_Deny',
			'feed'  => 'BlockList',
			'host'  => 'bad.host.example',
			'asn'   => '|AS12345:ISP|',
		];

		$result = pfb_syslog_format_ip($fields);

		$pos_ipver = strpos($result, 'ipver=');
		$pos_geoip = strpos($result, 'geoip=');
		$pos_alias = strpos($result, 'alias=');
		$pos_feed  = strpos($result, 'feed=');
		$pos_host  = strpos($result, 'host=');
		$pos_asn   = strpos($result, 'asn=');

		$this->assertLessThan($pos_geoip, $pos_ipver, 'ipver before geoip');
		$this->assertLessThan($pos_alias, $pos_geoip, 'geoip before alias');
		$this->assertLessThan($pos_feed,  $pos_alias, 'alias before feed');
		$this->assertLessThan($pos_host,  $pos_feed,  'feed before host');
		$this->assertLessThan($pos_asn,   $pos_host,  'host before asn');
	}
}
