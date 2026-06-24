<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-38 Amendment 1 — DNSBL syslog + unified.log formatter tests.
 *
 * Pins the behaviour of:
 *   pfb_syslog_format_dnsbl(array $fields): string
 *   pfb_unified_format_ip(array $fields): string
 *   pfb_unified_format_dnsbl(array $fields): string
 *   pfb_unified_format_dnsreply(array $fields): string
 *
 * All four functions are PURE (no I/O, no globals).  These tests are the only
 * callers during this phase.
 *
 * Coverage mandate (CLAUDE.md):
 *   - pfb_syslog_format_dnsbl: all fields; group absent; feed absent; both
 *     absent; a value with a space is double-quoted; NULL b_type + CNAME q_type.
 *   - pfb_unified_format_ip/dnsbl/dnsreply: exact golden-string fidelity.
 *
 * All assertions are against EXACT golden strings.
 */
final class UnifiedFormatTest extends TestCase
{
	// -----------------------------------------------------------------------
	// pfb_syslog_format_dnsbl
	// -----------------------------------------------------------------------

	/**
	 * All fields present (group + feed included) produces exact golden string.
	 *
	 * Scenario:
	 *   Given all 7 input fields populated.
	 *   When  pfb_syslog_format_dnsbl($fields).
	 *   Then  returns act=dnsbl qname qip qtype group feed btype eval in order.
	 */
	public function testDnsblAllFieldsProducesExactString(): void
	{
		$fields = [
			'q_name' => 'ads.example.com',
			'q_ip'   => '10.0.0.5',
			'q_type' => 'A',
			'group'  => 'ADs',
			'feed'   => 'EasyList',
			'b_type' => 'VIP',
			'b_eval' => 'ads.example.com',
		];

		$result = pfb_syslog_format_dnsbl($fields);

		$this->assertSame(
			'act=dnsbl qname=ads.example.com qip=10.0.0.5 qtype=A group=ADs feed=EasyList btype=VIP eval=ads.example.com',
			$result,
			'DNSBL: all fields present — golden string'
		);
	}

	/**
	 * Empty group is omitted; feed still present.
	 *
	 * Scenario:
	 *   Before: group='ADs' -> group=ADs present in output.
	 *   After:  group=''    -> group= token absent from output.
	 */
	public function testDnsblEmptyGroupOmitted(): void
	{
		$base = [
			'q_name' => 'ads.example.com',
			'q_ip'   => '10.0.0.5',
			'q_type' => 'A',
			'feed'   => 'EasyList',
			'b_type' => 'VIP',
			'b_eval' => 'ads.example.com',
		];

		// Before: group present.
		$before = pfb_syslog_format_dnsbl(array_merge($base, ['group' => 'ADs']));
		$this->assertStringContainsString('group=ADs', $before, 'group=ADs must appear when set');

		// After: group empty -> omitted.
		$after = pfb_syslog_format_dnsbl(array_merge($base, ['group' => '']));
		$this->assertStringNotContainsString('group=', $after, 'group= must be absent when empty');

		// After: feed still present.
		$this->assertStringContainsString('feed=EasyList', $after, 'feed must still appear');
	}

	/**
	 * Empty feed is omitted; group still present.
	 *
	 * Scenario:
	 *   Before: feed='EasyList' -> feed=EasyList present.
	 *   After:  feed=''         -> feed= token absent.
	 */
	public function testDnsblEmptyFeedOmitted(): void
	{
		$base = [
			'q_name' => 'ads.example.com',
			'q_ip'   => '10.0.0.5',
			'q_type' => 'A',
			'group'  => 'ADs',
			'b_type' => 'VIP',
			'b_eval' => 'ads.example.com',
		];

		// Before: feed present.
		$before = pfb_syslog_format_dnsbl(array_merge($base, ['feed' => 'EasyList']));
		$this->assertStringContainsString('feed=EasyList', $before, 'feed=EasyList must appear when set');

		// After: feed empty -> omitted.
		$after = pfb_syslog_format_dnsbl(array_merge($base, ['feed' => '']));
		$this->assertStringNotContainsString('feed=', $after, 'feed= must be absent when empty');

		// group still present.
		$this->assertStringContainsString('group=ADs', $after, 'group must still appear');
	}

	/**
	 * Both group and feed empty are both omitted.
	 *
	 * Scenario:
	 *   Given group='' and feed=''.
	 *   When  pfb_syslog_format_dnsbl($fields).
	 *   Then  neither group= nor feed= appears in output.
	 */
	public function testDnsblBothGroupAndFeedEmptyBothOmitted(): void
	{
		$fields = [
			'q_name' => 'ads.example.com',
			'q_ip'   => '10.0.0.5',
			'q_type' => 'A',
			'group'  => '',
			'feed'   => '',
			'b_type' => 'VIP',
			'b_eval' => 'ads.example.com',
		];

		$result = pfb_syslog_format_dnsbl($fields);

		$this->assertStringNotContainsString('group=', $result, 'group= must be absent');
		$this->assertStringNotContainsString('feed=',  $result, 'feed= must be absent');
		$this->assertSame(
			'act=dnsbl qname=ads.example.com qip=10.0.0.5 qtype=A btype=VIP eval=ads.example.com',
			$result,
			'Both group and feed empty: exact golden string'
		);
	}

	/**
	 * A value containing a space is double-quoted.
	 *
	 * Scenario:
	 *   Given b_eval = 'some domain.com' (contains a space).
	 *   When  pfb_syslog_format_dnsbl($fields).
	 *   Then  eval="some domain.com" appears quoted in output.
	 */
	public function testDnsblValueWithSpaceIsDoubleQuoted(): void
	{
		$fields = [
			'q_name' => 'ads.example.com',
			'q_ip'   => '10.0.0.5',
			'q_type' => 'A',
			'group'  => '',
			'feed'   => '',
			'b_type' => 'VIP',
			'b_eval' => 'some domain.com',
		];

		$result = pfb_syslog_format_dnsbl($fields);

		$this->assertStringContainsString('eval="some domain.com"', $result, 'space in value must be double-quoted');
	}

	/**
	 * NULL block type and CNAME query type are passed through unmodified.
	 *
	 * Scenario:
	 *   Given b_type='NULL' (literal string) and q_type='CNAME'.
	 *   When  pfb_syslog_format_dnsbl($fields).
	 *   Then  btype=NULL and qtype=CNAME appear in output.
	 */
	public function testDnsblNullBlockTypeAndCnameQueryType(): void
	{
		$fields = [
			'q_name' => 'tracker.example.com',
			'q_ip'   => '192.168.1.100',
			'q_type' => 'CNAME',
			'group'  => 'Trackers',
			'feed'   => 'AdGuard',
			'b_type' => 'NULL',
			'b_eval' => 'tracker.example.com',
		];

		$result = pfb_syslog_format_dnsbl($fields);

		$this->assertSame(
			'act=dnsbl qname=tracker.example.com qip=192.168.1.100 qtype=CNAME group=Trackers feed=AdGuard btype=NULL eval=tracker.example.com',
			$result,
			'NULL btype + CNAME qtype: exact golden string'
		);
	}

	// -----------------------------------------------------------------------
	// pfb_unified_format_ip
	// -----------------------------------------------------------------------

	/**
	 * Four named fields are joined in order, exactly.
	 *
	 * Scenario:
	 *   Given l_type='A', log='B', details='C', dup='+'.
	 *   When  pfb_unified_format_ip($fields).
	 *   Then  returns 'A,B,C,+'.
	 */
	public function testUnifiedIpFidelity(): void
	{
		$result = pfb_unified_format_ip([
			'l_type'  => 'A',
			'log'     => 'B',
			'details' => 'C',
			'dup'     => '+',
		]);

		$this->assertSame('A,B,C,+', $result, 'IP unified row: exact golden string');
	}

	/**
	 * Missing keys coerce to '' (no crash, no fatal).
	 *
	 * Scenario:
	 *   Given an empty array.
	 *   When  pfb_unified_format_ip([]).
	 *   Then  returns ',,,' (four empty segments).
	 */
	public function testUnifiedIpMissingKeysCoerceToEmpty(): void
	{
		$result = pfb_unified_format_ip([]);

		$this->assertSame(',,,', $result, 'missing keys must coerce to empty strings');
	}

	// -----------------------------------------------------------------------
	// pfb_unified_format_dnsbl
	// -----------------------------------------------------------------------

	/**
	 * 11 named fields joined in the dnsbl.log column order.
	 *
	 * Scenario:
	 *   Given the 11 fields from a representative real dnsbl.log line.
	 *   When  pfb_unified_format_dnsbl($fields).
	 *   Then  returns the exact golden CSV string.
	 */
	public function testUnifiedDnsblFidelity(): void
	{
		$fields = [
			'l_type'   => 'DNSBL-python',
			'datetime' => '06/24/26 10:00:00',
			'q_name'   => 'ads.example.com',
			'q_ip'     => '10.0.0.5',
			'p_type'   => 'Python',
			'b_type'   => 'VIP',
			'group'    => 'ADs',
			'b_eval'   => 'ads.example.com',
			'feed'     => 'EasyList',
			'dup'      => '+',
			'q_type'   => 'A',
		];

		$result = pfb_unified_format_dnsbl($fields);

		$this->assertSame(
			'DNSBL-python,06/24/26 10:00:00,ads.example.com,10.0.0.5,Python,VIP,ADs,ads.example.com,EasyList,+,A',
			$result,
			'DNSBL unified row: exact golden string'
		);
	}

	/**
	 * Missing keys coerce to '' — empty o_type segment rendered correctly.
	 *
	 * Scenario:
	 *   Given all 11 fields, with an empty p_type value.
	 *   When  pfb_unified_format_dnsbl($fields).
	 *   Then  the empty p_type renders as an empty segment between commas.
	 */
	public function testUnifiedDnsblEmptyFieldRendersAsEmptySegment(): void
	{
		$fields = [
			'l_type'   => 'DNSBL-python',
			'datetime' => '06/24/26 10:00:00',
			'q_name'   => 'ads.example.com',
			'q_ip'     => '10.0.0.5',
			'p_type'   => '',
			'b_type'   => 'VIP',
			'group'    => 'ADs',
			'b_eval'   => 'ads.example.com',
			'feed'     => 'EasyList',
			'dup'      => '+',
			'q_type'   => 'A',
		];

		$result = pfb_unified_format_dnsbl($fields);

		$this->assertSame(
			'DNSBL-python,06/24/26 10:00:00,ads.example.com,10.0.0.5,,VIP,ADs,ads.example.com,EasyList,+,A',
			$result,
			'empty p_type must render as empty segment'
		);
	}

	// -----------------------------------------------------------------------
	// pfb_unified_format_dnsreply
	// -----------------------------------------------------------------------

	/**
	 * 10 named fields joined in DNS-reply column order.
	 *
	 * Scenario:
	 *   Given the 10 fields from a representative DNS-reply row.
	 *   When  pfb_unified_format_dnsreply($fields).
	 *   Then  returns the exact golden CSV string (empty o_type renders as empty
	 *   segment between commas).
	 */
	public function testUnifiedDnsreplyFidelity(): void
	{
		$fields = [
			'l_type'   => 'DNS-reply',
			'datetime' => '06/24/26 10:00:00',
			'm_type'   => 'cache',
			'o_type'   => '',
			'q_type'   => 'A',
			'ttl'      => '30',
			'q_name'   => 'good.example.com',
			'q_ip'     => '10.0.0.5',
			'r_addr'   => '93.184.216.34',
			'iso_code' => 'US',
		];

		$result = pfb_unified_format_dnsreply($fields);

		$this->assertSame(
			'DNS-reply,06/24/26 10:00:00,cache,,A,30,good.example.com,10.0.0.5,93.184.216.34,US',
			$result,
			'DNS-reply unified row: exact golden string (empty o_type = empty segment)'
		);
	}

	/**
	 * Missing keys coerce to '' — the empty o_type renders as an empty segment.
	 *
	 * Scenario:
	 *   Given the DNS-reply fields with o_type absent from the array entirely.
	 *   When  pfb_unified_format_dnsreply($fields).
	 *   Then  the absent o_type renders as an empty segment (same as '').
	 */
	public function testUnifiedDnsreplyMissingKeyCoercesToEmpty(): void
	{
		$fields = [
			'l_type'   => 'DNS-reply',
			'datetime' => '06/24/26 10:00:00',
			'm_type'   => 'cache',
			// 'o_type' intentionally absent
			'q_type'   => 'A',
			'ttl'      => '30',
			'q_name'   => 'good.example.com',
			'q_ip'     => '10.0.0.5',
			'r_addr'   => '93.184.216.34',
			'iso_code' => 'US',
		];

		$result = pfb_unified_format_dnsreply($fields);

		$this->assertSame(
			'DNS-reply,06/24/26 10:00:00,cache,,A,30,good.example.com,10.0.0.5,93.184.216.34,US',
			$result,
			'absent o_type must coerce to empty and render as empty segment'
		);
	}
}
