<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-38 Amendment 1 — DNSBL syslog + unified.log formatter tests.
 * ADR-38 Amendment 3 (issue #1369) — ASN CSV-column helper tests.
 * ADR-38 Amendment 4 (issue #2075) — the DNSBL formatter remains a pure
 * fixed-column compatibility/schema oracle, not the production RFC4180 writer.
 *
 * Pins the behaviour of:
 *   pfb_syslog_format_dnsbl(array $fields): string
 *   pfb_unified_format_ip(array $fields): string
 *   pfb_unified_format_dnsbl(array $fields): string
 *   pfb_unified_format_dnsreply(array $fields): string
 *   pfb_asn_blob_split(string $blob): array
 *   pfb_asn_csv_fields(string $blob): string
 *
 * All six functions are PURE (no I/O, no globals -- pfb_asn_csv_fields()'s
 * only I/O is an in-memory php://temp stream). These tests are the only
 * callers during this phase.
 *
 * Coverage mandate (CLAUDE.md):
 *   - pfb_syslog_format_dnsbl: all fields; group absent; feed absent; both
 *     absent; a value with a space is double-quoted; NULL b_type + CNAME q_type.
 *   - pfb_unified_format_ip/dnsbl/dnsreply: exact golden-string fidelity.
 *   - pfb_asn_blob_split/pfb_asn_csv_fields (issue #1369): the real pipe-blob
 *     shape from the issue's own pasted example; bare 'Unknown'/'null'/''
 *     states; comma/quote/colon/Unicode/CR/LF in domain or name (fputcsv()
 *     also quotes any value containing a space -- stricter than bare
 *     RFC4180, still valid); the encoded 3-field tail round-trips through
 *     fgetcsv() with no bespoke escaping, including when spliced into a full
 *     unified.log row via pfb_unified_format_ip() (field-local CSV quoting
 *     composes).
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
	 * A non-string scalar (FALSE) for 'group' must be coerced to '' BEFORE
	 * the '' emptiness check, so it is treated as empty and omitted entirely
	 * — never emitted as 'group='.
	 *
	 * Scenario:
	 *   Given group = FALSE (not a string).
	 *   When  pfb_syslog_format_dnsbl($fields).
	 *   Then  the output contains no 'group=' token at all.
	 */
	public function testDnsblGroupFalseBooleanIsCoercedAndOmitted(): void
	{
		$fields = [
			'q_name' => 'ads.example.com',
			'q_ip'   => '10.0.0.5',
			'q_type' => 'A',
			'group'  => FALSE,
			'feed'   => 'EasyList',
			'b_type' => 'VIP',
			'b_eval' => 'ads.example.com',
		];

		$result = pfb_syslog_format_dnsbl($fields);

		$this->assertStringNotContainsString('group=', $result, "group=FALSE must coerce to '' and be omitted");
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
	 * 11 plain named fields joined in the legacy dnsbl.log column order.
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

	/**
	 * ADR-60 P4: verifies (not just asserts) unilog's python-sourced DNSBL row
	 * needs zero further change once pfb_unbound.py's make_timestamp() goes
	 * ISO -- pfb_unified_format_dnsbl() is a pure comma-join, so a NEW
	 * year-bearing 'datetime' value renders through byte-identical, same as
	 * the old no-year value already did above.
	 *
	 * Scenario:
	 *   Given datetime='2026-07-08 14:30:45' (the new ISO-8601 shape).
	 *   When  pfb_unified_format_dnsbl($fields).
	 *   Then  the golden string carries that exact value unmodified.
	 */
	public function testUnifiedDnsblPassesThroughNewIsoTimestampUnmodified(): void
	{
		$fields = [
			'l_type'   => 'DNSBL-python',
			'datetime' => '2026-07-08 14:30:45',
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
			'DNSBL-python,2026-07-08 14:30:45,ads.example.com,10.0.0.5,Python,VIP,ADs,ads.example.com,EasyList,+,A',
			$result,
			'the new ISO-8601 datetime must pass through unmodified -- zero further change needed'
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

	/**
	 * ADR-60 P4: same "zero further change needed" verification as
	 * testUnifiedDnsblPassesThroughNewIsoTimestampUnmodified, for the
	 * DNS-reply formatter -- pfb_unified_format_dnsreply() is likewise a pure
	 * comma-join with no timestamp-shape awareness.
	 */
	public function testUnifiedDnsreplyPassesThroughNewIsoTimestampUnmodified(): void
	{
		$fields = [
			'l_type'   => 'DNS-reply',
			'datetime' => '2026-07-08 14:30:45',
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
			'DNS-reply,2026-07-08 14:30:45,cache,,A,30,good.example.com,10.0.0.5,93.184.216.34,US',
			$result,
			'the new ISO-8601 datetime must pass through unmodified -- zero further change needed'
		);
	}

	// -----------------------------------------------------------------------
	// pfb_asn_blob_split (issue #1369 / ADR-38 Amendment 3)
	// -----------------------------------------------------------------------

	/**
	 * The real blob shape from issue #1369's own pasted example line, verbatim
	 * (not re-derived): "|ASN:  AS50360 | domain:  4vendeta.com | name:
	 * Tamatiya EOOD |". Confirms the label/value split at the FIRST ':' per
	 * segment, trimming the padding whitespace mmdblookup's flattening leaves.
	 */
	public function testAsnBlobSplitRealExampleFromIssue(): void
	{
		$blob = '|ASN:  AS50360 | domain:  4vendeta.com | name:  Tamatiya EOOD |';

		$result = pfb_asn_blob_split($blob);

		$this->assertSame(
			['asn' => 'AS50360', 'domain' => '4vendeta.com', 'name' => 'Tamatiya EOOD'],
			$result,
			'the real issue #1369 example blob must split into these exact 3 parts'
		);
	}

	/**
	 * A bare 'Unknown' state literal (the lookup found nothing) has no '|' or
	 * ':' -- passed through verbatim as 'asn', domain/name empty.
	 */
	public function testAsnBlobSplitUnknownStateLiteral(): void
	{
		$result = pfb_asn_blob_split('Unknown');

		$this->assertSame(['asn' => 'Unknown', 'domain' => '', 'name' => ''], $result);
	}

	/**
	 * A bare 'null' state literal (ASN reporting was off at write time) --
	 * same bare-literal handling as 'Unknown'.
	 */
	public function testAsnBlobSplitNullStateLiteral(): void
	{
		$result = pfb_asn_blob_split('null');

		$this->assertSame(['asn' => 'null', 'domain' => '', 'name' => ''], $result);
	}

	/**
	 * An empty blob coerces to the 'Unknown' state (never a blank asn value).
	 */
	public function testAsnBlobSplitEmptyStringCoercesToUnknown(): void
	{
		$result = pfb_asn_blob_split('');

		$this->assertSame(['asn' => 'Unknown', 'domain' => '', 'name' => ''], $result);
	}

	/**
	 * A domain/name carrying a comma, a double quote, a colon, and a
	 * Unicode codepoint all split correctly -- the label split only ever
	 * consumes the segment's FIRST ':', so a colon inside the VALUE (not
	 * just the label) is preserved verbatim.
	 */
	public function testAsnBlobSplitPreservesCommaQuoteColonAndUnicodeInValues(): void
	{
		$blob = '|ASN:  AS64500 | domain:  ex,ample.com | name:  Ünïcödé "Org", Ltd: EMEA |';

		$result = pfb_asn_blob_split($blob);

		$this->assertSame('AS64500', $result['asn']);
		$this->assertSame('ex,ample.com', $result['domain']);
		$this->assertSame('Ünïcödé "Org", Ltd: EMEA', $result['name']);
	}

	// -----------------------------------------------------------------------
	// pfb_asn_csv_fields (issue #1369 / ADR-38 Amendment 3)
	// -----------------------------------------------------------------------

	/**
	 * Single-token domain/name (no comma/quote/space anywhere) renders as 3
	 * fully unquoted CSV fields -- nothing forces fputcsv() to quote.
	 */
	public function testAsnCsvFieldsSingleTokenValuesRenderFullyUnquoted(): void
	{
		$blob = '|ASN:  AS64599 | domain:  example.com | name:  ExampleOrg |';

		$result = pfb_asn_csv_fields($blob);

		$this->assertSame('AS64599,example.com,ExampleOrg', $result);
	}

	/**
	 * The real blob shape from issue #1369's own pasted example. PHP's
	 * fputcsv() quotes ANY field containing a space -- a stricter guarantee
	 * than the bare RFC4180 minimum (delimiter/enclosure/newline only), still
	 * valid CSV that round-trips identically (proved by the fgetcsv
	 * round-trip tests below), so the multi-word org name comes back quoted.
	 */
	public function testAsnCsvFieldsRealExampleFromIssueQuotesTheSpaceContainingName(): void
	{
		$blob = '|ASN:  AS50360 | domain:  4vendeta.com | name:  Tamatiya EOOD |';

		$result = pfb_asn_csv_fields($blob);

		$this->assertSame('AS50360,4vendeta.com,"Tamatiya EOOD"', $result);
	}

	/**
	 * A comma inside the org name forces RFC4180 double-quoting of THAT field
	 * only -- native fputcsv() behaviour with an explicit empty escape arg
	 * (never PHP's default backslash-escape quirk).
	 */
	public function testAsnCsvFieldsCommaInNameIsDoubleQuoted(): void
	{
		$blob = '|ASN:  AS64500 | domain:  example.com | name:  Example, Inc |';

		$result = pfb_asn_csv_fields($blob);

		$this->assertSame('AS64500,example.com,"Example, Inc"', $result);
	}

	/**
	 * A double quote inside the org name is doubled per RFC4180 (never
	 * backslash-escaped) -- exercises fputcsv()'s explicit empty escape arg.
	 */
	public function testAsnCsvFieldsQuoteInNameIsRfc4180Doubled(): void
	{
		$blob = '|ASN:  AS64501 | domain:  example.net | name:  "Quoted" Org |';

		$result = pfb_asn_csv_fields($blob);

		$this->assertSame('AS64501,example.net,"""Quoted"" Org"', $result);
	}

	/**
	 * A colon inside the org name (not just the label) survives -- the
	 * blob-split only consumes the segment's FIRST ':', and CSV has no
	 * quoting rule for ':' at all (the surrounding quotes here are the same
	 * space-triggered quoting as the real-example test above, not a colon
	 * escaping rule).
	 */
	public function testAsnCsvFieldsColonInNamePassesThroughUnescaped(): void
	{
		$blob = '|ASN:  AS64502 | domain:  example.org | name:  Org: EMEA Division |';

		$result = pfb_asn_csv_fields($blob);

		$this->assertSame('AS64502,example.org,"Org: EMEA Division"', $result);
	}

	/**
	 * A Unicode codepoint in the org name passes through byte-identical --
	 * fputcsv() is byte-oriented, not charset-aware, so UTF-8 needs no
	 * special handling (quoted here because the value also contains spaces).
	 */
	public function testAsnCsvFieldsUnicodeInNamePassesThroughUnmodified(): void
	{
		$blob = '|ASN:  AS64503 | domain:  xn--ls8h.example | name:  Ünïcödé Örg 日本 |';

		$result = pfb_asn_csv_fields($blob);

		$this->assertSame('AS64503,xn--ls8h.example,"Ünïcödé Örg 日本"', $result);
	}

	/**
	 * An empty domain/name (label present, value empty) renders as an empty
	 * CSV segment, never a stray placeholder.
	 */
	public function testAsnCsvFieldsEmptyDomainAndNameRenderAsEmptySegments(): void
	{
		$blob = '|ASN:  AS64504 | domain:   | name:   |';

		$result = pfb_asn_csv_fields($blob);

		$this->assertSame('AS64504,,', $result);
	}

	/**
	 * CR/LF embedded in the org name is normalized to a single space BEFORE
	 * CSV-encoding -- so a written row always stays exactly one physical
	 * line (reverse-tail readers rely on this), per the issue #1369
	 * amendment's explicit contract.
	 */
	public function testAsnCsvFieldsCrLfInNameNormalizedToSpace(): void
	{
		$blob = "|ASN:  AS64505 | domain:  example.io | name:  Line One\r\nLine Two |";

		$result = pfb_asn_csv_fields($blob);

		$this->assertSame('AS64505,example.io,"Line One Line Two"', $result);
		$this->assertStringNotContainsString("\n", $result, 'the encoded fragment must never contain a raw newline');
		$this->assertStringNotContainsString("\r", $result, 'the encoded fragment must never contain a raw carriage return');
	}

	/**
	 * A bare 'Unknown'/'null' state blob renders as a single unquoted token
	 * plus two empty segments -- exactly the writer's "no metadata" shape.
	 */
	public function testAsnCsvFieldsUnknownAndNullStatesRenderBareToken(): void
	{
		$this->assertSame('Unknown,,', pfb_asn_csv_fields('Unknown'));
		$this->assertSame('null,,', pfb_asn_csv_fields('null'));
		$this->assertSame('Unknown,,', pfb_asn_csv_fields(''));
	}

	/**
	 * End-to-end round trip: the encoded 3-field tail, spliced into a full
	 * comma-joined row exactly as pfb_daemon_filterlog() builds $details,
	 * parses back via fgetcsv() (matching escape argument) into the SAME 3
	 * values -- "round-trips through CSV without bespoke escaping" for a
	 * value carrying every awkward character in the coverage matrix at once.
	 */
	public function testAsnCsvFieldsRoundTripsThroughFgetcsv(): void
	{
		$blob = '|ASN:  AS64506 | domain:  ex,am"ple.com | name:  Ünïcödé "Org", Ltd: EMEA |';
		$asnCsv = pfb_asn_csv_fields($blob);

		// Mirrors pfb_daemon_filterlog()'s $details construction: the 3-field
		// tail is spliced onto the end of an otherwise plain comma-joined row.
		$line = "2026-07-18 00:00:00,rule1,em0,WAN,block,4,tcp,TCP,192.0.2.1,198.51.100.1,1,2,in,US,Alias,192.0.2.1,Feed,,," . $asnCsv;

		$fh = fopen('php://temp', 'r+');
		$this->assertNotFalse($fh);
		fwrite($fh, $line . "\n");
		rewind($fh);
		$parsed = fgetcsv($fh, 0, ',', '"', '');
		fclose($fh);

		$this->assertNotFalse($parsed, 'the spliced row must parse as valid CSV');
		// Indices 0-18 are the 19 plain fields (timestamp through Client
		// Hostname) before the ASN triplet at 19/20/21.
		$this->assertSame('AS64506', $parsed[19] ?? null, 'asn column');
		$this->assertSame('ex,am"ple.com', $parsed[20] ?? null, 'asn_domain column, comma+quote intact');
		$this->assertSame('Ünïcödé "Org", Ltd: EMEA', $parsed[21] ?? null, 'asn_name column, comma+quote+colon+unicode intact');
		$this->assertCount(22, $parsed, 'exactly 22 fields: 19 plain (incl. timestamp) + asn + asn_domain + asn_name');
	}

	/**
	 * Same round trip, but the encoded tail is spliced through
	 * pfb_unified_format_ip() itself (the 'details' key) -- proving
	 * field-local CSV quoting composes: pre-escaping the 3-field tail with
	 * fputcsv() and then string-joining it into the simple l_type/log/
	 * details/dup concat is equivalent to escaping the whole row at once,
	 * because RFC4180 quoting never depends on neighbouring fields.
	 */
	public function testAsnCsvFieldsSurviveThroughPfbUnifiedFormatIpAndFgetcsv(): void
	{
		$blob = '|ASN:  AS64507 | domain:  4vendeta.com | name:  Tamatiya, EOOD |';
		$asnCsv = pfb_asn_csv_fields($blob);

		$log = '2026-07-18 00:00:00,rule1,em0,WAN,block,4,tcp,TCP,192.0.2.1,198.51.100.1,1,2';
		$details = 'in,US,Alias,192.0.2.1,Feed,ResolvedHost,ClientHost,' . $asnCsv;

		$unified = pfb_unified_format_ip([
			'l_type'  => 'Block',
			'log'     => $log,
			'details' => $details,
			'dup'     => '+',
		]);

		$fh = fopen('php://temp', 'r+');
		$this->assertNotFalse($fh);
		fwrite($fh, $unified . "\n");
		rewind($fh);
		$parsed = fgetcsv($fh, 0, ',', '"', '');
		fclose($fh);

		$this->assertNotFalse($parsed);
		$this->assertSame('Block', $parsed[0] ?? null, 'unified row keeps its leading event-type prefix');
		$this->assertCount(24, $parsed, 'l_type + 19 plain fields (incl. timestamp) + asn + asn_domain + asn_name + dup = 24');
		$this->assertSame('AS64507', $parsed[20] ?? null, 'asn column');
		$this->assertSame('4vendeta.com', $parsed[21] ?? null, 'asn_domain column');
		$this->assertSame('Tamatiya, EOOD', $parsed[22] ?? null, 'asn_name column, comma intact');
		$this->assertSame('+', $parsed[23] ?? null, 'trailing duplicate-marker column unaffected');
	}
}
