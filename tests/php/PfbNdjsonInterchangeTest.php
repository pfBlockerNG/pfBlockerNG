<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * NDJSON interchange schema v1 (#1083 Phase 2) -- emit/parse primitives, no call
 * sites yet. pfb_dnsbl_ndjson_emit_domain_row()/pfb_dnsbl_ndjson_emit_abp_row() are
 * the two writers; pfb_dnsbl_ndjson_parse_row() is the strict reader both this file
 * and tests/test_issue1083_ndjson_primitives.py (the Python twin) exercise against
 * the identical hostile-input matrix, proving cross-language agreement.
 */
#[CoversFunction('pfb_dnsbl_ndjson_emit_domain_row')]
#[CoversFunction('pfb_dnsbl_ndjson_emit_abp_row')]
#[CoversFunction('pfb_dnsbl_ndjson_parse_row')]
final class PfbNdjsonInterchangeTest extends TestCase
{
	// =========================================================================
	// Hostile-input matrix -- parse rejects every malformed/wrong-kind line.
	// =========================================================================

	public static function rejectedLineProvider(): array
	{
		return [
			'empty string'                    => [''],
			'whitespace-only line'            => ["   "],
			'truncated open brace'            => ['{'],
			'truncated partial object'        => ['{"kind":"domain"'],
			'json array (non-object)'         => ['[]'],
			'json string (non-object)'        => ['"str"'],
			'json number (non-object)'        => ['42'],
			'json null (non-object)'          => ['null'],
			'json true (non-object)'          => ['true'],
			'unknown kind'                    => ['{"kind":"bogus","domain":"a.com","log":"1","feed":"f","group":"g"}'],
			'missing kind'                    => ['{"domain":"a.com","log":"1","feed":"f","group":"g"}'],
			'domain: missing domain field'    => ['{"kind":"domain","log":"1","feed":"f","group":"g"}'],
			'domain: empty domain'            => ['{"kind":"domain","domain":"","log":"1","feed":"f","group":"g"}'],
			'domain: non-string domain'       => ['{"kind":"domain","domain":123,"log":"1","feed":"f","group":"g"}'],
			'domain: non-string log'          => ['{"kind":"domain","domain":"a.com","log":1,"feed":"f","group":"g"}'],
			'abp: missing raw'                => ['{"kind":"abp"}'],
			'abp: empty raw'                  => ['{"kind":"abp","raw":""}'],
			// BOM (EF BB BF) is not part of the JSON grammar -- json_decode() refuses it.
			'BOM-prefixed valid object'       => ["\xEF\xBB\xBF" . '{"kind":"domain","domain":"a.com","log":"1","feed":"f","group":"g"}'],
			// The migration's generation discriminator: a legacy positional-CSV line is
			// simply not valid JSON, so it rejects for free -- no special-casing needed.
			'legacy CSV line'                 => [',a.com,,1,f,g'],
			// json_decode() refuses a raw invalid-UTF-8 byte outright (PHP-only row --
			// Python strings can't carry an unpaired invalid byte the same way).
			'raw invalid UTF-8 byte'          => ['{"kind":"domain","domain":"' . "\xFF" . '","log":"1","feed":"f","group":"g"}'],
		];
	}

	#[DataProvider('rejectedLineProvider')]
	public function testRejectedLinesReturnNull(string $line): void
	{
		$this->assertNull(pfb_dnsbl_ndjson_parse_row($line), 'this line must be rejected as NULL');
	}

	public function testExtraUnknownKeyAlongsideValidDomainRowIsIgnoredIncidentally(): void
	{
		// Incidental behaviour of json_decode()'s associative mode -- NOT a forward-
		// compatibility promise (schema v1 has none); pinned so a future change to the
		// parser's key handling shows up here first.
		$row = pfb_dnsbl_ndjson_parse_row('{"kind":"domain","domain":"a.com","log":"1","feed":"f","group":"g","extra":"ignored-me"}');

		$this->assertIsArray($row);
		$this->assertSame('a.com', $row['domain']);
	}

	public function testDuplicateKeyLastValueWinsIncidentally(): void
	{
		// Pins json_decode()'s actual last-wins duplicate-key behaviour (verified via
		// a bare json_decode() probe before this test was written) -- not a contract.
		$row = pfb_dnsbl_ndjson_parse_row('{"kind":"domain","domain":"a.com","domain":"b.com","log":"1","feed":"f","group":"g"}');

		$this->assertIsArray($row);
		$this->assertSame('b.com', $row['domain']);
	}

	public function testOversizedDomainValueParsesShapeOnlySyntaxIsNotValidated(): void
	{
		// The helper validates the interchange SHAPE, not domain syntax -- that stays
		// with the existing validators (e.g. PFB_FILTER_DOMAIN) downstream of parsing.
		$huge = str_repeat('a', 100000) . '.com';
		$row  = pfb_dnsbl_ndjson_parse_row('{"kind":"domain","domain":"' . $huge . '","log":"1","feed":"f","group":"g"}');

		$this->assertIsArray($row);
		$this->assertSame($huge, $row['domain']);
	}

	// =========================================================================
	// Round-trip + determinism -- emit() -> parse() identity, grep-stable shape.
	// =========================================================================

	public static function domainRoundTripProvider(): array
	{
		return [
			'plain ASCII domain'               => ['example.com'],
			'punycode domain'                  => ['xn--nxasmq6b.com'],
			'domain with quote and backslash'  => ['ex"a\\mple.com'],
			'domain with raw newline'          => ["example\ncom"],
		];
	}

	#[DataProvider('domainRoundTripProvider')]
	public function testEmitDomainRowRoundTripsAndStaysSingleLine(string $domain): void
	{
		$line = pfb_dnsbl_ndjson_emit_domain_row($domain, '1', 'feedA', 'groupA');

		$this->assertStringStartsWith('{"kind":"domain","domain":"', $line, 'fixed key order: kind first then domain');
		$this->assertSame(1, substr_count($line, "\n"), 'exactly one raw newline byte -- the trailing one');
		$this->assertStringEndsWith("\n", $line);

		$parsed = pfb_dnsbl_ndjson_parse_row(rtrim($line, "\n"));
		$this->assertIsArray($parsed, 'the emitted line must parse back');
		$this->assertSame($domain, $parsed['domain'], 'round-trip must recover the exact original domain, escaping notwithstanding');
		$this->assertSame('1', $parsed['log']);
		$this->assertSame('feedA', $parsed['feed']);
		$this->assertSame('groupA', $parsed['group']);
	}

	public function testEmitDomainRowLiteralGrepSubstringForPlainDomain(): void
	{
		$line = pfb_dnsbl_ndjson_emit_domain_row('example.com', '1', 'feedA', 'groupA');

		$this->assertStringContainsString('"domain":"example.com"', $line, 'later phases grep this exact substring');
	}

	public static function abpRoundTripProvider(): array
	{
		return [
			'adblock network rule'  => ['||example.com^'],
			'allow exception rule'  => ['@@||allow.example^'],
			'regex rule'            => ['/^ad[0-9]+\\./'],
			'hosts-style line'      => ['0.0.0.0 host.example'],
			'comma and hash raw'    => ['ads,tracker#comment'],
		];
	}

	#[DataProvider('abpRoundTripProvider')]
	public function testEmitAbpRowRoundTrips(string $raw): void
	{
		$line = pfb_dnsbl_ndjson_emit_abp_row($raw);

		$this->assertStringStartsWith('{"kind":"abp","raw":"', $line, 'fixed key order: kind first then raw');
		$this->assertSame(1, substr_count($line, "\n"));

		$parsed = pfb_dnsbl_ndjson_parse_row(rtrim($line, "\n"));
		$this->assertIsArray($parsed);
		$this->assertSame($raw, $parsed['raw']);
	}

	public function testEmitAbpRowLiteralGrepSubstringAndUnescapedSlashes(): void
	{
		$line = pfb_dnsbl_ndjson_emit_abp_row('||example.com^');
		$this->assertStringContainsString('"raw":"||example.com^"', $line);

		// JSON_UNESCAPED_SLASHES proof: a raw containing '/' must not gain '\/'.
		$regexLine = pfb_dnsbl_ndjson_emit_abp_row('/^ad[0-9]+\\./');
		$this->assertStringNotContainsString('\\/', $regexLine, 'JSON_UNESCAPED_SLASHES must leave "/" unescaped');
	}

	// =========================================================================
	// Cross-language byte-exact fixtures -- also hardcoded verbatim in the Python
	// twin (tests/test_issue1083_ndjson_primitives.py) to prove agreement.
	// =========================================================================

	public function testEmitDomainRowByteExactOutput(): void
	{
		$this->assertSame(
			"{\"kind\":\"domain\",\"domain\":\"example.com\",\"log\":\"1\",\"feed\":\"feedA\",\"group\":\"groupA\"}\n",
			pfb_dnsbl_ndjson_emit_domain_row('example.com', '1', 'feedA', 'groupA')
		);
	}

	public function testEmitAbpRowByteExactOutput(): void
	{
		$this->assertSame(
			"{\"kind\":\"abp\",\"raw\":\"/^ad[0-9]+\\\\./\"}\n",
			pfb_dnsbl_ndjson_emit_abp_row('/^ad[0-9]+\\./')
		);
	}
}
