<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * NDJSON interchange -- compact tagged-array writers plus schema-v1 object fallback.
 */
#[CoversClass(PfbDnsblRowKind::class)]
#[CoversFunction('pfb_dnsbl_ndjson_emit_row')]
#[CoversFunction('pfb_dnsbl_ndjson_parse_row')]
final class PfbNdjsonInterchangeTest extends TestCase
{
	public function testCompactRowKindsOwnWireTags(): void
	{
		$this->assertSame('d', PfbDnsblRowKind::Domain->value);
		$this->assertSame('a', PfbDnsblRowKind::Abp->value);
		$this->assertNull(PfbDnsblRowKind::tryFrom('x'));
	}

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
			'empty compact array'             => ['[]'],
			'json string (non-object)'        => ['"str"'],
			'json number (non-object)'        => ['42'],
			'json null (non-object)'          => ['null'],
			'json true (non-object)'          => ['true'],
			'compact missing payload'         => ['["d"]'],
			'compact empty payload'           => ['["d",""]'],
			'compact non-string tag'          => ['[1,"x.example"]'],
			'compact non-string payload'      => ['["d",1]'],
			'compact unknown tag'             => ['["x","x.example"]'],
			'compact extra element'           => ['["d","x.example","extra"]'],
			'compact truncated array'         => ['["d"'],
			'compact ABP missing payload'     => ['["a"]'],
			'compact ABP empty payload'       => ['["a",""]'],
			'compact ABP non-string payload'  => ['["a",1]'],
			'compact ABP extra element'       => ['["a","x","extra"]'],
			'numeric-key object'              => ['{"0":"d","1":"x.example"}'],
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

	public function testLegacyDomainRowRetainsExtraFields(): void
	{
		// Legacy schema-v1 metadata remains available while only kind is normalized
		// to the internal enum.
		$row = pfb_dnsbl_ndjson_parse_row('{"kind":"domain","domain":"a.com","log":"1","feed":"f","group":"g","extra":"ignored-me"}');

		$this->assertSame([
			'kind'   => PfbDnsblRowKind::Domain,
			'domain' => 'a.com',
			'log'    => '1',
			'feed'   => 'f',
			'group'  => 'g',
			'extra'  => 'ignored-me',
		], $row);
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

	public function testCompactDomainRowNormalizesToSchemaFields(): void
	{
		$this->assertSame(
			['kind' => PfbDnsblRowKind::Domain, 'domain' => 'example.com'],
			pfb_dnsbl_ndjson_parse_row('["d","example.com"]')
		);
	}

	public function testCompactAbpRowNormalizesToSchemaFields(): void
	{
		$this->assertSame(
			['kind' => PfbDnsblRowKind::Abp, 'raw' => '@@||allow.example^'],
			pfb_dnsbl_ndjson_parse_row('["a","@@||allow.example^"]')
		);
	}

	public function testCompactOversizedDomainValueParsesShapeOnly(): void
	{
		$huge = str_repeat('a', 100000) . '.com';
		$this->assertSame(
			['kind' => PfbDnsblRowKind::Domain, 'domain' => $huge],
			pfb_dnsbl_ndjson_parse_row('["d","' . $huge . '"]')
		);
	}

	public function testLegacyObjectRowsRetainSchemaV1Fields(): void
	{
		$this->assertSame(
			[
				'kind' => PfbDnsblRowKind::Domain,
				'domain' => 'legacy.example',
				'log' => '1',
				'feed' => 'feedA',
				'group' => 'groupA',
			],
			pfb_dnsbl_ndjson_parse_row('{"kind":"domain","domain":"legacy.example","log":"1","feed":"feedA","group":"groupA"}')
		);
		$this->assertSame(
			['kind' => PfbDnsblRowKind::Abp, 'raw' => '@@||legacy.example^'],
			pfb_dnsbl_ndjson_parse_row('{"kind":"abp","raw":"@@||legacy.example^"}')
		);
	}

	// =========================================================================
	// Round-trip + determinism -- emit() -> parse() identity, compact tagged shape.
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
		$line = pfb_dnsbl_ndjson_emit_row(PfbDnsblRowKind::Domain, $domain);

		$this->assertStringStartsWith('["d","', $line, 'compact domain tag first');
		$this->assertSame(1, substr_count($line, "\n"), 'exactly one raw newline byte -- the trailing one');
		$this->assertStringEndsWith("\n", $line);

		$parsed = pfb_dnsbl_ndjson_parse_row(rtrim($line, "\n"));
		$this->assertIsArray($parsed, 'the emitted line must parse back');
		$this->assertSame($domain, $parsed['domain'], 'round-trip must recover the exact original domain, escaping notwithstanding');
		$this->assertSame(['kind' => PfbDnsblRowKind::Domain, 'domain' => $domain], $parsed);
	}

	public static function abpRoundTripProvider(): array
	{
		return [
			'adblock network rule'       => ['||example.com^'],
			'allow exception rule'       => ['@@||allow.example^'],
			'regex rule'                 => ['/^ad[0-9]+\\./'],
			'hosts-style line'           => ['0.0.0.0 host.example'],
			'comma and hash raw'         => ['ads,tracker#comment'],
			'tab spaces shell regex raw' => ["@@||x^\$important\t  /[a-z]+/;\$(x)"],
		];
	}

	#[DataProvider('abpRoundTripProvider')]
	public function testEmitAbpRowRoundTrips(string $raw): void
	{
		$line = pfb_dnsbl_ndjson_emit_row(PfbDnsblRowKind::Abp, $raw);

		$this->assertStringStartsWith('["a","', $line, 'compact ABP tag first');
		$this->assertSame(1, substr_count($line, "\n"));

		$parsed = pfb_dnsbl_ndjson_parse_row(rtrim($line, "\n"));
		$this->assertIsArray($parsed);
		$this->assertSame($raw, $parsed['raw']);
	}

	public function testEmitAbpRowUsesExpectedTagAndUnescapedSlashes(): void
	{
		$line = pfb_dnsbl_ndjson_emit_row(PfbDnsblRowKind::Abp, '||example.com^');
		$this->assertSame("[\"a\",\"||example.com^\"]\n", $line);

		// JSON_UNESCAPED_SLASHES proof: a raw containing '/' must not gain '\/'.
		$regexLine = pfb_dnsbl_ndjson_emit_row(PfbDnsblRowKind::Abp, '/^ad[0-9]+\\./');
		$this->assertStringNotContainsString('\\/', $regexLine, 'JSON_UNESCAPED_SLASHES must leave "/" unescaped');
	}

	// =========================================================================
	// Byte-exact emit fixtures -- pin the exact on-wire NDJSON bytes the writers
	// produce (the Python read-side twin that once cross-checked these was retired
	// in issue #1349).
	// =========================================================================

	public function testEmitDomainRowByteExactOutput(): void
	{
		$this->assertSame(
			"[\"d\",\"example.com\"]\n",
			pfb_dnsbl_ndjson_emit_row(PfbDnsblRowKind::Domain, 'example.com')
		);
	}

	public function testEmitAbpRowByteExactOutput(): void
	{
		$this->assertSame(
			"[\"a\",\"/^ad[0-9]+\\\\./\"]\n",
			pfb_dnsbl_ndjson_emit_row(PfbDnsblRowKind::Abp, '/^ad[0-9]+\\./')
		);
	}

	// =========================================================================
	// Invalid-UTF-8 bytes -- json_encode() returns FALSE on malformed UTF-8, and
	// FALSE . "\n" coerces to a bare "\n": without JSON_INVALID_UTF8_SUBSTITUTE the
	// row is a phantom blank line, not valid interchange (issue #1083 review).
	// =========================================================================

	public static function invalidUtf8ByteProvider(): array
	{
		return [
			'lone continuation byte'      => ["\xFF"],
			'truncated 2-byte sequence'   => ["\xC3\x28"],
		];
	}

	#[DataProvider('invalidUtf8ByteProvider')]
	public function testEmitDomainRowWithInvalidUtf8DomainStaysAValidRow(string $badBytes): void
	{
		$line = pfb_dnsbl_ndjson_emit_row(PfbDnsblRowKind::Domain, "bad{$badBytes}domain.com");

		$this->assertSame(1, substr_count($line, "\n"), 'exactly one line, never a phantom blank');
		$this->assertNotSame("\n", $line, 'must never degrade to a bare newline');
		$this->assertNotFalse(json_decode(rtrim($line, "\n"), TRUE), 'must stay JSON-decodable');

		$row = pfb_dnsbl_ndjson_parse_row(rtrim($line, "\n"));
		$this->assertIsArray($row, 'the emitted line must parse back as valid interchange');
		$this->assertSame(PfbDnsblRowKind::Domain, $row['kind']);
		$expected = $badBytes === "\xFF" ? 'bad�domain.com' : 'bad�(domain.com';
		$this->assertSame($expected, $row['domain']);
	}

	#[DataProvider('invalidUtf8ByteProvider')]
	public function testEmitAbpRowWithInvalidUtf8RawStaysAValidRow(string $badBytes): void
	{
		$line = pfb_dnsbl_ndjson_emit_row(PfbDnsblRowKind::Abp, "||bad{$badBytes}domain.example^");

		$this->assertSame(1, substr_count($line, "\n"), 'exactly one line, never a phantom blank');
		$this->assertNotSame("\n", $line, 'must never degrade to a bare newline');
		$this->assertNotFalse(json_decode(rtrim($line, "\n"), TRUE), 'must stay JSON-decodable');

		$row = pfb_dnsbl_ndjson_parse_row(rtrim($line, "\n"));
		$this->assertIsArray($row, 'the emitted line must parse back as valid interchange');
		$this->assertSame(PfbDnsblRowKind::Abp, $row['kind']);
		$expected = $badBytes === "\xFF" ? '||bad�domain.example^' : '||bad�(domain.example^';
		$this->assertSame($expected, $row['raw']);
	}
}
