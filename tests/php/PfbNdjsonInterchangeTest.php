<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * NDJSON interchange -- compact tagged-array reader plus schema-v1 object fallback.
 */
#[CoversClass(PfbDnsblRowKind::class)]
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
}
