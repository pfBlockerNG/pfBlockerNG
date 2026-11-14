<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The text rules of pfb_download() against the tables shared with Core (#3973), which
 * go/pfb_core/feedfetch/sanity_internal_test.go runs against the Go port: ADR-49's sanity verdicts
 * (tests/feedfetch/fixtures/text_sanity.json) and the UTF-8 that UTF-16/32 text behind a byte order mark decodes to
 * (utf_transcode.json). A row that passes here and fails there, or the reverse, is a divergence.
 */
#[CoversFunction('pfb_text_sanity')]
#[CoversFunction('pfb_utf16_sample_to_utf8')]
final class FeedFetchTextTablesTest extends TestCase
{
	private static function table(string $name): array
	{
		return json_decode((string) file_get_contents(__DIR__ . "/../feedfetch/fixtures/{$name}.json"), TRUE, 512,
			JSON_THROW_ON_ERROR);
	}

	public static function sanityRows(): array
	{
		$cases = [];
		foreach (self::table('text_sanity') as $row) {
			$cases[$row['name']] = [(string) base64_decode($row['sample_b64'], TRUE), $row['verdict']];
		}
		return $cases;
	}

	public static function transcodeRows(): array
	{
		$cases = [];
		foreach (self::table('utf_transcode') as $row) {
			$cases[$row['name']] = [(string) base64_decode($row['in_b64'], TRUE), (string) base64_decode($row['out_b64'], TRUE)];
		}
		return $cases;
	}

	#[DataProvider('sanityRows')]
	public function testSanityVerdictIsTheSharedTables(string $sample, ?string $verdict): void
	{
		$this->assertSame($verdict, pfb_text_sanity($sample));
	}

	#[DataProvider('transcodeRows')]
	public function testDecodingIsTheSharedTables(string $in, string $out): void
	{
		$this->assertSame(bin2hex($out), bin2hex(pfb_utf16_sample_to_utf8($in)));
	}
}
