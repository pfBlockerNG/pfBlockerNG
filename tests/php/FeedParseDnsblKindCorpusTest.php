<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/FeedParseCorpusFile.php';

/**
 * Replays go/pfb_core/feedparse/testdata/dnsbl_kind.json (schema: that directory's README.md) through the old path's feed
 * classification (issue #4272): pfb_dnsbl_feed_is_abp() for a downloaded feed, pfb_dnsbl_feed_has_abp_header() for a custom
 * list. The Go runner (dnsbl_kind_corpus_test.go) replays the same file through DNSBLFeedIsABP().
 */
#[CoversFunction('pfb_dnsbl_feed_is_abp')]
#[CoversFunction('pfb_dnsbl_feed_has_abp_header')]
final class FeedParseDnsblKindCorpusTest extends TestCase
{
	private const FILE = __DIR__ . '/../../go/pfb_core/feedparse/testdata/dnsbl_kind.json';

	private string $path = '';

	/** @return array<string, array{array<string, mixed>}> */
	public static function caseProvider(): array
	{
		$out = [];
		foreach (FeedParseCorpusFile::load(self::FILE, ['cases'])['cases'] as $case) {
			$w = "case {$case['id']}";
			FeedParseCorpusFile::keys($case, ['id', 'description', array_key_exists('input_hex', $case) ? 'input_hex' : 'input', 'expect'], $w);
			FeedParseCorpusFile::flags($case['expect'], ['feed', 'custom'], "{$w} expect");
			$out[$case['id']] = [$case];
		}
		return $out;
	}

	protected function setUp(): void
	{
		$this->path = (string) tempnam(sys_get_temp_dir(), 'pfb_kind_');
	}

	protected function tearDown(): void
	{
		@unlink($this->path);
	}

	/** @param array<string, mixed> $case */
	#[DataProvider('caseProvider')]
	public function testTheFeedKindIsTheOldPaths(array $case): void
	{
		file_put_contents($this->path, FeedParseCorpusFile::bytes($case, 'input', "case {$case['id']}"));
		$this->assertSame($case['expect']['feed'], pfb_dnsbl_feed_is_abp($this->path), 'a downloaded feed');
		$this->assertSame($case['expect']['custom'], pfb_dnsbl_feed_has_abp_header($this->path), 'a custom list');
	}
}
