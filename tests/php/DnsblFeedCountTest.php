<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_dnsbl_feed_count() -- issue #1263: replaces `cat *.txt | grep -c ^`
 * (exec'd at the DNSBL feed-count site) with a per-file pfb_count_lines()
 * sum. This is an INTENDED behaviour change on unterminated input: cat welds
 * an unterminated file's last record onto the next file's first and
 * undercounts; the per-file sum cannot weld and is the correct total.
 * Brand-new function -- tests assert real behaviour, not mere existence.
 */
#[CoversFunction('pfb_dnsbl_feed_count')]
final class DnsblFeedCountTest extends TestCase
{
	private string $dir;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_dnsbl_feed_count_' . uniqid();
		mkdir($this->dir);
	}

	protected function tearDown(): void
	{
		array_map('unlink', glob("{$this->dir}/*") ?: array());
		rmdir($this->dir);
	}

	public function testSumsPerFileCountsAcrossAnUnterminatedFileNeverWeldingRecords(): void
	{
		// The reported defect, reproduced directly: an old cat|grep -c ^ over these
		// two files would weld "5.6.7.8" onto "9.9.9.9" into ONE fused record and
		// report 2, not the true 3.
		file_put_contents("{$this->dir}/FeedA.txt", "1.2.3.4\n5.6.7.8"); // unterminated
		file_put_contents("{$this->dir}/FeedB.txt", "9.9.9.9\n");
		$this->assertSame(3, pfb_dnsbl_feed_count($this->dir),
			'the per-file sum must count the true 3 records, never the welded 2');
	}

	public function testTerminatedFilesSumNormally(): void
	{
		file_put_contents("{$this->dir}/FeedA.txt", "1.2.3.4\n5.6.7.8\n");
		file_put_contents("{$this->dir}/FeedB.txt", "9.9.9.9\n");
		$this->assertSame(3, pfb_dnsbl_feed_count($this->dir));
	}

	public function testEmptyDirectoryCountsZero(): void
	{
		$this->assertSame(0, pfb_dnsbl_feed_count($this->dir), 'no matching files -- zero, not a warning or TypeError');
	}

	public function testMissingDirectoryCountsZero(): void
	{
		$missing = $this->dir . '-does-not-exist';
		$this->assertSame(0, pfb_dnsbl_feed_count($missing), 'a missing directory -- zero, not a warning or TypeError');
	}

	public function testNonTxtFilesAreIgnored(): void
	{
		file_put_contents("{$this->dir}/FeedA.txt", "1.2.3.4\n");
		file_put_contents("{$this->dir}/FeedA.manifest", "should not be counted\nat all\n");
		$this->assertSame(1, pfb_dnsbl_feed_count($this->dir));
	}
}
