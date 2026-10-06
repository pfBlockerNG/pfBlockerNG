<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_ip_feed_content_count() — issue #3457: the IP emptiness probe must not
 * count blank lines or '#', ';', '!', '//' comment lines, so a feed that turned
 * comment-only (e.g. Spamhaus EDROP, whose body is all ';' lines) is empty and
 * takes the "Empty file, Adding '<placeholder>'" path instead of keeping its
 * stale entries. The probe is not the parser: a non-comment line without an IP
 * still counts.
 */
#[CoversFunction('pfb_ip_feed_content_count')]
final class IpFeedContentCountTest extends TestCase
{
	private const APPLY = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';

	private const EDROP_BODY = "; This list has been merged into https://www.spamhaus.org/drop/drop.txt\n"
		. "; Spamhaus EDROP List 2026/10/05 - (c) 2026 The Spamhaus Project SLU\n"
		. "; https://www.spamhaus.org/drop/edrop.txt\n"
		. "; Last-Modified: Mon, 05 Oct 2026 10:14:02 GMT\n"
		. "; Expires: Tue, 06 Oct 2026 10:14:02 GMT\n"
		. "; EOF\n";

	private string $grep;
	/** @var list<string> */
	private array $cleanup = [];

	public static function setUpBeforeClass(): void
	{
		require_once self::APPLY;
	}

	protected function setUp(): void
	{
		$this->grep = trim((string) shell_exec('command -v grep'));
		if ($this->grep === '') {
			$this->markTestSkipped('grep not found on PATH');
		}
	}

	protected function tearDown(): void
	{
		foreach (array_reverse($this->cleanup) as $path) {
			is_dir($path) ? @rmdir($path) : @unlink($path);
		}
		$this->cleanup = [];
	}

	private function feed(string $content): string
	{
		$path = tempnam(sys_get_temp_dir(), 'pfb3457_');
		$this->assertNotFalse($path);
		$this->cleanup[] = $path;
		file_put_contents($path, $content);
		return $path;
	}

	public function testEdropSemicolonBodyIsEmpty(): void
	{
		$this->assertSame('0', pfb_ip_feed_content_count($this->grep, $this->feed(self::EDROP_BODY)));
	}

	public function testHashCommentsAndBlankLinesAreEmpty(): void
	{
		$this->assertSame('0', pfb_ip_feed_content_count($this->grep, $this->feed("# a\n\n#b\n\n")));
	}

	public function testBangAndSlashSlashCommentsAreEmpty(): void
	{
		$this->assertSame('0', pfb_ip_feed_content_count($this->grep, $this->feed("! a\n// b\n")));
	}

	public function testLeadingWhitespaceCommentsAreEmpty(): void
	{
		$this->assertSame('0', pfb_ip_feed_content_count($this->grep, $this->feed("   ; x\n\t# y\n  // z\n")));
	}

	public function testCrlfCommentsAndWhitespaceOnlyLinesAreEmpty(): void
	{
		$this->assertSame('0', pfb_ip_feed_content_count($this->grep, $this->feed("; a\r\n\r\n# b\r\n")));
		$this->assertSame('0', pfb_ip_feed_content_count($this->grep, $this->feed("   \n\t\n")));
	}

	public function testSpamhausDropShapeCountsDataLines(): void
	{
		$this->assertSame('2', pfb_ip_feed_content_count(
			$this->grep,
			$this->feed("; hdr\n1.2.3.0/24 ; SBL1\n5.6.7.0/24 ; SBL2\n")
		));
	}

	public function testMidLineSemicolonOrHashStillCounts(): void
	{
		$this->assertSame('2', pfb_ip_feed_content_count($this->grep, $this->feed("1.2.3.4;note\n1.2.3.5 # note\n")));
	}

	public function testCrlfDataLineCounts(): void
	{
		$this->assertSame('1', pfb_ip_feed_content_count($this->grep, $this->feed("1.2.3.4\r\n")));
	}

	public function testNonCommentLineWithoutIpStillCounts(): void
	{
		$this->assertSame('1', pfb_ip_feed_content_count($this->grep, $this->feed("not-an-ip\n")));
	}

	public function testShellHostilePathIsQuoted(): void
	{
		$dir = sys_get_temp_dir() . '/pfb3457_dir_' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir($dir, 0700));
		$this->cleanup[] = $dir;
		$file = "{$dir}/a b'c;\$(x).orig";
		file_put_contents($file, "; only\n");
		$this->cleanup[] = $file;

		$cwd = getcwd();
		$this->assertTrue(chdir($dir));
		try {
			$this->assertSame('0', pfb_ip_feed_content_count($this->grep, $file));
			$this->assertFileDoesNotExist("{$dir}/x");
		} finally {
			chdir($cwd);
		}
	}

	public function testZeroByteFileIsEmpty(): void
	{
		$this->assertSame('0', pfb_ip_feed_content_count($this->grep, $this->feed('')));
	}
}
