<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/FeedFetchParityCorpusTest.php';

/**
 * The PHP corpus runner never holds a published copy over 1 MiB (#3989): a raised ceiling once published a 2 GiB
 * extraction, and reading it back whole for the comparison OOMed the host. A larger file still compares unequal to a
 * different one.
 */
#[CoversNothing]
final class FeedFetchParityCorpusReadTest extends TestCase
{
	private const LIMIT = 1 << 20;

	private string $dir = '';

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_ffcorpus_read_' . getmypid() . '_' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir($this->dir, 0700));
	}

	protected function tearDown(): void
	{
		exec('rm -rf ' . escapeshellarg($this->dir));
	}

	public function testStateFileStaysBoundedAndDistinguishesLargeFiles(): void
	{
		$over = self::LIMIT + (4 << 20);
		$a = FeedFetchParityCorpusTest::stateFile($this->sparse('a', $over, 'a'));
		$b = FeedFetchParityCorpusTest::stateFile($this->sparse('b', $over, 'b'));
		foreach ([$a, $b] as $v) {
			$this->assertIsString($v);
			$this->assertLessThanOrEqual(self::LIMIT, strlen($v), "a {$over}-byte file must read back bounded");
		}
		$this->assertNotSame($a, $b, "two different {$over}-byte files must read back unequal");

		$this->assertSame(str_repeat("\0", self::LIMIT - 1) . 'z',
			FeedFetchParityCorpusTest::stateFile($this->sparse('at-cap', self::LIMIT, 'z')),
			'a file of exactly the cap reads back verbatim');
		$this->assertNull(FeedFetchParityCorpusTest::stateFile("{$this->dir}/missing"));
	}

	private function sparse(string $name, int $size, string $last): string
	{
		$path = "{$this->dir}/{$name}";
		$h = fopen($path, 'wb');
		$this->assertNotFalse($h);
		fseek($h, $size - 1);
		fwrite($h, $last);
		fclose($h);
		return $path;
	}
}
