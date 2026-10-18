<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * #3522: the update-pass timing state file (pfb_pass_status.json) that the metrics exporter
 * reads back as last_start / last_end.
 */
#[CoversFunction('pfb_pass_status_path')]
#[CoversFunction('pfb_pass_status_record')]
#[CoversFunction('pfb_pass_status_read')]
final class PassStatusTest extends TestCase
{
	private string $dir;
	private mixed $priorDbdir;

	protected function setUp(): void
	{
		global $pfb;

		$this->priorDbdir = $pfb['dbdir'] ?? NULL;
		$this->dir = sys_get_temp_dir() . '/pfb_pass_status_' . bin2hex(random_bytes(8));
		mkdir($this->dir, 0777, TRUE);
		$pfb['dbdir'] = $this->dir;
	}

	protected function tearDown(): void
	{
		global $pfb;

		$pfb['dbdir'] = $this->priorDbdir;
		rmdir_recursive($this->dir);
	}

	public function testStartThenEndProduceBothFields(): void
	{
		$this->assertTrue(pfb_pass_status_record('last_start', 1700000000));
		$this->assertTrue(pfb_pass_status_record('last_end', 1700000060));

		$this->assertSame(['last_start' => 1700000000, 'last_end' => 1700000060], pfb_pass_status_read());
	}

	public function testRecordingOneFieldPreservesTheOther(): void
	{
		pfb_pass_status_record('last_end', 90);
		pfb_pass_status_record('last_start', 200);

		$this->assertSame(['last_start' => 200, 'last_end' => 90], pfb_pass_status_read());
	}

	public function testUnknownFieldReturnsFalseAndLeavesFileUnchanged(): void
	{
		pfb_pass_status_record('last_start', 100);
		$before = file_get_contents(pfb_pass_status_path());

		$this->assertFalse(pfb_pass_status_record('last_bogus', 999));

		$this->assertSame($before, file_get_contents(pfb_pass_status_path()));
	}

	public function testCorruptFileReadsAsNull(): void
	{
		file_put_contents(pfb_pass_status_path(), '{"last_start": 1,');

		$this->assertNull(pfb_pass_status_read());
	}

	public function testRecordReplacesCorruptFile(): void
	{
		file_put_contents(pfb_pass_status_path(), '{"last_start": 1,');

		$this->assertTrue(pfb_pass_status_record('last_end', 7));

		$this->assertSame(['last_start' => 0, 'last_end' => 7], pfb_pass_status_read());
	}

	public function testAbsentFileReadsAsZeros(): void
	{
		$this->assertSame(['last_start' => 0, 'last_end' => 0], pfb_pass_status_read());
	}

	public function testMissingFieldReadsAsZero(): void
	{
		file_put_contents(pfb_pass_status_path(), '{"last_end": 5}');

		$this->assertSame(['last_start' => 0, 'last_end' => 5], pfb_pass_status_read());
	}

	public function testPublishedFileIsWorldReadable(): void
	{
		pfb_pass_status_record('last_start', 100);

		$this->assertSame(0644, fileperms(pfb_pass_status_path()) & 0777);
	}

	public function testRenameOntoDirectoryFailsAndLeavesItUntouched(): void
	{
		// rename() onto a directory fails even as root, so this exercises the real publish failure.
		$target = pfb_pass_status_path();
		mkdir($target);
		file_put_contents("{$target}/keep.txt", 'unchanged');

		$this->assertFalse(pfb_pass_status_record('last_start', 100));

		$this->assertDirectoryExists($target);
		$this->assertSame(['keep.txt'], array_values(array_diff(scandir($target), ['.', '..'])));
		$this->assertSame('unchanged', file_get_contents("{$target}/keep.txt"));
		$this->assertSame([], glob("{$this->dir}/.pfbpass_*"));
	}
}
