<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * #3522: the update-pass timing state file (pfb_pass_status.json) that the metrics exporter
 * reads back as last_start / last_end.
 */
#[CoversFunction('pfb_pass_status_path')]
#[CoversFunction('pfb_pass_status_read')]
final class PassStatusTest extends TestCase
{
	private string $dir;
	private mixed $priorDbdir;
	private mixed $priorPassStatus;

	protected function setUp(): void
	{
		global $pfb;

		$this->priorDbdir = $pfb['dbdir'] ?? NULL;
		$this->priorPassStatus = $pfb['pass_status'] ?? NULL;
		$this->dir = sys_get_temp_dir() . '/pfb_pass_status_' . bin2hex(random_bytes(8));
		mkdir("{$this->dir}/db", 0777, TRUE);
		mkdir("{$this->dir}/etc", 0777, TRUE);
		$pfb['dbdir'] = "{$this->dir}/db";
		$pfb['pass_status'] = "{$this->dir}/etc/pfb_pass_status.json";
	}

	protected function tearDown(): void
	{
		global $pfb;

		$pfb['dbdir'] = $this->priorDbdir;
		$pfb['pass_status'] = $this->priorPassStatus;
		rmdir_recursive($this->dir);
	}

	public function testTheRecordLivesInUsrLocalEtcWhichSurvivesARamDiskVar(): void
	{
		global $pfb;

		$pfb['pass_status'] = $this->priorPassStatus;

		$this->assertSame('/usr/local/etc/pfb_pass_status.json', pfb_pass_status_path());
	}

	public function testCorruptFileReadsAsNull(): void
	{
		file_put_contents(pfb_pass_status_path(), '{"last_start": 1,');

		$this->assertNull(pfb_pass_status_read());
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
}
