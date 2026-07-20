<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_top1m_refresh_needed')]
#[CoversFunction('pfb_top1m_fetch_if_needed')]
final class Top1mApplyRefreshMatrixTest extends TestCase
{
	private string $dbdir;

	protected function setUp(): void
	{
		$this->dbdir = sys_get_temp_dir() . '/pfb_top1m_apply_matrix_' . getmypid() . '_' . uniqid();
		$this->assertTrue(@mkdir($this->dbdir, 0777, TRUE), "could not create sandbox {$this->dbdir}");
	}

	protected function tearDown(): void
	{
		foreach ((array) (@glob("{$this->dbdir}/*") ?: []) as $path) {
			@unlink($path);
		}
		@rmdir($this->dbdir);
	}

	public function testMissingActiveCsvWithBaselineRetries(): void
	{
		$this->assertNotFalse(file_put_contents("{$this->dbdir}/top-1m.csv.zip.orig", "raw\n"));
		$this->assertTrue(
			pfb_top1m_refresh_needed($this->dbdir),
			'missing active CSV must retry even with a detector baseline'
		);
	}

	public function testUpdateMarkerWithCompleteSourceStaysOnLocalReprocess(): void
	{
		$this->assertNotFalse(file_put_contents("{$this->dbdir}/top-1m.csv", "live\n"));
		$this->assertNotFalse(file_put_contents("{$this->dbdir}/top-1m.csv.zip.orig", "raw\n"));
		$this->assertNotFalse(file_put_contents("{$this->dbdir}/top-1m.update", ''));
		$attempts = 0;

		$this->assertFalse(
			pfb_top1m_fetch_if_needed($this->dbdir, static function () use (&$attempts): bool {
				$attempts++;
				return FALSE;
			}),
			'update marker with complete source must stay on local reprocess path'
		);
		$this->assertSame(0, $attempts, 'local reprocess marker must not invoke provider fetch');
	}
}
