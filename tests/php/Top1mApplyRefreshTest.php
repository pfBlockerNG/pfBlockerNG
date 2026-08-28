<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Behavior-preserving seam extraction for TOP1M's existing active-file fetch gate.
 */
#[CoversFunction('pfb_top1m_refresh_needed')]
#[CoversFunction('pfb_top1m_fetch_if_needed')]
final class Top1mApplyRefreshTest extends TestCase
{
	private string $dbdir;

	protected function setUp(): void
	{
		$this->dbdir = sys_get_temp_dir() . '/pfb_top1m_apply_' . getmypid() . '_' . uniqid();
		$this->assertTrue(@mkdir($this->dbdir, 0777, TRUE), "could not create sandbox {$this->dbdir}");
	}

	protected function tearDown(): void
	{
		foreach ((array) (@glob("{$this->dbdir}/*") ?: []) as $path) {
			@unlink($path);
		}
		@rmdir($this->dbdir);
	}

	private function activePath(): string
	{
		return "{$this->dbdir}/top-1m.csv";
	}

	private function baselinePath(): string
	{
		return "{$this->dbdir}/top-1m.csv.zip.orig";
	}

	public function testMissingActiveCsvNeedsRefresh(): void
	{
		$this->assertTrue(pfb_top1m_refresh_needed($this->dbdir), 'missing active CSV must retry provider fetch');
	}

	public function testActiveCsvSkipsRefreshRegardlessOfBaseline(): void
	{
		$this->assertNotFalse(file_put_contents($this->activePath(), "live\n"));
		$this->assertNotFalse(file_put_contents($this->baselinePath(), "raw\n"));
		$this->assertFalse(pfb_top1m_refresh_needed($this->dbdir), 'existing active CSV with baseline must still skip');
		unlink($this->baselinePath());
		$this->assertTrue(pfb_top1m_refresh_needed($this->dbdir), 'missing detector baseline must force provider retry');
	}

	public function testFetchSeamOnlyRunsWhenActiveCsvMissing(): void
	{
		$attempts = 0;
		$this->assertTrue(
			pfb_top1m_fetch_if_needed($this->dbdir, static function () use (&$attempts): bool {
				$attempts++;
				return FALSE;
			}),
			'missing active CSV must attempt provider fetch'
		);
		$this->assertSame(1, $attempts, 'failed fetch must be observable as one attempt');
		$this->assertNotFalse(file_put_contents($this->activePath(), "live\n"));
		$this->assertNotFalse(file_put_contents($this->baselinePath(), "raw\n"));
		$this->assertFalse(
			pfb_top1m_fetch_if_needed($this->dbdir, static function () use (&$attempts): bool {
				$attempts++;
				return FALSE;
			}),
			'existing active CSV must skip provider fetch'
		);
		$this->assertSame(1, $attempts, 'active CSV must suppress a second fetch attempt');
	}

	public function testFailedFetchPreservesLiveOutputsAndRemainsRetryable(): void
	{
		$active = "live\n";
		$whitelist = ".example.com,,\n,example.com,,\n,www.example.com,,\n";
		$whitelistPath = "{$this->dbdir}/pfbalexawhitelist.txt";
		$this->assertNotFalse(file_put_contents($this->activePath(), $active));
		$this->assertNotFalse(file_put_contents($whitelistPath, $whitelist));
		$attempts = 0;

		$this->assertTrue(
			pfb_top1m_fetch_if_needed($this->dbdir, static function () use (&$attempts): bool {
				$attempts++;
				return FALSE;
			}),
			'missing detector baseline must attempt provider fetch'
		);
		$this->assertSame(1, $attempts, 'failed fetch must be observable as one attempt');
		$this->assertSame($active, file_get_contents($this->activePath()), 'failed fetch must preserve active CSV');
		$this->assertSame($whitelist, file_get_contents($whitelistPath), 'failed fetch must preserve whitelist');
		$this->assertTrue(pfb_top1m_refresh_needed($this->dbdir), 'missing baseline must force the next retry');
	}

}
