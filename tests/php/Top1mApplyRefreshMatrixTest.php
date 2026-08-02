<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_top1m_refresh_needed')]
#[CoversFunction('pfb_top1m_fetch_if_needed')]
#[CoversFunction('pfb_top1m_reprocess_needed')]
#[CoversFunction('pfb_top1m_apply_reprocess_if_ready')]
#[CoversFunction('pfb_dnsbl_publish_result')]
#[CoversFunction('pfb_dnsbl_reload_needed')]
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

	public function testFailedIdentityReplacementDefersCombinedSettingsReprocess(): void
	{
		$base = "{$this->dbdir}/top-1m.csv.zip";
		$active = "{$this->dbdir}/top-1m.csv";
		$whitelist = "{$this->dbdir}/pfbalexawhitelist.txt";
		$marker = "{$this->dbdir}/top-1m.update";
		$oldActive = "1,old.example\n";
		$oldWhitelist = "old-derived\n";
		$this->assertNotFalse(file_put_contents($active, $oldActive));
		$this->assertNotFalse(file_put_contents($whitelist, $oldWhitelist));
		$this->assertNotFalse(file_put_contents($marker, 'pending-combined-change'));

		$attempts = 0;
		$this->assertTrue(pfb_top1m_fetch_if_needed(
			$this->dbdir,
			static function () use (&$attempts): bool {
				$attempts++;
				return FALSE;
			}
		), 'missing identity baseline must attempt the replacement provider fetch');
		$this->assertSame(1, $attempts);
		$this->assertFalse(
			pfb_top1m_reprocess_needed($this->dbdir),
			'provider identity failure must defer a simultaneous count/TLD reprocess'
		);
		$this->assertSame($oldActive, file_get_contents($active));
		$this->assertSame($oldWhitelist, file_get_contents($whitelist));
		$this->assertSame('pending-combined-change', file_get_contents($marker),
			'deferred reprocess marker must survive for recovery');

		$raw = "{$this->dbdir}/replacement.raw";
		$this->assertTrue(pfb_top1m_fetch_if_needed(
			$this->dbdir,
			static function () use (&$attempts, $active, $base, $raw): bool {
				$attempts++;
				if (file_put_contents($active, "1,new.example\n") === FALSE ||
				    file_put_contents($raw, "replacement raw\n") === FALSE) {
					return FALSE;
				}
				return pfb_top1m_persist_baseline($base, $raw);
			}
		));
		$this->assertSame(2, $attempts);
		$this->assertTrue(pfb_top1m_reprocess_needed($this->dbdir),
			'successful replacement must release the deferred rebuild exactly once');
		$this->assertSame('pending-combined-change', file_get_contents($marker));
	}

	public function testApplyReprocessesOnlyWhenIdentityGateIsReady(): void
	{
		$attempts = 0;
		$this->assertFalse(pfb_top1m_apply_reprocess_if_ready($this->dbdir, static function () use (&$attempts): void {
			$attempts++;
		}), 'missing active identity must not convert');
		$this->assertSame(0, $attempts);

		file_put_contents("{$this->dbdir}/top-1m.csv", "live\n");
		file_put_contents("{$this->dbdir}/top-1m.csv.zip.orig", "raw\n");
		file_put_contents("{$this->dbdir}/top-1m.update", 'pending');
		$this->assertTrue(pfb_top1m_apply_reprocess_if_ready($this->dbdir, static function () use (&$attempts): void {
			$attempts++;
		}), 'current identity plus update marker must convert');
		$this->assertSame(1, $attempts);
	}

	public function testPublishResultLogsOnlyTheTruthfulOutcome(): void
	{
		$messages = [];
		$logger = static function (string $message, int $level) use (&$messages): void {
			$messages[] = [$message, $level];
		};
		$hadFailure = array_key_exists('dnsbl_publish_failed', $GLOBALS['pfb']);
		$previousFailure = $GLOBALS['pfb']['dnsbl_publish_failed'] ?? NULL;
		try {
			unset($GLOBALS['pfb']['dnsbl_publish_failed']);
			$this->assertFalse(pfb_dnsbl_publish_result(FALSE, $logger));
			$this->assertTrue($GLOBALS['pfb']['dnsbl_publish_failed']);
			$this->assertSame([["... FAILED (publication error)", 2]], $messages);

			unset($GLOBALS['pfb']['dnsbl_publish_failed']);
			$messages = [];
			$this->assertTrue(pfb_dnsbl_publish_result(TRUE, $logger));
			$this->assertArrayNotHasKey('dnsbl_publish_failed', $GLOBALS['pfb']);
			$this->assertSame([["... completed", 1]], $messages);
		} finally {
			if ($hadFailure) {
				$GLOBALS['pfb']['dnsbl_publish_failed'] = $previousFailure;
			} else {
				unset($GLOBALS['pfb']['dnsbl_publish_failed']);
			}
		}
	}

	public function testPublishFailureSuppressesReloadAndPostHookChangeSignal(): void
	{
		$this->assertFalse(pfb_dnsbl_reload_needed(TRUE, TRUE, TRUE, TRUE, TRUE, TRUE));
		$this->assertFalse(pfb_dnsbl_reload_needed(FALSE, FALSE, FALSE, FALSE, FALSE, FALSE));
		foreach (range(0, 4) as $enabledIndex) {
			$flags = array_fill(0, 5, FALSE);
			$flags[$enabledIndex] = TRUE;
			$this->assertTrue(pfb_dnsbl_reload_needed(FALSE, ...$flags));
		}
	}
}
