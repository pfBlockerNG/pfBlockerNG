<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** issue #2122: scheduled timeout state follows the due-ledger persistence boundary. */
final class TickLockCounterPersistenceTest extends TestCase
{
	public function testRamdiskArchiveIncludesTimeoutCounterWhenPresent(): void
	{
		$source = php_strip_whitespace(
			dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc'
		);
		$this->assertNotFalse($source);
		$start = strpos($source, 'function pfb_aliastables(');
		$end = strpos($source, 'function pfb_dnsbl_cache(', $start);
		$this->assertNotFalse($start);
		$this->assertNotFalse($end);
		$body = substr($source, $start, $end - $start);

		$this->assertStringContainsString('$pfb[\'dbdir\']}/pfb_tick_lock_timeouts', $body,
			'the consecutive-timeout counter must survive the same RAM-disk restore as the due ledger');
	}

	public function testKeepOffUninstallWipesCounterWithDatabaseDirectory(): void
	{
		$source = php_strip_whitespace(
			dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc'
		);
		$this->assertNotFalse($source);
		$this->assertStringContainsString('rmdir_recursive("{$pfb[\'dbdir\']}")', $source,
			'keep-off uninstall must wipe all persistent scheduler state under dbdir');
	}
}
