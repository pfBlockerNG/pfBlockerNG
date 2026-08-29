<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-65 — pfb_dnsbl_manifest_failure_notice(): surfaces a still-open DNSBL
 * manifest parse-stage ledger entry (Python's pfb_py_status.json) as a GUI
 * file_notice, mirroring the MaxMind/VIP credential-notice pattern (issue #331).
 * Read-only -- never writes the ledger.
 *
 * Hostile-input coverage (CLAUDE.md "Hostile-input rows"): absent ledger file,
 * corrupt JSON, an open entry for a DIFFERENT item, an open entry with the
 * wrong stage, an empty message, a message carrying HTML/quotes/shell
 * metacharacters/newlines and an oversized (10 KB) message, and an
 * absolute-path item (basename-only match).
 */
#[CoversFunction('pfb_dnsbl_manifest_failure_notice')]
final class DnsblManifestFailureNoticeTest extends TestCase
{
	private string $tmp;
	private bool $hadPfb = false;
	private array $originalPfb = [];

	protected function setUp(): void
	{
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		$GLOBALS['pfb_test_file_notices'] = [];

		$this->tmp = sys_get_temp_dir() . '/pfb_manifest_failure_notice_' . uniqid('', true);
		mkdir($this->tmp, 0777, true);

		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'log'                => "{$this->tmp}/pfblockerng.log",
			'errlog'             => "{$this->tmp}/error.log",
			'dnsbldir'           => $this->tmp,
			'unbound_py_sources' => '/var/unbound/pfb_py_sources.json',
		]);
	}

	protected function tearDown(): void
	{
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		unset($GLOBALS['pfb_test_file_notices']);

		rmdir_recursive($this->tmp);
	}

	private function writeLedger(array $entries): void
	{
		file_put_contents("{$this->tmp}/pfb_py_status.json", json_encode($entries));
	}

	public function testOpenManifestParseEntryFiresExactlyOneNotice(): void
	{
		$this->writeLedger([
			['facility' => 'dnsbl', 'item' => 'pfb_py_sources.json', 'stage' => 'parse',
				'message' => 'DNSBL manifest absent', 'first_seen' => 1, 'last_seen' => 2],
		]);

		$fired = pfb_dnsbl_manifest_failure_notice();

		$this->assertTrue($fired);
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices']);
		$this->assertSame('pfBlockerNG DNSBL', $GLOBALS['pfb_test_file_notices'][0]['id']);
		$this->assertStringContainsString('DNSBL manifest absent', $GLOBALS['pfb_test_file_notices'][0]['notice']);
	}

	public function testAbsentLedgerFileFiresNoNotice(): void
	{
		$fired = pfb_dnsbl_manifest_failure_notice();

		$this->assertFalse($fired);
		$this->assertSame([], $GLOBALS['pfb_test_file_notices']);
	}

	public function testCorruptJsonLedgerFiresNoNotice(): void
	{
		file_put_contents("{$this->tmp}/pfb_py_status.json", '{ not json');

		$fired = pfb_dnsbl_manifest_failure_notice();

		$this->assertFalse($fired);
		$this->assertSame([], $GLOBALS['pfb_test_file_notices']);
	}

	public function testOpenEntryForADifferentItemFiresNoNotice(): void
	{
		$this->writeLedger([
			['facility' => 'dnsbl', 'item' => 'pfb_unbound.ini', 'stage' => 'parse',
				'message' => 'boom', 'first_seen' => 1, 'last_seen' => 2],
		]);

		$fired = pfb_dnsbl_manifest_failure_notice();

		$this->assertFalse($fired);
		$this->assertSame([], $GLOBALS['pfb_test_file_notices']);
	}

	public function testManifestItemWithWrongStageFiresNoNotice(): void
	{
		$this->writeLedger([
			['facility' => 'dnsbl', 'item' => 'pfb_py_sources.json', 'stage' => 'apply',
				'message' => 'boom', 'first_seen' => 1, 'last_seen' => 2],
		]);

		$fired = pfb_dnsbl_manifest_failure_notice();

		$this->assertFalse($fired);
		$this->assertSame([], $GLOBALS['pfb_test_file_notices']);
	}

	public function testEmptyMessageStillFiresANoticeWithoutWarning(): void
	{
		$this->writeLedger([
			['facility' => 'dnsbl', 'item' => 'pfb_py_sources.json', 'stage' => 'parse',
				'message' => '', 'first_seen' => 1, 'last_seen' => 2],
		]);

		$fired = pfb_dnsbl_manifest_failure_notice();

		$this->assertTrue($fired);
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices']);
	}

	public function testHostileMessageContentPassesThroughUnharmed(): void
	{
		$hostile = "<b>x</b> \"quoted\" \$(rm -rf /) \n" . str_repeat('A', 10_000);
		$this->writeLedger([
			['facility' => 'dnsbl', 'item' => 'pfb_py_sources.json', 'stage' => 'parse',
				'message' => $hostile, 'first_seen' => 1, 'last_seen' => 2],
		]);

		$fired = pfb_dnsbl_manifest_failure_notice();

		$this->assertTrue($fired);
		$this->assertStringContainsString($hostile, $GLOBALS['pfb_test_file_notices'][0]['notice']);
	}

	public function testAbsolutePathItemMatchesOnBasename(): void
	{
		$this->writeLedger([
			// A DIFFERENT directory than the configured unbound_py_sources: only a
			// basename comparison (not exact-string) can match this item.
			['facility' => 'dnsbl', 'item' => '/some/other/dir/pfb_py_sources.json', 'stage' => 'parse',
				'message' => 'boom', 'first_seen' => 1, 'last_seen' => 2],
		]);

		$fired = pfb_dnsbl_manifest_failure_notice();

		$this->assertTrue($fired);
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices']);
	}
}
