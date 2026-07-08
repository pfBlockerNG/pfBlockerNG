<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-61 Phase 4 — read-only PHP reader for Python's OWN status ledger
 * (pfb_py_status.json). PHP NEVER writes this file -- pfb_unbound.py owns it
 * exclusively (the two-file boundary, ADR §2.3). This reader degrades every
 * hostile input to "no open Python-side entries", never a warning/exception,
 * so a merge with the PHP-owned ledger (pfb_sync_status_list_open()) is safe
 * regardless of the Python module's version/health.
 *
 * Function under test:
 *   pfb_py_sync_status_list_open(string $status_dir): array
 *
 * Hostile-input coverage mandate (CLAUDE.md "Hostile-input rows"):
 *   absent file, empty file, truncated/corrupt JSON, wrong top-level JSON
 *   type (object, scalar), well-formed-but-wrong-shape JSON (missing keys) --
 *   every case asserts the ACTUAL returned value ([]), not merely "no throw".
 */
#[CoversFunction('pfb_py_sync_status_list_open')]
final class PfbPySyncStatusReaderTest extends TestCase
{
	private string $dir;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_py_status_test_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);
	}

	protected function tearDown(): void
	{
		foreach (glob($this->dir . '/*') ?: [] as $file) {
			@unlink($file);
		}
		@rmdir($this->dir);
	}

	private function writeStatusFile(string $contents): void
	{
		file_put_contents($this->dir . '/pfb_py_status.json', $contents);
	}

	// -----------------------------------------------------------------------
	// Happy path -- the shape Python actually writes.
	// -----------------------------------------------------------------------

	public function testWellFormedEntriesAreReturnedInTheSameShapeAsThePhpLedger(): void
	{
		$this->writeStatusFile(json_encode([
			[
				'facility'   => 'dnsbl',
				'item'       => 'pfb_py_zone.txt',
				'stage'      => 'parse',
				'message'    => 'Failed to load: pfb_py_zone.txt: boom',
				'first_seen' => 1000,
				'last_seen'  => 2000,
			],
		]));

		$open = pfb_py_sync_status_list_open($this->dir);

		$this->assertCount(1, $open);
		$this->assertSame('dnsbl', $open[0]['facility']);
		$this->assertSame('pfb_py_zone.txt', $open[0]['item']);
		$this->assertSame('parse', $open[0]['stage']);
		$this->assertSame('Failed to load: pfb_py_zone.txt: boom', $open[0]['message']);
		$this->assertSame(1000, $open[0]['first_seen']);
		$this->assertSame(2000, $open[0]['last_seen']);
	}

	public function testMultipleEntriesAreAllReturned(): void
	{
		$this->writeStatusFile(json_encode([
			['facility' => 'dnsbl', 'item' => 'pfb_py_zone.txt', 'stage' => 'parse', 'message' => 'a', 'first_seen' => 1, 'last_seen' => 1],
			['facility' => 'dnsbl', 'item' => 'pfb_py_data.txt', 'stage' => 'parse', 'message' => 'b', 'first_seen' => 2, 'last_seen' => 2],
		]));

		$this->assertCount(2, pfb_py_sync_status_list_open($this->dir));
	}

	// -----------------------------------------------------------------------
	// Hostile input -- every case degrades to [], never a warning/exception.
	// -----------------------------------------------------------------------

	public function testAbsentFileReadsAsEmpty(): void
	{
		$this->assertSame([], pfb_py_sync_status_list_open($this->dir));
	}

	public function testEmptyFileReadsAsEmpty(): void
	{
		$this->writeStatusFile('');

		$this->assertSame([], pfb_py_sync_status_list_open($this->dir));
	}

	public function testTruncatedCorruptJsonReadsAsEmpty(): void
	{
		$this->writeStatusFile('[{"facility": "dnsbl", "item": "x", "stage": "parse"');	// truncated mid-object

		$this->assertSame([], pfb_py_sync_status_list_open($this->dir));
	}

	public function testWrongTopLevelTypeObjectReadsAsEmpty(): void
	{
		// A JSON OBJECT (associative array in PHP) is not the list-of-entries
		// shape Python writes -- array_is_list() must reject it.
		$this->writeStatusFile(json_encode(['facility' => 'dnsbl', 'item' => 'x', 'stage' => 'parse']));

		$this->assertSame([], pfb_py_sync_status_list_open($this->dir));
	}

	public function testWrongTopLevelTypeScalarReadsAsEmpty(): void
	{
		$this->writeStatusFile(json_encode('just a string'));

		$this->assertSame([], pfb_py_sync_status_list_open($this->dir));
	}

	public function testWellFormedButWrongShapeEntriesAreSkipped(): void
	{
		// A JSON array (top-level shape correct), but its entries are scalars /
		// missing the required keys -- every entry must be dropped, never crash.
		$this->writeStatusFile(json_encode([
			'not-an-object',
			['message' => 'no facility/item/stage keys at all'],
			42,
		]));

		$this->assertSame([], pfb_py_sync_status_list_open($this->dir));
	}

	public function testMalformedEntryAmongValidOnesIsSkippedNotFatal(): void
	{
		$this->writeStatusFile(json_encode([
			['facility' => 'dnsbl', 'item' => 'pfb_py_zone.txt', 'stage' => 'parse', 'message' => 'ok', 'first_seen' => 1, 'last_seen' => 1],
			['message' => 'missing facility/item/stage'],
		]));

		$open = pfb_py_sync_status_list_open($this->dir);

		$this->assertCount(1, $open, 'the malformed entry must be dropped, the valid one kept');
		$this->assertSame('pfb_py_zone.txt', $open[0]['item']);
	}

	public function testMissingOptionalFieldsDefaultSafely(): void
	{
		// message/first_seen/last_seen are OPTIONAL from the reader's point of view
		// (only facility/item/stage are load-bearing) -- absent ones default rather
		// than raising an undefined-index warning.
		$this->writeStatusFile(json_encode([
			['facility' => 'dnsbl', 'item' => 'pfb_py_zone.txt', 'stage' => 'parse'],
		]));

		$open = pfb_py_sync_status_list_open($this->dir);

		$this->assertCount(1, $open);
		$this->assertSame('', $open[0]['message']);
		$this->assertSame(0, $open[0]['first_seen']);
		$this->assertSame(0, $open[0]['last_seen']);
	}
}
