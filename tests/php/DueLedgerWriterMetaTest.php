<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * The due-ledger writer must author a document its own cache reader accepts.
 *
 * pfb_due_ledger_cache_valid() requires a `_meta` stamp carrying the schema and the
 * config-generation hash. pfb_due_ledger_write_entry()/pfb_due_ledger_update_entry()
 * are the other sanctioned authors of pfb_due_ledger.json, so a document they produce
 * from scratch has to satisfy that same gate -- otherwise the writer's own reader
 * returns NULL and the tick suppresses cron selection (issue #2598).
 *
 * The stamp is written only when the document does not already carry one: an existing
 * stamp identifies the generation the rows were computed for, and refreshing it would
 * make a stale cache look current.
 */
final class DueLedgerWriterMetaTest extends TestCase
{
	/** A row shape pfb_due_ledger_entry_valid() accepts. */
	private const ENTRY = ['last_run' => 100, 'next_due' => 200, 'jitter' => 0];

	/** A well-formed hash that is deliberately not this fixture's generation. */
	private const OTHER_GENERATION_HASH =
		'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

	private string $dir = '';
	private string $path = '';
	private mixed $originalConfig = NULL;
	private string $configHash = '';

	protected function setUp(): void
	{
		$this->originalConfig = $GLOBALS['config'] ?? NULL;
		$this->configureSchedule('3', '4', '15');

		$this->dir = sys_get_temp_dir() . '/pfb_due_writer_meta_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0755, TRUE);
		$this->path = $this->dir . '/pfb_due_ledger.json';
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = $this->originalConfig;
		foreach (glob($this->dir . '/*') ?: [] as $artifact) {
			@unlink($artifact);
		}
		@rmdir($this->dir);
	}

	/**
	 * Stand up a self-contained schedule configuration and record its generation hash.
	 *
	 * Written per test rather than inherited from whatever ran earlier in the process,
	 * so the generation this fixture asserts against is the one it set.
	 */
	private function configureSchedule(string $weekday, string $hour, string $minute): void
	{
		$GLOBALS['config'] = [];
		config_set_path('installedpackages/pfblockerng/config/0/pfb_scheduled_feed_updates', 'on');
		config_set_path('installedpackages/pfblockerng/config/0/pfb_schedule_weekday', $weekday);
		config_set_path('installedpackages/pfblockerng/config/0/pfb_schedule_hour', $hour);
		config_set_path('installedpackages/pfblockerng/config/0/pfb_schedule_minute', $minute);
		config_set_path('installedpackages/pfblockernglistsv4/config', []);
		config_set_path('installedpackages/pfblockernglistsv6/config', []);
		config_set_path('installedpackages/pfblockerngdnsbl/config', []);
		$model = pfb_schedule_runtime_config();
		$this->configHash = is_array($model) ? (string) $model['config_hash'] : '';
	}

	/** Decoded pfb_due_ledger.json, or NULL when nothing is on disk. */
	private function document(): ?array
	{
		if (!is_file($this->path)) {
			return NULL;
		}
		$decoded = json_decode((string) file_get_contents($this->path), TRUE);
		return is_array($decoded) ? $decoded : NULL;
	}

	private function report(string $what): string
	{
		return $what . '; document=' . var_export($this->document(), TRUE)
			. '; generation=' . $this->configHash;
	}

	/**
	 * Scenario: the ledger is authored from scratch by pfb_due_ledger_write_entry() alone.
	 *
	 * Given no pfb_due_ledger.json exists, so the cache reader has nothing to accept,
	 * When the writer publishes one row and nothing else touches the file,
	 * Then the cache reader accepts that document for the current generation.
	 */
	public function testFromScratchWriteEntryRoundTripsThroughTheCacheReader(): void
	{
		$this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/D', $this->configHash,
			'harness: the fixture must resolve a config generation to stamp against');
		$this->assertFileDoesNotExist($this->path, 'precondition: no prior author');
		$this->assertNull(pfb_due_ledger_read_cache($this->dir, $this->configHash),
			'precondition: an absent ledger must read back as no cache');

		$this->assertTrue(pfb_due_ledger_write_entry('cron', self::ENTRY, $this->dir),
			'the writer must report a successful publication');

		$cache = pfb_due_ledger_read_cache($this->dir, $this->configHash);
		$this->assertIsArray($cache, $this->report(
			'a ledger authored only through pfb_due_ledger_write_entry() must round-trip '
			. 'through pfb_due_ledger_read_cache(), expected an array, got NULL'
		));
		$this->assertSame(['schema' => 1, 'config_hash' => $this->configHash], $cache['_meta'] ?? NULL,
			$this->report('the writer must stamp the current generation, not a placeholder'));
		$this->assertSame(self::ENTRY, $cache['cron'] ?? NULL,
			$this->report('the published row must survive the stamp'));
	}

	/**
	 * Scenario: the ledger is authored from scratch through the read-modify-write entry point.
	 *
	 * pfb_due_ledger_update_entry() is called directly by callers that need the previous
	 * row (pfb_due_ledger_set_pending, the schedule-runtime harness), so the stamp cannot
	 * live in the pfb_due_ledger_write_entry() wrapper alone.
	 */
	public function testFromScratchUpdateEntryRoundTripsThroughTheCacheReader(): void
	{
		$this->assertNull(pfb_due_ledger_read_cache($this->dir, $this->configHash),
			'precondition: an absent ledger must read back as no cache');

		$this->assertTrue(pfb_due_ledger_update_entry(
			'ss_refresh',
			static fn (?array $current): array => $current ?? self::ENTRY,
			$this->dir
		), 'the read-modify-write entry point must report a successful publication');

		$cache = pfb_due_ledger_read_cache($this->dir, $this->configHash);
		$this->assertIsArray($cache, $this->report(
			'a ledger authored only through pfb_due_ledger_update_entry() must round-trip '
			. 'through pfb_due_ledger_read_cache(), expected an array, got NULL'
		));
		$this->assertSame(['schema' => 1, 'config_hash' => $this->configHash], $cache['_meta'] ?? NULL,
			$this->report('the read-modify-write entry point must stamp the current generation'));
		$this->assertSame(self::ENTRY, $cache['ss_refresh'] ?? NULL,
			$this->report('the published row must survive the stamp'));
	}

	/**
	 * Scenario: a ledger written before this contract existed gets a row appended.
	 *
	 * Given an unstamped document on disk -- what an upgraded appliance carries until the
	 * first schedule refresh, and what an older writer left behind,
	 * When the writer appends a row,
	 * Then the document the writer leaves behind is readable, not still rejected.
	 */
	public function testAnUnstampedDocumentOnDiskIsStampedByTheNextWrite(): void
	{
		file_put_contents($this->path, json_encode(['dcc' => self::ENTRY]));
		$this->assertTrue(pfb_due_ledger_document_valid($this->document()),
			'precondition: the unstamped document must be a valid legacy ledger');
		$this->assertNull(pfb_due_ledger_read_cache($this->dir, $this->configHash),
			'precondition: an unstamped document must not read back as a cache');

		$this->assertTrue(pfb_due_ledger_write_entry('cron', self::ENTRY, $this->dir),
			'appending to an unstamped document must still publish');

		$cache = pfb_due_ledger_read_cache($this->dir, $this->configHash);
		$this->assertIsArray($cache, $this->report(
			'a write into an unstamped document must leave it readable, expected an array, got NULL'
		));
		$this->assertSame(self::ENTRY, $cache['dcc'] ?? NULL,
			$this->report('the pre-existing row must be preserved'));
		$this->assertSame(self::ENTRY, $cache['cron'] ?? NULL,
			$this->report('the appended row must be present'));
	}

	/**
	 * Scenario: an unstamped document has one of its existing rows rewritten.
	 *
	 * The stamp belongs to the document, not to the row: overwriting a row that was
	 * already there has to leave the document readable just as adding a new one does.
	 */
	public function testRewritingAnExistingRowStampsAnUnstampedDocument(): void
	{
		file_put_contents($this->path, json_encode(['cron' => self::ENTRY]));
		$this->assertSame(self::ENTRY, pfb_due_ledger_read_entry('cron', $this->dir),
			'precondition: the row to be rewritten must already be on disk');
		$this->assertNull(pfb_due_ledger_read_cache($this->dir, $this->configHash),
			'precondition: an unstamped document must not read back as a cache');

		$replacement = ['last_run' => 300, 'next_due' => 400, 'jitter' => 0];
		$this->assertTrue(pfb_due_ledger_write_entry('cron', $replacement, $this->dir),
			'rewriting a row in an unstamped document must still publish');

		$cache = pfb_due_ledger_read_cache($this->dir, $this->configHash);
		$this->assertIsArray($cache, $this->report(
			'rewriting an existing row must leave the document readable, expected an array, got NULL'
		));
		$this->assertSame($replacement, $cache['cron'] ?? NULL,
			$this->report('the rewritten row must be the published one'));
	}

	/**
	 * Scenario: the writer touches a document stamped for a different generation.
	 *
	 * Given a document stamped for a generation that is not the current one -- the exact
	 * state the generation check exists to detect,
	 * When the writer publishes a row into it,
	 * Then the stamp is left as it was, so the stale cache is still rejected for the
	 * current generation instead of being adopted by it.
	 */
	public function testAStampFromAnotherGenerationIsPreservedNotRefreshed(): void
	{
		$this->assertNotSame(self::OTHER_GENERATION_HASH, $this->configHash,
			'harness: the fixture stamp must differ from the current generation');
		$this->assertTrue(pfb_due_ledger_write_cache(
			['dcc' => self::ENTRY],
			self::OTHER_GENERATION_HASH,
			$this->dir
		), 'precondition: the stale-generation document must publish');
		$this->assertIsArray(pfb_due_ledger_read_cache($this->dir, self::OTHER_GENERATION_HASH),
			'precondition: it must read back under its own generation');

		$this->assertTrue(pfb_due_ledger_write_entry('cron', self::ENTRY, $this->dir),
			'the writer must publish into a stamped document');

		$this->assertSame(
			['schema' => 1, 'config_hash' => self::OTHER_GENERATION_HASH],
			$this->document()['_meta'] ?? NULL,
			$this->report('an existing stamp must be preserved verbatim')
		);
		$this->assertNull(pfb_due_ledger_read_cache($this->dir, $this->configHash),
			$this->report('a stale document must not be adopted by the current generation'));
		$this->assertIsArray(pfb_due_ledger_read_cache($this->dir, self::OTHER_GENERATION_HASH),
			$this->report('the stale document must still read back under its own generation'));
	}

	/**
	 * Scenario: the schedule configuration cannot be built, so there is no generation to stamp.
	 *
	 * The writer is on the tick's failure path (pfb_due_ledger_set_pending after a failed
	 * apply), so an unresolvable generation must not cost the caller its row. The document
	 * stays unstamped -- and unreadable as a cache -- which is what the schedule refresh
	 * repairs; nothing reads the cache in this state anyway, because the tick needs the
	 * same model to produce the hash it would read with.
	 */
	public function testAnUnresolvableGenerationStillPublishesTheRow(): void
	{
		$this->configureSchedule('3', '99', '15');
		$this->assertNull(pfb_schedule_runtime_config(),
			'precondition: the fixture must make the runtime model unbuildable');

		$this->assertTrue(pfb_due_ledger_write_entry('cron', self::ENTRY, $this->dir),
			'an unresolvable generation must not cost the caller its row');

		$this->assertSame(self::ENTRY, pfb_due_ledger_read_entry('cron', $this->dir),
			$this->report('the row must be readable through the per-entry reader'));
		$this->assertArrayNotHasKey('_meta', (array) $this->document(),
			$this->report('no generation is known, so nothing may be stamped'));
	}
}
