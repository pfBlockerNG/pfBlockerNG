<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * pfb_open_sqlite()'s DB-corruption recovery path -- exercised against a
 * REAL SQLite3 database (issue #713 bug 10).
 *
 * On a failed `PRAGMA integrity_check`, pfb_open_sqlite() builds:
 *
 *   "DROP TABLE IF EXISTS {$db_table}; {$db_create}"
 *
 * wrapped in `BEGIN TRANSACTION; ... END TRANSACTION;` and runs it via
 * SQLite3::exec(). Two defects combined to break recovery for table 6:
 *
 *   1. $db_table was 'stats' while $db_create actually built 'lastclear'
 *      (pinned separately in SqliteTableSpecTest).
 *   2. The DROP had no `IF EXISTS`, so dropping a table that does not exist
 *      -- including a freshly-created / never-populated database, or the
 *      wrong ('stats') name from defect 1 -- makes SQLite3::exec() fail and
 *      abort the whole transaction, so the CREATE TABLE never runs and the
 *      table is never rebuilt.
 *
 * These tests build the exact recovery SQL pfb_open_sqlite() constructs
 * (using the real pfb_sqlite_table_spec() mapping for the CREATE half) and
 * run it against a real, empty SQLite3 database -- proving both the fixed
 * statement succeeds and the pre-fix statement(s) fail.
 */
final class SqliteCorruptRecoveryTest extends TestCase
{
	private function recoverySql(string $dropClause, string $dbCreate): string
	{
		// Mirrors pfb_open_sqlite(): $db_create = "DROP TABLE ...; {$db_create}";
		// then exec("BEGIN TRANSACTION;" . $db_create . "END TRANSACTION;").
		return 'BEGIN TRANSACTION;' . $dropClause . '; ' . $dbCreate . 'END TRANSACTION;';
	}

	private function lastclearTableExists(SQLite3 $db): bool
	{
		$count = @$db->querySingle("SELECT COUNT(*) FROM lastclear");
		return $count !== FALSE;
	}

	public function testFixedRecoveryDropIfExistsRebuildsAbsentTable(): void
	{
		$spec = pfb_sqlite_table_spec(6);
		$db   = new SQLite3(':memory:');

		// Given: a brand-new database -- 'lastclear' has never existed.
		$this->assertFalse($this->lastclearTableExists($db), 'expected lastclear to be absent before recovery');

		// When: the CURRENT (fixed) recovery statement runs.
		$sql    = $this->recoverySql("DROP TABLE IF EXISTS {$spec['db_table']}", $spec['db_create']);
		$result = @$db->exec($sql);

		// Then: it succeeds (no "no such table" abort) and the table is queryable.
		$this->assertTrue(
			$result,
			"expected DROP TABLE IF EXISTS recovery to succeed on an absent table, got: {$db->lastErrorMsg()}"
		);
		$this->assertTrue($this->lastclearTableExists($db), 'expected lastclear to exist after recovery');
	}

	public function testOldBareDropTableAbortsRecoveryEvenWithCorrectName(): void
	{
		// Isolates defect 2 alone: even with the CORRECT db_table ('lastclear'),
		// a bare DROP TABLE (no IF EXISTS) on an absent table aborts the batch.
		$spec = pfb_sqlite_table_spec(6);
		$db   = new SQLite3(':memory:');

		$this->assertFalse($this->lastclearTableExists($db), 'expected lastclear to be absent before recovery');

		$sql    = $this->recoverySql("DROP TABLE {$spec['db_table']}", $spec['db_create']);
		$result = @$db->exec($sql);

		$this->assertFalse(
			$result,
			'expected the pre-fix bare DROP TABLE (no IF EXISTS) to fail on an absent table'
		);
		$this->assertStringContainsString('no such table', $db->lastErrorMsg());
		$this->assertFalse($this->lastclearTableExists($db), 'lastclear must NOT have been (re)created -- recovery aborted');
	}

	public function testOldBuggyStatsMappingAlsoAbortsRecovery(): void
	{
		// Reproduces the full original bug 10 combination: the pre-fix db_table
		// ('stats', which never has a matching table) plus the bare DROP.
		$db_create = "CREATE TABLE IF NOT EXISTS lastclear ( row INTEGER, lastipclear TEXT, lastdnsblclear TEXT );";
		$db        = new SQLite3(':memory:');

		$sql    = $this->recoverySql('DROP TABLE stats', $db_create);
		$result = @$db->exec($sql);

		$this->assertFalse(
			$result,
			'expected the pre-fix "DROP TABLE stats" (wrong name, no IF EXISTS) to abort recovery'
		);
		$this->assertStringContainsString('no such table', $db->lastErrorMsg());
		$this->assertFalse($this->lastclearTableExists($db), 'lastclear must NOT have been rebuilt -- this is the reported bug');
	}
}
