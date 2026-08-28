<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfb_sqlite_table_spec() — maps a numeric SQLite3 handle index (1-7) to its
 * table name + CREATE statement, extracted out of pfb_open_sqlite()'s
 * if/elseif chain so the mapping is unit-testable in isolation.
 *
 * Issue #713 bug 10: table 6 mapped to db_table 'stats' while its CREATE
 * TABLE statement actually built 'lastclear' -- the name every other query
 * in pfblockerng.inc uses (e.g. `UPDATE lastclear SET lastipclear = ...`).
 * db_table is what DB-corruption recovery DROPs and re-creates, so the
 * mismatch pointed recovery at a table ('stats') that was never the real
 * one. testTableSixMapsToLastclearNotStats is the regression pin: it fails
 * on the pre-fix mapping ('stats') and passes once table 6 reads 'lastclear'.
 */
#[CoversFunction('pfb_sqlite_table_spec')]
final class SqliteTableSpecTest extends TestCase
{
	public function testTableSixMapsToLastclearNotStats(): void
	{
		$spec = pfb_sqlite_table_spec(6);

		// The pre-fix code returned 'stats' here, disagreeing with every other
		// `lastclear`-named query in the file (see pfb_reset_last_clear_dates()
		// and its `UPDATE lastclear SET ...` statements).
		$this->assertSame('lastclear', $spec['db_table']);
	}

	public function testTableSixCreateStatementBuildsLastclear(): void
	{
		$spec = pfb_sqlite_table_spec(6);

		$this->assertStringContainsString('CREATE TABLE IF NOT EXISTS lastclear', $spec['db_create']);
	}

	public static function tableIndexProvider(): array
	{
		return [
			'1 dnsbl'        => [1, 'dnsbl'],
			'2 lastevent'    => [2, 'lastevent'],
			'3 resolver'     => [3, 'resolver'],
			'5 asncache'     => [5, 'asncache'],
			'6 lastclear'    => [6, 'lastclear'],
			'7 ipcache'      => [7, 'ipcache'],
		];
	}

	public function testTableFourIsAReservedEmptySlot(): void
	{
		$spec = pfb_sqlite_table_spec(4);

		$this->assertSame('', $spec['db_table']);
		$this->assertSame('', $spec['db_create']);
	}

	#[DataProvider('tableIndexProvider')]
	public function testKnownIndexMapsToExpectedTableName(int $table, string $expectedDbTable): void
	{
		$spec = pfb_sqlite_table_spec($table);

		$this->assertSame($expectedDbTable, $spec['db_table']);
		$this->assertStringContainsString("CREATE TABLE IF NOT EXISTS {$expectedDbTable}", $spec['db_create']);
	}

	public function testUnknownIndexReturnsEmptyBehaviourPreservingDefault(): void
	{
		// Callers only ever pass 1-7; an out-of-range value falls back to the
		// same empty-string default the original if/elseif chain (no `else`)
		// left $db_table/$db_create as.
		$spec = pfb_sqlite_table_spec(99);

		$this->assertSame('', $spec['db_table']);
		$this->assertSame('', $spec['db_create']);
		$this->assertNull(pfb_open_sqlite(99, 'unknown table'));
	}
}
