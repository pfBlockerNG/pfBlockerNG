<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/PfbNoPhpWarningTrait.php';

/**
 * pfb_open_sqlite() -- both connection attempts throwing (issue #1494 defect 3;
 * #1497 red-proof). A database path nested under a directory that never exists
 * makes BOTH `new SQLite3($database)` attempts (primary ~14903, retry ~14910)
 * throw -- SQLite's default open flags (SQLITE3_OPEN_READWRITE |
 * SQLITE3_OPEN_CREATE) cannot create the file when its parent directory is
 * absent. Pre-fix, $db_handle was never assigned on this path, so
 * `if ($db_handle)` (~14918) read an undefined variable (PHP E_WARNING) before
 * falling through to `return FALSE;`. Fix: `$db_handle = NULL;` before the
 * first try -- same FALSE return, no warning.
 */
#[CoversFunction('pfb_open_sqlite')]
final class PfbOpenSqliteFailureTest extends TestCase
{
	use PfbNoPhpWarningTrait;

	private string $tmp;
	private array $savedPfb = [];

	protected function setUp(): void
	{
		$this->savedPfb = $GLOBALS['pfb'] ?? [];

		$this->tmp = sys_get_temp_dir() . '/pfb_open_sqlite_qa_' . uniqid('', true);
		mkdir($this->tmp, 0777, true);

		$GLOBALS['pfb'] = [
			// Nested under a directory that is never created -- both the primary
			// and retry `new SQLite3()` attempts fail with SQLITE_CANTOPEN.
			'dnsbl_info'     => "{$this->tmp}/missing/nested/dnsbl.sqlite3",
			'sqlite_timeout' => 2000,
			'errlog'         => "{$this->tmp}/error.log",
		];
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb'] = $this->savedPfb;
		@unlink("{$this->tmp}/error.log");
		@rmdir($this->tmp);
	}

	public function testBothConnectionAttemptsThrowingReturnsFalseWithoutWarning(): void
	{
		$result = $this->assertNoPhpWarning(function () {
			return pfb_open_sqlite(1, 'Test double connection failure');
		});

		$this->assertFalse($result, 'expected pfb_open_sqlite() to return FALSE when both connection attempts throw');
	}
}
