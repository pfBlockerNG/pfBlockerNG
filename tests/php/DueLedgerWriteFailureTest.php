<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** issue #2122: atomic due-ledger publication fails closed without PHP warnings. */
final class DueLedgerWriteFailureTest extends TestCase
{
	private string $dbdir = '';

	protected function setUp(): void
	{
		$this->dbdir = sys_get_temp_dir() . '/pfb_due_write_failure_' . uniqid('', TRUE);
		mkdir($this->dbdir, 0755, TRUE);
	}

	protected function tearDown(): void
	{
		foreach (glob("{$this->dbdir}/*") ?: [] as $path) {
			@unlink($path);
		}
		@rmdir($this->dbdir);
	}

	private function ledger(): array
	{
		return ['cron' => ['last_run' => 1, 'next_due' => 2, 'jitter' => 0]];
	}

	public function testWriteFailureReturnsFalseAndRemovesUniqueTemporaryFile(): void
	{
		$this->assertTrue(function_exists('pfb_due_ledger_write_all'));
		$tmp = "{$this->dbdir}/.pfb_due_ledger.test-write";
		file_put_contents($tmp, 'partial');

		$result = pfb_due_ledger_write_all(
			$this->ledger(),
			$this->dbdir,
			static fn(string $dir, string $prefix): string => $tmp,
			static fn(string $path, string $json): bool => FALSE,
			static fn(string $from, string $to): bool => TRUE
		);

		$this->assertFalse($result);
		$this->assertFileDoesNotExist($tmp);
		$this->assertFileDoesNotExist("{$this->dbdir}/pfb_due_ledger.json");
	}

	public function testRenameFailureReturnsFalseAndRemovesUniqueTemporaryFile(): void
	{
		$this->assertTrue(function_exists('pfb_due_ledger_write_all'));
		$tmp = "{$this->dbdir}/.pfb_due_ledger.test-rename";

		$result = pfb_due_ledger_write_all(
			$this->ledger(),
			$this->dbdir,
			static fn(string $dir, string $prefix): string => $tmp,
			static fn(string $path, string $json): int => file_put_contents($path, $json),
			static fn(string $from, string $to): bool => FALSE
		);

		$this->assertFalse($result);
		$this->assertFileDoesNotExist($tmp);
		$this->assertFileDoesNotExist("{$this->dbdir}/pfb_due_ledger.json");
	}
}
