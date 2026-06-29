<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Oracle tests for pfb_validate_archive() — ADR-45 Phase 1.
 *
 * pfb_validate_archive() runs the integrity probe returned by pfb_archive_probe()
 * via an injectable runner so the decision logic is unit-tested entirely off-appliance
 * with no shell execution. The runner contract is: callable(array $argv): int, where
 * exit 0 means the archive is valid.
 *
 * All tests inject a custom $runner — never shells out. The default runner (shell exec)
 * is covered by the live-VM smoke (ADR-04 Phase 4).
 */
#[CoversFunction('pfb_validate_archive')]
final class ArchiveValidateTest extends TestCase
{
	public function test_non_archive_type_returns_true_without_calling_runner(): void
	{
		// pfb_archive_probe('text/plain') returns NULL → pfb_validate_archive() must
		// short-circuit to TRUE without ever invoking the runner. This pins the
		// non-archive branch: no structural probe is run for plain-text feeds.
		// The runner is a sentinel that would return 1 (fail) if called — a call
		// proves the short-circuit is absent, flipping the assertion to false.
		$runnerCalled = FALSE;
		$runner = function (array $argv) use (&$runnerCalled): int {
			$runnerCalled = TRUE;
			return 1;
		};

		$result = pfb_validate_archive('/tmp/feed.txt', 'text/plain', $runner);

		$this->assertTrue($result, 'Non-archive type must return TRUE regardless of what runner would return');
		$this->assertFalse($runnerCalled, 'Runner must NOT be called for a non-archive type (NULL probe short-circuit)');
	}

	public function test_archive_type_runner_exit_0_returns_true(): void
	{
		// A gzip feed whose probe exits 0 is structurally valid → TRUE.
		// Pins the "archive probe passed" branch.
		$runner = fn(array $argv): int => 0;

		$result = pfb_validate_archive('/var/db/pfblockerng/feed.gz', 'application/gzip', $runner);

		$this->assertTrue($result, 'Archive probe exit 0 must return TRUE (archive is valid)');
	}

	public function test_archive_type_runner_exit_1_returns_false(): void
	{
		// A bzip2 feed whose probe exits 1 is corrupt/truncated → FALSE.
		// Pins the "archive probe failed, non-zero exit" branch.
		$runner = fn(array $argv): int => 1;

		$result = pfb_validate_archive('/var/db/pfblockerng/feed.bz2', 'application/x-bzip2', $runner);

		$this->assertFalse($result, 'Archive probe exit 1 must return FALSE (archive is corrupt/invalid)');
	}

	public function test_archive_type_runner_exit_2_returns_false(): void
	{
		// Any non-zero exit code signals failure, not just exit 1.
		// Pins that the check is "=== 0", not "=== 1".
		$runner = fn(array $argv): int => 2;

		$result = pfb_validate_archive('/var/db/pfblockerng/feed.zip', 'application/zip', $runner);

		$this->assertFalse($result, 'Archive probe exit 2 (or any non-zero) must return FALSE');
	}

	public function test_file_is_appended_as_last_argv_element(): void
	{
		// pfb_validate_archive() must append $file as the last element of the argv
		// array returned by pfb_archive_probe(). This pins the file-append contract
		// that Phases 2 and 3 depend on — the runner receives the complete command
		// argv with the file path at position 2 (index 2 for binary+flag+file).
		$capturedArgv = NULL;
		$runner = function (array $argv) use (&$capturedArgv): int {
			$capturedArgv = $argv;
			return 0;
		};

		$file = '/var/db/pfblockerng/GeoLite2-Country-CSV.zip';
		pfb_validate_archive($file, 'application/zip', $runner);

		$this->assertNotNull($capturedArgv, 'Runner must have been called');
		$this->assertSame('/usr/bin/tar', $capturedArgv[0], 'argv[0] must be the probe binary');
		$this->assertSame('-tf',          $capturedArgv[1], 'argv[1] must be the probe flags');
		$this->assertSame($file,          $capturedArgv[2], 'argv[2] must be the $file path (last element)');
		$this->assertCount(3, $capturedArgv, 'argv must have exactly 3 elements: binary, flags, file');
	}

	public function test_file_append_contract_for_gzip(): void
	{
		// Covers the gzip probe shape: /usr/bin/gunzip -t <file>.
		// Ensures the file-append contract holds for a different probe type.
		$capturedArgv = NULL;
		$runner = function (array $argv) use (&$capturedArgv): int {
			$capturedArgv = $argv;
			return 0;
		};

		$file = '/var/db/pfblockerng/nixspam.gz';
		pfb_validate_archive($file, 'application/gzip', $runner);

		$this->assertSame('/usr/bin/gunzip', $capturedArgv[0]);
		$this->assertSame('-t',              $capturedArgv[1]);
		$this->assertSame($file,             $capturedArgv[2]);
	}
}
