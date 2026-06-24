<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_dnsbl_artifacts_exist() — the pure decider that gates the empty-feeds clear branch.
 *
 * When DNSBL is enabled but no feeds are subscribed, the $dnsbl_missing check sets
 * reuse_dnsbl='on' and touches .reload (feed-blind: the py_data file doesn't exist, so it
 * declares "missing"). Without a gate, every subsequent pass restarts Unbound even though
 * there is nothing to clear.
 *
 * pfb_dnsbl_artifacts_exist() is called in the empty-feeds branch:
 *   - TRUE  => artifacts exist on disk (first pass after the last feed is removed): clear +
 *              restart once so Unbound stops serving stale DNSBL data.
 *   - FALSE => nothing subscribed AND nothing on disk (steady state): suppress the
 *              feed-blind reuse_dnsbl/.reload flags; the pass is a no-op.
 *
 * Per CLAUDE.md test-coverage rules: both branches are proven with a before-state assertion
 * (no files => FALSE) and an after-state assertion (one file created => TRUE), so the test
 * is evidence of a real branch, not always-true.
 */
#[CoversFunction('pfb_dnsbl_artifacts_exist')]
final class DnsblArtifactsExistTest extends TestCase
{
	private string $tmpDir;

	protected function setUp(): void
	{
		$this->tmpDir = sys_get_temp_dir() . '/pfb_artifact_test_' . getmypid();
		mkdir($this->tmpDir, 0700, TRUE);
	}

	protected function tearDown(): void
	{
		foreach (glob("{$this->tmpDir}/*") ?: [] as $f) {
			@unlink($f);
		}
		@rmdir($this->tmpDir);
	}

	/**
	 * Scenario: steady-state empty — no feeds subscribed and no artifacts on disk.
	 *
	 * Given:  an array of paths that do not exist on disk
	 * When:   pfb_dnsbl_artifacts_exist() is called
	 * Then:   it returns FALSE, suppressing the restart
	 */
	public function testReturnsFalseWhenNoArtifactExists(): void
	{
		$paths = [
			"{$this->tmpDir}/pfb_py.data",
			"{$this->tmpDir}/pfb_py.zone",
			"{$this->tmpDir}/pfb_py.wh",
		];

		// Before state: none of the paths exist (confirm they really don't).
		foreach ($paths as $p) {
			$this->assertFileDoesNotExist($p, "precondition: $p must not exist before the test");
		}

		$this->assertFalse(
			pfb_dnsbl_artifacts_exist($paths),
			'Expected FALSE (no artifacts on disk => steady-state no-op, no restart)'
		);
	}

	/**
	 * Scenario: first-removal pass — the last feed was just unsubscribed; py_data still exists.
	 *
	 * Given:  an array of paths where at least one file exists (a leftover artifact)
	 * When:   pfb_dnsbl_artifacts_exist() is called
	 * Then:   it returns TRUE, allowing the clear-and-restart once
	 *
	 * The before-state (FALSE with none present) is proven in testReturnsFalseWhenNoArtifactExists;
	 * here we assert that creating one file flips the result, proving it's a real branch.
	 */
	public function testReturnsTrueWhenAtLeastOneArtifactExists(): void
	{
		$dataFile = "{$this->tmpDir}/pfb_py.data";
		$paths    = [
			$dataFile,
			"{$this->tmpDir}/pfb_py.zone",
		];

		// Before state: no files yet => FALSE.
		$this->assertFalse(
			pfb_dnsbl_artifacts_exist($paths),
			'Before state: no artifacts => FALSE (confirms the flip below is caused by the file)'
		);

		// Create one artifact (simulates leftover DNSBL data after the last feed is removed).
		file_put_contents($dataFile, '');

		// After state: one file present => TRUE (triggers clear + restart once).
		$this->assertTrue(
			pfb_dnsbl_artifacts_exist($paths),
			'Expected TRUE (at least one artifact exists => first-removal pass, clear + restart once)'
		);
	}

	/**
	 * Scenario: empty-string paths are ignored (guard against blank $pfb[] entries).
	 *
	 * Given:  an array containing only empty strings
	 * When:   pfb_dnsbl_artifacts_exist() is called
	 * Then:   it returns FALSE (empty strings are not checked via file_exists)
	 */
	public function testIgnoresEmptyStringPaths(): void
	{
		$this->assertFalse(
			pfb_dnsbl_artifacts_exist(['', '', '']),
			'Empty-string paths must be skipped, not treated as a present file'
		);
	}
}
