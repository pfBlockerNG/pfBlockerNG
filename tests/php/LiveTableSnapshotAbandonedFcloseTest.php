<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #1852: a live CE 2.8 UI-render run hit
 * `TypeError: fclose(): Argument #1 ($stream) must be of type resource, null
 * given in pfblockerng_extra.inc:4182` -- pfb_live_table_snapshot()'s
 * `finally { fclose($handle); ... }`.
 *
 * Root cause: pfb_live_table_snapshot() is a \Generator. Its only production
 * consumer, pfb_live_punch_plan(), drains it with a plain foreach and no
 * break/return -- but a foreach that exits early via an UNCAUGHT exception
 * thrown from the loop BODY (e.g. a malformed table entry reaching
 * ip_in_subnet()/pfb_v4_carve_single()) abandons the generator mid-try
 * without a normal return. Per bugs.php.net #76006 ("PHP engine execute the
 * code after shutdown_function by finally block" -- WONTFIX/expected), a
 * generator that never finishes has its pending `finally` run only at the
 * LAST step of request shutdown, strictly AFTER every registered shutdown
 * function and after PHP's own resource-list teardown for the request. On
 * the PHP builds pfSense CE 2.8 ships (8.1.x/8.2.x -- both predate the
 * upstream fix for php-src GH-19844, "Don't bail when closing resources on
 * shutdown", landed only in 8.3.28/8.4.15/8.5.0), that ordering means the
 * scratch-file resource is already gone by the time this finally finally
 * runs, and the unguarded `fclose($handle)` throws.
 *
 * The dev sandbox only has PHP >= 8.3.28 (already carrying the GH-19844
 * fix), so the exact shutdown-ordering race cannot be coaxed out of gc
 * timing alone here (confirmed: unset()+gc_collect_cycles() on an abandoned
 * generator alone stays green on this interpreter). This test instead
 * forces the REAL precondition PHP's own request shutdown creates on the
 * affected builds -- the SAME underlying stream resource the still-suspended
 * generator holds gets closed by something else first -- via the standard,
 * version-independent get_resources()/stream_get_meta_data() introspection,
 * against the real, unmodified production function. That reliably reproduces
 * the same fclose() TypeError class from the same finally block (message
 * text differs by PHP-internal detail -- "must be an open stream resource"
 * here vs "null given" in the field report -- both are fclose() rejecting an
 * already-invalid $handle; both are fixed by the same is_resource() guard).
 */
#[CoversFunction('pfb_live_table_snapshot')]
final class LiveTableSnapshotAbandonedFcloseTest extends TestCase
{
	private string $tmpDir;
	private string $aliasdir;
	private string $dbdir;

	protected function setUp(): void
	{
		$this->tmpDir   = sys_get_temp_dir() . '/pfb_live_table_snapshot_fclose_' . bin2hex(random_bytes(6));
		$this->aliasdir = "{$this->tmpDir}/alias";
		$this->dbdir    = "{$this->tmpDir}/db";
		mkdir($this->aliasdir, 0777, TRUE);
		mkdir($this->dbdir, 0777, TRUE);
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->tmpDir);
	}

	private function writeShim(string $body): string
	{
		$shim = "{$this->tmpDir}/pfctl-shim-" . bin2hex(random_bytes(4)) . '.sh';
		file_put_contents($shim, "#!/bin/sh\n{$body}\n");
		chmod($shim, 0755);
		return $shim;
	}

	/**
	 * Abandon the generator after one entry (same shape as
	 * LiveTableSnapshotTest::testTempFileCleanedUpAfterAbandonedIteration()),
	 * then close the scratch-file resource it still holds from OUTSIDE --
	 * emulating PHP's own request-shutdown resource teardown racing ahead of
	 * the deferred `finally` on an abandoned generator (bugs.php.net #76006).
	 * The finally's fclose() must tolerate that: no TypeError, and the
	 * scratch file is still unlinked (never leaked).
	 */
	public function testAbandonedGeneratorFinallyToleratesResourceClosedByShutdownFirst(): void
	{
		$shim = $this->writeShim("printf '10.0.0.1\\n10.0.0.2\\n10.0.0.3\\n'");

		$gen = pfb_live_table_snapshot($shim, $this->aliasdir, $this->dbdir, 'pfB_ShutdownRace_v4');
		foreach ($gen as $entry) {
			break; // take exactly one entry, then abandon -- same as the sibling test
		}

		$scratch_before = glob("{$this->dbdir}/pfb_punch_*");
		$this->assertCount(1, $scratch_before, 'setup: exactly one scratch file must be open at this point');

		// realpath() on both sides -- macOS resolves sys_get_temp_dir() through a
		// /var -> /private/var symlink, so tempnam()'s path and the stream's own
		// reported 'uri' meta can differ by that symlink even though they name the
		// same file.
		$scratch_real = realpath($scratch_before[0]);
		$closed       = 0;
		foreach (get_resources('stream') as $res) {
			$meta = stream_get_meta_data($res);
			if (isset($meta['uri']) && realpath($meta['uri']) === $scratch_real) {
				fclose($res);
				$closed++;
			}
		}
		$this->assertSame(1, $closed, 'setup: expected to find and externally close exactly the scratch-file resource');

		try {
			unset($gen);
			gc_collect_cycles();
		} catch (\TypeError $e) {
			$this->fail(
				"abandoned generator's finally must not let fclose() throw when the handle is already invalid: "
				. $e->getMessage()
			);
		}

		$this->assertSame(
			[],
			glob("{$this->dbdir}/pfb_punch_*"),
			'the scratch temp file must still be unlinked even when fclose() is skipped as already-invalid'
		);
	}
}
