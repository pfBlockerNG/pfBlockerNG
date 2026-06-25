<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_file_mtime() — reads a file's mtime with PHP's per-process stat cache cleared
 * first (issue #536), so a long-lived process (e.g. the filterlog daemon) — and any
 * caller — always sees the true on-disk mtime rather than a value PHP cached on an
 * earlier stat of the same path. A single choke point: every filemtime read in the tree
 * routes through it, so no call site has to remember to clear the cache.
 *
 * The bug it fixes: PHP's per-process stat cache holds the mtime from the first stat of
 * a path. If the file is then changed by ANOTHER process, a bare filemtime() in this
 * process keeps returning the cached (stale) value until clearstatcache() is called.
 * The filterlog daemon captured its config.xml baseline that way and could miss the very
 * first config-change event.
 */
#[CoversFunction('pfb_file_mtime')]
final class FileMtimeTest extends TestCase
{
	/** @var string */
	private string $tmp;

	protected function setUp(): void
	{
		$tmp = tempnam(sys_get_temp_dir(), 'pfb_mtime_test_');
		if ($tmp === FALSE) {
			$this->fail('Could not create temp file');
		}
		$this->tmp = $tmp;
	}

	protected function tearDown(): void
	{
		if (file_exists($this->tmp)) {
			unlink($this->tmp);
		}
	}

	/**
	 * Read a file's true on-disk mtime via a FRESH PHP process (empty stat cache, so no
	 * shared cache with this process). Uses PHP_BINARY rather than shelling out to `stat`
	 * because `stat`'s mtime flag differs by platform (BSD `-f %m` vs GNU `-c %Y`) — a fresh
	 * `php -r filemtime()` is identical on macOS and the Linux CI runner. Returns the epoch int.
	 */
	private function onDiskMtime(string $path): int
	{
		$out = shell_exec(
			escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg('echo (int) filemtime($argv[1]);')
			. ' ' . escapeshellarg($path)
		);
		return (int) trim((string) $out);
	}

	/**
	 * THE FIX. pfb_file_mtime() returns the true on-disk mtime even when PHP's stat
	 * cache was primed with the pre-mutation value.
	 *
	 * Fail-before: without clearstatcache the helper returns the cached pre-mutation
	 * mtime; this assertion goes red on Linux/CI. macOS local can't show red (the VFS
	 * provides stat coherency, so a bare filemtime is already fresh after an external
	 * mutation) — CI (Linux) is the proving platform.
	 *
	 *   GIVEN a temp file whose mtime is read in-process, priming PHP's stat cache;
	 *    WHEN a SEPARATE process changes the file's mtime (so PHP's in-process cache is
	 *         NOT auto-cleared — unlike PHP's own touch(), which clears its own cache);
	 *    THEN pfb_file_mtime() returns the NEW on-disk mtime, not the primed value.
	 */
	public function test_pfb_file_mtime_returns_fresh_mtime_after_out_of_process_change(): void
	{
		$tmp = $this->tmp;

		// GIVEN: create content and prime PHP's stat cache for this path (records t0).
		file_put_contents($tmp, 'a');
		$primed = filemtime($tmp);
		$this->assertIsInt($primed, 'filemtime() must prime with an int mtime (t0)');

		// WHEN: mutate the mtime OUT-OF-PROCESS to an explicit year-2030 value, so PHP's
		// in-process stat cache is not auto-invalidated (POSIX `touch -t CCYYMMDDhhmm.SS`).
		$touch_rc = -1;
		exec('/usr/bin/touch -t 203001010000.00 ' . escapeshellarg($tmp), $touch_out, $touch_rc);
		$this->assertSame(0, $touch_rc, 'out-of-process `touch -t` must succeed (test setup)');
		$expected = $this->onDiskMtime($tmp);
		$this->assertGreaterThan(
			$primed,
			$expected,
			sprintf(
				'Out-of-process touch must advance the on-disk mtime above the primed value '
				. '(primed=%d, on-disk=%d)',
				$primed,
				$expected
			)
		);

		// Control (soft, documents the bug across platforms): a bare filemtime() now.
		// On Linux this is the STALE primed t0 (cache primed, not cleared); on macOS VFS
		// coherency it may already read fresh. We do not hard-assert this (it is
		// platform-dependent) — we surface what the platform did so the diagnostic is honest.
		$bare = filemtime($tmp);
		if ($bare === $primed) {
			fwrite(STDERR, sprintf(
				"[FileMtimeTest] per-process stat cache is STALE here: bare filemtime()=%d (primed), "
				. "on-disk=%d — the bug is reproducible on this platform.\n",
				$bare,
				$expected
			));
		} else {
			fwrite(STDERR, sprintf(
				"[FileMtimeTest] VFS stat coherency here: bare filemtime()=%d already matches "
				. "on-disk=%d — staleness not reproducible locally (expected on macOS); Linux/CI proves it.\n",
				$bare,
				$expected
			));
		}

		// THEN (the real failable assertion): the helper returns the fresh on-disk value.
		$result = pfb_file_mtime($tmp);
		$this->assertSame(
			$expected,
			$result,
			sprintf(
				'Expected pfb_file_mtime() to return the fresh on-disk mtime %d, got %s '
				. '(primed/stale value was %d — a missing clearstatcache returns that on Linux/CI).',
				$expected,
				var_export($result, TRUE),
				$primed
			)
		);
	}

	/**
	 * Contract: pfb_file_mtime() returns the on-disk mtime of a freshly-written file.
	 *
	 *  GIVEN a file with content just written;
	 *   WHEN pfb_file_mtime() is called with its path;
	 *   THEN the returned mtime matches the on-disk value (read by a fresh process).
	 */
	public function test_pfb_file_mtime_returns_correct_mtime_for_existing_file(): void
	{
		file_put_contents($this->tmp, 'x');
		$expected = $this->onDiskMtime($this->tmp);

		$result = pfb_file_mtime($this->tmp);

		$this->assertSame(
			$expected,
			$result,
			sprintf(
				'Expected pfb_file_mtime() to return on-disk mtime %d, got %s',
				$expected,
				var_export($result, TRUE)
			)
		);
	}

	/**
	 * Contract: pfb_file_mtime() returns FALSE for a path that does not exist.
	 * Proves the @filemtime() error-suppression and FALSE-return path.
	 *
	 *  GIVEN a path that does not exist on disk;
	 *   WHEN pfb_file_mtime() is called with it;
	 *   THEN it returns FALSE (not an exception, not 0, not '').
	 */
	public function test_pfb_file_mtime_returns_false_for_missing_path(): void
	{
		$missing = $this->tmp . '_does_not_exist';

		$result = pfb_file_mtime($missing);

		$this->assertFalse(
			$result,
			sprintf('Expected FALSE for missing path, got %s', var_export($result, TRUE))
		);
	}
}
