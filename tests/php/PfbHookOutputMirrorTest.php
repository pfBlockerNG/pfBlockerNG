<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #693 (follow-up to #690): pfb_run_hooks() redirects each hook's stdout/stderr to a LOG
 * FILE (never a pipe, so a daemon-restarting hook can't hang the pass -- #662). The cost is that
 * during a package install/upgrade/uninstall pfSense's Software page -- which shows only STDOUT --
 * frames the hook with its markers but shows an empty body.
 *
 * pfb_mirror_hook_output() closes that gap: while a pkg lifecycle callback is active
 * ($pfb['hook_lifecycle']), it prints exactly the bytes the hook appended to the log (from the
 * pre-exec offset to EOF). The bytes are already in the file, so it only prints -- never re-logs --
 * and a plain file read cannot hang the pass.
 *
 * Branch coverage: lifecycle active (mirror the delta) vs inactive (silent) for the SAME appended
 * bytes, plus the no-new-bytes and empty-path guards.
 */
#[CoversFunction('pfb_mirror_hook_output')]
final class PfbHookOutputMirrorTest extends TestCase
{
	private string $logfile = '';

	protected function setUp(): void
	{
		global $pfb;
		$this->logfile = (string) tempnam(sys_get_temp_dir(), 'pfb_hook_mirror_');
		unset($pfb['hook_lifecycle']);
	}

	protected function tearDown(): void
	{
		global $pfb;
		if ($this->logfile !== '') {
			@unlink($this->logfile);
		}
		unset($pfb['hook_lifecycle']);
	}

	/** Write the "framing marker" already there before the hook runs, then return the pre-exec offset. */
	private function seedAndOffset(string $preamble): int
	{
		@file_put_contents($this->logfile, $preamble);
		clearstatcache(TRUE, $this->logfile);
		return (int) filesize($this->logfile);
	}

	private function capture(int $offset): string
	{
		ob_start();
		pfb_mirror_hook_output($this->logfile, $offset);
		return (string) ob_get_clean();
	}

	public function testMirrorsOnlyTheHookBodyDeltaDuringALifecycleCallback(): void
	{
		global $pfb;
		// Given the header marker is already logged (offset), a hook then appends its own output...
		$offset = $this->seedAndOffset("[ pfB Hook ] post haproxy (hook_post_haproxy.sh)\n");
		@file_put_contents($this->logfile, "Firing up HAProxy ACL update hook\nReloading HAProxy\n", FILE_APPEND);

		// When a package lifecycle callback is active...
		$pfb['hook_lifecycle'] = 'install';

		// Then exactly the appended body (not the pre-existing header) reaches STDOUT.
		$this->assertSame("Firing up HAProxy ACL update hook\nReloading HAProxy\n", $this->capture($offset));
	}

	public function testStaysSilentWithoutALifecycleCallback(): void
	{
		// The pre-#693 behaviour: a normal cron/manual/Run-Now pass (no lifecycle marker) does NOT
		// print the hook body to STDOUT -- the Update-page tail already reads it from the file.
		$offset = $this->seedAndOffset("header\n");
		@file_put_contents($this->logfile, "hook body\n", FILE_APPEND);

		$this->assertSame('', $this->capture($offset));
	}

	public function testPrintsNothingWhenTheHookAppendedNoOutput(): void
	{
		global $pfb;
		// A silent hook (offset == EOF) yields no output even inside a lifecycle callback.
		$pfb['hook_lifecycle'] = 'uninstall';
		$offset = $this->seedAndOffset("header only\n");

		$this->assertSame('', $this->capture($offset));
	}

	public function testEmptyLogPathIsANoOp(): void
	{
		global $pfb;
		$pfb['hook_lifecycle'] = 'install';
		ob_start();
		pfb_mirror_hook_output('', 0);
		$this->assertSame('', (string) ob_get_clean());
	}
}
