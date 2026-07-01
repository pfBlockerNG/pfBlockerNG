<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #690: during a package install/upgrade/uninstall, pfSense's native Software page shows
 * only what the operation writes to STDOUT. pfb_logger() normally writes the whole sync pass to
 * the log FILE, so the delegated page sits silent and looks like a frozen/lost pipe.
 *
 * pfb_logger() now mirrors its main-log output (cases 1 and 2) to STDOUT while a package lifecycle
 * callback is active -- $pfb['hook_lifecycle'] is set by the install command ('install') and the
 * pre-deinstall ('uninstall'), and unset on every normal cron/manual/Run-Now pass and in the log
 * daemon. The mirror is visibility only: it does not touch the file writes, the redirected update
 * hooks, or the detached rc.d daemons.
 *
 * Branch coverage: lifecycle-active (mirror) vs no-lifecycle (silent) for the SAME call, plus the
 * non-progress case (3) staying unmirrored even inside a lifecycle callback.
 */
#[CoversFunction('pfb_logger')]
final class LiveLogPkgMirrorTest extends TestCase
{
	protected function setUp(): void
	{
		global $pfb;
		// Known-writable log file; no active per-run log (that path is the Update viewer's, not
		// the pkg page's). Start from a clean lifecycle marker so each test sets its own.
		@mkdir($pfb['logdir'], 0777, TRUE);
		@file_put_contents($pfb['log'], '');
		unset($pfb['runlog_active'], $pfb['hook_lifecycle']);
	}

	protected function tearDown(): void
	{
		global $pfb;
		// Never leak the lifecycle marker into a sibling test -- it would silently turn the
		// STDOUT mirror on for an unrelated pfb_logger() assertion.
		unset($pfb['hook_lifecycle']);
	}

	private function capture(string $msg, int $logtype): string
	{
		ob_start();
		pfb_logger($msg, $logtype);
		return (string) ob_get_clean();
	}

	public function testMainLogMirrorsToStdoutDuringAPackageLifecycleCallback(): void
	{
		global $pfb;
		// Given a package install/upgrade is running (the install command set 'install')...
		$pfb['hook_lifecycle'] = 'install';

		// When pfBlockerNG logs a progress line...
		$out = $this->capture("Removing pfBlockerNG...", 1);

		// Then it reaches the package-manager output so the page streams it, AND the log file
		// still receives it (visibility is additive, not a redirect).
		$this->assertSame('Removing pfBlockerNG...', $out, 'progress must stream to STDOUT during a lifecycle callback');
		$this->assertStringContainsString('Removing pfBlockerNG...', (string) @file_get_contents($pfb['log']));
	}

	public function testMainLogStaysSilentOnStdoutWithoutALifecycleCallback(): void
	{
		global $pfb;
		// Given a normal cron/manual/Run-Now pass (no lifecycle marker) -- the pre-#690 behaviour...
		unset($pfb['hook_lifecycle']);

		// When the SAME progress line is logged...
		$out = $this->capture("Removing pfBlockerNG...", 1);

		// Then nothing is printed (a normal pass must not spew onto whatever is reading STDOUT),
		// but the file write is unchanged.
		$this->assertSame('', $out, 'a non-lifecycle pass must not mirror to STDOUT');
		$this->assertStringContainsString('Removing pfBlockerNG...', (string) @file_get_contents($pfb['log']));
	}

	public function testErrorLogCaseAlsoMirrorsDuringALifecycleCallback(): void
	{
		global $pfb;
		// case 2 (pfBlockerNG log + error log) is a progress line too -> mirrored.
		$pfb['hook_lifecycle'] = 'uninstall';
		$this->assertSame('a warning', $this->capture('a warning', 2));
	}

	public function testUnboundStopWaitDotsStreamDuringALifecycleCallback(): void
	{
		global $pfb;
		// The up-to-30s pfb_stop_start_unbound() wait emits its keepalive dots via case 1, so the
		// same mirror closes that silent gap with no separate keepalive path.
		$pfb['hook_lifecycle'] = 'install';
		$this->assertSame('.', $this->capture('.', 1));
	}

	public function testNonProgressCaseIsNotMirroredEvenInALifecycleCallback(): void
	{
		global $pfb;
		// case 3 is the Extras log (a side channel), not the install/upgrade progress -- it must
		// NOT leak onto the package page even while a lifecycle callback is active.
		$pfb['hook_lifecycle'] = 'install';
		$this->assertSame('', $this->capture('extras-only detail', 3));
	}
}
