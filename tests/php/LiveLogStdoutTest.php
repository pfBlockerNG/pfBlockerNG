<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-58 (supersedes issue #690's LiveLogPkgMirrorTest): pfb_logger()'s run-progress lines (cases 1
 * and 2) mirror to the process's STDOUT whenever STDOUT is a real WATCHED surface --
 * pfb_run_streams_to_stdout(): a package lifecycle callback (the pkg Software page's pipe to `tee`,
 * #690) OR an interactive terminal (ADR-58's addition). They do NOT print when STDOUT is redirected
 * to a log FILE the logger already writes (the cron tick, the detached Run-Now, a nested extras
 * dispatch) -- that would double every line -- nor for a web in-process caller (the HTTP response).
 *
 * Everything else is exactly issue #690's behaviour: the file writes (cumulative + errlog) and the
 * per-run-log fwrite-mirror (which populates the runlog the Update viewer tails, regardless of where
 * the run's STDOUT points) are unchanged.
 *
 * Branch coverage: lifecycle-active (mirror to STDOUT) vs a plain non-lifecycle pass with STDOUT not
 * a terminal (silent -- the anti-double property, and what a normal cron/Run-Now pass must do); the
 * override forcing the print on WITHOUT a lifecycle (the ADR-58 widening -- RED on pre-change code
 * that only printed under hook_lifecycle); the fwrite-mirror still writing the runlog; case 2's error
 * log; and case 3 never printing.
 */
#[CoversFunction('pfb_logger')]
#[CoversFunction('pfb_run_streams_to_stdout')]
final class LiveLogStdoutTest extends TestCase
{
	private ?string $origRunlog = null;

	protected function setUp(): void
	{
		global $pfb;
		@mkdir($pfb['logdir'], 0777, TRUE);
		@file_put_contents($pfb['log'], '');
		@file_put_contents($pfb['errlog'], '');
		// $pfb['runlog'] is a shared bootstrap key other test classes depend on -- save it (the
		// mirror test below overrides it) and restore in tearDown; never unset it.
		$this->origRunlog = $pfb['runlog'] ?? null;
		unset($pfb['runlog_active'], $pfb['hook_lifecycle'], $pfb['run_stdout_override']);
	}

	protected function tearDown(): void
	{
		global $pfb;
		if ($this->origRunlog !== null) {
			$pfb['runlog'] = $this->origRunlog;
		}
		unset($pfb['run_stdout_override'], $pfb['runlog_active'], $pfb['hook_lifecycle']);
	}

	private function capture(string $msg, int $logtype): string
	{
		ob_start();
		pfb_logger($msg, $logtype);
		return (string) ob_get_clean();
	}

	public function testMainLogMirrorsToStdoutDuringALifecycleCallback(): void
	{
		global $pfb;
		// Given an install/upgrade (the pkg Software page reads STDOUT) -- issue #690's case...
		$pfb['hook_lifecycle'] = 'install';

		$out = $this->capture('Removing pfBlockerNG...', 1);

		// Then the line reaches STDOUT so the page streams it (ADR-60 P2: with pfb_logger()'s
		// leading ISO-8601 stamp, now unconditional), AND the cumulative log records it.
		$this->assertMatchesRegularExpression(
			'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} Removing pfBlockerNG\.\.\.$/',
			$out,
			'a lifecycle pass must mirror progress to STDOUT'
		);
		$this->assertStringContainsString('Removing pfBlockerNG...', (string) @file_get_contents($pfb['log']));
	}

	public function testPlainPassWithStdoutNotATerminalStaysSilent(): void
	{
		global $pfb;
		// Given a normal cron/manual/Run-Now pass: no lifecycle, and STDOUT is NOT a terminal (the
		// PHPUnit process's STDOUT is a pipe/file). This is the case where the run's STDOUT is often
		// redirected into a log file the logger already writes, so a print would DOUBLE every line.
		unset($pfb['hook_lifecycle'], $pfb['run_stdout_override']);

		$out = $this->capture('Removing pfBlockerNG...', 1);

		// Then nothing is emitted to STDOUT (no double), but the file write is unchanged.
		$this->assertSame('', $out, 'a plain non-lifecycle pass with a non-tty STDOUT must not print');
		$this->assertStringContainsString('Removing pfBlockerNG...', (string) @file_get_contents($pfb['log']));
	}

	public function testOverrideForcesTheMirrorOnWithoutALifecycle(): void
	{
		global $pfb;
		// The ADR-58 widening: pfb_run_streams_to_stdout() prints when STDOUT is a watched surface,
		// not only under a lifecycle callback. The override models "STDOUT is a terminal" here (a tty
		// is not reproducible under PHPUnit). This FAILS on pre-ADR-58 code, which only printed when
		// $pfb['hook_lifecycle'] was set -- proving the gate is genuinely widened.
		unset($pfb['hook_lifecycle']);
		$pfb['run_stdout_override'] = TRUE;

		$this->assertMatchesRegularExpression(
			'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} a warning$/',
			$this->capture('a warning', 2),
			'the widened gate must print without a lifecycle'
		);
		$this->assertStringContainsString('a warning', (string) @file_get_contents($pfb['errlog']));
	}

	public function testOverrideOffSuppressesTheMirrorEvenUnderALifecycle(): void
	{
		global $pfb;
		// FALSE wins over the lifecycle default -- the web in-process caller's silent path.
		$pfb['hook_lifecycle'] = 'install';
		$pfb['run_stdout_override'] = FALSE;

		$this->assertSame('', $this->capture('Removing pfBlockerNG...', 1), 'override=FALSE must suppress the STDOUT print');
	}

	public function testFwriteMirrorStillWritesThePerRunLog(): void
	{
		global $pfb;
		// The per-run-log fwrite-mirror is UNCHANGED from #690: while a run is active it appends each
		// main-log line to the run-log the Update viewer tails, regardless of where STDOUT points.
		$pfb['runlog_active'] = TRUE;
		$pfb['runlog']        = "{$pfb['logdir']}/adr58_runlog_probe.log";
		@file_put_contents($pfb['runlog'], '');

		$this->capture('Removing pfBlockerNG...', 1);

		$this->assertStringContainsString(
			'Removing pfBlockerNG...',
			(string) @file_get_contents($pfb['runlog']),
			'the per-run-log mirror must still populate the runlog the viewer tails'
		);
	}

	public function testNonProgressExtrasCaseNeverPrints(): void
	{
		global $pfb;
		// case 3 is the Extras log (a side channel), not run progress -- never on STDOUT, even under
		// a lifecycle callback or an override.
		$pfb['hook_lifecycle'] = 'install';
		$pfb['run_stdout_override'] = TRUE;
		$this->assertSame('', $this->capture('extras-only detail', 3));
	}
}
