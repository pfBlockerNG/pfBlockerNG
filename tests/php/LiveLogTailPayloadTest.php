<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Pin pfb_log_tail_payload() -- the response builder behind the ?ajax=tail branch on the Update
 * page (issue #671). It maps the requested source to its per-run log + pidfile,
 * reads the next slice via pfb_log_tail_chunk(), and reports whether the client should keep
 * polling. The 'done' flag is driven by the dispatched process's liveness (isvalidpid on the
 * pidfile), doubled here via $GLOBALS['pfb_test_valid_pids'].
 *
 * Branch coverage: live run (running, not done) vs finished run (gone, done + flush) vs the
 * no-run-file View fallback (last 15KB of the cumulative log, one-shot done) vs nothing-to-show.
 */
#[CoversFunction('pfb_log_tail_payload')]
final class LiveLogTailPayloadTest extends TestCase
{
	private const UPDATE_PID = '/var/run/pfb_runnow.pid';

	protected function setUp(): void
	{
		global $pfb;
		// Start each test from empty run/cumulative logs and a not-running process.
		@mkdir($pfb['logdir'], 0777, TRUE);
		@file_put_contents($pfb['runlog'], '');
		@file_put_contents($pfb['log'], '');
		$GLOBALS['pfb_test_valid_pids'] = [];
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb_test_valid_pids'] = [];
	}

	public function testInvalidSourceReturnsError(): void
	{
		$this->assertSame(['error' => 'invalid source'], pfb_log_tail_payload('bogus', -1, FALSE));
	}

	public function testFirstPollOfALiveRunTailsTheRunLogAndKeepsPolling(): void
	{
		global $pfb;
		file_put_contents($pfb['runlog'], "starting run\nfetching feed\n");
		$GLOBALS['pfb_test_valid_pids'][self::UPDATE_PID] = TRUE;

		$p = pfb_log_tail_payload('update', -1, FALSE);

		$this->assertSame('run', $p['source']);
		$this->assertSame("starting run\nfetching feed\n", $p['data']);
		$this->assertTrue($p['running']);
		$this->assertFalse($p['done'], 'a live run must keep the client polling');
		$this->assertSame(27, $p['offset']);
	}

	public function testContinuingPollReturnsOnlyNewBytes(): void
	{
		global $pfb;
		file_put_contents($pfb['runlog'], "line A\n");
		$GLOBALS['pfb_test_valid_pids'][self::UPDATE_PID] = TRUE;

		$first = pfb_log_tail_payload('update', -1, FALSE);
		file_put_contents($pfb['runlog'], "line B\n", FILE_APPEND);

		$next = pfb_log_tail_payload('update', $first['offset'], TRUE);
		$this->assertSame("line B\n", $next['data']);
		$this->assertFalse($next['done']);
	}

	public function testFinishedRunFlushesAndSignalsDone(): void
	{
		global $pfb;
		// Output ends WITHOUT a trailing newline; a finished run must still flush it.
		file_put_contents($pfb['runlog'], "done line\ntrailing-partial");
		$GLOBALS['pfb_test_valid_pids'][self::UPDATE_PID] = FALSE; // process gone

		$p = pfb_log_tail_payload('update', -1, FALSE);

		$this->assertTrue($p['done'], 'a gone process ends the poll');
		$this->assertFalse($p['running']);
		$this->assertStringContainsString('trailing-partial', $p['data'], 'final partial line is flushed');
	}

	public function testLiveRunWithEmptyRunLogKeepsPollingNotFallback(): void
	{
		global $pfb;
		// The run log is freshly truncated (empty) but the dispatched process is ALIVE — the
		// client's first poll commonly beats the daemon's first write. This must NOT one-shot the
		// cumulative fallback (which would stop the tail before any live output); it must follow the
		// run log and keep polling. Regression guard for the first-poll false-'done' bug.
		file_put_contents($pfb['runlog'], '');
		file_put_contents($pfb['log'], "old cumulative history line\n"); // fallback HAS content
		$GLOBALS['pfb_test_valid_pids'][self::UPDATE_PID] = TRUE;

		$p = pfb_log_tail_payload('update', -1, FALSE);

		$this->assertSame('run', $p['source'], 'a live run must follow the run log, never the cumulative fallback');
		$this->assertFalse($p['done'], 'must keep polling while the process is alive and the run log is still empty');
		$this->assertTrue($p['running']);
		$this->assertSame('', $p['data'], 'no data yet — the daemon has not written its first line');
	}

	public function testNoRunFileFallsBackToCumulativeTailOneShot(): void
	{
		global $pfb;
		// No run-file content; cumulative log has history -> View fallback.
		file_put_contents($pfb['runlog'], '');
		file_put_contents($pfb['log'], "old run line 1\nold run line 2\n");
		$GLOBALS['pfb_test_valid_pids'][self::UPDATE_PID] = FALSE;

		$p = pfb_log_tail_payload('update', -1, FALSE);

		$this->assertSame('fallback', $p['source']);
		$this->assertTrue($p['done'], 'the fallback View is a one-shot');
		$this->assertStringContainsString('old run line 2', $p['data']);
	}

	public function testNothingToShowWhenBothLogsEmpty(): void
	{
		$p = pfb_log_tail_payload('update', -1, FALSE);
		$this->assertSame('none', $p['source']);
		$this->assertSame('', $p['data']);
		$this->assertTrue($p['done']);
	}
}
