<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Tests for the two pure helpers of pfb_pfctl_table_op():
 *   - pfb_pfctl_error_message() — the formatter that names a failed pfctl table
 *     operation (adding attribution to "pfctl: Table does not exist" floods that
 *     the original exec() call sites logged with no table/op info); and
 *   - pfb_pfctl_op_failed() — the predicate that decides WHETHER a completed op is
 *     a failure worth logging, exempting the idempotent absent-table `kill`.
 *
 * pfb_pfctl_table_op() wraps exec() and cannot be exercised off-appliance, so only
 * its pure helpers are tested here (exec doubles would add fragile complexity for no
 * new coverage benefit — the helpers are the testable invariants).
 *
 * Scenarios:
 *   A — failure message contains table, op, rc, and trimmed stderr.
 *   B — multiline stderr collapses to a single line.
 *   C — message format is stable across all four mutation ops (kill/replace/add/delete).
 *   D — empty stderr is represented cleanly (no trailing colon-space).
 *   E — pfb_pfctl_op_failed(): an absent-table `kill` is success (not logged); every
 *       other kill error, non-kill absent-table op, and clean success is classified right.
 */
#[CoversFunction('pfb_pfctl_error_message')]
#[CoversFunction('pfb_pfctl_op_failed')]
final class PfctlTableOpTest extends TestCase
{
	// -----------------------------------------------------------------------
	// Scenario A — standard failure: message contains all four fields
	// -----------------------------------------------------------------------

	/**
	 * Scenario A — pfb_pfctl_error_message names table, op, rc, and stderr.
	 *
	 * Given: table='pfB_DNSBLIP_v4', op='replace', rc=1, stderr from pfctl.
	 * When:  pfb_pfctl_error_message() is called.
	 * Then:  the returned line contains each field so the log is attributable.
	 *
	 * This test is RED before the function exists (calling an undefined function
	 * raises a Fatal; no assertion needed to prove RED).  GREEN after the function
	 * is defined AND all four fields appear in the message.
	 */
	public function testMessageContainsTableOpRcAndStderr(): void
	{
		$table  = 'pfB_DNSBLIP_v4';
		$op     = 'replace';
		$rc     = 1;
		$stderr = 'pfctl: Table does not exist.';

		$msg = pfb_pfctl_error_message($table, $op, $rc, $stderr);

		$this->assertStringContainsString($table, $msg,
			"expected: message contains table name '{$table}';\nactual: {$msg}");
		$this->assertStringContainsString($op, $msg,
			"expected: message contains op '{$op}';\nactual: {$msg}");
		$this->assertStringContainsString((string) $rc, $msg,
			"expected: message contains rc='{$rc}';\nactual: {$msg}");
		$this->assertStringContainsString($stderr, $msg,
			"expected: message contains stderr text '{$stderr}';\nactual: {$msg}");
	}

	// -----------------------------------------------------------------------
	// Scenario B — multiline stderr collapses to a single output line
	// -----------------------------------------------------------------------

	/**
	 * Scenario B — multiline stderr is collapsed to a single line in the output.
	 *
	 * Given: stderr contains embedded newlines (pfctl occasionally emits multi-line
	 *        error text).
	 * When:  pfb_pfctl_error_message() is called.
	 * Then:  the returned string contains no newline characters so a single
	 *        pfb_logger() call emits exactly one log line (the caller appends \n).
	 */
	public function testMultilineStderrCollapsesToSingleLine(): void
	{
		$msg = pfb_pfctl_error_message(
			'pfB_Test_v4',
			'kill',
			2,
			"pfctl: Table does not exist.\nAnother error line.\r\nThird line."
		);

		$this->assertStringNotContainsString("\n", $msg,
			"expected: no embedded newlines in the formatted message;\nactual: " . json_encode($msg));
		$this->assertStringNotContainsString("\r", $msg,
			"expected: no embedded carriage returns in the formatted message;\nactual: " . json_encode($msg));
	}

	// -----------------------------------------------------------------------
	// Scenario C — format is stable across op variants
	// -----------------------------------------------------------------------

	/**
	 * Scenario C — format is stable for all expected op values.
	 *
	 * Given: the four mutation ops used at the routed call sites.
	 * When:  pfb_pfctl_error_message() is called with each op.
	 * Then:  each returned message contains the op string and the table name.
	 */
	public function testFormatStableAcrossOps(): void
	{
		$table = 'pfB_Deny_v4';
		$ops   = ['kill', 'replace', 'add', 'delete'];

		foreach ($ops as $op) {
			$msg = pfb_pfctl_error_message($table, $op, 1, 'pfctl: EINVAL');
			$this->assertStringContainsString($op, $msg,
				"expected: message for op='{$op}' contains the op string;\nactual: {$msg}");
			$this->assertStringContainsString($table, $msg,
				"expected: message for op='{$op}' contains the table name;\nactual: {$msg}");
		}
	}

	// -----------------------------------------------------------------------
	// Scenario D — empty stderr produces a clean message (no trailing artifact)
	// -----------------------------------------------------------------------

	/**
	 * Scenario D — empty stderr is represented cleanly.
	 *
	 * Given: stderr is an empty string (pfctl exited non-zero with no output).
	 * When:  pfb_pfctl_error_message() is called.
	 * Then:  the message ends at the rc — no trailing ": " artifact. (The header
	 *        always claimed this; production emitted the dangling colon-space and
	 *        the old assertions never checked it — #723.)
	 */
	public function testEmptyStderrProducesCleanMessage(): void
	{
		$msg = pfb_pfctl_error_message('pfB_Permit_v6', 'kill', 1, '');

		$this->assertSame('[pfctl] op=kill table=pfB_Permit_v6 failed (rc=1)', $msg,
			"expected: message ends at the rc with no trailing colon-space;\nactual: {$msg}");
	}

	/**
	 * Scenario D counterpart — non-empty stderr keeps the ": <stderr>" suffix.
	 */
	public function testNonEmptyStderrKeepsSuffix(): void
	{
		$msg = pfb_pfctl_error_message('pfB_Permit_v6', 'kill', 1, 'pfctl: Table does not exist.');

		$this->assertSame(
			'[pfctl] op=kill table=pfB_Permit_v6 failed (rc=1): pfctl: Table does not exist.',
			$msg,
			"expected: stderr suffix preserved;\nactual: {$msg}");
	}

	// -----------------------------------------------------------------------
	// Scenario E — pfb_pfctl_op_failed: absent-table `kill` is idempotent
	//              success, NOT an attributed failure
	// -----------------------------------------------------------------------

	/**
	 * Scenario E — a `kill` of a table that does not exist is NOT a failure.
	 *
	 * Given: op='kill', rc=1, stderr='pfctl: Table does not exist.' — the shape produced when the
	 *        unguarded kill sites (an enabled alias with no URL/customlist; an empty aggregate
	 *        union) kill a table that was never created.
	 * When:  pfb_pfctl_op_failed() classifies it.
	 * Then:  it returns FALSE — the kill's goal (table gone) is already met, so no attributed
	 *        failure line is logged. Pre-fix this reported TRUE and flooded the log every tick.
	 */
	public function testKillOfAbsentTableIsNotAFailure(): void
	{
		$this->assertFalse(
			pfb_pfctl_op_failed('kill', 1, 'pfctl: Table does not exist.'),
			'expected: absent-table kill classified as success (FALSE);\nactual: TRUE (would log a benign no-op)'
		);
	}

	/**
	 * Scenario E (branch) — the carve-out is kill-ONLY: a non-kill op on an absent table is
	 * still a real failure.
	 *
	 * Given: op='replace', rc=1, stderr='pfctl: Table does not exist.'.
	 * When:  pfb_pfctl_op_failed() classifies it.
	 * Then:  it returns TRUE — a replace needs the table, so its absence IS a failure to attribute.
	 */
	public function testReplaceOfAbsentTableStillFails(): void
	{
		$this->assertTrue(
			pfb_pfctl_op_failed('replace', 1, 'pfctl: Table does not exist.'),
			'expected: absent-table replace still a failure (TRUE);\nactual: FALSE (would swallow a real error)'
		);
	}

	/**
	 * Scenario E (branch) — a `kill` that fails for ANOTHER reason is still a real failure.
	 *
	 * Given: op='kill', rc=1, stderr='pfctl: permission denied' (no "Table does not exist").
	 * When:  pfb_pfctl_op_failed() classifies it.
	 * Then:  it returns TRUE — only the absent-table kill is exempt; every other kill error is
	 *        attributed.
	 */
	public function testKillWithOtherErrorStillFails(): void
	{
		$this->assertTrue(
			pfb_pfctl_op_failed('kill', 1, 'pfctl: permission denied'),
			'expected: kill failing for a non-absent-table reason still a failure (TRUE);\nactual: FALSE'
		);
	}

	/**
	 * Scenario E (branch) — a clean success (rc=0, no stderr) is never a failure, for any op.
	 *
	 * Given: op='add', rc=0, stderr=''.
	 * When:  pfb_pfctl_op_failed() classifies it.
	 * Then:  it returns FALSE — nothing to log on a healthy mutation.
	 */
	public function testCleanSuccessIsNotAFailure(): void
	{
		$this->assertFalse(
			pfb_pfctl_op_failed('add', 0, ''),
			'expected: rc=0 clean op classified as success (FALSE);\nactual: TRUE'
		);
	}
}
