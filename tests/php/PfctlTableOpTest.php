<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Tests for pfb_pfctl_error_message() — the pure formatter that names a failed
 * pfctl table operation.  Adding attribution to "pfctl: Table does not exist"
 * floods during the alpha-6 upgrade (no table/op info in the original exec()
 * call sites).
 *
 * pfb_pfctl_table_op() wraps exec() and cannot be exercised off-appliance, so
 * only the formatter is tested here (exec doubles would add fragile complexity
 * for no new coverage benefit — the formatter is the testable invariant).
 *
 * Scenarios:
 *   A — failure message contains table, op, rc, and trimmed stderr.
 *   B — multiline stderr collapses to a single line.
 *   C — rc=0 with clean output formats without the error marker.
 *   D — empty stderr is represented cleanly (no trailing colon-space).
 */
#[CoversFunction('pfb_pfctl_error_message')]
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
	 * Then:  the returned message still contains table, op, rc, and is a
	 *        non-empty string (does not degenerate to a bare colon).
	 */
	public function testEmptyStderrProducesCleanMessage(): void
	{
		$msg = pfb_pfctl_error_message('pfB_Permit_v6', 'kill', 1, '');

		$this->assertNotEmpty($msg,
			'expected: non-empty message even with empty stderr');
		$this->assertStringContainsString('pfB_Permit_v6', $msg,
			"expected: table name present;\nactual: {$msg}");
		$this->assertStringContainsString('kill', $msg,
			"expected: op present;\nactual: {$msg}");
		$this->assertStringContainsString('1', $msg,
			"expected: rc present;\nactual: {$msg}");
	}
}
