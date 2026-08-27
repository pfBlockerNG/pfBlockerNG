<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_log_max_lines() — resolves a stored 'log_max_<type>' config value to the
 * truncation limit pfb_log_mgmt() applies (issue #713).
 *
 * The web UI stores the literal string 'nolimit' for the "No Limit - Not
 * recommended" option (pfblockerng_general.php), but pfb_log_mgmt() used to run
 * that raw value through pfb_filter(..., PFB_FILTER_NUM, ...) BEFORE checking
 * for the sentinel. PFB_FILTER_NUM only accepts digit strings
 * ('/^[0-9]+$/'), so 'nolimit' failed the filter and silently collapsed to
 * the numeric default (20000) — the "No Limit" opt-out never took effect and
 * every log was truncated regardless of the setting. This helper must be
 * called on the RAW config value so the sentinel survives.
 *
 * Branch coverage: all three input classes pfb_log_mgmt() can see for a
 * 'log_max_<type>' field.
 */
#[CoversFunction('pfb_log_max_lines')]
final class LogMaxLinesTest extends TestCase
{
	/**
	 * The 'nolimit' sentinel MUST survive unchanged — this is the exact defect
	 * from issue #713. On the pre-fix inline code (running 'nolimit' through
	 * PFB_FILTER_NUM first) this collapses to 20000 instead.
	 */
	public function testNolimitSentinelSurvives(): void
	{
		$this->assertSame(
			'nolimit',
			pfb_log_max_lines('nolimit'),
			"'nolimit' must be returned verbatim so pfb_log_mgmt() can skip truncation for it"
		);
	}

	/**
	 * A digit-string config value resolves to that same limit as an int.
	 */
	public function testNumericRawResolvesToThatIntLimit(): void
	{
		$this->assertSame(
			5000,
			pfb_log_max_lines('5000'),
			"a numeric raw value must resolve to its own int limit, not the 20000 default"
		);
	}

	/**
	 * Anything that is neither 'nolimit' nor a digit string (empty, garbage,
	 * or absent/null) falls back to the 20000 default — the same default
	 * pfb_log_mgmt() historically applied via PFB_FILTER_NUM's $default arg.
	 */
	public function testInvalidOrEmptyRawFallsBackToDefault(): void
	{
		$this->assertSame(20000, pfb_log_max_lines(''), "empty raw value must fall back to the 20000 default");
		$this->assertSame(20000, pfb_log_max_lines('not-a-number'), "non-numeric raw value must fall back to the 20000 default");
		$this->assertSame(20000, pfb_log_max_lines(null), "absent (null) raw value must fall back to the 20000 default");
	}
}
