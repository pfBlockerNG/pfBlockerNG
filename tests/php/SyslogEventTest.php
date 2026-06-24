<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-38 Amendment 1 — pfb_syslog_event() tests.
 *
 * pfb_syslog_event() is the PHP IP-leg syslog emitter.  It reads the log_syslog
 * toggle fresh on every call (no static cache).  When the toggle is on it records
 * calls via $GLOBALS['pfb_test_syslog_spy'] using a hardcoded facility (LOG_LOCAL6)
 * and severity (LOG_INFO).  log_syslog_facility and log_syslog_priority no longer
 * exist as registered config keys; the function no longer reads them.
 *
 * Contract under test (ADR-38 Amendment 1):
 *   - Toggle OFF  => zero syslog calls (no emission, no side effect).
 *   - Toggle ON   => exactly one call per pfb_syslog_event() invocation, with the
 *                    exact body passed, ident 'pfblockerng', facility LOG_LOCAL6,
 *                    and severity LOG_INFO (both hardcoded — not configurable).
 */
final class SyslogEventTest extends TestCase
{
	/** Install the spy; no cache-reset needed (function reads fresh each call). */
	protected function setUp(): void
	{
		$GLOBALS['pfb_test_syslog_spy']   = TRUE;
		$GLOBALS['pfb_test_syslog_calls'] = [];
	}

	protected function tearDown(): void
	{
		unset(
			$GLOBALS['pfb_test_syslog_spy'],
			$GLOBALS['pfb_test_syslog_calls']
		);
		// Wipe any log_syslog config seeded by individual tests.
		config_del_path('installedpackages/pfblockerng/config/0/log_syslog');
	}

	// -----------------------------------------------------------------------
	// Toggle OFF — no emission
	// -----------------------------------------------------------------------

	/**
	 * pfb_syslog_event is a no-op when log_syslog is off.
	 *
	 * Scenario:
	 *   Background: log_syslog toggle follows PfbToggle (off = '').
	 *     Given log_syslog is '' (off, the default).
	 *     When  pfb_syslog_event('act=block dir=in if=em0 ...') is called.
	 *     Then  no syslog call is recorded.
	 */
	public function testToggleOffProducesNoSyslogCall(): void
	{
		// Given: toggle explicitly off.
		config_set_path('installedpackages/pfblockerng/config/0/log_syslog', '');

		// Before: spy installed, no calls yet.
		$this->assertSame([], $GLOBALS['pfb_test_syslog_calls'], 'before: no calls before event');

		// When.
		pfb_syslog_event('act=block dir=in if=em0 proto=TCP src=1.2.3.4 dst=5.6.7.8 ipver=4');

		// Then: no syslog call.
		$calls = $GLOBALS['pfb_test_syslog_calls'] ?? [];
		$this->assertSame([], $calls, 'toggle off: pfb_syslog_event() must produce no syslog call');
	}

	/**
	 * Toggle absent (key not set in config) — treated as off, no emission.
	 *
	 * Scenario:
	 *   Background: PfbConfig returns PfbToggle::Off for absent log_syslog (default '').
	 *     Given log_syslog is absent from config (key not present).
	 *     When  pfb_syslog_event() is called.
	 *     Then  no syslog call is recorded.
	 */
	public function testToggleAbsentProducesNoSyslogCall(): void
	{
		// Before: no log_syslog key in config (setUp already cleared it).

		pfb_syslog_event('act=pass dir=out if=wan proto=UDP src=10.0.0.1 dst=8.8.8.8 ipver=4');

		$calls = $GLOBALS['pfb_test_syslog_calls'] ?? [];
		$this->assertSame([], $calls, 'toggle absent: pfb_syslog_event() must produce no syslog call');
	}

	// -----------------------------------------------------------------------
	// Toggle ON — exactly one call, hardcoded facility LOG_LOCAL6 + severity LOG_INFO
	// -----------------------------------------------------------------------

	/**
	 * pfb_syslog_event emits exactly one syslog call with the supplied body when on.
	 *
	 * Scenario:
	 *   Background: toggle on; facility hardcoded to LOG_LOCAL6, severity to LOG_INFO.
	 *     Given log_syslog is 'on' (PfbToggle::On).
	 *     When  pfb_syslog_event('act=block dir=in ...') is called once.
	 *     Then  exactly one syslog call is recorded.
	 *     And   the recorded body equals the argument passed to pfb_syslog_event().
	 *     And   the ident is 'pfblockerng'.
	 *     And   the facility is LOG_LOCAL6 (hardcoded).
	 *     And   the severity is LOG_INFO (hardcoded).
	 */
	public function testToggleOnEmitsExactlyOneCallWithCorrectBody(): void
	{
		// Before: confirm no calls before enabling.
		$this->assertSame([], $GLOBALS['pfb_test_syslog_calls'], 'before: no calls before toggle on');

		// Given: enable syslog toggle.
		config_set_path('installedpackages/pfblockerng/config/0/log_syslog', 'on');

		$body = 'act=block dir=in if=em0 proto=TCP src=203.0.113.1 dst=192.168.1.1 sport=54321 dport=80 ipver=4 geoip=US alias=pfB_DENY feed=EasyList';

		// When: call once.
		pfb_syslog_event($body);

		// Then: exactly one call.
		$calls = $GLOBALS['pfb_test_syslog_calls'];
		$this->assertCount(1, $calls, 'toggle on: exactly one syslog call per pfb_syslog_event() invocation');

		// And: correct body.
		$this->assertSame($body, $calls[0]['body'], 'toggle on: syslog body equals the argument passed');

		// And: correct ident.
		$this->assertSame('pfblockerng', $calls[0]['ident'], 'toggle on: ident is pfblockerng');

		// And: hardcoded facility LOG_LOCAL6 (not configurable — Amendment 1).
		$this->assertSame(LOG_LOCAL6, $calls[0]['facility'], 'toggle on: facility is hardcoded LOG_LOCAL6');

		// And: hardcoded severity LOG_INFO (not configurable — Amendment 1).
		$this->assertSame(LOG_INFO, $calls[0]['severity'], 'toggle on: severity is hardcoded LOG_INFO');
	}

	/**
	 * pfb_syslog_event called twice emits two records when on.
	 *
	 * Scenario:
	 *   Background: toggle on; two independent events.
	 *     Given log_syslog is 'on'.
	 *     When  pfb_syslog_event() is called twice with different bodies.
	 *     Then  two syslog calls are recorded, each with the correct body.
	 */
	public function testMultipleCallsEachEmitOneRecord(): void
	{
		config_set_path('installedpackages/pfblockerng/config/0/log_syslog', 'on');

		$body1 = 'act=block dir=in if=em0 proto=TCP src=203.0.113.1 dst=10.0.0.1 ipver=4';
		$body2 = 'act=pass dir=out if=wan proto=UDP src=10.0.0.1 dst=8.8.8.8 sport=12345 dport=53 ipver=4';

		// Before: no calls yet.
		$this->assertSame([], $GLOBALS['pfb_test_syslog_calls'], 'before: no calls yet');

		pfb_syslog_event($body1);
		pfb_syslog_event($body2);

		$calls = $GLOBALS['pfb_test_syslog_calls'];
		$this->assertCount(2, $calls, 'two events => two syslog calls');
		$this->assertSame($body1, $calls[0]['body'], 'first call: correct body');
		$this->assertSame($body2, $calls[1]['body'], 'second call: correct body');
	}

	// -----------------------------------------------------------------------
	// Toggle flip: off then on — before/after
	// -----------------------------------------------------------------------

	/**
	 * Flipping the toggle from off to on changes emission — before/after asserted.
	 *
	 * Since pfb_syslog_event() reads the toggle fresh on every call (no static cache),
	 * switching the stored value between calls is sufficient to change behaviour.
	 *
	 * Scenario:
	 *   Background: function reads log_syslog fresh each call.
	 *     Given log_syslog starts as '' (off).
	 *     When  pfb_syslog_event() is called => no emission (before).
	 *     Then  toggle is set to 'on'.
	 *     When  pfb_syslog_event() is called again => one emission (after).
	 *     Then  the change in emission was CAUSED by the toggle flip.
	 */
	public function testToggleFlipOffToOnChangesEmission(): void
	{
		// --- BEFORE: toggle off ---
		config_set_path('installedpackages/pfblockerng/config/0/log_syslog', '');

		pfb_syslog_event('act=block dir=in if=em0 proto=TCP src=1.2.3.4 dst=5.6.7.8 ipver=4');

		$calls_before = $GLOBALS['pfb_test_syslog_calls'];
		$this->assertSame([], $calls_before, 'before flip: no emission when toggle is off');

		// Reset accumulated calls for the next assertion.
		$GLOBALS['pfb_test_syslog_calls'] = [];

		// --- AFTER: toggle on (fresh read, no reset flag needed) ---
		config_set_path('installedpackages/pfblockerng/config/0/log_syslog', 'on');

		$body = 'act=block dir=in if=em0 proto=TCP src=1.2.3.4 dst=5.6.7.8 ipver=4';
		pfb_syslog_event($body);

		$calls_after = $GLOBALS['pfb_test_syslog_calls'];
		$this->assertCount(1, $calls_after, 'after flip: exactly one emission when toggle is on');
		$this->assertSame($body, $calls_after[0]['body'], 'after flip: body matches');
		$this->assertSame(LOG_LOCAL6, $calls_after[0]['facility'], 'after flip: facility is LOG_LOCAL6');
		$this->assertSame(LOG_INFO, $calls_after[0]['severity'], 'after flip: severity is LOG_INFO');
	}
}
