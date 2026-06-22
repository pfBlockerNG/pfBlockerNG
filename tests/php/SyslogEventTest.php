<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-38 Phase 3 — pfb_syslog_event() tests.
 *
 * pfb_syslog_event() is the PHP IP-leg syslog emitter.  It reads the toggle,
 * facility, and severity from PfbConfig once per process (static cache, resettable
 * via $GLOBALS['pfb_test_syslog_reset']).  The test-spy path records calls in
 * $GLOBALS['pfb_test_syslog_calls'] when $GLOBALS['pfb_test_syslog_spy'] is set.
 *
 * Contract under test (ADR-38 §2.2):
 *   - Toggle OFF  ⇒ zero syslog calls (no emission, no side effect).
 *   - Toggle ON   ⇒ exactly one call per pfb_syslog_event() invocation, with the
 *                   exact body passed, the configured facility, and the configured
 *                   severity.
 */
final class SyslogEventTest extends TestCase
{
	/** Seed config + reset the static cache between every test. */
	protected function setUp(): void
	{
		// Install the spy so real syslog() is never called in tests.
		$GLOBALS['pfb_test_syslog_spy']   = TRUE;
		$GLOBALS['pfb_test_syslog_calls'] = [];
		// Force the static cache to re-read from config on the next call.
		$GLOBALS['pfb_test_syslog_reset'] = TRUE;
	}

	protected function tearDown(): void
	{
		unset(
			$GLOBALS['pfb_test_syslog_spy'],
			$GLOBALS['pfb_test_syslog_calls'],
			$GLOBALS['pfb_test_syslog_reset']
		);
		// Wipe config seeded by individual tests.
		config_del_path('installedpackages/pfblockerng/config/0/log_syslog');
		config_del_path('installedpackages/pfblockerng/config/0/log_syslog_facility');
		config_del_path('installedpackages/pfblockerng/config/0/log_syslog_priority');
		// Reset the static cache one more time so next test starts clean.
		$GLOBALS['pfb_test_syslog_reset'] = TRUE;
		pfb_syslog_event('__teardown_reset__');
		unset($GLOBALS['pfb_test_syslog_reset'], $GLOBALS['pfb_test_syslog_calls'], $GLOBALS['pfb_test_syslog_spy']);
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
		// Before: seed toggle explicitly as off; spy installed by setUp().
		config_set_path('installedpackages/pfblockerng/config/0/log_syslog', '');
		// Force re-read of config (cache was reset in setUp).

		// When: call the emitter with a realistic body.
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
	// Toggle ON — exactly one call, correct body + facility + severity
	// -----------------------------------------------------------------------

	/**
	 * pfb_syslog_event emits exactly one syslog call with the supplied body when on.
	 *
	 * Scenario:
	 *   Background: toggle on, default facility (log_local6) and severity (log_notice).
	 *     Given log_syslog is 'on' (PfbToggle::On).
	 *     When  pfb_syslog_event('act=block dir=in ...') is called once.
	 *     Then  exactly one syslog call is recorded.
	 *     And   the recorded body equals the argument passed to pfb_syslog_event().
	 *     And   the ident is 'pfblockerng'.
	 *     And   the facility is LOG_LOCAL6 (the default).
	 *     And   the severity is LOG_NOTICE (the default).
	 */
	public function testToggleOnEmitsExactlyOneCallWithCorrectBody(): void
	{
		// Before: confirm no calls before enabling.
		$this->assertSame([], $GLOBALS['pfb_test_syslog_calls'], 'before: no calls before toggle on');

		// Given: enable syslog with default facility/severity.
		config_set_path('installedpackages/pfblockerng/config/0/log_syslog', 'on');
		// log_syslog_facility and log_syslog_priority absent → defaults.

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

		// And: default facility (log_syslog_facility absent → LOG_LOCAL6).
		$this->assertSame(LOG_LOCAL6, $calls[0]['facility'], 'toggle on: default facility is LOG_LOCAL6');

		// And: default severity (log_syslog_priority absent → LOG_NOTICE).
		$this->assertSame(LOG_NOTICE, $calls[0]['severity'], 'toggle on: default severity is LOG_NOTICE');
	}

	/**
	 * pfb_syslog_event respects a non-default facility token.
	 *
	 * Scenario:
	 *   Background: toggle on, facility overridden to log_local2.
	 *     Given log_syslog_facility is 'log_local2'.
	 *     When  pfb_syslog_event() is called.
	 *     Then  the recorded facility is LOG_LOCAL2.
	 */
	public function testConfiguredFacilityIsUsed(): void
	{
		config_set_path('installedpackages/pfblockerng/config/0/log_syslog', 'on');
		config_set_path('installedpackages/pfblockerng/config/0/log_syslog_facility', 'log_local2');

		pfb_syslog_event('act=pass dir=out if=em0 proto=UDP src=192.168.1.10 dst=8.8.8.8 ipver=4');

		$calls = $GLOBALS['pfb_test_syslog_calls'];
		$this->assertCount(1, $calls, 'non-default facility: exactly one call');
		$this->assertSame(LOG_LOCAL2, $calls[0]['facility'], 'non-default facility: LOG_LOCAL2 used');
	}

	/**
	 * pfb_syslog_event respects a non-default severity token.
	 *
	 * Scenario:
	 *   Background: toggle on, severity overridden to log_warning.
	 *     Given log_syslog_priority is 'log_warning'.
	 *     When  pfb_syslog_event() is called.
	 *     Then  the recorded severity is LOG_WARNING.
	 */
	public function testConfiguredSeverityIsUsed(): void
	{
		config_set_path('installedpackages/pfblockerng/config/0/log_syslog', 'on');
		config_set_path('installedpackages/pfblockerng/config/0/log_syslog_priority', 'log_warning');

		pfb_syslog_event('act=block dir=in if=em0 proto=TCP src=198.51.100.5 dst=10.0.0.1 ipver=4');

		$calls = $GLOBALS['pfb_test_syslog_calls'];
		$this->assertCount(1, $calls, 'non-default severity: exactly one call');
		$this->assertSame(LOG_WARNING, $calls[0]['severity'], 'non-default severity: LOG_WARNING used');
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

		pfb_syslog_event($body1);
		pfb_syslog_event($body2);

		$calls = $GLOBALS['pfb_test_syslog_calls'];
		$this->assertCount(2, $calls, 'two events → two syslog calls');
		$this->assertSame($body1, $calls[0]['body'], 'first call: correct body');
		$this->assertSame($body2, $calls[1]['body'], 'second call: correct body');
	}

	// -----------------------------------------------------------------------
	// Toggle flip: off then on — before/after
	// -----------------------------------------------------------------------

	/**
	 * Flipping the toggle from off to on changes emission — before/after asserted.
	 *
	 * Scenario:
	 *   Background: static cache re-read after reset.
	 *     Given log_syslog starts as '' (off).
	 *     When  pfb_syslog_event() is called → no emission (before).
	 *     Then  toggle is set to 'on' and cache is reset.
	 *     When  pfb_syslog_event() is called again → one emission (after).
	 *     Then  the change in emission was CAUSED by the toggle flip.
	 */
	public function testToggleFlipOffToOnChangesEmission(): void
	{
		// --- BEFORE: toggle off ---
		config_set_path('installedpackages/pfblockerng/config/0/log_syslog', '');

		pfb_syslog_event('act=block dir=in if=em0 proto=TCP src=1.2.3.4 dst=5.6.7.8 ipver=4');

		$calls_before = $GLOBALS['pfb_test_syslog_calls'];
		$this->assertSame([], $calls_before, 'before flip: no emission when toggle is off');

		// Reset for next state.
		$GLOBALS['pfb_test_syslog_calls'] = [];
		$GLOBALS['pfb_test_syslog_reset'] = TRUE;

		// --- AFTER: toggle on ---
		config_set_path('installedpackages/pfblockerng/config/0/log_syslog', 'on');

		$body = 'act=block dir=in if=em0 proto=TCP src=1.2.3.4 dst=5.6.7.8 ipver=4';
		pfb_syslog_event($body);

		$calls_after = $GLOBALS['pfb_test_syslog_calls'];
		$this->assertCount(1, $calls_after, 'after flip: exactly one emission when toggle is on');
		$this->assertSame($body, $calls_after[0]['body'], 'after flip: body matches');
	}
}
