<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * ADR-38 Phase 2 — pfb_syslog_facility_constant() / pfb_syslog_priority_constant() tests.
 *
 * Two pure helpers mapping stored Snort-style tokens to PHP LOG_* constants.
 * Tests cover: every vocabulary token → expected constant; unknown token → safe default.
 *
 * Scenario: every stored token maps to a distinct, non-zero (or zero for LOG_EMERG/LOG_KERN)
 *   PHP syslog constant; an unknown token falls back to the documented safe default.
 */
final class SyslogFacilityMapTest extends TestCase
{
	// -----------------------------------------------------------------------
	// pfb_syslog_facility_constant — full vocabulary
	// -----------------------------------------------------------------------

	/**
	 * Every Snort-style facility token maps to the expected PHP LOG_* constant.
	 *
	 * Scenario:
	 *   Background: pfb_syslog_facility_constant() maps stored tokens.
	 *     Given each token in the documented facility vocabulary.
	 *     When pfb_syslog_facility_constant($token).
	 *     Then the returned value equals the expected PHP LOG_* constant.
	 */
	public function testFacilityKernMapsToLogKern(): void
	{
		$this->assertSame(LOG_KERN, pfb_syslog_facility_constant('log_kern'));
	}

	public function testFacilityUserMapsToLogUser(): void
	{
		$this->assertSame(LOG_USER, pfb_syslog_facility_constant('log_user'));
	}

	public function testFacilityMailMapsToLogMail(): void
	{
		$this->assertSame(LOG_MAIL, pfb_syslog_facility_constant('log_mail'));
	}

	public function testFacilityDaemonMapsToLogDaemon(): void
	{
		$this->assertSame(LOG_DAEMON, pfb_syslog_facility_constant('log_daemon'));
	}

	public function testFacilityAuthMapsToLogAuth(): void
	{
		$this->assertSame(LOG_AUTH, pfb_syslog_facility_constant('log_auth'));
	}

	public function testFacilitySyslogMapsToLogSyslog(): void
	{
		$this->assertSame(LOG_SYSLOG, pfb_syslog_facility_constant('log_syslog'));
	}

	public function testFacilityLprMapsToLogLpr(): void
	{
		$this->assertSame(LOG_LPR, pfb_syslog_facility_constant('log_lpr'));
	}

	public function testFacilityNewsMapsToLogNews(): void
	{
		$this->assertSame(LOG_NEWS, pfb_syslog_facility_constant('log_news'));
	}

	public function testFacilityUucpMapsToLogUucp(): void
	{
		$this->assertSame(LOG_UUCP, pfb_syslog_facility_constant('log_uucp'));
	}

	public function testFacilityCronMapsToLogCron(): void
	{
		$this->assertSame(LOG_CRON, pfb_syslog_facility_constant('log_cron'));
	}

	public function testFacilityLocal0MapsToLogLocal0(): void
	{
		$this->assertSame(LOG_LOCAL0, pfb_syslog_facility_constant('log_local0'));
	}

	public function testFacilityLocal1MapsToLogLocal1(): void
	{
		$this->assertSame(LOG_LOCAL1, pfb_syslog_facility_constant('log_local1'));
	}

	public function testFacilityLocal2MapsToLogLocal2(): void
	{
		$this->assertSame(LOG_LOCAL2, pfb_syslog_facility_constant('log_local2'));
	}

	public function testFacilityLocal3MapsToLogLocal3(): void
	{
		$this->assertSame(LOG_LOCAL3, pfb_syslog_facility_constant('log_local3'));
	}

	public function testFacilityLocal4MapsToLogLocal4(): void
	{
		$this->assertSame(LOG_LOCAL4, pfb_syslog_facility_constant('log_local4'));
	}

	public function testFacilityLocal5MapsToLogLocal5(): void
	{
		$this->assertSame(LOG_LOCAL5, pfb_syslog_facility_constant('log_local5'));
	}

	/**
	 * log_local6 is the registered default facility — maps to LOG_LOCAL6.
	 *
	 * This is also the safe default for unknown tokens (see testFacilityUnknownTokenDefaultsToLocal6).
	 */
	public function testFacilityLocal6MapsToLogLocal6(): void
	{
		// Before: the function exists and is pure.
		$this->assertTrue(function_exists('pfb_syslog_facility_constant'));

		// When/Then: log_local6 → LOG_LOCAL6.
		$this->assertSame(LOG_LOCAL6, pfb_syslog_facility_constant('log_local6'));
	}

	public function testFacilityLocal7MapsToLogLocal7(): void
	{
		$this->assertSame(LOG_LOCAL7, pfb_syslog_facility_constant('log_local7'));
	}

	// -----------------------------------------------------------------------
	// pfb_syslog_facility_constant — unknown token → safe default
	// -----------------------------------------------------------------------

	/**
	 * An unknown facility token returns LOG_LOCAL6 (the safe default, not a crash).
	 *
	 * Scenario:
	 *   Background: a syslog export config from an older package version may carry
	 *     a token that this version does not recognise.
	 *     Given an unrecognised facility token.
	 *     When pfb_syslog_facility_constant($token).
	 *     Then LOG_LOCAL6 is returned (the registered default; no crash).
	 */
	public function testFacilityUnknownTokenDefaultsToLocal6(): void
	{
		// Before: confirm LOG_LOCAL6 is non-zero (not confused with a failure code).
		$this->assertNotSame(0, LOG_LOCAL6);

		// When: unknown token.
		$result = pfb_syslog_facility_constant('log_totally_unknown');

		// Then: LOG_LOCAL6 (safe default, not a crash).
		$this->assertSame(LOG_LOCAL6, $result,
			'Unknown facility token must fall back to LOG_LOCAL6 (registered default)'
		);

		// And: empty string (missing config) also falls back.
		$result_empty = pfb_syslog_facility_constant('');
		$this->assertSame(LOG_LOCAL6, $result_empty,
			'Empty facility token must fall back to LOG_LOCAL6'
		);
	}

	// -----------------------------------------------------------------------
	// pfb_syslog_priority_constant — full vocabulary
	// -----------------------------------------------------------------------

	/**
	 * Every Snort-style severity token maps to the expected PHP LOG_* constant.
	 *
	 * Scenario:
	 *   Background: pfb_syslog_priority_constant() maps stored tokens.
	 *     Given each token in the documented severity vocabulary.
	 *     When pfb_syslog_priority_constant($token).
	 *     Then the returned value equals the expected PHP LOG_* constant.
	 */
	public function testPriorityEmergMapsToLogEmerg(): void
	{
		$this->assertSame(LOG_EMERG, pfb_syslog_priority_constant('log_emerg'));
	}

	public function testPriorityAlertMapsToLogAlert(): void
	{
		$this->assertSame(LOG_ALERT, pfb_syslog_priority_constant('log_alert'));
	}

	public function testPriorityCritMapsToLogCrit(): void
	{
		$this->assertSame(LOG_CRIT, pfb_syslog_priority_constant('log_crit'));
	}

	public function testPriorityErrMapsToLogErr(): void
	{
		$this->assertSame(LOG_ERR, pfb_syslog_priority_constant('log_err'));
	}

	public function testPriorityWarningMapsToLogWarning(): void
	{
		$this->assertSame(LOG_WARNING, pfb_syslog_priority_constant('log_warning'));
	}

	/**
	 * log_notice is the registered default severity — maps to LOG_NOTICE.
	 *
	 * Also the safe default for unknown tokens (testPriorityUnknownTokenDefaultsToNotice).
	 */
	public function testPriorityNoticeMapsToLogNotice(): void
	{
		// Before: the function exists.
		$this->assertTrue(function_exists('pfb_syslog_priority_constant'));

		// When/Then: log_notice → LOG_NOTICE.
		$this->assertSame(LOG_NOTICE, pfb_syslog_priority_constant('log_notice'));
	}

	public function testPriorityInfoMapsToLogInfo(): void
	{
		$this->assertSame(LOG_INFO, pfb_syslog_priority_constant('log_info'));
	}

	public function testPriorityDebugMapsToLogDebug(): void
	{
		$this->assertSame(LOG_DEBUG, pfb_syslog_priority_constant('log_debug'));
	}

	// -----------------------------------------------------------------------
	// pfb_syslog_priority_constant — unknown token → safe default
	// -----------------------------------------------------------------------

	/**
	 * An unknown severity token returns LOG_NOTICE (the safe default, not a crash).
	 *
	 * Scenario:
	 *   Background: a syslog export config from an older package version may carry
	 *     a token that this version does not recognise.
	 *     Given an unrecognised severity token.
	 *     When pfb_syslog_priority_constant($token).
	 *     Then LOG_NOTICE is returned (the registered default; no crash).
	 */
	public function testPriorityUnknownTokenDefaultsToNotice(): void
	{
		// Before: LOG_NOTICE is the registered default.
		$this->assertSame(5, LOG_NOTICE);   // sanity — not confused with success/failure

		// When: unknown token.
		$result = pfb_syslog_priority_constant('log_totally_unknown');

		// Then: LOG_NOTICE (safe default, not a crash).
		$this->assertSame(LOG_NOTICE, $result,
			'Unknown severity token must fall back to LOG_NOTICE (registered default)'
		);

		// And: empty string (missing config) also falls back.
		$result_empty = pfb_syslog_priority_constant('');
		$this->assertSame(LOG_NOTICE, $result_empty,
			'Empty severity token must fall back to LOG_NOTICE'
		);
	}

	// -----------------------------------------------------------------------
	// Cross-check: facility and priority maps are disjoint token sets
	// -----------------------------------------------------------------------

	/**
	 * No facility token is a valid priority token, and vice versa (disjoint vocabularies).
	 *
	 * Scenario:
	 *   Background: Snort separates facility and severity namespaces.
	 *     Given the two vocabulary sets.
	 *     When computing their intersection.
	 *     Then it is empty (no shared token would silently resolve to the wrong constant).
	 */
	public function testFacilityAndPriorityVocabulariesAreDisjoint(): void
	{
		$facility_tokens = [
			'log_kern', 'log_user', 'log_mail', 'log_daemon', 'log_auth', 'log_syslog',
			'log_lpr', 'log_news', 'log_uucp', 'log_cron',
			'log_local0', 'log_local1', 'log_local2', 'log_local3',
			'log_local4', 'log_local5', 'log_local6', 'log_local7',
		];
		$priority_tokens = [
			'log_emerg', 'log_alert', 'log_crit', 'log_err',
			'log_warning', 'log_notice', 'log_info', 'log_debug',
		];

		$intersection = array_intersect($facility_tokens, $priority_tokens);
		$this->assertEmpty(
			$intersection,
			'Facility and priority vocabulary sets must not overlap: '
			. implode(', ', $intersection)
		);
	}
}
