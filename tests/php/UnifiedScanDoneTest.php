<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_alerts_unified_scan_done() -- the Unified-log early-exit predicate added for
 * issue #809 (Alerts page render-time performance) Phase 2. It tells the Unified
 * render loop in pfblockerng_alerts.php when NO converter (convert_dnsbl_log() /
 * convert_dns_reply_log() / convert_ip_log()) can possibly render another row, so
 * the loop can break instead of parsing the rest of the log for nothing.
 *
 * Two independent modes, selected by $filterlogentries:
 *   - non-filter: all three converters share one counter ($counter['Unified']) and
 *     one limit ($pfbentries) -- done as soon as the counter reaches the limit.
 *   - filter: each converter gates on its OWN per-type flag
 *     ($ipfilterlimit/$dnsblfilterlimit/$dnsfilterlimit) -- done only once ALL
 *     THREE are set, mirroring the <tfoot> Unified summary's own
 *     "Filter Limit setting reached" check.
 *
 * Feature: the Unified scan stops exactly when rendering can no longer progress
 *   Background:
 *     Given the shared inputs the render loop already tracks: the running
 *           Unified counter, the view's entry limit, and the three per-type
 *           filter-limit flags
 */
#[CoversFunction('pfb_alerts_unified_scan_done')]
final class UnifiedScanDoneTest extends TestCase
{
	// --- Non-filter mode: done iff $unified_count >= $pfbentries ---------------

	public function testNonFilterModeUnderLimitIsNotDone(): void
	{
		// Given non-filter mode and a counter still below the entries limit,
		$result = pfb_alerts_unified_scan_done(false, 4, 5, false, false, false);

		// Then the scan is not yet done -- more rows may still render.
		$this->assertFalse($result, "expected FALSE for count=4 < limit=5 (non-filter), got [" . var_export($result, true) . "]");
	}

	public function testNonFilterModeExactlyAtLimitIsDone(): void
	{
		// Given the counter has reached exactly the entries limit,
		$result = pfb_alerts_unified_scan_done(false, 5, 5, false, false, false);

		// Then the scan is done: every converter's own `>= $pfbentries` gate would
		// now trip on the very next call, so nothing further can render.
		$this->assertTrue($result, "expected TRUE for count=5 == limit=5 (non-filter), got [" . var_export($result, true) . "]");
	}

	public function testNonFilterModeOverLimitIsDone(): void
	{
		// Given the counter has already gone past the limit (can happen once the
		// last accepted row's increment crosses it),
		$result = pfb_alerts_unified_scan_done(false, 9, 5, false, false, false);

		// Then the scan is done.
		$this->assertTrue($result, "expected TRUE for count=9 > limit=5 (non-filter), got [" . var_export($result, true) . "]");
	}

	public function testNonFilterModeIgnoresFilterFlags(): void
	{
		// Given non-filter mode with the count still under the limit, but ALL
		// THREE filter-limit flags already TRUE (they belong to filter mode and
		// must not leak into this decision),
		$result = pfb_alerts_unified_scan_done(false, 0, 5, true, true, true);

		// Then the scan is still not done -- the mode split must be a genuine
		// branch, not an "any flag/counter" always-done shortcut.
		$this->assertFalse($result, "expected FALSE: non-filter mode must ignore the filter flags entirely, got [" . var_export($result, true) . "]");
	}

	// --- Filter mode: done iff ipfilterlimit && dnsblfilterlimit && dnsfilterlimit -

	public function testFilterModeNoFlagsSetIsNotDone(): void
	{
		// Given filter mode with none of the three per-type limits reached yet,
		$result = pfb_alerts_unified_scan_done(true, 0, 5, false, false, false);

		// Then the scan is not done.
		$this->assertFalse($result, "expected FALSE for no flags set (filter mode), got [" . var_export($result, true) . "]");
	}

	public function testFilterModeOnlyIpFlagIsNotDone(): void
	{
		// Given only the IP-type limit reached (DNSBL/DNS rows can still render),
		$result = pfb_alerts_unified_scan_done(true, 0, 5, true, false, false);

		$this->assertFalse($result, "expected FALSE with only ipfilterlimit set, got [" . var_export($result, true) . "]");
	}

	public function testFilterModeOnlyDnsblFlagIsNotDone(): void
	{
		// Given only the DNSBL-type limit reached (IP/DNS rows can still render),
		$result = pfb_alerts_unified_scan_done(true, 0, 5, false, true, false);

		$this->assertFalse($result, "expected FALSE with only dnsblfilterlimit set, got [" . var_export($result, true) . "]");
	}

	public function testFilterModeOnlyDnsFlagIsNotDone(): void
	{
		// Given only the DNS-reply-type limit reached (IP/DNSBL rows can still render),
		$result = pfb_alerts_unified_scan_done(true, 0, 5, false, false, true);

		$this->assertFalse($result, "expected FALSE with only dnsfilterlimit set, got [" . var_export($result, true) . "]");
	}

	public function testFilterModeIpAndDnsblPairIsNotDone(): void
	{
		// Given two of three flags set (DNS-reply rows can still render),
		$result = pfb_alerts_unified_scan_done(true, 0, 5, true, true, false);

		$this->assertFalse($result, "expected FALSE with ip+dnsbl set but dns unset, got [" . var_export($result, true) . "]");
	}

	public function testFilterModeIpAndDnsPairIsNotDone(): void
	{
		// Given two of three flags set (DNSBL rows can still render),
		$result = pfb_alerts_unified_scan_done(true, 0, 5, true, false, true);

		$this->assertFalse($result, "expected FALSE with ip+dns set but dnsbl unset, got [" . var_export($result, true) . "]");
	}

	public function testFilterModeDnsblAndDnsPairIsNotDone(): void
	{
		// Given two of three flags set (IP rows can still render),
		$result = pfb_alerts_unified_scan_done(true, 0, 5, false, true, true);

		$this->assertFalse($result, "expected FALSE with dnsbl+dns set but ip unset, got [" . var_export($result, true) . "]");
	}

	public function testFilterModeAllThreeFlagsIsDone(): void
	{
		// Given all three per-type limits reached -- no type can render anymore,
		$result = pfb_alerts_unified_scan_done(true, 0, 5, true, true, true);

		// Then the scan is done, matching the <tfoot> Unified summary's own
		// "Filter Limit setting reached" condition exactly.
		$this->assertTrue($result, "expected TRUE with ip+dnsbl+dns all set (filter mode), got [" . var_export($result, true) . "]");
	}

	public function testFilterModeIgnoresTheCounter(): void
	{
		// Given filter mode with the shared Unified counter already at/above
		// $pfbentries (a value filter mode never consults) but NOT all three
		// per-type flags set,
		$result = pfb_alerts_unified_scan_done(true, 99, 5, true, true, false);

		// Then the scan is still not done -- filter mode must never fall back to
		// the non-filter counter check.
		$this->assertFalse($result, "expected FALSE: filter mode must ignore \$unified_count/\$pfbentries entirely, got [" . var_export($result, true) . "]");
	}
}
