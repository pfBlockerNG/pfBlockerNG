<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * ADR-19 Phase 2 — the PURE software-update decision core in pfblockerng.inc.
 *
 * Pins every branch of the channel/provenance/version/notify deciders behind the
 * Software tab + the cron new-version notice: strings in, decisions out (no GUI,
 * no cron, no pkg IO). Each toggle/mode/input-class is asserted on BOTH sides, and
 * the de-dupe state machine carries a BDD Given/When/Then lifecycle with the
 * before-state asserted at each tick so green proves the transition CAUSED the flip.
 */
#[CoversFunction('pfb_channel_from_pkgname')]
#[CoversFunction('pfb_pkg_repo_name_for_channel')]
#[CoversFunction('pfb_software_is_our_build')]
#[CoversFunction('pfb_update_available')]
#[CoversFunction('pfb_software_check_enabled')]
#[CoversFunction('pfb_should_notify')]
final class SoftwareUpdateDecisionTest extends TestCase
{
	/*
	 * ---- pfb_channel_from_pkgname() — package name -> channel ----
	 * The installed package name is authoritative for "what channel am I on". Each of
	 * the three shipped names maps to its channel; anything else (incl. empty/null) is
	 * an UNKNOWN channel -> null, the safe default (no feature without a known channel).
	 */
	public static function channelProvider(): array
	{
		return [
			'stable: bare release name'   => ['pfSense-pkg-pfBlockerNG', 'stable'],
			'devel: -devel suffix'        => ['pfSense-pkg-pfBlockerNG-devel', 'devel'],
			'nightly: -NIGHTLY suffix'    => ['pfSense-pkg-pfBlockerNG-NIGHTLY', 'nightly'],
			'nightly: case-insensitive'   => ['pfSense-pkg-pfBlockerNG-nightly', 'nightly'],
			'devel: case-insensitive'     => ['PFSENSE-PKG-PFBLOCKERNG-DEVEL', 'devel'],
			'unknown: other package'      => ['pfSense-pkg-suricata', null],
			'unknown: foreign suffix'     => ['pfSense-pkg-pfBlockerNG-beta', null],
			'unknown: empty string'       => ['', null],
			'unknown: null'               => [null, null],
		];
	}

	#[DataProvider('channelProvider')]
	public function testChannelFromPkgname(?string $name, ?string $expected): void
	{
		$this->assertSame($expected, pfb_channel_from_pkgname($name));
	}

	/*
	 * ---- pfb_pkg_repo_name_for_channel() — channel -> our repo to read latest from ----
	 * 2026-06-14 + 2026-06-15 amendments: stable AND devel share ONE repo 'pfblockerng'
	 * (the channel selects the package, not a per-channel repo); 'nightly' is the sole
	 * separately-channelled build, repo 'pfblockerng-nightly'. Unknown channel -> null.
	 */
	public static function repoForChannelProvider(): array
	{
		return [
			'stable -> shared pfblockerng'  => ['stable', 'pfblockerng'],
			'devel -> shared pfblockerng'   => ['devel', 'pfblockerng'],
			'nightly -> pfblockerng-nightly' => ['nightly', 'pfblockerng-nightly'],
			'unknown channel -> null'        => ['beta', null],
			'null channel -> null'           => [null, null],
		];
	}

	#[DataProvider('repoForChannelProvider')]
	public function testRepoNameForChannel(?string $channel, ?string $expected): void
	{
		$this->assertSame($expected, pfb_pkg_repo_name_for_channel($channel));
	}

	/*
	 * ---- pfb_software_is_our_build() — the provenance gate (2026-06-15) ----
	 * TRUE only for a build installed FROM one of OUR repos ('pfblockerng' /
	 * 'pfblockerng-nightly', the `pkg query %R` origin). A Netgate-installed add-on
	 * (repo 'pfSense'), an empty/'unknown' origin, or anything else -> FALSE. Both sides
	 * pinned: this single predicate gates the tab, the page guard, the priv match[] line,
	 * AND the cron notice, so a false positive would leak the whole feature onto a stock
	 * build and a false negative would hide it from our users.
	 */
	public static function provenanceProvider(): array
	{
		return [
			// Ours -> present.
			'ours: pfblockerng (stable+devel)'   => ['pfblockerng', true],
			'ours: pfblockerng-nightly'          => ['pfblockerng-nightly', true],
			// Not ours -> absent.
			'netgate: pfSense repo'              => ['pfSense', false],
			'empty origin'                       => ['', false],
			'literal unknown'                    => ['unknown', false],
			'null origin'                        => [null, false],
			'foreign repo'                       => ['netgate-decoy', false],
		];
	}

	#[DataProvider('provenanceProvider')]
	public function testSoftwareIsOurBuild(?string $installedRepo, bool $expected): void
	{
		$this->assertSame($expected, pfb_software_is_our_build($installedRepo));
	}

	/*
	 * ---- pfb_update_available() — latest strictly newer than installed? ----
	 * Via pkg_version_compare (never a string compare). Newer -> true; equal/older ->
	 * false; an empty/missing installed or latest -> false (never "an update is
	 * available"). Nightly's dated versions compare nightly-to-nightly.
	 */
	public static function availableProvider(): array
	{
		return [
			'newer latest -> available'        => ['3.2.0_5', '3.2.0_6', true],
			'newer minor -> available'         => ['3.2.0', '3.2.1', true],
			'equal -> not available'           => ['3.2.0', '3.2.0', false],
			'older latest -> not available'    => ['3.2.0_6', '3.2.0_5', false],
			'nightly newer date -> available'  => ['20260101', '20260615', true],
			'nightly same date -> not avail'   => ['20260615', '20260615', false],
			'nightly older date -> not avail'  => ['20260615', '20260101', false],
			'empty installed -> not available' => ['', '3.2.1', false],
			'empty latest -> not available'    => ['3.2.0', '', false],
			'null installed -> not available'  => [null, '3.2.1', false],
			'null latest -> not available'     => ['3.2.0', null, false],
		];
	}

	#[DataProvider('availableProvider')]
	public function testUpdateAvailable(?string $installed, ?string $latest, bool $expected): void
	{
		$this->assertSame($expected, pfb_update_available($installed, $latest));
	}

	/*
	 * ---- pfb_software_check_enabled() — the single "Check for new versions" boolean ----
	 * Default ENABLED: only an explicit 'off' (the user un-ticking the box, persisted by the
	 * page) disables it. An unset value (null, never saved), 'on', or any other string reads
	 * as enabled. Both sides asserted so green proves 'off' is a real disabling branch, not an
	 * always-enabled path.
	 */
	public static function checkEnabledProvider(): array
	{
		return [
			'unset (never saved) -> enabled' => [null, true],
			'on -> enabled'                  => ['on', true],
			'off -> disabled'                => ['off', false],
			'empty string -> enabled'        => ['', true],
			'legacy/other -> enabled'        => ['default', true],
		];
	}

	#[DataProvider('checkEnabledProvider')]
	public function testCheckEnabled(?string $raw, bool $expected): void
	{
		$this->assertSame($expected, pfb_software_check_enabled($raw));
	}

	/*
	 * ---- pfb_should_notify() — the enabled x available x de-dupe matrix ----
	 * A notice fires ONLY when checking is enabled AND an update is available AND it has not
	 * already been notified for this exact latest. The matrix pins each clause on BOTH sides:
	 *   - enabled true + available + new -> notify;
	 *   - enabled false suppresses even when available + new (the gate);
	 *   - enabled true but not available -> silent;
	 *   - enabled true + available but already notified -> silent (de-dupe).
	 * Notifications are channel-agnostic now (the single boolean gates every channel equally),
	 * so there is no per-channel default to assert here.
	 */
	public static function shouldNotifyMatrixProvider(): array
	{
		// [installed, latest, last_notified, enabled, expected]
		return [
			'enabled + available + new -> notify'        => ['1.0', '1.1', '', true, true],
			'disabled + available + new -> silent'       => ['1.0', '1.1', '', false, false],
			'enabled + not available -> silent'          => ['1.0', '1.0', '', true, false],
			'disabled + not available -> silent'         => ['1.0', '1.0', '', false, false],
			'enabled + available + already notified -> silent' => ['1.0', '1.1', '1.1', true, false],
			'enabled + older latest -> silent'           => ['1.1', '1.0', '', true, false],
		];
	}

	#[DataProvider('shouldNotifyMatrixProvider')]
	public function testShouldNotifyMatrix(
		?string $installed,
		?string $latest,
		?string $lastNotified,
		bool $enabled,
		bool $expected
	): void {
		$this->assertSame(
			$expected,
			pfb_should_notify($installed, $latest, $lastNotified, $enabled)
		);
	}

	/*
	 * ---- pfb_should_notify() — the per-version de-dupe lifecycle (BDD) ----
	 *
	 * Scenario: a daily cron must notify ONCE per new version, not once per tick.
	 *   Background: checking ENABLED so only the de-dupe clause varies. installed stays '1.0';
	 *               the catalog's latest advances over time.
	 *
	 *   GIVEN nothing has been notified yet (last_notified empty) and a newer latest 1.1
	 *    THEN the first tick notifies (the before-state: no prior notice).
	 *   WHEN that 1.1 has been recorded as last_notified and the same tick repeats
	 *    THEN it does NOT renotify (the before-state: already notified for 1.1).
	 *   WHEN a yet-newer latest 1.2 arrives (last_notified still 1.1)
	 *    THEN it notifies again (the before-state: 1.2 not yet notified).
	 *   WHEN 1.2 is then recorded and its tick repeats
	 *    THEN it does NOT renotify.
	 */
	public function testShouldNotifyDeDupeLifecycle(): void
	{
		$installed = '1.0';
		$enabled = true;

		// GIVEN never-notified + a newer latest 1.1 -> first tick notifies.
		$lastNotified = '';
		$this->assertTrue(
			pfb_should_notify($installed, '1.1', $lastNotified, $enabled),
			'first sighting of 1.1 must notify'
		);

		// WHEN 1.1 recorded as last_notified -> the SAME tick must not renotify.
		$lastNotified = '1.1';
		$this->assertFalse(
			pfb_should_notify($installed, '1.1', $lastNotified, $enabled),
			'a repeat tick at the already-notified 1.1 must NOT renotify (de-dupe)'
		);

		// WHEN a newer latest 1.2 arrives (last_notified still 1.1) -> notify again.
		// Before-state: re-assert the 1.1 tick is still suppressed so the flip is caused
		// by the newer version, not by time.
		$this->assertFalse(
			pfb_should_notify($installed, '1.1', $lastNotified, $enabled),
			'before the newer version, 1.1 is still de-duped'
		);
		$this->assertTrue(
			pfb_should_notify($installed, '1.2', $lastNotified, $enabled),
			'a newer 1.2 (not yet notified) must notify again'
		);

		// WHEN 1.2 recorded -> its repeat tick is de-duped again.
		$lastNotified = '1.2';
		$this->assertFalse(
			pfb_should_notify($installed, '1.2', $lastNotified, $enabled),
			'a repeat tick at the already-notified 1.2 must NOT renotify'
		);
	}
}
