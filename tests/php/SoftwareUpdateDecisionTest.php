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
#[CoversFunction('pfb_channel_from_repo_name')]
#[CoversFunction('pfb_channel_for_install')]
#[CoversFunction('pfb_software_cache_matches_repo')]
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
			'testing: -testing suffix'    => ['pfSense-pkg-pfBlockerNG-testing', 'testing'],
			'edge: -edge suffix'          => ['pfSense-pkg-pfBlockerNG-edge', 'edge'],
			'edge: case-insensitive'      => ['PFSENSE-PKG-PFBLOCKERNG-EDGE', 'edge'],
			'testing: case-insensitive'   => ['PFSENSE-PKG-PFBLOCKERNG-TESTING', 'testing'],
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
	 * ---- pfb_channel_from_repo_name() — installed repo -> channel (issue #2148) ----
	 * Four-channel cutover: every channel catalogue publishes the ONE canonical identity
	 * 'pfSense-pkg-pfBlockerNG', so the NAME can no longer say which channel a box is on —
	 * the repository it was installed from (`pkg query %R`) is authoritative. Each of the
	 * four per-channel repos maps to its channel; the LEGACY shared 'pfblockerng' repo maps
	 * to null ON PURPOSE (it carries both the stable and -devel identities, so there the
	 * name still discriminates and the caller must fall back to pfb_channel_from_pkgname()).
	 * A foreign repo, '', null and a near-miss like 'pfblockerng-edgey' are all null: an
	 * unknown catalogue must never be read as a channel.
	 */
	public static function channelFromRepoNameProvider(): array
	{
		return [
			'stable catalogue'            => ['pfblockerng-stable', 'stable'],
			'testing catalogue'           => ['pfblockerng-testing', 'testing'],
			'edge catalogue'              => ['pfblockerng-edge', 'edge'],
			'nightly catalogue'           => ['pfblockerng-nightly', 'nightly'],
			'legacy shared repo -> null'  => ['pfblockerng', null],
			'near-miss suffix -> null'    => ['pfblockerng-edgey', null],
			'foreign prefix -> null'      => ['other-pfblockerng-edge', null],
			'netgate repo -> null'        => ['pfSense', null],
			'empty repo -> null'          => ['', null],
			'null repo -> null'           => [null, null],
		];
	}

	#[DataProvider('channelFromRepoNameProvider')]
	public function testChannelFromRepoName(?string $repo, ?string $expected): void
	{
		$this->assertSame($expected, pfb_channel_from_repo_name($repo));
	}

	/*
	 * ---- pfb_channel_for_install() — the ONE derivation both callers use (issue #2148) ----
	 * The Software page label and the cron notice text must never disagree about what
	 * channel a box is on, so the repo-first/name-fallback composition lives in one
	 * function rather than as a repeated expression at each call site. Pinned here on all
	 * three outcomes: the repo decides when it names a channel, the name decides when the
	 * repo is the legacy shared catalogue (or is absent, as on a sideloaded `pkg add`),
	 * and neither recognising the install yields null for the caller to render 'unknown'.
	 */
	public static function channelForInstallProvider(): array
	{
		return [
			// The repo WINS over the name: this is the whole point of the cutover — the
			// canonical identity lives in every catalogue, so the name would say 'stable'.
			'edge catalogue beats the canonical name' => ['pfblockerng-edge', 'pfSense-pkg-pfBlockerNG', 'edge'],
			'testing catalogue beats the name'        => ['pfblockerng-testing', 'pfSense-pkg-pfBlockerNG', 'testing'],
			// Legacy shared repo: it names no channel, so the NAME still discriminates.
			'legacy repo falls back to -devel'        => ['pfblockerng', 'pfSense-pkg-pfBlockerNG-devel', 'devel'],
			'legacy repo falls back to canonical'     => ['pfblockerng', 'pfSense-pkg-pfBlockerNG', 'stable'],
			// A sideloaded `pkg add` records no repo at all — the Tier-A deploy's case.
			'no repo falls back to the name'          => ['', 'pfSense-pkg-pfBlockerNG-nightly', 'nightly'],
			'null repo falls back to the name'        => [null, 'pfSense-pkg-pfBlockerNG', 'stable'],
			// Neither half recognises it: a Netgate or hand-built package.
			'netgate repo, foreign name -> null'      => ['pfSense', 'pfSense-pkg-suricata', null],
			'unknown repo, unknown name -> null'      => ['whatever', '', null],
		];
	}

	#[DataProvider('channelForInstallProvider')]
	public function testChannelForInstall(?string $repo, ?string $pkgname, ?string $expected): void
	{
		$this->assertSame($expected, pfb_channel_for_install($repo, $pkgname));
	}

	/*
	 * ---- pfb_software_cache_matches_repo() — is this cache still ours? (issue #2148) ----
	 * Two consumers ask it: the cron orchestrator, deciding whether cached
	 * latest/last_notified may be REUSED, and the Software page, deciding whether cached
	 * latest/last-checked/status may be DISPLAYED. They must answer identically — the
	 * orchestrator's rescope lands only on the next tick, so a page using a looser rule
	 * would pair the new channel's label with the previous catalogue's version in between.
	 * A cache with NO repo key predates the scope and is adopted, not discarded: that is
	 * every existing box exactly once, and discarding it re-notifies an announced version.
	 */
	public static function cacheMatchesRepoProvider(): array
	{
		return [
			'same catalogue'                  => [['repo' => 'pfblockerng-edge'], 'pfblockerng-edge', TRUE],
			'different catalogue'             => [['repo' => 'pfblockerng-stable'], 'pfblockerng-edge', FALSE],
			'legacy repo vs a channel repo'   => [['repo' => 'pfblockerng'], 'pfblockerng-stable', FALSE],
			'pre-#2148 cache: no repo key'    => [['pkgname' => 'pfSense-pkg-pfBlockerNG'], 'pfblockerng', TRUE],
			'empty cache: nothing recorded'   => [[], 'pfblockerng-edge', TRUE],
			'recorded empty vs a real repo'   => [['repo' => ''], 'pfblockerng-edge', FALSE],
			'recorded empty vs empty (sideload)' => [['repo' => ''], '', TRUE],
		];
	}

	#[DataProvider('cacheMatchesRepoProvider')]
	public function testCacheMatchesRepo(array $cache, string $repo, bool $expected): void
	{
		$this->assertSame($expected, pfb_software_cache_matches_repo($cache, $repo));
	}

	/*
	 * ---- pfb_software_is_our_build() — the provenance gate (2026-06-15, widened #2148) ----
	 * TRUE only for a build installed FROM one of OUR repos — the `pkg query %R` origin.
	 * Issue #2148 made that FIVE repos: the legacy shared 'pfblockerng' (stable + the
	 * retired -devel identity) plus the four per-channel catalogues
	 * 'pfblockerng-stable|-testing|-edge|-nightly'. A box subscribed to any of the new
	 * catalogues must keep the Software tab, the priv match[] line and the update notice;
	 * before the widening they all read as NOT-our-build and silently lost the feature.
	 * A Netgate-installed add-on (repo 'pfSense'), an empty/'unknown' origin, or anything
	 * else -> FALSE. Both sides pinned: this single predicate gates the tab, the page
	 * guard, the priv match[] line, AND the cron notice, so a false positive would leak
	 * the whole feature onto a stock build and a false negative would hide it from ours.
	 */
	public static function provenanceProvider(): array
	{
		return [
			// Ours -> present.
			'ours: legacy pfblockerng (stable+devel)' => ['pfblockerng', true],
			'ours: pfblockerng-stable'           => ['pfblockerng-stable', true],
			'ours: pfblockerng-testing'          => ['pfblockerng-testing', true],
			'ours: pfblockerng-edge'             => ['pfblockerng-edge', true],
			'ours: pfblockerng-nightly'          => ['pfblockerng-nightly', true],
			// Not ours -> absent.
			'netgate: pfSense repo'              => ['pfSense', false],
			'empty origin'                       => ['', false],
			'literal unknown'                    => ['unknown', false],
			'null origin'                        => [null, false],
			'foreign repo'                       => ['netgate-decoy', false],
			'near-miss catalogue'                => ['pfblockerng-edgey', false],
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
	 * Default ENABLED via the registry (issue #1887): absent resolves to the registered
	 * default 'on'; present '' is explicit Off. Legacy 'off' — in any letter case —
	 * also disables; junk tokens fall back to Off like every other toggle (the pre-#1887
	 * reader treated any non-'off' string as enabled). Both sides asserted so green proves
	 * 'off' is a real disabling branch, not an always-enabled path.
	 */
	public static function checkEnabledProvider(): array
	{
		return [
			// issue #1887: the accessor reads the gateway itself (zero-arg); the ON
			// default lives in the registry. Present '' is explicit Off; absent uses
			// that default. Junk falls back to Off like every other toggle (it read as
			// enabled under the old hand-written `!== 'off'` reader).
			'unset (never saved) -> enabled' => [null, true],
			'on -> enabled'                  => ['on', true],
			'off -> disabled'                => ['off', false],
			'OFF (case variant) -> disabled' => ['OFF', false],
			'empty string -> disabled'       => ['', false],
			'legacy/other -> disabled'       => ['default', false],
		];
	}

	#[DataProvider('checkEnabledProvider')]
	public function testCheckEnabled(?string $raw, bool $expected): void
	{
		// Swap the process-global config for this case and ALWAYS restore it: the last
		// data-provider case must not leak its fixture into later tests in the process.
		$previous = $GLOBALS['config'] ?? NULL;
		$GLOBALS['config'] = [];
		try {
			if ($raw !== null) {
				config_set_path('installedpackages/pfblockerng/config/0/pfb_software_check', $raw);
			}
			$this->assertSame($expected, pfb_software_check_enabled());
		} finally {
			if ($previous === NULL) {
				unset($GLOBALS['config']);
			} else {
				$GLOBALS['config'] = $previous;
			}
		}
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
