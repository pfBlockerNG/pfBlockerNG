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
#[CoversFunction('pfb_channel_from_build_record')]
#[CoversFunction('pfb_channel_recognized')]
#[CoversFunction('pfb_channel_for_install')]
#[CoversFunction('pfb_pkg_is_our_name')]
#[CoversFunction('pfb_pkg_newest_version')]
#[CoversFunction('pfb_software_cache_matches_install')]
#[CoversFunction('pfb_software_is_our_build')]
#[CoversFunction('pfb_software_update_href')]
#[CoversFunction('pfb_software_uninstall_href')]
#[CoversFunction('pfb_update_available')]
#[CoversFunction('pfb_software_check_enabled')]
#[CoversFunction('pfb_should_notify')]
final class SoftwareUpdateDecisionTest extends TestCase
{
	/*
	 * ---- pfb_channel_from_pkgname() — leftover name suffix -> channel (issue #2395) ----
	 * The canonical name is NOT a channel (all four catalogues publish it). Only a
	 * non-empty recognised suffix maps; empty/null/foreign -> null.
	 */
	public static function channelProvider(): array
	{
		return [
			'canonical: empty suffix is not a channel' => ['pfSense-pkg-pfBlockerNG', null],
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
	 * ---- pfb_channel_for_install() — the ONE derivation both callers use (#2148 / #2395) ----
	 * Precedence: recognised repo, then a valid pfb_build_record.channel, then a leftover
	 * name suffix. The canonical name alone is never 'stable'.
	 */
	public static function channelForInstallProvider(): array
	{
		return [
			// The repo WINS over the name and over an annotation.
			'edge catalogue beats the canonical name' => ['pfblockerng-edge', 'pfSense-pkg-pfBlockerNG', 'edge'],
			'testing catalogue beats the name'        => ['pfblockerng-testing', 'pfSense-pkg-pfBlockerNG', 'testing'],
			'repo beats annotation'                   => ['pfblockerng-edge', 'pfSense-pkg-pfBlockerNG', 'edge', 'testing'],
			// Legacy shared repo: it names no channel. A leftover suffix still maps;
			// the canonical name does not invent 'stable'.
			'legacy repo falls back to -devel'        => ['pfblockerng', 'pfSense-pkg-pfBlockerNG-devel', 'devel'],
			'legacy repo + canonical name -> unknown' => ['pfblockerng', 'pfSense-pkg-pfBlockerNG', null],
			// A sideloaded `pkg add` records no repo at all — the Tier-A deploy's case.
			'no repo falls back to the name suffix'   => ['', 'pfSense-pkg-pfBlockerNG-nightly', 'nightly'],
			'sideload -edge suffix'                   => ['', 'pfSense-pkg-pfBlockerNG-edge', 'edge'],
			'sideload canonical is not stable'        => ['', 'pfSense-pkg-pfBlockerNG', null],
			'null repo + canonical name -> unknown'   => [null, 'pfSense-pkg-pfBlockerNG', null],
			// Annotation fills in when repo and suffix cannot.
			'empty repo + annotation testing'         => ['', 'pfSense-pkg-pfBlockerNG', 'testing', 'testing'],
			'annotation beats empty suffix'           => [null, 'pfSense-pkg-pfBlockerNG', 'edge', 'edge'],
			// Netgate origin still accepts a leftover suffix (devel leftover).
			'netgate repo + devel suffix -> devel'    => ['pfSense', 'pfSense-pkg-pfBlockerNG-devel', 'devel'],
			// Neither half recognises it: a Netgate or hand-built package.
			'netgate repo, foreign name -> null'      => ['pfSense', 'pfSense-pkg-suricata', null],
			'unknown repo, unknown name -> null'      => ['whatever', '', null],
		];
	}

	#[DataProvider('channelForInstallProvider')]
	public function testChannelForInstall(
		?string $repo,
		?string $pkgname,
		?string $expected,
		?string $recordChannel = null
	): void {
		$this->assertSame($expected, pfb_channel_for_install($repo, $pkgname, $recordChannel));
	}

	/*
	 * ---- pfb_channel_from_build_record() / pfb_channel_recognized() ----
	 */
	public static function buildRecordProvider(): array
	{
		return [
			'testing annotation' => ['{"channel":"testing"}', 'testing'],
			'stable annotation'  => ['{"channel":"stable"}', 'stable'],
			'EDGE mixed case'    => ['{"channel":"EDGE"}', 'edge'],
			'junk channel'       => ['{"channel":"beta"}', null],
			'missing channel'    => ['{"source_sha":"abc"}', null],
			'not json'           => ['{not json', null],
			'empty'              => ['', null],
			'null'               => [null, null],
		];
	}

	#[DataProvider('buildRecordProvider')]
	public function testChannelFromBuildRecord(?string $json, ?string $expected): void
	{
		$this->assertSame($expected, pfb_channel_from_build_record($json));
	}

	/*
	 * ---- pfb_pkg_is_our_name() — identity after empty-suffix stopped meaning stable ----
	 */
	public static function ourNameProvider(): array
	{
		return [
			'canonical'     => ['pfSense-pkg-pfBlockerNG', true],
			'devel leftover'=> ['pfSense-pkg-pfBlockerNG-devel', true],
			'edge leftover' => ['pfSense-pkg-pfBlockerNG-edge', true],
			'foreign pkg'   => ['pfSense-pkg-suricata', false],
			'foreign suffix'=> ['pfSense-pkg-pfBlockerNG-beta', false],
			'empty'         => ['', false],
			'null'          => [null, false],
		];
	}

	#[DataProvider('ourNameProvider')]
	public function testPkgIsOurName(?string $name, bool $expected): void
	{
		$this->assertSame($expected, pfb_pkg_is_our_name($name));
	}

	/*
	 * ---- pfb_pkg_newest_version() — rquery lines, not $out[0] (issue #2379) ----
	 */
	public static function newestVersionProvider(): array
	{
		return [
			'3.3.0 then 3.3.2'           => [['3.3.0', '3.3.2'], '3.3.2'],
			'3.3.2 then 3.3.0'           => [['3.3.2', '3.3.0'], '3.3.2'],
			'single 3.3.2'               => [['3.3.2'], '3.3.2'],
			'empty / blanks skipped'     => [['', '3.3.0', '  ', '3.3.2'], '3.3.2'],
			'empty list'                 => [[], ''],
			'nightly dated'              => [['20260801', '20260814_2'], '20260814_2'],
			'nightly timestamp.hex'      => [['20260801120000.abc1234', '20260814120000.def5678'], '20260814120000.def5678'],
		];
	}

	#[DataProvider('newestVersionProvider')]
	public function testPkgNewestVersion(array $versions, string $expected): void
	{
		$this->assertSame($expected, pfb_pkg_newest_version($versions));
	}

	/*
	 * ---- Software-page action hrefs (issue #2653) ----
	 * The deep link carries the package NAME, and pkg_mgr_install.php acts on that name:
	 * it validates pkg_valid_name() and then runs pfSense-upgrade with -i <pkg> -f
	 * (reinstall) or -r <pkg> (delete). The %R filter that hides a channel install lives
	 * in get_pkg_info(), which drives only the listing pages -- so the origin never
	 * decides the href. What gates it is what the operation itself needs: an update to
	 * install, and a package name to name.
	 *
	 * #2380 gated both hrefs on %R === 'pfSense', on the premise that a Package Manager
	 * reinstall would resolve against -r pfSense. The generated repo conf sets priority
	 * 100 above the Netgate repo precisely so cross-repo resolution picks the
	 * pfBlockerNG build.
	 */
	public static function updateHrefProvider(): array
	{
		$pkg = 'pfSense-pkg-pfBlockerNG';
		$pm = '/pkg_mgr_install.php?mode=reinstallpkg&pkg=' . rawurlencode($pkg);
		return [
			'update available'    => [$pkg, true, $pm],
			'no update'           => [$pkg, false, '#'],
			'empty pkgname'       => ['', true, '#'],
			'empty pkgname, none' => ['', false, '#'],
		];
	}

	#[DataProvider('updateHrefProvider')]
	public function testSoftwareUpdateHref(string $pkgname, bool $available, string $expected): void
	{
		$this->assertSame($expected, pfb_software_update_href($pkgname, $available));
	}

	public static function uninstallHrefProvider(): array
	{
		$pkg = 'pfSense-pkg-pfBlockerNG';
		$pm = '/pkg_mgr_install.php?mode=delete&pkg=' . rawurlencode($pkg);
		return [
			'installed'     => [$pkg, $pm],
			'empty pkgname' => ['', '#'],
		];
	}

	#[DataProvider('uninstallHrefProvider')]
	public function testSoftwareUninstallHref(string $pkgname, string $expected): void
	{
		$this->assertSame($expected, pfb_software_uninstall_href($pkgname));
	}

	/*
	 * The origin must not gate either href (issue #2653). The per-origin data rows that
	 * used to carry that oracle are gone with the $repo parameter, so it is pinned at both
	 * doors an origin could come back through: the signature, and a read from inside the
	 * body. A parameter is the obvious one; a global or a fresh pfb_pkg_installed_repo()
	 * call inside the function would restore #2380 with every behavioural assertion still
	 * green, which is exactly what a reviewer demonstrated against the signature check
	 * alone.
	 */
	public static function originFreeHrefProvider(): array
	{
		return [
			'update'    => ['pfb_software_update_href', ['pkgname', 'update_available']],
			'uninstall' => ['pfb_software_uninstall_href', ['pkgname']],
		];
	}

	#[DataProvider('originFreeHrefProvider')]
	public function testHrefIsBlindToTheInstallOrigin(string $function, array $expected_params): void
	{
		$reflected = new ReflectionFunction($function);

		$this->assertSame(
			$expected_params,
			array_map(
				static fn (ReflectionParameter $p): string => $p->getName(),
				$reflected->getParameters()
			),
			"{$function}() must take no origin argument"
		);

		$file = (array) file((string) $reflected->getFileName());
		$body = implode('', array_slice(
			$file,
			(int) $reflected->getStartLine() - 1,
			(int) $reflected->getEndLine() - (int) $reflected->getStartLine() + 1
		));

		foreach (['global', 'pfb_pkg_installed_repo', 'pfb_software_pkgmgr_usable', '%R'] as $side_channel) {
			$this->assertStringNotContainsString(
				$side_channel,
				$body,
				"{$function}() must not reach for the origin from inside its body ({$side_channel})"
			);
		}
	}

	public function testSoftwarePageDoesNotHardcodePkgMgrForAllOrigins(): void
	{
		$src = (string) file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_software.php'
		);
		$this->assertStringContainsString('pfb_software_update_href', $src);
		$this->assertStringContainsString('pfb_software_uninstall_href', $src);
		$this->assertStringNotContainsString(
			'mode=reinstallpkg&pkg={$pfb_pkg_arg}',
			$src,
			'the reinstall href must come from the tested decider, not be rebuilt inline on the page'
		);
		$this->assertStringNotContainsString(
			'mode=delete&pkg={$pfb_pkg_arg}',
			$src,
			'the delete href must come from the tested decider, not be rebuilt inline on the page'
		);
	}

	/*
	 * ---- pfb_software_cache_matches_install() — is this cache still ours? (#2148) ----
	 * Two consumers ask it, and must ask the WHOLE of it: the cron orchestrator, deciding
	 * whether cached latest/last_notified may be REUSED, and the Software page, deciding
	 * whether cached latest/last-checked/status may be DISPLAYED. They must answer
	 * identically — the orchestrator's rescope lands only on the next tick, so a page
	 * asking a looser question pairs the current install's label with the previous one's
	 * version and verdict in between.
	 *
	 * Both halves matter because either can change alone: a channel switch keeps the
	 * canonical NAME and changes the repo, while an identity swap inside the legacy
	 * shared catalogue (canonical <-> -devel) keeps the REPO and changes the name.
	 *
	 * A cache with no repo key predates the scope and is adopted, not discarded: that is
	 * every existing box exactly once, and discarding it re-notifies an announced version.
	 */
	public static function cacheMatchesInstallProvider(): array
	{
		$canonical = 'pfSense-pkg-pfBlockerNG';
		$devel = 'pfSense-pkg-pfBlockerNG-devel';
		return [
			// Repo half.
			'same install'                => [['pkgname' => $canonical, 'repo' => 'pfblockerng-edge'], $canonical, 'pfblockerng-edge', TRUE],
			'channel switch'              => [['pkgname' => $canonical, 'repo' => 'pfblockerng-stable'], $canonical, 'pfblockerng-edge', FALSE],
			'legacy repo vs channel repo' => [['pkgname' => $canonical, 'repo' => 'pfblockerng'], $canonical, 'pfblockerng-stable', FALSE],
			'recorded empty vs a repo'    => [['pkgname' => $canonical, 'repo' => ''], $canonical, 'pfblockerng-edge', FALSE],
			'sideload: both empty'        => [['pkgname' => $canonical, 'repo' => ''], $canonical, '', TRUE],
			// Name half — the in-repo identity swap the legacy shared catalogue allows.
			'identity swap, same repo'    => [['pkgname' => $devel, 'repo' => 'pfblockerng'], $canonical, 'pfblockerng', FALSE],
			'identity swap, no repo key'  => [['pkgname' => $devel], $canonical, 'pfblockerng', FALSE],
			// Pre-#2148 caches carry a name but no repo: adopted on the repo half.
			'pre-#2148 cache'             => [['pkgname' => $canonical], $canonical, 'pfblockerng', TRUE],
			// A cache that names no install describes none.
			'empty cache'                 => [[], $canonical, 'pfblockerng-edge', FALSE],
		];
	}

	#[DataProvider('cacheMatchesInstallProvider')]
	public function testCacheMatchesInstall(array $cache, string $pkgname, string $repo, bool $expected): void
	{
		$this->assertSame($expected, pfb_software_cache_matches_install($cache, $pkgname, $repo));
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
			'3.3.0 vs 3.3.2 -> available'      => ['3.3.0', '3.3.2', true],
			'3.3.2 vs 3.3.0 -> not available'  => ['3.3.2', '3.3.0', false],
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
