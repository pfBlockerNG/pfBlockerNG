<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * ADR-19 Phase 3 — the cron-driven software-update orchestrator pfb_software_update_check()
 * + the cache helpers, with the pkg IO INJECTED (no real `pkg` off-appliance).
 *
 * Scenario: a cron tick reads installed-vs-our-repo-latest, writes a cache, and raises a
 * de-duped file_notice — but ONLY on a build installed from one of OUR repos.
 *
 * Background: the pure decision core (Phase 2) is already pinned; here we pin the
 * SIDE-EFFECTS — the provenance gate (no-op on a Netgate build), the pkg-lock / no-DNS
 * short-circuits (serve cache, no network, no error), the cache contents, and the
 * per-version de-dupe across ticks. Every branch asserts the BEFORE-state (cache present?
 * notice fired?) and the AFTER-state so green proves the side-effect was CAUSED by the
 * input, not pre-existing.
 *
 * The IO is doubled by passing $io = ['installed_name','installed','installed_repo',
 * 'latest'] to the orchestrator (its documented unit-test seam). file_notice /
 * is_subsystem_dirty / get_dnsavailable are doubled in pfsense_doubles.php, driven via
 * $GLOBALS (pfb_test_file_notices / pfb_test_pkg_locked / pfb_test_dns_available).
 */
#[CoversFunction('pfb_software_update_check')]
#[CoversFunction('pfb_software_cache_file')]
#[CoversFunction('pfb_software_read_cache')]
#[CoversFunction('pfb_software_write_cache')]
#[CoversFunction('pfb_pkg_latest')]
final class SoftwareUpdateCheckTest extends TestCase
{
	private string $dbdir = '';

	protected function setUp(): void
	{
		// Each test gets a private temp dbdir so the cache file is isolated and the
		// orchestrator's $pfb['dbdir'] lookup resolves there.
		$this->dbdir = sys_get_temp_dir() . '/pfb_adr19_' . uniqid('', true);
		mkdir($this->dbdir, 0755, true);
		$GLOBALS['pfb']['dbdir'] = $this->dbdir;

		// Reset the test-driveable doubles to their permissive defaults.
		$GLOBALS['pfb_test_file_notices'] = [];
		$GLOBALS['pfb_test_pkg_locked']   = false;
		$GLOBALS['pfb_test_dns_available'] = true;

		// Quiet default knob unless a test overrides it — exercise the channel-aware
		// default rather than a forced on/off.
		$GLOBALS['config'] = [];
	}

	protected function tearDown(): void
	{
		$file = $this->dbdir . '/software_update.json';
		if (is_file($file)) {
			unlink($file);
		}
		if (is_dir($this->dbdir)) {
			rmdir($this->dbdir);
		}
		unset(
			$GLOBALS['pfb']['dbdir'],
			$GLOBALS['pfb_test_file_notices'],
			$GLOBALS['pfb_test_pkg_locked'],
			$GLOBALS['pfb_test_dns_available'],
			$GLOBALS['config']
		);
	}

	private function cacheFile(): string
	{
		return $this->dbdir . '/software_update.json';
	}

	private function readCache(): ?array
	{
		$file = $this->cacheFile();
		if (!is_file($file)) {
			return null;
		}
		$data = json_decode((string) file_get_contents($file), true);
		return is_array($data) ? $data : null;
	}

	private function setKnob(string $value): void
	{
		$GLOBALS['config'] = [
			'installedpackages' => ['pfblockerng' => ['config' => [0 => ['pfb_software_notify' => $value]]]],
		];
	}

	private function ourBuildIo(string $installed, string $latest, string $repo = 'pfblockerng', string $name = 'pfSense-pkg-pfBlockerNG-devel'): array
	{
		return [
			'installed_name' => $name,
			'installed'      => $installed,
			'installed_repo' => $repo,
			'latest'         => $latest,
		];
	}

	/*
	 * ---- Provenance gate (the 2026-06-15 amendment) — BOTH sides ----
	 */

	/**
	 * Given a build installed from OUR repo with a newer version available,
	 * When the check runs,
	 * Then it writes the cache AND reaches a notify decision (a notice fires under an
	 * ON knob). This is the "feature present" side of the gate.
	 */
	public function testOurBuildRunsCheckWritesCacheAndCanNotify(): void
	{
		// Given: no cache yet, no notice yet (before-state).
		$this->setKnob('on');
		$this->assertNull($this->readCache(), 'before: no cache file should exist');
		$this->assertSame([], $GLOBALS['pfb_test_file_notices'], 'before: no notice raised');

		// When.
		$cache = pfb_software_update_check(false, $this->ourBuildIo('3.2.0_1', '3.2.0_9'));

		// Then: cache written with the read values, and a notice fired (update available).
		$onDisk = $this->readCache();
		$this->assertNotNull($onDisk, 'after: cache file must be written for our build');
		$this->assertSame('devel', $onDisk['channel']);
		$this->assertSame('3.2.0_1', $onDisk['installed']);
		$this->assertSame('3.2.0_9', $onDisk['latest']);
		$this->assertSame('3.2.0_9', $onDisk['last_notified']);
		$this->assertArrayHasKey('last_checked', $onDisk);
		$this->assertSame($onDisk, $cache, 'returns the freshly written cache');
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices'], 'after: exactly one notice fired');
		$this->assertStringContainsString('3.2.0_9 available (devel)', $GLOBALS['pfb_test_file_notices'][0]['notice']);
	}

	/**
	 * Given a build installed from the Netgate ports repo ('pfSense') — or any non-our
	 * origin — with a newer version nominally available,
	 * When the check runs,
	 * Then it is a COMPLETE no-op: no cache is written and no notice is raised. This is
	 * the "feature absent on a stock build" side of the gate; it must be the FIRST thing
	 * the check does.
	 */
	#[DataProvider('foreignRepoProvider')]
	public function testNetgateBuildIsCompleteNoOp(string $repo): void
	{
		// Given: ON knob (would notify if the gate let it through), clean before-state.
		$this->setKnob('on');
		$this->assertNull($this->readCache(), 'before: no cache file');
		$this->assertSame([], $GLOBALS['pfb_test_file_notices'], 'before: no notice');

		// When: an update IS nominally available, but the build is not ours.
		$io = $this->ourBuildIo('3.2.0_1', '3.2.0_9', $repo);
		pfb_software_update_check(false, $io);

		// Then: nothing happened — no cache write, no notice.
		$this->assertNull($this->readCache(), 'after: Netgate build must NOT write a cache');
		$this->assertSame([], $GLOBALS['pfb_test_file_notices'], 'after: Netgate build raises NO notice');
	}

	public static function foreignRepoProvider(): array
	{
		return [
			'Netgate ports repo' => ['pfSense'],
			'empty/unknown'      => [''],
			'literal unknown'    => ['unknown'],
			'a decoy repo'       => ['netgate-decoy'],
		];
	}

	/*
	 * ---- pkg-lock / no-DNS short-circuit — serve cache, no network, no error ----
	 *
	 * These exercise the LIVE pfb_pkg_latest() path (no injected 'latest'), so the
	 * is_subsystem_dirty('pkg') / get_dnsavailable() guards inside it are hit. Because
	 * the guard returns '' (no live read) and there is no injected latest, the
	 * orchestrator preserves the cached latest.
	 */

	/**
	 * Given a pre-existing cache (an earlier tick found 3.2.0_9) and the pkg subsystem
	 * locked,
	 * When the check runs without an injected latest,
	 * Then the cached latest is preserved, no notice fires (it already de-duped), and no
	 * error is thrown.
	 */
	public function testPkgLockedServesCacheNoNetworkNoNotice(): void
	{
		// Given: seed a cache as if a prior tick already notified for 3.2.0_9 (a real prior
		// tick records the pkgname it was for, so the same-package reuse path is taken).
		$this->setKnob('on');
		pfb_software_write_cache([
			'pkgname'       => 'pfSense-pkg-pfBlockerNG-devel',
			'channel'       => 'devel',
			'installed'     => '3.2.0_1',
			'latest'        => '3.2.0_9',
			'last_checked'  => 100,
			'last_notified' => '3.2.0_9',
		]);
		$before = $this->readCache();
		$this->assertSame('3.2.0_9', $before['latest'], 'before: cache holds the prior latest');
		$this->assertSame([], $GLOBALS['pfb_test_file_notices'], 'before: no notice this run yet');

		// When: pkg locked; no injected latest -> pfb_pkg_latest() short-circuits to ''.
		$GLOBALS['pfb_test_pkg_locked'] = true;
		$cache = pfb_software_update_check(false, [
			'installed_name' => 'pfSense-pkg-pfBlockerNG-devel',
			'installed'      => '3.2.0_1',
			'installed_repo' => 'pfblockerng',
			// note: NO 'latest' key -> forces the guarded live read.
		]);

		// Then: cached latest preserved, last_notified intact, no NEW notice.
		$this->assertSame('3.2.0_9', $cache['latest'], 'after: cached latest preserved when pkg locked');
		$this->assertSame('3.2.0_9', $cache['last_notified'], 'after: de-dupe state intact');
		$this->assertSame([], $GLOBALS['pfb_test_file_notices'], 'after: no notice while locked');
	}

	/**
	 * Given the same pre-existing cache but DNS unavailable,
	 * When the check runs without an injected latest,
	 * Then identical behaviour to the locked case — the cache is served, no network read,
	 * no notice.
	 */
	public function testNoDnsServesCacheNoNetworkNoNotice(): void
	{
		$this->setKnob('on');
		pfb_software_write_cache([
			'pkgname'       => 'pfSense-pkg-pfBlockerNG-devel',
			'channel'       => 'devel',
			'installed'     => '3.2.0_1',
			'latest'        => '3.2.0_9',
			'last_checked'  => 100,
			'last_notified' => '3.2.0_9',
		]);
		$this->assertSame('3.2.0_9', $this->readCache()['latest'], 'before: cache holds prior latest');

		$GLOBALS['pfb_test_dns_available'] = false;
		$cache = pfb_software_update_check(false, [
			'installed_name' => 'pfSense-pkg-pfBlockerNG-devel',
			'installed'      => '3.2.0_1',
			'installed_repo' => 'pfblockerng',
		]);

		$this->assertSame('3.2.0_9', $cache['latest'], 'after: cached latest preserved when no DNS');
		$this->assertSame([], $GLOBALS['pfb_test_file_notices'], 'after: no notice without DNS');
	}

	/**
	 * Given a cache left by a DIFFERENT installed package (a prior nightly build) and a
	 * live read that comes back empty (pkg locked) for the now-installed devel build,
	 * When the check runs,
	 * Then the stale nightly latest/last_notified are NOT reused — latest regresses to ''
	 * and last_notified resets — so a channel switch can neither show a wrong version nor
	 * suppress the first valid notice for the new package. Paired with the pkg-locked test
	 * above (same-package reuse) so the pkgname-match branch is proven both ways.
	 */
	public function testChannelSwitchDoesNotReuseStaleCache(): void
	{
		// Given: a cache from a nightly build that had announced a nightly version.
		$this->setKnob('on');
		pfb_software_write_cache([
			'pkgname'       => 'pfSense-pkg-pfBlockerNG-nightly',
			'channel'       => 'nightly',
			'installed'     => '3.2.0_1',
			'latest'        => '3.2.0_99',
			'last_checked'  => 100,
			'last_notified' => '3.2.0_99',
		]);
		$this->assertSame('3.2.0_99', $this->readCache()['latest'], 'before: stale nightly latest present');

		// When: now a DEVEL build is installed and the live read is unavailable (pkg locked).
		$GLOBALS['pfb_test_pkg_locked'] = true;
		$cache = pfb_software_update_check(false, [
			'installed_name' => 'pfSense-pkg-pfBlockerNG-devel',
			'installed'      => '3.2.0_1',
			'installed_repo' => 'pfblockerng',
			// no 'latest' -> guarded live read returns '' (pkg locked).
		]);

		// Then: the stale nightly values are discarded, not carried into the devel cache.
		$this->assertSame('devel', $cache['channel'], 'after: cache rekeyed to the devel build');
		$this->assertSame('', (string) ($cache['latest'] ?? ''), 'after: stale nightly latest NOT reused');
		$this->assertSame('', (string) ($cache['last_notified'] ?? ''), 'after: stale last_notified reset');
		$this->assertSame([], $GLOBALS['pfb_test_file_notices'], 'after: no notice (no known latest yet)');
	}

	/*
	 * ---- Knob gating — notice fires exactly when pfb_should_notify says so ----
	 */

	/**
	 * Given an our-repo build with an update available but the notify knob OFF,
	 * When the check runs,
	 * Then the cache is still refreshed (the page always shows latest) but NO notice fires.
	 * Paired with testOurBuildRunsCheckWritesCacheAndCanNotify (knob on) so the branch is real.
	 */
	public function testKnobOffRefreshesCacheButSuppressesNotice(): void
	{
		$this->setKnob('off');
		$this->assertSame([], $GLOBALS['pfb_test_file_notices'], 'before: no notice');

		$cache = pfb_software_update_check(false, $this->ourBuildIo('3.2.0_1', '3.2.0_9'));

		$this->assertSame('3.2.0_9', $cache['latest'], 'after: cache refreshed to latest');
		$this->assertSame('', (string) ($cache['last_notified'] ?? ''), 'after: last_notified NOT advanced');
		$this->assertSame([], $GLOBALS['pfb_test_file_notices'], 'after: knob off suppresses the notice');
	}

	/**
	 * Given an our-repo build already at the latest (no update),
	 * When the check runs with the knob ON,
	 * Then the cache is refreshed but no notice fires (nothing newer to announce).
	 */
	public function testNoUpdateAvailableRefreshesCacheNoNotice(): void
	{
		$this->setKnob('on');

		$cache = pfb_software_update_check(false, $this->ourBuildIo('3.2.0_9', '3.2.0_9'));

		$this->assertSame('3.2.0_9', $cache['installed']);
		$this->assertSame('3.2.0_9', $cache['latest']);
		$this->assertSame('', (string) ($cache['last_notified'] ?? ''), 'after: no notify when not newer');
		$this->assertSame([], $GLOBALS['pfb_test_file_notices'], 'after: no notice when up to date');
	}

	/*
	 * ---- De-dupe lifecycle across ticks (the §2 "persist last-notified" contract) ----
	 *
	 * GIVEN a fresh our-repo build at 3.2.0_1, knob ON, no cache;
	 * WHEN tick 1 sees latest 3.2.0_9       -> notify ONCE, persist last_notified=3.2.0_9;
	 * WHEN tick 2 sees the SAME 3.2.0_9     -> NO renotify (de-duped);
	 * WHEN tick 3 sees a newer 3.2.0_10     -> notify AGAIN, persist last_notified=3.2.0_10;
	 * WHEN tick 4 sees the SAME 3.2.0_10    -> NO renotify.
	 * The persisted last_notified is asserted BEFORE each tick so each (no-)notify is
	 * proven CAUSED by the version change, not coincidence.
	 */
	public function testNoticeDeDupesPerVersionAcrossTicks(): void
	{
		$this->setKnob('on');

		// Tick 1: first sight of 3.2.0_9 -> one notice, last_notified advanced.
		$this->assertNull($this->readCache(), 'before tick 1: no cache');
		$c1 = pfb_software_update_check(false, $this->ourBuildIo('3.2.0_1', '3.2.0_9'));
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices'], 'tick 1: exactly one notice');
		$this->assertSame('3.2.0_9', $c1['last_notified']);

		// Tick 2: same latest, already notified -> NO new notice.
		$this->assertSame('3.2.0_9', $this->readCache()['last_notified'], 'before tick 2: 3.2.0_9 recorded');
		$c2 = pfb_software_update_check(false, $this->ourBuildIo('3.2.0_1', '3.2.0_9'));
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices'], 'tick 2: still one notice (de-duped)');
		$this->assertSame('3.2.0_9', $c2['last_notified']);

		// Tick 3: a newer latest -> notify AGAIN (re-assert tick-2 suppression first).
		$this->assertSame('3.2.0_9', $this->readCache()['last_notified'], 'before tick 3: still at 3.2.0_9');
		$c3 = pfb_software_update_check(false, $this->ourBuildIo('3.2.0_1', '3.2.0_10'));
		$this->assertCount(2, $GLOBALS['pfb_test_file_notices'], 'tick 3: a second notice for the newer version');
		$this->assertSame('3.2.0_10', $c3['last_notified']);
		$this->assertStringContainsString('3.2.0_10 available', $GLOBALS['pfb_test_file_notices'][1]['notice']);

		// Tick 4: same newer latest -> NO renotify.
		$this->assertSame('3.2.0_10', $this->readCache()['last_notified'], 'before tick 4: 3.2.0_10 recorded');
		pfb_software_update_check(false, $this->ourBuildIo('3.2.0_1', '3.2.0_10'));
		$this->assertCount(2, $GLOBALS['pfb_test_file_notices'], 'tick 4: still two notices total (de-duped)');
	}
}
