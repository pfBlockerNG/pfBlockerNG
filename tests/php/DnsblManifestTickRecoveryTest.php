<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #2607 — a DNSBL manifest that is GONE must get an update pass from the very
 * next tick, whatever else is or is not due, and whatever the apply window says.
 *
 * The manifest is Python's sole DNSBL source (ADR-65). A real `pkg delete` tears it
 * down, and the reinstall's resync is a config-save pass, whose feed section — and
 * with it the pfb_dnsbl_manifest_missing() rebuild gate — is guarded by !$pfb['save'].
 * So the resolver comes back up matching nothing and stays that way until a feed
 * happens to fall due: minutes on an hourly schedule, a day on a daily one.
 *
 * This is a failure condition, not a change waiting for a convenient moment, so it
 * dispatches on the same footing as a *.fail marker — outside the quiet-hours window
 * too (owner ruling, 2026-08-21: a box mid-upgrade has bigger concerns than deferring
 * a feed download). Quiet hours defer things the operator chose to defer; they must
 * not extend an outage.
 */
final class DnsblManifestTickRecoveryTest extends TestCase
{
	private string $dir = '';
	private string $stateDir = '';
	private mixed $originalPfb = NULL;
	private mixed $originalConfig = NULL;
	private mixed $originalG = NULL;
	private int $feedRuns = 0;

	protected function setUp(): void
	{
		$this->originalPfb = $GLOBALS['pfb'];
		$this->originalConfig = $GLOBALS['config'] ?? NULL;
		$this->originalG = $GLOBALS['g'] ?? NULL;
		$this->dir = sys_get_temp_dir() . '/pfb_manifest_tick_' . getmypid() . '_' . uniqid();
		$this->stateDir = $this->dir . '/state';
		mkdir($this->stateDir, 0755, TRUE);
		$GLOBALS['pfb']['dbdir'] = $this->dir;
		$GLOBALS['pfb']['schedule_state_dir'] = $this->stateDir;
		$GLOBALS['pfb']['runlog'] = $this->dir . '/run.log';
		$GLOBALS['pfb']['extraslog'] = $this->dir . '/extras.log';
		$GLOBALS['pfb']['log'] = $this->dir . '/pfb.log';
		$GLOBALS['pfb']['logdir'] = $this->dir;
		$GLOBALS['pfb']['errlog'] = $this->dir . '/error.log';
		$GLOBALS['pfb']['denydir'] = $this->dir . '/deny';
		$GLOBALS['pfb']['matchdir'] = $this->dir . '/match';
		$GLOBALS['pfb']['permitdir'] = $this->dir . '/permit';
		$GLOBALS['pfb']['nativedir'] = $this->dir . '/native';
		$GLOBALS['pfb']['dnsdir'] = $this->dir . '/dnsbl';
		foreach (['denydir', 'matchdir', 'permitdir', 'nativedir', 'dnsdir'] as $dir) {
			mkdir($GLOBALS['pfb'][$dir], 0755, TRUE);
		}
		$GLOBALS['pfb']['enable'] = PfbToggle::On;
		$GLOBALS['pfb']['blconfig'] = [];
		$GLOBALS['pfb']['php'] = $this->recorder();
		$GLOBALS['pfb']['unbound_py_sources'] = $this->dir . '/pfb_py_sources.json';
		$GLOBALS['config'] = [];

		// Live Python mode: the manifest is the resolver's only blocklist source.
		$GLOBALS['config']['unbound'] = ['python' => 'on', 'python_script' => 'pfb_unbound'];

		// A schedule whose next occurrence is a day out: nothing is due this tick, so a
		// dispatch can only have come from the missing manifest.
		$now = new DateTimeImmutable('now', new DateTimeZone(date_default_timezone_get()));
		$slot = $now->modify('+1 day');
		$minute = intdiv((int) $slot->format('i'), 15) * 15;

		// An apply window that does NOT contain now, so a queued manual apply would be
		// deferred out of this tick entirely.
		$closed_from = $now->modify('+2 hours');
		$closed_to = $now->modify('+3 hours');
		$quiet_hours = $closed_from->format('H:i') . '-' . $closed_to->format('H:i');

		$general = [
			'pfb_scheduled_feed_updates' => 'on',
			'pfb_schedule_weekday' => $slot->format('N'),
			'pfb_schedule_hour' => $slot->format('G'),
			'pfb_schedule_minute' => (string) $minute,
			'pfb_quiet_hours' => $quiet_hours,
			'skipfeed' => '0',
		];
		foreach ($general as $key => $value) {
			config_set_path('installedpackages/pfblockerng/config/0/' . $key, $value);
		}
		foreach (['suppression' => '', 'database_cc' => '', 'maxmind_locale' => 'en',
			'asn_reporting' => 'disabled', 'asn_token' => '', 'maxmind_account' => '',
			'maxmind_key' => ''] as $key => $value) {
			config_set_path('installedpackages/pfblockerngipsettings/config/0/' . $key, $value);
		}
		foreach (['pfb_dnsvip4' => '', 'pfb_dnsvip6' => '', 'pfb_dnsport' => '8081',
			'pfb_dnsport_ssl' => '8443'] as $key => $value) {
			config_set_path('installedpackages/pfblockerngdnsblsettings/config/0/' . $key, $value);
		}
		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '8.8.8.8');
		PfbConfig::writeSystem('dnsbl/pfb_dnsbl', PfbToggle::On);
		// ADR-13 auto-VIP: without it, pfb_global()'s manual-mode VIP validation force-disables
		// DNSBL at runtime for these VIP-less fixtures, so the box under test would not be one
		// where DNSBL is actually live.
		PfbConfig::writeSystem('dnsbl/pfb_dnsvip_auto', PfbToggle::On);
		$GLOBALS['g']['unbound_chroot_path'] = '/var/unbound';
		config_set_path('installedpackages/pfblockernglistsv4/config', [[
			'action' => 'Deny_Inbound',
			'cron' => 'EveryDay',
			'schedule_override' => '',
			'row' => [['header' => 'runtime', 'url' => 'https://example.test/feed', 'state' => 'Enabled']],
		]]);
		config_set_path('installedpackages/pfblockernglistsv6/config', []);
		config_set_path('installedpackages/pfblockerngdnsbl/config', []);

		$model = pfb_schedule_runtime_model(
			[
				'pfb_scheduled_feed_updates' => 'on',
				'pfb_schedule_weekday' => $slot->format('N'),
				'pfb_schedule_hour' => $slot->format('G'),
				'pfb_schedule_minute' => (string) $minute,
			],
			[
				'ipv4' => config_get_path('installedpackages/pfblockernglistsv4/config', []),
				'ipv6' => [],
				'dnsbl' => [],
			]
		);
		$this->assertIsArray($model);
		$future = time() + 86400;
		$this->assertTrue(pfb_due_ledger_write_cache([
			'cron' => ['last_run' => time(), 'next_due' => $future, 'jitter' => 0],
			'dcc' => ['last_run' => $future - 1, 'next_due' => $future, 'jitter' => 0],
			'bl' => ['last_run' => $future - 1, 'next_due' => $future, 'jitter' => 0],
			'ss_refresh' => ['last_run' => $future - 1, 'next_due' => $future, 'jitter' => 0],
			'apply_reconcile' => ['last_run' => $future - 1, 'next_due' => $future, 'jitter' => 0],
		], $model['config_hash'], $this->dir));

		// A published manifest is the healthy baseline every test starts from.
		file_put_contents($GLOBALS['pfb']['unbound_py_sources'], '{"version":1,"config":{},"feeds":[]}');

		// Settle the schedule: a feed that has never run counts its current occurrence as
		// pending, which would dispatch on its own and mask what these tests measure. One
		// warm-up tick completes it, leaving a steady state with nothing outstanding.
		$this->warmUp();
		$GLOBALS['pfb_test_logger_calls'] = [];
	}

	/** Drive one tick that completes every pending occurrence, then reset the counters. */
	private function warmUp(): void
	{
		pfblockerng_tick(
			[], NULL, NULL, 5.0, static fn (): bool => TRUE, NULL, 5.0,
			static fn (string $_job, string $_argument = ''): bool => TRUE,
			function (): void {
				$state = pfb_schedule_state_read($this->stateDir);
				foreach ($state['items'] ?? [] as $id => $item) {
					if (!str_starts_with($id, 'extra:') && isset($item['pending_occurrence'])) {
						pfb_schedule_state_record_outcome(
							$id, PfbScheduleTerminalResult::Success, $this->stateDir
						);
					}
				}
			},
			static fn (): bool => TRUE
		);
		$this->feedRuns = 0;
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb'] = $this->originalPfb;
		$GLOBALS['config'] = $this->originalConfig;
		$GLOBALS['g'] = $this->originalG;
		unset($GLOBALS['pfb_test_logger_calls']);
		$this->remove($this->dir);
	}

	/** Neutered $pfb['php'] so any real dispatch branch records instead of spawning. */
	private function recorder(): string
	{
		$path = $this->dir . '/php-recorder';
		file_put_contents($path, "#!/bin/sh\nprintf '%s\\n' \"\$*\" >> " . escapeshellarg($this->dir . '/spawns') . "\n");
		chmod($path, 0755);
		return $path;
	}

	private function remove(string $path): void
	{
		if (is_dir($path) && !is_link($path)) {
			foreach (scandir($path) ?: [] as $entry) {
				if ($entry !== '.' && $entry !== '..') {
					$this->remove("{$path}/{$entry}");
				}
			}
			@rmdir($path);
			return;
		}
		@unlink($path);
	}

	private function tick(): void
	{
		pfblockerng_tick(
			[], NULL, NULL, 5.0, static fn (): bool => TRUE, NULL, 5.0,
			static fn (string $_job, string $_argument = ''): bool => TRUE,
			function (): void {
				$this->feedRuns++;
			},
			static fn (): bool => TRUE
		);
	}

	/** The window really is shut, so a dispatch cannot be the window letting work through. */
	public function testTheApplyWindowIsClosedForTheseTests(): void
	{
		$this->assertFalse(
			pfb_quiet_hours_in_window(time(), (string) PfbConfig::read('gen/pfb_quiet_hours')),
			'fixture precondition: now must sit outside the configured apply window'
		);
	}

	/**
	 * Scenario: nothing is due and the window is shut.
	 *   Given a published manifest, the tick dispatches nothing;
	 *   When the manifest is gone (the teardown of a real `pkg delete`),
	 *   Then the very next tick runs an update pass anyway.
	 */
	public function testMissingManifestDispatchesAnUpdatePassOutsideTheApplyWindow(): void
	{
		$this->tick();
		$this->assertSame(0, $this->feedRuns,
			'before-state: with the manifest published and nothing due, a shut window dispatches nothing');

		$this->assertTrue(unlink($GLOBALS['pfb']['unbound_py_sources']));
		$this->tick();

		$this->assertSame(1, $this->feedRuns,
			'a missing DNSBL manifest must dispatch an update pass on the next tick, rather than leaving '
			. 'the resolver matching nothing until a feed falls due');
		$messages = array_column($GLOBALS['pfb_test_logger_calls'] ?? [], 'message');
		$this->assertContains(
			'Tick: running scheduled feed pass.',
			$messages,
			'the recovery pass must be visible in the log, not silent'
		);
		$this->assertContains(
			'Tick: DNSBL manifest absent - this pass rebuilds it.',
			$messages,
			'an out-of-window pass needs its reason on the record, or the operator sees only '
			. 'an update that ran when they asked for none to'
		);
	}

	/**
	 * Scheduled Feed Updates OFF is an explicit opt-out of automatic dispatch, and the
	 * *.fail marker this recovery is modelled on honours it (its due-condition is gated on
	 * $runtime_model['scheduled']). A missing manifest gets the same treatment, and the box
	 * is not left silent about it: the GUI notice pfb_dnsbl_manifest_failure_notice() raises
	 * from the pass that found the manifest gone is independent of both the tick and this
	 * toggle. Only the automatic rebuild waits for the Update the operator runs themselves.
	 */
	public function testMissingManifestIsIgnoredWhenScheduledFeedUpdatesAreOff(): void
	{
		config_set_path('installedpackages/pfblockerng/config/0/pfb_scheduled_feed_updates', '');
		$this->assertTrue(unlink($GLOBALS['pfb']['unbound_py_sources']));

		$this->tick();

		$this->assertSame(0, $this->feedRuns,
			'with scheduled feed updates opted out, a missing manifest must not force an '
			. 'automatic pass -- the same gate the *.fail dispatch respects');
	}

	/**
	 * With DNSBL switched off, a dispatched pass takes the disable branch and publishes no
	 * manifest — so dispatching on its absence would repeat every tick forever without ever
	 * repairing anything. There is nothing to repair: DNSBL is off.
	 */
	public function testMissingManifestIsIgnoredWhenDnsblIsDisabled(): void
	{
		PfbConfig::writeSystem('dnsbl/pfb_dnsbl', PfbToggle::Off);
		$GLOBALS['pfb']['dnsbl'] = PfbToggle::Off;
		$this->assertTrue(unlink($GLOBALS['pfb']['unbound_py_sources']));

		$this->tick();

		$this->assertSame(0, $this->feedRuns,
			'with DNSBL disabled no pass can publish a manifest, so dispatching on its absence '
			. 'would be an unbounded retry loop');
	}

	/**
	 * DNSBL can be enabled in the configuration and still be OFF at runtime: manual VIP mode
	 * with a missing or invalid sinkhole VIP makes pfb_global() force-disable it (issue #331).
	 * A pass dispatched in that state publishes no manifest either, so the gate has to read
	 * the effective value, not the stored one.
	 */
	public function testMissingManifestIsIgnoredWhenAnInvalidVipDisablesDnsblAtRuntime(): void
	{
		PfbConfig::writeSystem('dnsbl/pfb_dnsvip_auto', PfbToggle::Off);
		$GLOBALS['pfb']['dnsbl'] = PfbToggle::Off;
		$this->assertSame(PfbToggle::On, PfbConfig::read('dnsbl/pfb_dnsbl'),
			'before-state: the stored setting still says DNSBL is enabled');
		$this->assertTrue(unlink($GLOBALS['pfb']['unbound_py_sources']));

		$this->tick();

		$this->assertSame(0, $this->feedRuns,
			'a runtime-disabled DNSBL publishes no manifest, so dispatching on its absence '
			. 'would retry every tick forever -- the gate must read the effective state');
	}

	/**
	 * A manifest path that is empty rather than merely missing is a broken configuration,
	 * not an empty resolver: file_exists('') is false, so without this guard every tick
	 * would read it as "manifest gone" and dispatch forever.
	 */
	public function testEmptyManifestPathDoesNotDispatch(): void
	{
		$GLOBALS['pfb']['unbound_py_sources'] = '';

		$this->tick();

		$this->assertSame(0, $this->feedRuns,
			'an unset manifest path must not be read as an absent manifest');
	}

	/**
	 * The contract belongs to Python mode: with the resolver not wired to pfb_unbound.py
	 * the manifest is not its blocklist source, so its absence dispatches nothing.
	 */
	public function testMissingManifestIsIgnoredWhenPythonModeIsNotLive(): void
	{
		$GLOBALS['config']['unbound'] = ['python' => '', 'python_script' => ''];
		$this->assertTrue(unlink($GLOBALS['pfb']['unbound_py_sources']));

		$this->tick();

		$this->assertSame(0, $this->feedRuns,
			'without the Python integration live there is no manifest contract to repair');
	}
}
