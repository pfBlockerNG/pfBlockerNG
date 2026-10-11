<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3452 -- the apply record: state key `apply` = NULL | {time, outcome: waiting|failed|applied,
 * reason?} in {dbdir}/pfb_sync_receive.json (docs/specs/xmlrpc-per-field-sync.md, "Reporting",
 * acceptance 10). A changed receive opens it as `waiting`; the tick and the apply end only move an
 * OPEN record, so a purely local apply never creates or changes one. The receive record (`last`)
 * keeps its own vocabulary whatever the apply does.
 *
 * Also pins the state file write: a unique 0600 temp file, never a followed symlink.
 */
#[CoversFunction('pfb_sync_receive_state_read')]
#[CoversFunction('pfb_sync_receive_state_write')]
#[CoversFunction('pfb_sync_receive_record')]
#[CoversFunction('pfb_sync_receive_accepted_clear')]
#[CoversFunction('pfblockerng_plugin_xmlrpc_recv_done')]
#[CoversFunction('pfblockerng_tick')]
#[CoversFunction('sync_package_pfblockerng')]
final class SyncPolicyApplyRecordTest extends TestCase
{
	private const REASON_WINDOW = 'outside the apply window';
	private const REASON_FAILED = 'apply failed; pending changes kept';
	private const REASON_RELOAD = 'firewall reload not confirmed; pending changes kept';

	private string $dir = '';
	private string $stateDir = '';
	private mixed $originalPfb = NULL;
	private mixed $originalConfig = NULL;
	private mixed $originalG = NULL;

	protected function setUp(): void
	{
		$this->originalPfb    = $GLOBALS['pfb'];
		$this->originalConfig = $GLOBALS['config'] ?? NULL;
		$this->originalG      = $GLOBALS['g'] ?? NULL;

		$this->dir      = sys_get_temp_dir() . '/pfb_apply_record_' . getmypid() . '_' . bin2hex(random_bytes(4));
		$this->stateDir = $this->dir . '/state';
		mkdir($this->stateDir, 0755, TRUE);
		$GLOBALS['pfb']['dbdir']              = $this->dir;
		$GLOBALS['pfb']['pending_marker']     = $this->dir . '/pfb_pending_changes';
		$GLOBALS['pfb']['schedule_state_dir'] = $this->stateDir;
		$GLOBALS['pfb']['runlog']             = $this->dir . '/run.log';
		$GLOBALS['pfb']['extraslog']          = $this->dir . '/extras.log';
		$GLOBALS['pfb']['log']                = $this->dir . '/pfb.log';
		$GLOBALS['pfb']['logdir']             = $this->dir;
		$GLOBALS['pfb']['errlog']             = $this->dir . '/error.log';
		$GLOBALS['pfb']['denydir']            = $this->dir . '/deny';
		$GLOBALS['pfb']['matchdir']           = $this->dir . '/match';
		$GLOBALS['pfb']['permitdir']          = $this->dir . '/permit';
		$GLOBALS['pfb']['nativedir']          = $this->dir . '/native';
		$GLOBALS['pfb']['dnsdir']             = $this->dir . '/dnsbl';
		foreach (['denydir', 'matchdir', 'permitdir', 'nativedir', 'dnsdir'] as $dir) {
			mkdir($GLOBALS['pfb'][$dir], 0755, TRUE);
		}
		$GLOBALS['pfb']['enable']    = PfbToggle::On;
		$GLOBALS['pfb']['blconfig']  = [];
		$GLOBALS['pfb']['php']       = $this->dir . '/php-recorder';
		$GLOBALS['pfb_test_mwexec_bg']    = [];
		$GLOBALS['pfb_test_logger_calls'] = [];
		$GLOBALS['config'] = [];
		pfb_sync_receive_changed(FALSE);

		$now      = new DateTimeImmutable('now', new DateTimeZone(date_default_timezone_get()));
		$slot     = $now->modify('-15 minutes');
		$general  = [
			'pfb_scheduled_feed_updates' => 'on',
			'pfb_schedule_weekday'       => $slot->format('N'),
			'pfb_schedule_hour'          => $slot->format('G'),
			'pfb_schedule_minute'        => (string) (intdiv((int) $slot->format('i'), 15) * 15),
			'pfb_quiet_hours'            => '',
			'skipfeed'                   => '0',
		];
		foreach ($general as $key => $value) {
			config_set_path('installedpackages/pfblockerng/config/0/' . $key, $value);
		}
		foreach (['suppression' => '', 'database_cc' => '', 'maxmind_locale' => 'en', 'asn_reporting' => 'disabled', 'asn_token' => '', 'maxmind_account' => '', 'maxmind_key' => ''] as $key => $value) {
			config_set_path('installedpackages/pfblockerngipsettings/config/0/' . $key, $value);
		}
		foreach (['pfb_dnsvip4' => '', 'pfb_dnsvip6' => '', 'pfb_dnsport' => '8081', 'pfb_dnsport_ssl' => '8443'] as $key => $value) {
			config_set_path('installedpackages/pfblockerngdnsblsettings/config/0/' . $key, $value);
		}
		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '8.8.8.8');
		config_set_path('installedpackages/pfblockernglistsv4/config', []);
		config_set_path('installedpackages/pfblockernglistsv6/config', []);
		config_set_path('installedpackages/pfblockerngdnsbl/config', []);
		$GLOBALS['g']['unbound_chroot_path'] = '/var/unbound';
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb']    = $this->originalPfb;
		$GLOBALS['config'] = $this->originalConfig;
		if ($this->originalG === NULL) {
			unset($GLOBALS['g']);
		} else {
			$GLOBALS['g'] = $this->originalG;
		}
		unset($GLOBALS['pfb_test_mwexec_bg'], $GLOBALS['pfb_test_logger_calls']);
		pfb_sync_receive_changed(FALSE);
		$this->remove($this->dir);
	}

	private function remove(string $path): void
	{
		if (is_link($path) || is_file($path)) {
			@unlink($path);
			return;
		}
		foreach (glob($path . '/{,.}*', GLOB_BRACE) ?: [] as $entry) {
			if (!in_array(basename($entry), ['.', '..'], TRUE)) {
				$this->remove($entry);
			}
		}
		@rmdir($path);
	}

	// ---- helpers -----------------------------------------------------------------------

	/** @return array<string,mixed> */
	private function state(): array
	{
		return pfb_sync_receive_state_read($this->dir);
	}

	/** @return array<string,mixed>|NULL */
	private function apply(): ?array
	{
		return $this->state()['apply'] ?? NULL;
	}

	/** Seeds the state as a prior changed receive that opened an apply record. */
	private function seedRecord(string $outcome, string $reason = ''): int
	{
		$time  = time() - 100;
		$apply = ['time' => $time, 'outcome' => $outcome] + ($reason === '' ? [] : ['reason' => $reason]);
		pfb_sync_receive_state_write([
			'accepted_digest' => 'ab' . str_repeat('0', 62),
			'last'            => ['time' => $time, 'outcome' => 'changed'],
			'apply'           => $apply,
		], $this->dir);

		return $time;
	}

	private function assertLastStillChanged(): void
	{
		$this->assertSame('changed', $this->state()['last']['outcome'] ?? NULL, 'the receive record keeps its own vocabulary');
	}

	/** Runs a policy receive and applies the result as core's xmlrpc.php does. @return array<string,mixed> */
	private function receive(array $sections): array
	{
		$result = pfblockerng_plugin_xmlrpc_recv(['installedpackages' => $sections]);
		foreach ($result as $path => $value) {
			if ($path !== 'xmlrpc_recv_result') {
				config_set_path($path, $value);
			}
		}
		return $result;
	}

	/** @return array<string,mixed> */
	private static function policyPayload(string $scope = 'policy'): array
	{
		return [
			'pfblockerngsafesearch' => ['safesearch_enable' => 'on'],
			'pfblockerngsync'       => ['config' => [0 => ['syncscope' => $scope]]],
		];
	}

	private function tick(callable $manual): void
	{
		pfblockerng_tick(
			[], NULL, NULL, 5.0, NULL, NULL, 5.0,
			static fn (string $_job, string $_argument = ''): bool => TRUE,
			static function (): void {},
			$manual
		);
	}

	/** A pending manual apply in the due ledger, the cache regenerated for the current model. */
	private function seedPendingCron(bool $outsideWindow): void
	{
		if ($outsideWindow) {
			$start = ((int) date('G') + 12) % 24;
			PfbConfig::writeSystem('gen/pfb_quiet_hours', sprintf('%02d:00-%02d:01', $start, $start));
		}
		$model = pfb_schedule_runtime_config();
		$this->assertIsArray($model);
		$this->assertTrue(pfb_schedule_cache_refresh(
			$model, ['schema' => 1, 'items' => []], time(), new DateTimeZone(date_default_timezone_get()), $this->dir
		));
		$cache = pfb_due_ledger_read_cache($this->dir, $model['config_hash']);
		$this->assertIsArray($cache);
		$cache['cron'] = ['last_run' => time() - 3600, 'next_due' => time() - 1, 'jitter' => 0, 'pending_apply' => TRUE];
		$state = ['schema' => 1, 'items' => []];
		foreach ($model['entries'] as $id => $entry) {
			if (str_starts_with($id, 'extra:') && $entry['enabled']) {
				$cache[$id]         = ['last_run' => time(), 'next_due' => time() + 86400, 'jitter' => 0];
				$state['items'][$id] = ['last_completed_occurrence' => time(), 'completion_outcome' => 'success'];
			}
		}
		$this->assertTrue(pfb_schedule_state_write($state, $this->stateDir));
		unset($cache['_meta']);
		$this->assertTrue(pfb_due_ledger_write_cache($cache, $model['config_hash'], $this->dir));
		foreach (['dcc', 'bl', 'ss_refresh', 'apply_reconcile'] as $job) {
			$entry = ['last_run' => time() + 86399, 'next_due' => time() + 86400, 'jitter' => 0];
			$this->assertTrue(pfb_due_ledger_write_entry($job, $entry, $this->dir));
		}
	}

	// ---- (a) the receive opens the record -----------------------------------------------

	public function testChangedReceiveOpensAWaitingApplyRecord(): void
	{
		$this->receive(self::policyPayload());
		$this->assertNull($this->apply(), 'before-state: the receive itself opens nothing');

		$before = time();
		pfblockerng_plugin_xmlrpc_recv_done(NULL);

		$apply = $this->apply();
		$this->assertIsArray($apply);
		$this->assertSame('waiting', $apply['outcome']);
		$this->assertArrayNotHasKey('reason', $apply);
		$this->assertGreaterThanOrEqual($before, $apply['time']);
		$this->assertLessThanOrEqual(time(), $apply['time']);
		$this->assertLastStillChanged();
		$this->assertCount(1, $GLOBALS['pfb_test_mwexec_bg'], 'the tick is still started once');
	}

	public function testUnchangedReceiveOpensNoApplyRecord(): void
	{
		$this->receive(self::policyPayload());
		pfblockerng_plugin_xmlrpc_recv_done(NULL);
		pfb_sync_receive_state_write(['apply' => NULL] + $this->state(), $this->dir);
		$this->assertSame([], $this->receive(self::policyPayload()), 'before-state: the second receive changes nothing');

		pfblockerng_plugin_xmlrpc_recv_done(NULL);

		$this->assertNull($this->apply());
		$this->assertSame('unchanged', $this->state()['last']['outcome']);
	}

	public function testLegacyReceiveOpensNoApplyRecord(): void
	{
		$payload = ['pfblockerngglobal' => ['feed_foo' => 'off'], 'pfblockerngsync' => ['config' => [0 => ['varsynconchanges' => 'auto']]]];
		$this->assertNotSame([], pfblockerng_plugin_xmlrpc_recv(['installedpackages' => $payload]));

		pfblockerng_plugin_xmlrpc_recv_done(NULL);

		$this->assertNull($this->apply());
		$this->assertFileDoesNotExist($this->dir . '/pfb_sync_receive.json');
	}

	public function testRefusedReceiveOpensNoApplyRecord(): void
	{
		$this->assertSame([], $this->receive(self::policyPayload('all')));

		pfblockerng_plugin_xmlrpc_recv_done(NULL);

		$this->assertNull($this->apply());
		$this->assertSame('refused', $this->state()['last']['outcome']);
	}

	// ---- (b) tick outside the window ----------------------------------------------------

	public function testTickOutsideTheWindowSettlesAnOpenRecordAsWaitingWithReason(): void
	{
		$this->seedRecord('failed', self::REASON_FAILED);
		$this->seedPendingCron(TRUE);
		$manualRuns = 0;

		$this->tick(static function () use (&$manualRuns): bool {
			$manualRuns++;
			return TRUE;
		});

		$this->assertSame(0, $manualRuns, 'the apply stays deferred outside its window');
		$this->assertTrue(pfb_due_ledger_read_entry('cron', $this->dir)['pending_apply'] ?? FALSE, 'pending changes are kept');
		$apply = $this->apply();
		$this->assertSame('waiting', $apply['outcome'] ?? NULL);
		$this->assertSame(self::REASON_WINDOW, $apply['reason'] ?? NULL);
		$this->assertLastStillChanged();
	}

	// ---- (c) manual apply fails inside the window ---------------------------------------

	public function testFailedManualApplySettlesAnOpenRecordAsFailed(): void
	{
		$this->seedRecord('waiting');
		$this->seedPendingCron(FALSE);
		$manualRuns = 0;

		$this->tick(static function () use (&$manualRuns): bool {
			$manualRuns++;
			return FALSE;
		});

		$this->assertSame(1, $manualRuns, 'the apply was dispatched');
		$this->assertFileExists($GLOBALS['pfb']['pending_marker'], 'the pending marker is kept for the next tick');
		$apply = $this->apply();
		$this->assertSame('failed', $apply['outcome'] ?? NULL);
		$this->assertSame(self::REASON_FAILED, $apply['reason'] ?? NULL);
		$this->assertLastStillChanged();
	}

	// ---- (d) a completed apply: the real end of sync_package_pfblockerng() ---------------

	private function seedApplyEnvironment(): void
	{
		$gen = 'installedpackages/pfblockerng/config/0';
		foreach (['pfb_min' => '0', 'pfb_hour' => '0', 'pfb_dailystart' => '0', 'pfb_interval' => '24', 'pfb_reuse' => '', 'enable_cb' => 'on'] as $key => $value) {
			config_set_path("{$gen}/{$key}", $value);
		}
		foreach (['enable_dup', 'enable_agg', 'enable_float', 'enable_log', 'killstates', 'ip_placeholder', 'inbound_deny_action', 'outbound_deny_action', 'pass_order', 'autorule_suffix'] as $key) {
			config_set_path("installedpackages/pfblockerngipsettings/config/0/{$key}", '');
		}
		config_set_path('installedpackages/pfblockerngblacklist/blacklist_enable', 'Disable');
		foreach (['enable_dedup', 'enable_pdup', 'enable_rep', 'et_update', 'ccwhite', 'ccblack', 'etblock', 'etmatch', 'p24_max_var', 'p24_dmax_var', 'p24_pmax_var', 'ccexclude'] as $key) {
			config_set_path("installedpackages/pfblockerngreputation/config/0/{$key}", '');
		}
		$dnsbl = 'installedpackages/pfblockerngdnsblsettings/config/0';
		foreach (['top1m_enable', 'top1m_count', 'top1m_inclusion', 'pfb_cache', 'pfb_py_reply', 'pfb_regex', 'pfb_regex_list', 'pfb_cname', 'tld_allow', 'pfb_py_nolog', 'pfb_noaaaa', 'pfb_noaaaa_list', 'pfb_gp', 'pfb_gp_bypass_list', 'pfb_dnsbl_rule', 'tld_wildcard', 'pfb_control'] as $key) {
			config_set_path("{$dnsbl}/{$key}", '');
		}
		$GLOBALS['g']['pfblockerng_install'] = FALSE;
		$GLOBALS['pfb']['install']      = FALSE;
		$GLOBALS['pfb']['domain_clear'] = FALSE;
		$GLOBALS['pfb']['save']         = FALSE;
		pfb_mark_pending_changes();
	}

	public function testCompletedApplySettlesAnOpenRecordAsApplied(): void
	{
		$this->seedRecord('waiting');
		$this->seedApplyEnvironment();

		sync_package_pfblockerng();

		$this->assertFileDoesNotExist($GLOBALS['pfb']['pending_marker'], 'before-state check: the pass cleared the pending marker');
		$apply = $this->apply();
		$this->assertSame('applied', $apply['outcome'] ?? NULL);
		$this->assertArrayNotHasKey('reason', $apply ?? []);
		$this->assertLastStillChanged();
	}

	public function testUnclearedPendingMarkerSettlesAnOpenRecordAsFailed(): void
	{
		$this->seedRecord('waiting');
		$this->seedApplyEnvironment();
		// A due-ledger entry that cannot be rewritten keeps the marker, as an unconfirmed reload does.
		$this->assertTrue(pfb_due_ledger_write_entry('cron', ['last_run' => 0, 'next_due' => 0, 'jitter' => 0, 'pending_apply' => TRUE], $this->dir));
		$ledger = json_decode((string) file_get_contents($this->dir . '/pfb_due_ledger.json'), TRUE);
		$ledger['dcc'] = 'not-an-entry';
		file_put_contents($this->dir . '/pfb_due_ledger.json', json_encode($ledger));

		sync_package_pfblockerng();

		$apply = $this->apply();
		$this->assertSame('failed', $apply['outcome'] ?? NULL);
		$this->assertSame(self::REASON_RELOAD, $apply['reason'] ?? NULL);
		$this->assertFileExists($GLOBALS['pfb']['pending_marker'], 'the pending marker survives');
		$this->assertLastStillChanged();
	}

	private function resetEnvironment(): void
	{
		$this->tearDown();
		$this->setUp();
	}

	// ---- (e) a local apply never creates or changes a record ----------------------------

	public function testLocalApplyWithNoOpenRecordLeavesTheApplyRecordNull(): void
	{
		$this->seedPendingCron(TRUE);
		$this->tick(static fn (): bool => TRUE);
		$this->assertNull($this->apply(), 'deferred outside the window');

		$this->resetEnvironment();
		$this->seedPendingCron(FALSE);
		$this->tick(static fn (): bool => FALSE);
		$this->assertNull($this->apply(), 'failed inside the window');

		$this->resetEnvironment();
		$this->seedApplyEnvironment();
		sync_package_pfblockerng();
		$this->assertNull($this->apply(), 'a completed local apply');
		$this->assertFileDoesNotExist($this->dir . '/pfb_sync_receive.json', 'no state file is created for it');
	}

	public function testAnAppliedRecordIsNotReopenedByALaterLocalFailureOrDeferral(): void
	{
		$time = $this->seedRecord('applied');
		$this->seedPendingCron(FALSE);
		$this->tick(static fn (): bool => FALSE);
		$this->assertSame(['time' => $time, 'outcome' => 'applied'], $this->apply(), 'a failed local apply');

		$this->resetEnvironment();
		$time = $this->seedRecord('applied');
		$this->seedPendingCron(TRUE);
		$this->tick(static fn (): bool => TRUE);
		$this->assertSame(['time' => $time, 'outcome' => 'applied'], $this->apply(), 'a deferred local apply');
	}

	// ---- (g) the receive helpers keep the apply record ----------------------------------

	public function testStateReadCarriesApplyOnlyWhenItIsAnArray(): void
	{
		// SyncPolicyReceiveTest pins the two-key shape for a state without an apply record.
		$this->assertSame(['accepted_digest' => NULL, 'last' => NULL], $this->state(), 'a missing file');

		file_put_contents($this->dir . '/pfb_sync_receive.json', json_encode(['accepted_digest' => NULL, 'last' => NULL, 'apply' => 'garbage']));
		$this->assertSame(['accepted_digest' => NULL, 'last' => NULL], $this->state(), 'a non-array apply is dropped');

		$time = $this->seedRecord('waiting');
		$this->assertSame(['time' => $time, 'outcome' => 'waiting'], $this->state()['apply'] ?? NULL);
	}

	public function testReceiveRecordKeepsAnExistingApplyRecord(): void
	{
		$time = $this->seedRecord('waiting');

		pfb_sync_receive_record('unchanged', str_repeat('c', 64), '', $this->dir);

		$this->assertSame(['time' => $time, 'outcome' => 'waiting'], $this->state()['apply'] ?? NULL);
		$this->assertSame('unchanged', $this->state()['last']['outcome']);
	}

	public function testAcceptedClearKeepsAnExistingApplyRecord(): void
	{
		$time = $this->seedRecord('failed', self::REASON_FAILED);

		pfb_sync_receive_accepted_clear($this->dir);

		$this->assertNull($this->state()['accepted_digest']);
		$this->assertSame(['time' => $time, 'outcome' => 'failed', 'reason' => self::REASON_FAILED], $this->state()['apply'] ?? NULL);
	}

	// ---- state file write ---------------------------------------------------------------

	public function testStateWriteNeverFollowsAPlantedTempSymlink(): void
	{
		$sentinel = $this->dir . '/sentinel.txt';
		file_put_contents($sentinel, 'SENTINEL-UNTOUCHED');
		$this->assertTrue(symlink($sentinel, $this->dir . '/pfb_sync_receive.json.tmp'));

		pfb_sync_receive_record('unchanged', str_repeat('d', 64), '', $this->dir);

		$this->assertSame('SENTINEL-UNTOUCHED', file_get_contents($sentinel), 'the symlink target is never written');
		$path = $this->dir . '/pfb_sync_receive.json';
		$this->assertFalse(is_link($path));
		$this->assertTrue(is_file($path));
		clearstatcache();
		$this->assertSame(0600, fileperms($path) & 0777);
		$this->assertSame('unchanged', $this->state()['last']['outcome']);
		$this->assertSame(str_repeat('d', 64), $this->state()['accepted_digest']);
	}

	public function testStateWriteLeavesNoTempFileBehind(): void
	{
		pfb_sync_receive_record('unchanged', str_repeat('e', 64), '', $this->dir);

		$leftovers = array_values(array_filter(
			array_map('basename', glob($this->dir . '/pfb_sync_receive*') ?: []),
			static fn (string $name): bool => $name !== 'pfb_sync_receive.json'
		));
		$this->assertSame([], $leftovers);
	}
}
