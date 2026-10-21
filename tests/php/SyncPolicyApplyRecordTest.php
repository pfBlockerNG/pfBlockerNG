<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3452 -- the apply record: state key `apply` = NULL | {time, outcome: waiting|failed|applied,
 * reason?} in {dbdir}/pfb_sync_receive.json (docs/specs/xmlrpc-per-field-sync.md, "Reporting",
 * acceptance 10). A changed receive opens it as `waiting`; the tick and the apply end only move an
 * OPEN record, so a purely local apply never creates or changes one. The receive record (`last`)
 * keeps its own vocabulary whatever the apply does.
 *
 * Also pins the state file write: an owner-only (0600) regular file, no temp file left behind.
 */
#[CoversFunction('pfb_sync_receive_state_read')]
#[CoversFunction('pfb_sync_apply_record')]
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
	private const REASON_APPLIED = 'update pass completed'; // these passes change no rule, so no reload is launched

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
		$GLOBALS['pfb_test_file_notices'] = [];
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
		unset($GLOBALS['pfb_test_mwexec_bg'], $GLOBALS['pfb_test_logger_calls'], $GLOBALS['pfb_test_file_notices'], $GLOBALS['pfb_test_vip_list']);
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

	/** Seeds the state file as a peer's earlier publication. */
	private function seedState(array $state): void
	{
		file_put_contents($this->dir . '/pfb_sync_receive.json', json_encode($state));
	}

	/** Seeds the state as a prior changed receive that opened an apply record $age seconds ago. */
	private function seedRecord(string $outcome, string $reason = '', int $age = 100): int
	{
		$time  = time() - $age;
		$apply = ['time' => $time, 'outcome' => $outcome] + ($reason === '' ? [] : ['reason' => $reason]);
		$this->seedState([
			'accepted_digest' => 'ab' . str_repeat('0', 62),
			'last'            => ['time' => $time, 'outcome' => 'changed'],
			'apply'           => $apply,
		]);

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

	/** A pending manual apply in the due ledger (or, with $ledgerPending FALSE, only due), the cache regenerated for the current model. */
	private function seedPendingCron(bool $outsideWindow, bool $ledgerPending = TRUE): void
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
		$cache['cron'] = ['last_run' => time() - 3600, 'next_due' => time() - 1, 'jitter' => 0] + ($ledgerPending ? ['pending_apply' => TRUE] : []);
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
		$this->seedState(['apply' => NULL] + $this->state());
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
		$this->assertTrue(pfb_pending_changes(), 'the pending mark is kept for the next tick');
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

		$this->assertFalse(pfb_pending_changes(), 'before-state check: the pass applied the pending mark');
		$apply = $this->apply();
		$this->assertSame('applied', $apply['outcome'] ?? NULL);
		$this->assertSame(self::REASON_APPLIED, $apply['reason'] ?? NULL, 'a pass that launched no reload does not claim one');
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
		$this->assertTrue(pfb_pending_changes(), 'the pending mark survives');
		$this->assertLastStillChanged();
	}

	// ---- (d2) what a completed pass records for the receiver (#3453) ---------------------

	/** Manual VIP mode with a VIP that fails validation: pfb_global() force-disables DNSBL (#331). */
	private function seedInvalidVip(): void
	{
		$GLOBALS['pfb_test_vip_list'] = [];
		PfbConfig::write('dnsbl/pfb_dnsbl', 'on');
		PfbConfig::write('dnsbl/pfb_dnsvip_auto', '');
		PfbConfig::write('dnsbl/dnsbl_interface', 'opt-double');
		config_set_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsvip4', '_vip_test_missing');
		config_set_path('installedpackages/pfblockerngdnsblsettings/config/0/tld_allow', 'on');	// issue #3539: a built-in answers with the VIP, so it is validated
	}

	/** @return list<string> */
	private function noticeTitles(): array
	{
		return array_column($GLOBALS['pfb_test_file_notices'], 'id');
	}

	public function testLocalApplyWithoutAReceiveRecordRecordsNoFindings(): void
	{
		$this->seedApplyEnvironment();
		$this->seedInvalidVip();

		sync_package_pfblockerng();

		$this->assertFalse(pfb_pending_changes(), 'before-state check: the pass completed');
		$this->assertContains('pfBlockerNG DNSBL', $this->noticeTitles(), 'before-state check: the VIP failed validation');
		$this->assertNotContains('pfBlockerNG Sync', $this->noticeTitles(), 'a node that never received policy raises no Sync notice');
		$this->assertFileDoesNotExist($this->dir . '/pfb_sync_findings.json');
		$this->assertFileDoesNotExist($this->dir . '/pfb_sync_receive.json', 'and no receive record is created');
	}

	public function testCompletedApplyWithAReceiveRecordRecordsTheFindingsOnce(): void
	{
		$this->seedRecord('waiting');
		$this->seedApplyEnvironment();
		$this->seedInvalidVip();
		config_set_path('installedpackages/pfblockernglistsv4/config', [[
			'aliasname' => 'Top', 'action' => 'Deny_Inbound', 'cron' => 'EveryDay', 'autoproto_in' => '', 'autoproto_out' => '', 'agateway_in' => 'default', 'agateway_out' => 'default',
			'row'       => [['format' => 'auto', 'state' => 'Enabled', 'url' => 'https://feeds.example/top', 'header' => 'DNSBLIP']],
		]]);

		sync_package_pfblockerng();
		$this->seedApplyEnvironment();
		$this->seedInvalidVip();
		sync_package_pfblockerng();

		$findings = pfb_sync_findings_read($this->dir)['findings'];
		$this->assertContains('DNSBL disabled: the DNSBL VIP failed validation', $findings);
		$this->assertContains('Header skipped as reserved: DNSBLIP (pfblockernglistsv4)', $findings, 'the pass captured its reserved-header skips');
		$this->assertSame(1, count(array_keys($this->noticeTitles(), 'pfBlockerNG Sync', TRUE)), 'one notice for unchanged findings');
	}

	public function testARefusedOnlyReceiveRecordRecordsNoFindings(): void
	{
		$this->seedState(['accepted_digest' => NULL, 'last' => ['time' => time() - 100, 'outcome' => 'refused', 'reason' => 'syncscope is not policy']]);
		$this->seedApplyEnvironment();
		$this->seedInvalidVip();

		sync_package_pfblockerng();

		$this->assertFalse(pfb_pending_changes(), 'before-state check: the pass completed');
		$this->assertContains('pfBlockerNG DNSBL', $this->noticeTitles(), 'before-state check: the VIP failed validation');
		$this->assertNotContains('pfBlockerNG Sync', $this->noticeTitles(), 'a node that never accepted a policy raises no Sync notice');
		$this->assertFileDoesNotExist($this->dir . '/pfb_sync_findings.json');
	}

	public function testTheSyncPageSaveStopsTheFindingsAndForgetsTheRecordedOnes(): void
	{
		$this->seedRecord('waiting');
		$this->seedApplyEnvironment();
		$this->seedInvalidVip();
		sync_package_pfblockerng();
		$this->assertFileExists($this->dir . '/pfb_sync_findings.json', 'before-state check: an accepting receiver records them');

		pfb_sync_receive_accepted_clear($this->dir);

		$this->assertFileDoesNotExist($this->dir . '/pfb_sync_findings.json', 'the role flip forgets the stored findings');
		$this->seedApplyEnvironment();
		sync_package_pfblockerng();

		$this->assertFileDoesNotExist($this->dir . '/pfb_sync_findings.json', 'a former receiver records nothing on the next pass');
		$this->assertSame(1, count(array_keys($this->noticeTitles(), 'pfBlockerNG Sync', TRUE)), 'and raises no further Sync notice');
		$panel = pfb_sync_receiver_panel(pfb_sync_receive_state_read($this->dir), NULL, pfb_sync_findings_read($this->dir), []);
		$this->assertNotSame('', $panel, 'the receive record keeps the panel');
		$this->assertStringNotContainsString('failed validation', $panel, 'and it lists no findings');
	}

	// A pass that saw the accepted digest just before a Sync save can write the findings after the save removed them.
	public function testAFormerReceiverShowsNoFindingsAnApplyWroteAfterTheSyncSave(): void
	{
		$this->seedRecord('waiting');
		pfb_sync_receive_accepted_clear($this->dir);
		pfb_sync_findings_record(['DNSBL disabled: the DNSBL VIP failed validation'], $this->dir);
		$this->assertFileExists($this->dir . '/pfb_sync_findings.json', 'before-state check: the late write landed');

		$panel = pfb_sync_receiver_panel(pfb_sync_receive_state_read($this->dir), NULL, pfb_sync_findings_read($this->dir), []);

		$this->assertNotSame('', $panel, 'the receive record keeps the panel');
		$this->assertStringNotContainsString('failed validation', $panel, 'a node that no longer accepts policy lists no findings');
	}

	public function testCompletedApplyRecordsTheCopiedAliasAndFilterState(): void
	{
		$this->seedApplyEnvironment();
		config_set_path('installedpackages/pfblockerng/config/0/enable_cb', ''); // a disabled pass still reconciles both writers
		$this->assertFileDoesNotExist($this->dir . '/pfb_sync_copied.json', 'before-state check');

		sync_package_pfblockerng();

		$recorded = pfb_sync_copied_read($this->dir)['recorded'];
		$this->assertArrayHasKey('aliases', $recorded, 'the alias writer ran the detector');
		$this->assertArrayHasKey('filter', $recorded, 'the filter writer ran the detector');
	}

	/** The pass's own apply reconciliation fails, so it leaves the pending mark unsettled, as an unconfirmed reload does. */
	private function breakTheDueLedger(): void
	{
		$this->assertTrue(pfb_due_ledger_write_entry('cron', ['last_run' => 0, 'next_due' => 0, 'jitter' => 0, 'pending_apply' => TRUE], $this->dir));
		$ledger = json_decode((string) file_get_contents($this->dir . '/pfb_due_ledger.json'), TRUE);
		$ledger['dcc'] = 'not-an-entry';
		file_put_contents($this->dir . '/pfb_due_ledger.json', json_encode($ledger));
	}

	/**
	 * Runs $action once from inside the next pass; the logger double is the pass's first observable
	 * call after it captured its start. Waits for the next second first unless $sameSecond.
	 */
	private function duringPass(callable $action, bool $sameSecond = FALSE): ArrayObject
	{
		$probe = new ArrayObject(['fired' => FALSE]);
		$GLOBALS['pfb_test_logger_calls'] = new class ($action, $probe, $sameSecond) implements ArrayAccess {
			public function __construct(private $action, private ArrayObject $probe, private bool $sameSecond) {}
			public function offsetExists(mixed $o): bool { return FALSE; }
			public function offsetGet(mixed $o): mixed { return NULL; }
			public function offsetSet(mixed $o, mixed $v): void
			{
				if (!$this->probe['fired']) {
					$this->probe['fired'] = TRUE;
					$this->sameSecond || time_sleep_until(floor(microtime(TRUE)) + 1);
					($this->action)();
				}
			}
			public function offsetUnset(mixed $o): void {}
		};

		return $probe;
	}

	/** @return array<string,mixed> outcome and reason of the apply record, nothing else */
	private function settled(): array
	{
		return array_intersect_key($this->apply() ?? [], ['outcome' => 1, 'reason' => 1]);
	}

	/** @return iterable<string,array{0:bool,1:array<string,string>}> */
	public static function passKinds(): iterable
	{
		yield 'completed pass'   => [FALSE, ['outcome' => 'applied', 'reason' => self::REASON_APPLIED]];
		yield 'unconfirmed pass' => [TRUE, ['outcome' => 'failed', 'reason' => self::REASON_RELOAD]];
	}

	/** @param array<string,string> $settled */
	#[DataProvider('passKinds')]
	public function testTickRestampDuringAPassDoesNotHideThatThePassSettledTheRecord(bool $unconfirmed, array $settled): void
	{
		// The tick re-stamps an open record as waiting (outside the window) on every run, before it takes any lock.
		$this->seedRecord('waiting', '', 100);
		$this->seedApplyEnvironment();
		$unconfirmed && $this->breakTheDueLedger();
		$probe = $this->duringPass(fn () => pfb_sync_apply_record('waiting', self::REASON_WINDOW, $this->dir));

		sync_package_pfblockerng();

		$this->assertTrue($probe['fired'], 'before-state check: the re-stamp ran inside the pass');
		$this->assertSame($unconfirmed, pfb_pending_changes(), 'before-state check: the pass ended as the case says');
		$this->assertSame($settled, $this->settled());
		$this->assertLastStillChanged();
	}

	/** @param array<string,string> $settled */
	#[DataProvider('passKinds')]
	public function testPassLeavesARecordReopenedAfterItStartedWaiting(bool $unconfirmed, array $settled): void
	{
		$this->seedRecord('waiting', '', 100);
		$this->seedApplyEnvironment();
		$unconfirmed && $this->breakTheDueLedger();
		// recv_done's order: open the record, then mark pending.
		$probe = $this->duringPass(function (): void {
			pfb_sync_apply_record('waiting', '', $this->dir, TRUE);
			pfb_mark_pending_changes();
		});

		sync_package_pfblockerng();

		$this->assertTrue($probe['fired'], 'before-state check: the receive reopened the record inside the pass');
		$this->assertTrue(pfb_pending_changes(), 'the receive the pass did not apply stays pending, so the next tick applies it');
		$this->assertSame(['outcome' => 'waiting'], $this->settled(), 'the pass did not apply that receive');
		$this->assertLastStillChanged();
	}

	// ---- (e) a mark taken during a pass belongs to the next pass -------------------------

	/**
	 * Given a pass that starts with a pending mark and finishes cleanly
	 * When a mark is taken inside the pass
	 * Then the marker survives it, because the pass cleared only the mark it saw at its start
	 */
	public function testAMarkTakenInsideACompletedPassSurvivesIt(): void
	{
		$this->seedApplyEnvironment();
		$this->assertFileExists($GLOBALS['pfb']['pending_marker'], 'before-state check: the pass starts with a mark');
		$atStart = (string) file_get_contents($GLOBALS['pfb']['pending_marker']);
		$probe = $this->duringPass(static fn () => pfb_mark_pending_changes(), TRUE);

		sync_package_pfblockerng();

		$this->assertTrue($probe['fired'], 'before-state check: the mark was taken inside the pass');
		$this->assertTrue(pfb_pending_changes(), 'a mark taken during the pass must survive it, so the next tick applies what the pass did not see');
		$this->assertNotSame($atStart, (string) file_get_contents($GLOBALS['pfb']['pending_marker']), 'and it is the mark of the pass, not the one the pass started with');
	}

	/**
	 * Given a pass that starts with no pending mark and finishes cleanly
	 * When a mark is taken inside the pass
	 * Then the marker survives it, because the pass saw no mark and so clears none
	 */
	public function testAMarkTakenInsideACompletedPassThatStartedCleanSurvivesIt(): void
	{
		$this->seedApplyEnvironment();
		unlink($GLOBALS['pfb']['pending_marker']);
		$this->assertFileDoesNotExist($GLOBALS['pfb']['pending_marker'], 'before-state check: the pass starts with no mark');
		$probe = $this->duringPass(static fn () => pfb_mark_pending_changes(), TRUE);

		sync_package_pfblockerng();

		$this->assertTrue($probe['fired'], 'before-state check: the mark was taken inside the pass');
		$this->assertTrue(pfb_pending_changes(), 'a mark taken during a pass that saw none must survive it');
	}

	public function testACompletedPassAppliesTheMarkItSawAtItsStart(): void
	{
		$this->seedApplyEnvironment();
		$this->assertFileExists($GLOBALS['pfb']['pending_marker'], 'before-state check: the pass starts with a mark');

		sync_package_pfblockerng();

		$this->assertFalse(pfb_pending_changes(), 'an untouched mark is applied by the pass');
	}

	public function testASurvivingMarkDoesNotKeepTheLedgerPending(): void
	{
		$this->seedApplyEnvironment();
		$this->assertTrue(pfb_due_ledger_write_entry('cron', ['last_run' => 0, 'next_due' => 0, 'jitter' => 0, 'pending_apply' => TRUE], $this->dir));
		$this->assertTrue(pfb_due_ledger_is_pending('cron', $this->dir), 'before-state check: the ledger starts pending');
		$this->duringPass(static fn () => pfb_mark_pending_changes(), TRUE);

		sync_package_pfblockerng();

		$this->assertTrue(pfb_pending_changes(), 'before-state check: the mark survived the pass');
		$this->assertFalse(pfb_due_ledger_is_pending('cron', $this->dir), 'the ledger is settled; the surviving marker alone carries the next apply');
	}

	public function testTickAppliesAPendingMarkTheLedgerDoesNotCarry(): void
	{
		$this->seedRecord('waiting');
		$this->seedPendingCron(FALSE, FALSE);
		$manualRuns = 0;
		$manual     = static function () use (&$manualRuns): bool {
			$manualRuns++;
			return TRUE;
		};

		$this->tick($manual);
		$this->assertSame(0, $manualRuns, 'before-state check: neither the ledger nor a marker is pending, so nothing is applied');

		pfb_mark_pending_changes();
		$this->tick($manual);

		$this->assertSame(1, $manualRuns, 'the marker alone makes the tick apply');
	}

	public function testASavePassLeavesTheMarkerAlone(): void
	{
		$this->seedApplyEnvironment();
		$GLOBALS['pfb']['save'] = TRUE;
		$this->assertFileExists($GLOBALS['pfb']['pending_marker'], 'before-state check: the pass starts with a mark');

		sync_package_pfblockerng();

		$this->assertTrue(pfb_pending_changes(), 'a settings-save pass applies no deferred change, so it stays pending');
	}

	/**
	 * Given a changed receive
	 * When recv_done writes the pending marker
	 * Then the apply record is already open: a pass that cleared an earlier mark either settles the record or leaves record and mark both
	 */
	public function testReceiveOpensTheRecordBeforeItMarksPending(): void
	{
		$this->receive(self::policyPayload());
		$this->assertNull($this->apply(), 'before-state check: the receive itself opens nothing');
		$markWriter = new class {
			public static array $outcomes = [];
			public static string $dir = '';
			public $context;
			public function stream_open(string $path, string $mode, int $options, ?string &$opened): bool
			{
				self::$outcomes[] = pfb_sync_receive_state_read(self::$dir)['apply']['outcome'] ?? NULL;
				return TRUE;
			}
			public function stream_write(string $data): int { return strlen($data); }
			public function stream_close(): void {}
		};
		$markWriter::$dir = $this->dir;
		$GLOBALS['pfb']['pending_marker'] = 'pfbmark://marker';
		$this->assertTrue(stream_wrapper_register('pfbmark', $markWriter::class), 'before-state check: the probe sees the marker write');

		try {
			pfblockerng_plugin_xmlrpc_recv_done(NULL);
		} finally {
			stream_wrapper_unregister('pfbmark');
		}

		$this->assertSame(['waiting'], $markWriter::$outcomes, 'the marker is written once, after the apply record opened');
	}

	// The settle compares the record's OPEN time with the pass start: opened in the pass's own second still settles.
	public function testSettleBoundaryIsTheSecondTheRecordWasOpenedIn(): void
	{
		$passStarted = time() - 10;
		$seed = fn (int $opened) => $this->seedState([
			'accepted_digest' => NULL,
			'last'            => NULL,
			'apply'           => ['time' => $passStarted + 5, 'opened' => $opened, 'outcome' => 'waiting'],
		]);

		$seed($passStarted);
		pfb_sync_apply_record('applied', '', $this->dir, FALSE, $passStarted);
		$this->assertSame(['outcome' => 'applied'], $this->settled(), 'opened in the pass start second, last moved later');

		$seed($passStarted + 1);
		pfb_sync_apply_record('applied', '', $this->dir, FALSE, $passStarted);
		$this->assertSame(['outcome' => 'waiting'], $this->settled(), 'opened the second after the pass started');
	}

	public function testLaterMovesKeepTheOpenTimeAndReopeningResetsIt(): void
	{
		$opened = time() - 100;
		$this->seedState(['accepted_digest' => NULL, 'last' => NULL, 'apply' => ['time' => $opened, 'opened' => $opened, 'outcome' => 'waiting']]);

		pfb_sync_apply_record('failed', self::REASON_FAILED, $this->dir);
		$this->assertSame($opened, $this->apply()['opened'] ?? NULL, 'a move keeps when the record was opened');
		$this->assertGreaterThan($opened, $this->apply()['time'] ?? 0);

		pfb_sync_apply_record('waiting', '', $this->dir, TRUE);
		$this->assertGreaterThan($opened, $this->apply()['opened'] ?? 0, 'opening again restarts it');
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

	public function testStateWriteIsAnOwnerOnlyRegularFile(): void
	{
		pfb_sync_receive_record('unchanged', str_repeat('d', 64), '', $this->dir);

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

		// The writer stages through a '.pfb_schedule.' temp file beside an empty '.lock' sidecar.
		$leftovers = array_values(array_diff(
			array_map('basename', glob($this->dir . '/{.pfb_schedule.,pfb_sync_receive}*', GLOB_BRACE) ?: []),
			['pfb_sync_receive.json', 'pfb_sync_receive.json.lock']
		));
		$this->assertSame([], $leftovers);
	}
}
