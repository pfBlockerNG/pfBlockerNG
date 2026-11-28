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
 * Also pins the state file write: an owner-only (0600) regular file, no temp file left behind.
 */
#[CoversFunction('pfb_sync_receive_state_read')]
#[CoversFunction('pfb_sync_apply_record')]
#[CoversFunction('pfb_sync_receive_record')]
#[CoversFunction('pfb_sync_receive_accepted_clear')]
#[CoversFunction('pfblockerng_plugin_xmlrpc_recv_done')]
#[CoversFunction('pfblockerng_tick')]
final class SyncPolicyApplyRecordTest extends TestCase
{
	private const REASON_WINDOW = 'outside the apply window';
	private const REASON_FAILED = 'apply failed; pending changes kept';

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

	/** One tick against a Core that admits every Update; $start is called with the trigger of each `StartUpdate` (the work Core would run). */
	private function tick(callable $start): void
	{
		pfblockerng_tick(
			ps_lines: [],
			ss_refresh: static fn (): bool => TRUE,
			apply_reconcile: static fn (): bool => TRUE,
			core_settings: static fn (): ?string => NULL,
			core_call: static function (string $method, array $params = []) use ($start): array {
				if ($method === 'StartUpdate') {
					$start($params['trigger']);
				}
				return ['status' => 200, 'body' => ['running' => FALSE], 'error' => NULL];
			}
		);
	}

	/** A pending manual apply in the due ledger (or, with $ledgerPending FALSE, none), inside the apply window unless $outsideWindow. */
	private function seedPendingCron(bool $outsideWindow, bool $ledgerPending = TRUE): void
	{
		if ($outsideWindow) {
			$start = ((int) date('G') + 12) % 24;
			PfbConfig::writeSystem('gen/pfb_quiet_hours', sprintf('%02d:00-%02d:01', $start, $start));
		}
		if ($ledgerPending) {
			$this->assertTrue(pfb_due_ledger_set_pending('cron', $this->dir));
		}
		foreach (['ss_refresh', 'apply_reconcile'] as $job) {
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

		$this->tick(static function () use (&$manualRuns): void {
			$manualRuns++;
		});

		$this->assertSame(0, $manualRuns, 'the apply stays deferred outside its window');
		$this->assertTrue(pfb_due_ledger_read_entry('cron', $this->dir)['pending_apply'] ?? FALSE, 'pending changes are kept');
		$apply = $this->apply();
		$this->assertSame('waiting', $apply['outcome'] ?? NULL);
		$this->assertSame(self::REASON_WINDOW, $apply['reason'] ?? NULL);
		$this->assertLastStillChanged();
	}

	// ---- (d2) what a completed pass records for the receiver (#3453) ---------------------

	// A pass that saw the accepted digest just before a Sync save can write the findings after the save removed them.
	public function testAFormerReceiverShowsNoFindingsAnApplyWroteAfterTheSyncSave(): void
	{
		$this->seedRecord('waiting');
		pfb_sync_receive_accepted_clear($this->dir);
		pfb_sync_findings_record(['TOP1M: provider token missing'], $this->dir);
		$this->assertFileExists($this->dir . '/pfb_sync_findings.json', 'before-state check: the late write landed');

		$panel = pfb_sync_receiver_panel(pfb_sync_receive_state_read($this->dir), NULL, pfb_sync_findings_read($this->dir), []);

		$this->assertNotSame('', $panel, 'the receive record keeps the panel');
		$this->assertStringNotContainsString('failed validation', $panel, 'a node that no longer accepts policy lists no findings');
	}

	/** @return array<string,mixed> outcome and reason of the apply record, nothing else */
	private function settled(): array
	{
		return array_intersect_key($this->apply() ?? [], ['outcome' => 1, 'reason' => 1]);
	}

	// ---- (e) a mark taken during a pass belongs to the next pass -------------------------

	public function testTickAppliesAPendingMarkTheLedgerDoesNotCarry(): void
	{
		$this->seedRecord('waiting');
		$this->seedPendingCron(FALSE, FALSE);
		$manualRuns = 0;
		$manual     = static function () use (&$manualRuns): void {
			$manualRuns++;
		};

		$this->tick($manual);
		$this->assertSame(0, $manualRuns, 'before-state check: neither the ledger nor a marker is pending, so nothing is applied');

		pfb_mark_pending_changes();
		$this->tick($manual);

		$this->assertSame(1, $manualRuns, 'the marker alone makes the tick apply');
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

	// ---- (e) a local apply never creates or changes a record ----------------------------

	public function testLocalApplyWithNoOpenRecordLeavesTheApplyRecordNull(): void
	{
		$this->seedPendingCron(TRUE);
		$this->tick(static function (): void {});
		$this->assertNull($this->apply(), 'deferred outside the window');
	}

	public function testAnAppliedRecordIsNotReopenedByALaterLocalDeferral(): void
	{
		$time = $this->seedRecord('applied');
		$this->seedPendingCron(TRUE);
		$this->tick(static function (): void {});
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
