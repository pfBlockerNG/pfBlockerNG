<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/SyncPolicyFixtureTrait.php';

/**
 * Issue #3452 — the receiver side of per-field XMLRPC policy sync: the gate dispatch of
 * pfblockerng_plugin_xmlrpc_recv(), the ledger close of a removed alias, the receive record, the
 * single apply of plugin_xmlrpc_recv_done and the received-digest suppression of this node's own
 * manual sync (docs/specs/xmlrpc-per-field-sync.md, "Receive merge", "Apply on receive and
 * authority", "Reporting").
 *
 * Every receive is applied the way core's xmlrpc.php does (config_set_path() of each returned path
 * except xmlrpc_recv_result), so the assertions read the values a consumer would find stored.
 * Receiver locals carry the visible sentinels LOCAL-SENTINEL-... and SECRET-..., sender-injected
 * locals carry EVIL..., so a leak in either direction shows in the failure diff. The merge itself is
 * pinned by SyncPolicyMergeTest.
 */
#[CoversFunction('pfblockerng_plugin_xmlrpc_recv')]
#[CoversFunction('pfblockerng_plugin_xmlrpc_recv_done')]
#[CoversFunction('pfblockerng_sync_on_changes')]
#[CoversFunction('pfb_sync_receive_state_read')]
#[CoversFunction('pfb_sync_receive_record')]
#[CoversFunction('pfb_sync_receive_accepted_clear')]
#[CoversFunction('pfb_sync_receive_suppressed')]
#[CoversFunction('pfb_sync_receive_changed')]
final class SyncPolicyReceiveTest extends TestCase
{
	use SyncPolicyFixtureTrait;

	private const NEW1 = ' lead/trail space ';
	private const NEW2 = '007';
	private const NEW3 = 'MiXeD';

	private const PRIOR_DIGEST = 'abababababababababababababababababababababababababababababababab';

	private string $dir;
	private mixed $savedConfig;
	private mixed $savedPfb;

	protected function setUp(): void
	{
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$this->savedPfb    = $GLOBALS['pfb'] ?? NULL;

		$this->dir = sys_get_temp_dir() . '/pfb_sync_receive_' . bin2hex(random_bytes(6));
		mkdir($this->dir, 0700);

		$GLOBALS['pfb']['dbdir']          = $this->dir;
		$GLOBALS['pfb']['log']            = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['pending_marker'] = "{$this->dir}/pfb_pending_changes";
		$GLOBALS['pfb_test_mwexec_bg']    = [];
		$GLOBALS['pfb_test_logger_calls'] = [];
		unset($GLOBALS['pfb_test_xmlrpc_connection']);

		pfb_sync_receive_changed(FALSE);
		$this->assertFalse(pfb_sync_receive_changed(), 'the request-local flag must be reset before every test');
		$this->seedReceiver('policy');
	}

	protected function tearDown(): void
	{
		foreach (glob("{$this->dir}/*") ?: [] as $file) {
			unlink($file);
		}
		rmdir($this->dir);

		if ($this->savedConfig === NULL) {
			unset($GLOBALS['config']);
		} else {
			$GLOBALS['config'] = $this->savedConfig;
		}
		if ($this->savedPfb === NULL) {
			unset($GLOBALS['pfb']);
		} else {
			$GLOBALS['pfb'] = $this->savedPfb;
		}
		unset($GLOBALS['pfb_test_mwexec_bg'], $GLOBALS['pfb_test_logger_calls'], $GLOBALS['pfb_test_xmlrpc_connection']);
		pfb_sync_receive_changed(FALSE);
	}

	// ---- fixtures ----------------------------------------------------------------------

	/** @return array<string,string> */
	private static function feedRow(string $alias): array
	{
		return ['format' => 'auto', 'state' => 'Enabled', 'url' => "https://feeds.example/{$alias}", 'header' => "Hdr{$alias}"];
	}

	/** @return array<string,mixed> */
	private static function groupRow(string $alias, bool $receiver): array
	{
		return ['aliasname' => $alias, 'action' => 'Deny_Inbound', 'cron' => 'EveryDay', 'row' => [0 => self::feedRow($alias)]]
			+ ($receiver ? ['srcint' => "LOCAL-SENTINEL-srcint-{$alias}", 'agateway_in' => "LOCAL-SENTINEL-gw-{$alias}"] : []);
	}

	/** @return array<string,mixed> */
	private static function alphaRow(): array
	{
		return [
			'aliasname' => 'Alpha', 'action' => self::NEW3, 'cron' => self::NEW2,
			'row' => [0 => ['format' => 'auto', 'state' => 'Enabled', 'url' => self::NEW1, 'header' => 'HdrAlpha']],
			'srcint' => 'EVIL-wan',
		];
	}

	/** @return array<string,string> */
	private static function item(string $xml, bool $receiver): array
	{
		return ['title' => "Title {$xml}", 'xml' => $xml, 'feed' => 'f', 'size' => '1', 'selected' => 'on']
			+ ($receiver ? ['username' => "SECRET-user-{$xml}", 'password' => "SECRET-pass-{$xml}"] : []);
	}

	/** @return array<string,mixed> the receiver's stored sections, its own Sync section included */
	private static function receiverSections(string $scope): array
	{
		return [
			'pfblockerng'            => ['config' => [0 => [
				'pfb_keep' => 'old', 'log_syslog' => 'LOCAL-SENTINEL-syslog', 'pfb_agg_types' => 'old-agg', 'zz_unknown' => 'UNKNOWN-zz',
			]]],
			'pfblockernglistsv4'     => ['config' => [0 => self::groupRow('Alpha', TRUE), 1 => self::groupRow('Bravo', TRUE)]],
			'pfblockernglistsv6'     => ['config' => [0 => self::groupRow('Gamma', TRUE)]],
			'pfblockerngdnsbl'       => ['config' => [0 => self::groupRow('Delta', TRUE), 1 => self::groupRow('Echo', TRUE)]],
			'pfblockerngblacklist'   => ['blacklist_enable' => 'on', 'blacklist_freq' => '12', 'item' => [
				0 => self::item('shallalist', TRUE), 1 => self::item('ut1', TRUE),
			]],
			'pfblockerngglobal'      => ['feed_foo' => 'on', 'alertrefresh' => 'LOCAL-SENTINEL-alert'],
			'pfblockerngsafesearch'  => ['safesearch_enable' => 'on'],
			'pfblockerngsync'        => ['config' => [0 => [
				'varsynconchanges' => 'manual', 'varsynctimeout' => '5', 'syncscope' => $scope,
				'row' => [0 => [
					'varsyncdestinenable' => 'ON', 'varsyncipaddress' => '192.0.2.10', 'varsyncport' => '443',
					'varsyncpassword' => 'target-pass', 'varsyncprotocol' => 'https', 'varsyncusername' => 'admin',
				]],
			]]],
		];
	}

	/**
	 * The sender's policy payload including the gate leaf. By default it changes six sections, drops
	 * Bravo (v4), Gamma (v6) and Echo (DNSBL), adds Foxtrot, and carries injected receiver-local leaves.
	 *
	 * @param list<string> $v4
	 * @param list<string> $v6
	 * @param list<string> $dnsbl
	 * @return array<string,mixed>
	 */
	private static function senderSections(array $v4 = ['Alpha', 'Foxtrot'], array $v6 = [], array $dnsbl = ['Delta']): array
	{
		$rows = static function (array $aliases): array {
			$out = [];
			foreach (array_values($aliases) as $i => $alias) {
				$out[$i] = $alias === 'Alpha' ? self::alphaRow() : self::groupRow($alias, FALSE);
			}
			return $out;
		};

		$payload = ['pfblockerng' => ['config' => [0 => [
			'pfb_keep' => self::NEW1, 'pfb_schedule_hour' => self::NEW2, 'pfb_schedule_minute' => self::NEW3,
			'skipfeed' => [], 'log_syslog' => 'EVIL-syslog',
		]]]];
		foreach (['pfblockernglistsv4' => $v4, 'pfblockernglistsv6' => $v6, 'pfblockerngdnsbl' => $dnsbl] as $section => $aliases) {
			if ($aliases !== []) {
				$payload[$section] = ['config' => $rows($aliases)];
			}
		}

		return $payload + [
			'pfblockerngblacklist'  => ['blacklist_enable' => 'on', 'item' => [
				0 => ['title' => 'New Title', 'username' => 'EVIL-user'] + self::item('shallalist', FALSE),
			]],
			'pfblockerngglobal'     => ['feed_foo' => [], 'alertrefresh' => 'EVIL-alert'],
			'pfblockerngsafesearch' => ['safesearch_enable' => 'on'],
			'pfblockerngsync'       => ['config' => [0 => [
				'syncscope' => 'policy', 'row' => [0 => ['varsyncipaddress' => 'EVIL-host']],
			]]],
		];
	}

	/** @return array<string,array<string,mixed>> section => the receiver's expected stored subtree after senderSections() */
	private static function expectedAfterDefaultReceive(): array
	{
		$rec = self::receiverSections('policy');
		$alpha = [
			'aliasname' => 'Alpha', 'action' => 'MiXeD', 'cron' => '007',
			'row' => [0 => ['format' => 'auto', 'state' => 'Enabled', 'url' => ' lead/trail space ', 'header' => 'HdrAlpha']],
			'srcint' => 'LOCAL-SENTINEL-srcint-Alpha', 'agateway_in' => 'LOCAL-SENTINEL-gw-Alpha',
		];
		$foxtrot = self::groupRow('Foxtrot', FALSE)
			+ ['srcint' => '', 'script_pre' => '', 'script_post' => '', 'agateway_in' => 'default', 'agateway_out' => 'default'];

		return [
			'pfblockerng' => ['config' => [0 => [
				'pfb_keep' => ' lead/trail space ', 'log_syslog' => 'LOCAL-SENTINEL-syslog', 'zz_unknown' => 'UNKNOWN-zz',
				'pfb_schedule_hour' => '007', 'pfb_schedule_minute' => 'MiXeD', 'skipfeed' => '',
			]]],
			'pfblockernglistsv4'    => ['config' => [0 => $alpha, 1 => $foxtrot]],
			'pfblockernglistsv6'    => [],
			'pfblockerngdnsbl'      => ['config' => [0 => $rec['pfblockerngdnsbl']['config'][0]]],
			'pfblockerngblacklist'  => ['blacklist_enable' => 'on', 'item' => [0 => [
				'title' => 'New Title', 'xml' => 'shallalist', 'feed' => 'f', 'size' => '1', 'selected' => 'on',
				'username' => 'SECRET-user-shallalist', 'password' => 'SECRET-pass-shallalist',
			]]],
			'pfblockerngglobal'     => ['feed_foo' => '', 'alertrefresh' => 'LOCAL-SENTINEL-alert'],
			'pfblockerngsafesearch' => $rec['pfblockerngsafesearch'],
		];
	}

	private function seedReceiver(string $scope): void
	{
		$GLOBALS['config'] = ['installedpackages' => self::receiverSections($scope)];
	}

	/** Open download+script ledger entries for every alias of the receiver, as a failing feed would leave them. */
	private function seedLedger(): void
	{
		$items = [['ip', 'pfB_Alpha_v4'], ['ip', 'pfB_Bravo_v4'], ['ip', 'pfB_Gamma_v6'], ['dnsbl', 'DNSBL_Delta'], ['dnsbl', 'DNSBL_Echo']];
		foreach ($items as [$facility, $item]) {
			foreach (['download', 'script'] as $stage) {
				pfb_sync_status_open($facility, $item, $stage, 'seeded', $this->dir);
			}
		}
	}

	/** @return list<string> sorted facility/item/stage of every open ledger entry */
	private function openLedger(): array
	{
		$open = array_map(
			static fn (array $e): string => "{$e['facility']}/{$e['item']}/{$e['stage']}",
			pfb_sync_status_list_open($this->dir)
		);
		sort($open);
		return $open;
	}

	/** Runs the receive hook and applies its result the way core's xmlrpc.php does. @return array<string,mixed> */
	private function receive(array $sections): array
	{
		$result = $this->assertNoDiagnostics(
			static fn (): array => pfblockerng_plugin_xmlrpc_recv(['installedpackages' => $sections])
		);
		foreach ($result as $path => $value) {
			if ($path !== 'xmlrpc_recv_result') {
				config_set_path($path, $value);
			}
		}
		return $result;
	}

	private function state(): array
	{
		return pfb_sync_receive_state_read($this->dir);
	}

	private function loggedText(): string
	{
		return implode("\n", array_column($GLOBALS['pfb_test_logger_calls'] ?? [], 'message'));
	}

	private function currentDigest(): string
	{
		$sections = [];
		foreach (pfblockerng_sync_sections(TRUE) as $section) {
			$value = config_get_path("installedpackages/{$section}");
			if ($value !== NULL) {
				$sections[$section] = $value;
			}
		}
		return pfb_sync_policy_digest(pfb_sync_policy_projection($sections));
	}

	/** recv_done must neither mark pending changes nor start a tick. */
	private function assertNoApply(): void
	{
		pfblockerng_plugin_xmlrpc_recv_done([]);
		$this->assertFileDoesNotExist($GLOBALS['pfb']['pending_marker'], 'no pending-changes marker may be written');
		$this->assertSame([], $GLOBALS['pfb_test_mwexec_bg'], 'no tick may be started');
	}

	private function syncAttempted(): bool
	{
		unset($GLOBALS['pfb_test_xmlrpc_connection']);
		pfblockerng_sync_on_changes();
		return isset($GLOBALS['pfb_test_xmlrpc_connection']);
	}

	/** Verbatim body of pfblockerng_plugin_xmlrpc_recv() as released before issue #3452. */
	private static function releasedHook($new_sections)
	{
		if (array_get_path($new_sections, 'installedpackages/pfblockerngsync/config/0/varsynconchanges') != 'auto') {
			return [];
		}

		$section_paths = [];
		foreach (pfblockerng_sync_sections(TRUE) as $section) {
			$section_paths[] = "installedpackages/{$section}";
		}

		$ret = [
			'xmlrpc_recv_result' => FALSE
		];
		foreach ($section_paths as $path) {
			$old_section = config_get_path($path, []);
			$new_section = array_get_path($new_sections, $path, []);

			// Don't save empty configuration sections.
			if (empty($old_section) && empty($new_section)) {
				continue;
			}
			// Ignore unchanged configuration sections.
			if ($old_section === $new_section) {
				continue;
			}

			$ret[$path] = array_merge($old_section, $new_section);
			$ret['xmlrpc_recv_result'] = TRUE;
		}

		return $ret;
	}

	// ---- providers ---------------------------------------------------------------------

	/** @return array<string,array{string}> */
	public static function receiverScopes(): array
	{
		return ['policy' => ['policy'], 'all' => ['all'], 'lists' => ['lists']];
	}

	/** @return array<string,array{array<string,mixed>,bool}> */
	public static function legacyPayloads(): array
	{
		$receiver = self::receiverSections('policy');
		unset($receiver['pfblockerngsync']);

		return [
			'changed: one section differs'               => [['pfblockerngglobal' => ['feed_foo' => 'off']], TRUE],
			'changed: sender sections omit receiver locals' => [
				['pfblockerngglobal' => ['feed_foo' => 'on'], 'pfblockerngsafesearch' => ['safesearch_enable' => 'off']], TRUE,
			],
			'unchanged: every section equals the receiver' => [$receiver, FALSE],
		];
	}

	/** @return array<string,array{mixed,bool}> gate value, whether varsynconchanges=auto rides along */
	public static function refusedGates(): array
	{
		$rows = [];
		foreach (['empty string' => '', 'empty array' => [], 'capitalised' => 'Policy', 'all' => 'all', 'lists' => 'lists', 'bogus' => 'bogus'] as $name => $gate) {
			$rows[$name]                              = [$gate, FALSE];
			$rows["{$name} with varsynconchanges=auto"] = [$gate, TRUE];
		}
		return $rows;
	}

	/** @return array<string,array{string,string,mixed}> side ('sender'|'receiver'), path under installedpackages, value */
	public static function malformedPayloads(): array
	{
		return [
			'section is a scalar'                    => ['sender', 'pfblockerngglobal', 'EVILVALUE'],
			'leaf is an int'                         => ['sender', 'pfblockerngglobal/feed_foo', 5],
			'non-empty array at a scalar key'        => ['sender', 'pfblockerngglobal/feed_foo', ['EVILVALUE']],
			'empty aliasname'                        => ['sender', 'pfblockernglistsv4/config/0/aliasname', ''],
			'aliasname with a non-word character'    => ['sender', 'pfblockernglistsv4/config/0/aliasname', 'EVILVALUE-bad'],
			'duplicate aliasname on the sender'      => ['sender', 'pfblockernglistsv4/config/1/aliasname', 'Alpha'],
			'duplicate aliasname on the receiver'    => ['receiver', 'pfblockernglistsv4/config/1/aliasname', 'Alpha'],
			'feed header the apply would change'     => ['sender', 'pfblockernglistsv4/config/0/row/0/header', 'EVILVALUE x'],
			'blacklist item with an empty xml'       => ['sender', 'pfblockerngblacklist/item/0/xml', ''],
			'duplicate blacklist xml'                => ['sender', 'pfblockerngblacklist/item/1/xml', 'shallalist'],
		];
	}

	/** @return array<string,array{mixed}> */
	public static function recvDoneArguments(): array
	{
		return ['null' => [NULL], 'empty array' => [[]], 'junk array' => [['pkg' => ['x' => 'y']]], 'junk string' => ['junk']];
	}

	// ---- gate absent: the legacy path stays byte-exact ---------------------------------

	/** @param array<string,mixed> $sections */
	#[DataProvider('legacyPayloads')]
	public function testGateAbsentWithAutoReturnsExactlyWhatTheReleasedHookReturned(array $sections, bool $changes): void
	{
		$sections['pfblockerngsync'] = ['config' => [0 => ['varsynconchanges' => 'auto']]];
		$payload = ['installedpackages' => $sections];

		$released = self::releasedHook($payload);
		$this->assertSame($changes, $released['xmlrpc_recv_result'], 'fixture must pin the legacy result key');

		$this->assertSame($released, pfblockerng_plugin_xmlrpc_recv($payload));
		$this->assertSame(['accepted_digest' => NULL, 'last' => NULL], $this->state(), 'a legacy receive records nothing');
		$this->assertSame([], $GLOBALS['pfb_test_logger_calls'], 'a legacy receive logs nothing');
		$this->assertNoApply();
	}

	public function testGateAbsentWithoutAutoReturnsNothing(): void
	{
		$payload = ['installedpackages' => ['pfblockerngglobal' => ['feed_foo' => 'off']]];

		$this->assertSame([], pfblockerng_plugin_xmlrpc_recv($payload));
		$this->assertSame(['accepted_digest' => NULL, 'last' => NULL], $this->state());
	}

	public function testScalarInstalledpackagesCarriesNoGateAndChangesNothing(): void
	{
		$before = serialize($GLOBALS['config']);

		$this->assertSame([], pfblockerng_plugin_xmlrpc_recv(['installedpackages' => 'EVILVALUE']));
		$this->assertSame($before, serialize($GLOBALS['config']));
		$this->assertSame(['accepted_digest' => NULL, 'last' => NULL], $this->state());
	}

	// ---- gate policy: merge, changed paths only ----------------------------------------

	public function testPolicyReceiveReturnsOnlyTheChangedSectionPaths(): void
	{
		$result = $this->receive(self::senderSections());

		$this->assertSame([
			'installedpackages/pfblockerng',
			'installedpackages/pfblockernglistsv4',
			'installedpackages/pfblockernglistsv6',
			'installedpackages/pfblockerngdnsbl',
			'installedpackages/pfblockerngblacklist',
			'installedpackages/pfblockerngglobal',
		], array_keys($result), 'exactly the changed installedpackages paths: no control or status key, unchanged sections omitted');
	}

	#[DataProvider('receiverScopes')]
	public function testPolicyReceiveStoresSenderPolicyByteIdenticalWhateverTheReceiverScope(string $scope): void
	{
		$this->seedReceiver($scope);
		$syncBefore = config_get_path('installedpackages/pfblockerngsync');

		$this->receive(self::senderSections());

		foreach (self::expectedAfterDefaultReceive() as $section => $expected) {
			$this->assertSame($expected, config_get_path("installedpackages/{$section}"), "stored {$section}");
		}
		$this->assertSame($syncBefore, config_get_path('installedpackages/pfblockerngsync'), 'the Sync section is never written');
		$this->assertStringNotContainsString('EVIL', serialize($GLOBALS['config']), 'sender-injected local leaves must not be stored');
	}

	public function testPolicyReceiveOfTheSamePayloadTwiceChangesNothingTheSecondTime(): void
	{
		$this->assertNotSame([], $this->receive(self::senderSections()));
		$this->seedLedger();
		$stored = serialize($GLOBALS['config']);
		$open   = $this->openLedger();
		pfblockerng_plugin_xmlrpc_recv_done(NULL);
		$GLOBALS['pfb_test_mwexec_bg'] = [];
		unlink($GLOBALS['pfb']['pending_marker']);
		$GLOBALS['pfb_test_logger_calls'] = [];

		$this->assertSame([], $this->receive(self::senderSections()));

		$this->assertSame($stored, serialize($GLOBALS['config']));
		$this->assertSame($open, $this->openLedger(), 'a repeated receive closes no ledger entry');
		$this->assertNoApply();
		$this->assertSame('unchanged', $this->state()['last']['outcome']);
		$this->assertSame($this->currentDigest(), $this->state()['accepted_digest']);
		$this->assertCount(1, $GLOBALS['pfb_test_logger_calls'], 'one log line per receive');
		$this->assertStringContainsString(': unchanged', $this->loggedText());
	}

	/**
	 * Emulates write_config() plus the next request's reparse for the two empty list containers the
	 * scenario below stores (pfsense/pfsense xmlparse.inc @9363ac5b): an empty listtag array is
	 * written as nothing (:264-268), and a section left without a child element reads back as ''
	 * (:105-111).
	 */
	private function persistEmptyListContainers(): void
	{
		$this->assertSame([], config_get_path('installedpackages/pfblockernglistsv4/config/1/row'), 'precondition: Foxtrot stored an empty row list');
		$this->assertSame(['config' => []], config_get_path('installedpackages/pfblockernglistsv6'), 'precondition: v6 stored an empty group list');
		unset($GLOBALS['config']['installedpackages']['pfblockernglistsv4']['config'][1]['row']);
		$GLOBALS['config']['installedpackages']['pfblockernglistsv6'] = '';
	}

	/**
	 * Scenario: the sender's disk still holds an empty <config></config> and a group's <row></row>.
	 * Given the receiver stored the first receive and pfSense rewrote and reread its config.xml,
	 * When the same payload arrives again (the client's retry or the next sync),
	 * Then nothing is reported changed, no apply starts, and the node keeps suppressing its echo.
	 */
	public function testEmptyListContainersSettleOnceTheStoredReceiveIsReread(): void
	{
		$payload = self::senderSections();
		$payload['pfblockernglistsv6'] = ['config' => []];
		$payload['pfblockernglistsv4']['config'][1]['row'] = [];
		$this->assertNotSame([], $this->receive($payload), 'before-state: the first receive changes the receiver');
		pfblockerng_plugin_xmlrpc_recv_done(NULL);
		$GLOBALS['pfb_test_mwexec_bg'] = [];
		unlink($GLOBALS['pfb']['pending_marker']);

		$this->persistEmptyListContainers();
		$this->assertTrue(pfb_sync_receive_suppressed(), 'the reread policy still equals the accepted one');
		$GLOBALS['pfb_test_logger_calls'] = [];

		$this->assertSame([], $this->receive($payload), 'the repeated receive changes nothing');
		$this->assertSame('unchanged', $this->state()['last']['outcome']);
		$this->assertNoApply();
		$this->assertTrue(pfb_sync_receive_suppressed(), 'the repeated receive keeps the suppression');
	}

	/**
	 * A group whose row list holds one empty entry reads back from config.xml once as `row => []`
	 * with the key present (pfsense/pfsense xmlparse.inc @9363ac5b), not as the settled shape; the
	 * suppression digest must normalise what the node stores, not hash it raw.
	 */
	public function testSuppressionHoldsAfterASingleReparseOfAnEmptyRowEntry(): void
	{
		$payload = self::senderSections();
		$payload['pfblockernglistsv4']['config'][1]['row'] = [0 => []];
		$this->assertNotSame([], $this->receive($payload), 'before-state: the first receive changes the receiver');
		$this->assertTrue(pfb_sync_receive_suppressed(), 'before-state: suppressed right after the receive');

		$GLOBALS['config']['installedpackages']['pfblockernglistsv4']['config'][1]['row'] = [];

		$this->assertTrue(pfb_sync_receive_suppressed(), 'the reparsed policy still equals the accepted one');
	}

	public function testChangedPolicyReceiveRecordsTheAcceptedDigestAndLogsOneValueFreeLine(): void
	{
		$payload = self::senderSections();
		$payload['pfblockerngglobal']['feed_foo'] = 'VALUE-SENTINEL-4f2a';

		$this->receive($payload);

		$state = $this->state();
		$this->assertSame('changed', $state['last']['outcome']);
		$this->assertIsInt($state['last']['time']);
		$this->assertSame($this->currentDigest(), $state['accepted_digest'], 'the digest of the projection stored by the merge');
		$this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/D', $state['accepted_digest']);
		$this->assertCount(1, $GLOBALS['pfb_test_logger_calls'], 'one log line per receive');
		$this->assertStringContainsString(': changed', $this->loggedText());
		$this->assertStringNotContainsString('VALUE-SENTINEL-4f2a', $this->loggedText());
	}

	// ---- any other gate is refused -----------------------------------------------------

	#[DataProvider('refusedGates')]
	public function testAnyGateOtherThanPolicyIsRefusedAndNeverReachesTheLegacyMerge(mixed $gate, bool $withAuto): void
	{
		$this->seedLedger();
		pfb_sync_receive_record('changed', self::PRIOR_DIGEST, '', $this->dir);
		$payload = self::senderSections();
		$payload['pfblockerngsync']['config'][0]['syncscope'] = $gate;
		if ($withAuto) {
			$payload['pfblockerngsync']['config'][0]['varsynconchanges'] = 'auto';
			$this->assertArrayHasKey(
				'installedpackages/pfblockerngglobal',
				self::releasedHook(['installedpackages' => $payload]),
				'before-state: the released hook would have merged this very payload'
			);
		}
		$before = serialize($GLOBALS['config']);
		$open   = $this->openLedger();
		$GLOBALS['pfb_test_logger_calls'] = [];

		$this->assertSame([], $this->receive($payload));

		$this->assertSame($before, serialize($GLOBALS['config']));
		$this->assertSame($open, $this->openLedger(), 'a refused receive closes no ledger entry');
		$state = $this->state();
		$this->assertSame('refused', $state['last']['outcome']);
		$this->assertNotSame('', $state['last']['reason'] ?? '');
		$this->assertSame(self::PRIOR_DIGEST, $state['accepted_digest'], 'a refusal keeps the previous accepted digest');
		$this->assertCount(1, $GLOBALS['pfb_test_logger_calls'], 'one log line per receive');
		$this->assertStringContainsString($state['last']['reason'], $this->loggedText());
		$this->assertNoApply();
	}

	#[DataProvider('malformedPayloads')]
	public function testMalformedPolicyPayloadIsRefusedWholeAndChangesNothing(string $side, string $path, mixed $value): void
	{
		$sender = self::senderSections();
		if ($side === 'sender') {
			self::setPath($sender, explode('/', $path), $value);
		} else {
			$tree = $GLOBALS['config']['installedpackages'];
			self::setPath($tree, explode('/', $path), $value);
			$GLOBALS['config']['installedpackages'] = $tree;
		}
		$this->seedLedger();
		$before = serialize($GLOBALS['config']);
		$open   = $this->openLedger();

		$this->assertSame([], $this->receive($sender));

		$this->assertSame($before, serialize($GLOBALS['config']));
		$this->assertSame($open, $this->openLedger(), 'a refused receive closes no ledger entry');
		$state = $this->state();
		$this->assertSame('refused', $state['last']['outcome']);
		$this->assertNotSame('', $state['last']['reason'] ?? '');
		$this->assertNull($state['accepted_digest'], 'a refusal records no accepted digest');
		$this->assertStringNotContainsString('EVILVALUE', (string) file_get_contents("{$this->dir}/pfb_sync_receive.json"));
		$this->assertStringNotContainsString('EVILVALUE', $this->loggedText());
		$this->assertNoApply();
	}

	// ---- ledger close ------------------------------------------------------------------

	public function testRemovedAliasesCloseTheirLedgerEntriesAndNoOtherEntry(): void
	{
		$this->seedLedger();
		$this->assertCount(10, $this->openLedger());

		$this->receive(self::senderSections());

		$this->assertSame([
			'dnsbl/DNSBL_Delta/download', 'dnsbl/DNSBL_Delta/script',
			'ip/pfB_Alpha_v4/download', 'ip/pfB_Alpha_v4/script',
		], $this->openLedger(), 'Bravo (v4), Gamma (v6) and Echo (DNSBL) closed; Alpha and Delta untouched');
	}

	public function testRenamedAliasClosesTheOldNameOnly(): void
	{
		$this->seedLedger();

		$this->receive(self::senderSections(['Alpha', 'Bravo2'], ['Gamma'], ['Delta', 'Echo']));

		$this->assertNotContains('ip/pfB_Bravo_v4/download', $this->openLedger());
		$this->assertCount(8, $this->openLedger(), 'only the two stages of Bravo closed');
	}

	public function testRepeatedReceiveClosesNothingEvenIfAClosedAliasReopens(): void
	{
		$this->receive(self::senderSections());
		pfb_sync_status_open('ip', 'pfB_Bravo_v4', 'download', 'reopened', $this->dir);

		$this->receive(self::senderSections());

		$this->assertSame(['ip/pfB_Bravo_v4/download'], $this->openLedger());
	}

	// ---- plugin_xmlrpc_recv_done: exactly one apply ------------------------------------

	#[DataProvider('recvDoneArguments')]
	public function testChangedReceiveMarksPendingAndStartsExactlyOneTick(mixed $argument): void
	{
		$this->receive(self::senderSections());
		$this->assertFileDoesNotExist($GLOBALS['pfb']['pending_marker'], 'before-state: the receive itself marks nothing');
		$this->assertSame([], $GLOBALS['pfb_test_mwexec_bg']);

		pfblockerng_plugin_xmlrpc_recv_done($argument);

		$this->assertFileExists($GLOBALS['pfb']['pending_marker']);
		$this->assertSame(
			["/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php tick >> {$this->dir}/pfblockerng.log 2>&1"],
			$GLOBALS['pfb_test_mwexec_bg']
		);

		pfblockerng_plugin_xmlrpc_recv_done($argument);

		$this->assertCount(1, $GLOBALS['pfb_test_mwexec_bg'], 'a second call in the same request starts no second tick');
	}

	public function testNoApplyAfterAnUnchangedReceive(): void
	{
		$this->receive(self::senderSections());
		pfblockerng_plugin_xmlrpc_recv_done(NULL);
		$GLOBALS['pfb_test_mwexec_bg'] = [];
		unlink($GLOBALS['pfb']['pending_marker']);

		$this->assertSame([], $this->receive(self::senderSections()));

		$this->assertNoApply();
	}

	public function testNoApplyAfterALegacyReceive(): void
	{
		$payload = ['installedpackages' => [
			'pfblockerngglobal' => ['feed_foo' => 'off'],
			'pfblockerngsync'   => ['config' => [0 => ['varsynconchanges' => 'auto']]],
		]];
		$this->assertNotSame([], pfblockerng_plugin_xmlrpc_recv($payload));

		$this->assertNoApply();
	}

	public function testNoApplyAfterARefusedReceive(): void
	{
		$payload = self::senderSections();
		$payload['pfblockerngsync']['config'][0]['syncscope'] = 'all';
		$this->assertSame([], $this->receive($payload));

		$this->assertNoApply();
	}

	public function testNoApplyWhenNothingWasReceived(): void
	{
		$this->assertNoApply();
	}

	// ---- received-digest suppression of this node's own sync ---------------------------

	public function testWithoutAStateFileTheNodeSyncsAsBefore(): void
	{
		$this->assertTrue($this->syncAttempted(), 'the observable must see a sync attempt when nothing suppresses it');
		$this->assertFalse(pfb_sync_receive_suppressed());
	}

	#[DataProvider('receiverScopes')]
	public function testAcceptedPolicyReceiveSuppressesTheNodesOwnSync(string $scope): void
	{
		$this->seedReceiver($scope);
		$this->assertTrue($this->syncAttempted(), 'before-state: the unsuppressed node syncs');

		$this->receive(self::senderSections());

		$this->assertTrue(pfb_sync_receive_suppressed());
		$this->assertFalse($this->syncAttempted());
	}

	#[DataProvider('receiverScopes')]
	public function testLocalPolicyEditLiftsTheSuppression(string $scope): void
	{
		$this->seedReceiver($scope);
		$this->receive(self::senderSections());
		$this->assertFalse($this->syncAttempted(), 'before-state: suppressed after the receive');

		config_set_path('installedpackages/pfblockerngglobal/feed_foo', 'edited-locally');

		$this->assertTrue($this->syncAttempted());
	}

	#[DataProvider('receiverScopes')]
	public function testLocalOnlyEditKeepsTheSuppression(string $scope): void
	{
		$this->seedReceiver($scope);
		$this->receive(self::senderSections());

		config_set_path('installedpackages/pfblockerngglobal/alertrefresh', 'edited-locally');
		config_set_path('installedpackages/pfblockernglistsv4/config/0/srcint', 'edited-locally');

		$this->assertFalse($this->syncAttempted());
	}

	#[DataProvider('receiverScopes')]
	public function testClearingTheAcceptedDigestLiftsTheSuppression(string $scope): void
	{
		$this->seedReceiver($scope);
		$this->receive(self::senderSections());
		$this->assertFalse($this->syncAttempted(), 'before-state: suppressed after the receive');

		pfb_sync_receive_accepted_clear($this->dir);

		$this->assertNull($this->state()['accepted_digest']);
		$this->assertSame('changed', $this->state()['last']['outcome'], 'only the digest is dropped');
		$this->assertTrue($this->syncAttempted());
	}

	#[DataProvider('receiverScopes')]
	public function testRefusedReceiveAfterAnAcceptedOneKeepsTheSuppression(string $scope): void
	{
		$this->seedReceiver($scope);
		$this->receive(self::senderSections());
		$payload = self::senderSections();
		$payload['pfblockerngsync']['config'][0]['syncscope'] = 'lists';

		$this->assertSame([], $this->receive($payload));

		$this->assertSame('refused', $this->state()['last']['outcome']);
		$this->assertFalse($this->syncAttempted());
	}

	public function testLegacyReceiveRecordsNoAcceptedDigestAndLeavesTheNodeSyncing(): void
	{
		$payload = ['installedpackages' => [
			'pfblockerngglobal' => ['feed_foo' => 'off'],
			'pfblockerngsync'   => ['config' => [0 => ['varsynconchanges' => 'auto']]],
		]];
		foreach (pfblockerng_plugin_xmlrpc_recv($payload) as $path => $value) {
			if ($path !== 'xmlrpc_recv_result') {
				config_set_path($path, $value);
			}
		}

		$this->assertNull($this->state()['accepted_digest']);
		$this->assertTrue($this->syncAttempted());
	}

	// ---- state file --------------------------------------------------------------------

	public function testMissingStateFileReadsAsNothingRecorded(): void
	{
		$this->assertSame(['accepted_digest' => NULL, 'last' => NULL], $this->state());
	}

	public function testCorruptStateFileReadsAsNothingRecordedAndSuppressesNothing(): void
	{
		$this->receive(self::senderSections());
		$this->assertTrue(pfb_sync_receive_suppressed(), 'before-state: a valid state file suppresses');

		file_put_contents("{$this->dir}/pfb_sync_receive.json", '{');

		$this->assertSame(['accepted_digest' => NULL, 'last' => NULL], $this->state());
		$this->assertFalse(pfb_sync_receive_suppressed());
		$this->assertTrue($this->syncAttempted());
	}

	public function testStateFileIsRootOnlyAndHoldsNoPayloadOrLocalValue(): void
	{
		$payload = self::senderSections();
		$payload['pfblockerngglobal']['feed_foo']      = 'POLICYSENTINEL-9f3a';
		$payload['pfblockerngglobal']['alertrefresh']  = 'LOCALSENTINEL-9f3a';
		$this->receive($payload);

		$file = "{$this->dir}/pfb_sync_receive.json";
		$this->assertFileExists($file);
		$this->assertSame(0600, fileperms($file) & 0777);
		$this->assertSame(
			[$file],
			array_values(array_diff(glob("{$this->dir}/{.pfb_schedule.,pfb_sync_receive}*", GLOB_BRACE) ?: [], ["{$file}.lock"])),
			'the atomic write leaves no temp file behind (the empty lock sidecar is not one)'
		);

		$text = (string) file_get_contents($file);
		foreach (['POLICYSENTINEL-9f3a', 'LOCALSENTINEL-9f3a', 'EVIL', 'SECRET', 'LOCAL-SENTINEL', 'target-pass', self::NEW1, self::NEW3] as $needle) {
			$this->assertStringNotContainsString($needle, $text);
			$this->assertStringNotContainsString($needle, $this->loggedText());
		}
	}
}
