<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/SyncPolicyFixtureTrait.php';

/**
 * Issue #3453 -- the receive record of an accepted policy receive: the incoming digest, the accepted
 * digest and the leaf paths the receiver ignored as local or unknown (docs/specs/xmlrpc-per-field-sync.md,
 * "Reporting", receiver items 1-3).
 *
 * Injected receiver-local leaves carry the sentinel LEAK_SENTINEL_KEY_7f3a_<n>: the state file and the
 * log must never contain one, and the payload provably does.
 */
#[CoversFunction('pfb_sync_policy_merge')]
#[CoversFunction('pfb_sync_receive_record')]
#[CoversFunction('pfb_sync_receive_policy')]
#[CoversFunction('pfb_sync_receive_state_read')]
#[CoversFunction('pfb_sync_receive_accepted_clear')]
final class SyncPolicyStatusTest extends TestCase
{
	use SyncPolicyFixtureTrait;

	private const SENTINEL = 'LEAK_SENTINEL_KEY_7f3a';

	private string $dir;
	private mixed $savedConfig;
	private mixed $savedPfb;

	protected function setUp(): void
	{
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$this->savedPfb    = $GLOBALS['pfb'] ?? NULL;

		$this->dir = sys_get_temp_dir() . '/pfb_sync_status_' . bin2hex(random_bytes(6));
		mkdir($this->dir, 0700);

		$GLOBALS['pfb']['dbdir']          = $this->dir;
		$GLOBALS['pfb']['log']            = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['pending_marker'] = "{$this->dir}/pfb_pending_changes";
		$GLOBALS['pfb_test_mwexec_bg']    = [];
		$GLOBALS['pfb_test_logger_calls'] = [];

		pfb_sync_receive_changed(FALSE);
		$GLOBALS['config'] = ['installedpackages' => self::receiverSections()];
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
		unset($GLOBALS['pfb_test_mwexec_bg'], $GLOBALS['pfb_test_logger_calls']);
		pfb_sync_receive_changed(FALSE);
	}

	// ---- fixtures ----------------------------------------------------------------------

	/** @return array<string,string> */
	private static function feedRow(): array
	{
		return ['format' => 'auto', 'state' => 'Enabled', 'url' => 'https://feeds.example/alpha', 'header' => 'HdrAlpha'];
	}

	/** @return array<string,mixed> the receiver's stored sections: every local leaf holds a RECV- value */
	private static function receiverSections(): array
	{
		return [
			'pfblockerng'              => ['config' => [0 => ['pfb_keep' => 'old', 'log_syslog' => 'RECV-syslog']]],
			'pfblockerngipsettings'    => ['config' => [0 => [
				'inbound_interface' => 'wan', 'maxmind_key' => 'RECV-maxmind', 'asn_token' => 'RECV-asn',
			]]],
			'pfblockerngdnsblsettings' => ['config' => [0 => ['dnsbl_interface' => 'lan', 'top1m_token' => 'RECV-top1m']]],
			'pfblockernglistsv4'       => ['config' => [0 => [
				'aliasname' => 'Alpha', 'action' => 'Deny_Inbound', 'cron' => 'EveryDay', 'row' => [0 => self::feedRow()],
				'srcint' => 'RECV-srcint', 'script_pre' => 'RECV-pre', 'agateway_in' => 'RECV-gw',
			]]],
			'pfblockerngblacklist'     => ['item' => [0 => [
				'title' => 'Title', 'xml' => 'shallalist', 'feed' => 'f', 'size' => '1', 'selected' => 'on',
				'username' => 'RECV-user', 'password' => 'RECV-pass',
			]]],
			'pfblockerngglobal'        => ['feed_foo' => 'on', 'alertrefresh' => 'RECV-alert'],
			'pfblockerngsync'          => ['config' => [0 => ['syncscope' => 'policy']]],
		];
	}

	/** @return array<string,string> receiver-local stored path => its seeded value */
	private static function localSeeds(): array
	{
		return [
			'installedpackages/pfblockerngipsettings/config/0/inbound_interface'    => 'wan',
			'installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_interface'   => 'lan',
			'installedpackages/pfblockerngipsettings/config/0/maxmind_key'          => 'RECV-maxmind',
			'installedpackages/pfblockerngipsettings/config/0/asn_token'            => 'RECV-asn',
			'installedpackages/pfblockerngdnsblsettings/config/0/top1m_token'       => 'RECV-top1m',
			'installedpackages/pfblockerngblacklist/item/0/username'                => 'RECV-user',
			'installedpackages/pfblockerngblacklist/item/0/password'                => 'RECV-pass',
			'installedpackages/pfblockernglistsv4/config/0/srcint'                  => 'RECV-srcint',
			'installedpackages/pfblockernglistsv4/config/0/script_pre'              => 'RECV-pre',
			'installedpackages/pfblockernglistsv4/config/0/agateway_in'             => 'RECV-gw',
			'installedpackages/pfblockerngglobal/alertrefresh'                      => 'RECV-alert',
		];
	}

	/** @return list<string> section-relative paths a sender injects: all receiver-local or unknown */
	private static function injectedPaths(): array
	{
		return [
			'pfblockerngipsettings/config/0/inbound_interface',
			'pfblockerngdnsblsettings/config/0/dnsbl_interface',
			'pfblockerngipsettings/config/0/maxmind_key',
			'pfblockerngipsettings/config/0/asn_token',
			'pfblockerngdnsblsettings/config/0/top1m_token',
			'pfblockerngblacklist/item/0/username',
			'pfblockerngblacklist/item/0/password',
			'pfblockernglistsv4/config/0/srcint',
			'pfblockernglistsv4/config/0/script_pre',
			'pfblockernglistsv4/config/0/agateway_in',
			'pfblockerng/hooks/row/0/script',
			'pfblockerngglobal/widget-pfblockerng',
		];
	}

	/** @return array<string,mixed> a policy payload with no receiver-local or unknown leaf */
	private static function cleanPayload(string $keep = 'new'): array
	{
		return [
			'pfblockerng'          => ['config' => [0 => ['pfb_keep' => $keep]]],
			'pfblockernglistsv4'   => ['config' => [0 => [
				'aliasname' => 'Alpha', 'action' => 'Deny_Inbound', 'cron' => 'EveryDay', 'row' => [0 => self::feedRow()],
			]]],
			'pfblockerngblacklist' => ['blacklist_enable' => 'on', 'item' => [0 => [
				'title' => 'Title', 'xml' => 'shallalist', 'feed' => 'f', 'size' => '1', 'selected' => 'on',
			]]],
			'pfblockerngglobal'    => ['feed_foo' => 'on'],
			'pfblockerngsync'      => ['config' => [0 => ['syncscope' => 'policy']]],
		];
	}

	/** @return array<string,mixed> cleanPayload() plus every injectedPaths() leaf holding a distinct sentinel */
	private static function injectedPayload(): array
	{
		$payload = self::cleanPayload();
		foreach (self::injectedPaths() as $n => $path) {
			self::setPath($payload, explode('/', $path), self::SENTINEL . "_{$n}");
		}
		return $payload;
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

	/** @return array<string,mixed> the recorded last receive, asserted present */
	private function last(): array
	{
		$last = $this->state()['last'];
		$this->assertIsArray($last, 'a receive must leave a last record');
		return $last;
	}

	private function rawState(): string
	{
		return (string) file_get_contents("{$this->dir}/pfb_sync_receive.json");
	}

	private function loggedText(): string
	{
		return implode("\n", array_column($GLOBALS['pfb_test_logger_calls'] ?? [], 'message'));
	}

	/** @return list<string> */
	private static function expectedIgnored(): array
	{
		$expected = array_map(static fn (string $p): string => "installedpackages/{$p}", self::injectedPaths());
		sort($expected, SORT_STRING);
		return $expected;
	}

	// ---- 1 ----------------------------------------------------------------------------

	public function testCleanPayloadRecordsEqualDigestsAndNoIgnoredPaths(): void
	{
		$this->receive(self::cleanPayload());

		$state = $this->state();
		$last  = $this->last();
		$this->assertSame('changed', $last['outcome']);
		$this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/D', (string) $state['accepted_digest']);
		$this->assertArrayHasKey('incoming_digest', $last);
		$this->assertArrayHasKey('accepted_digest', $last);
		$this->assertSame($state['accepted_digest'], $last['accepted_digest']);
		$this->assertSame($last['accepted_digest'], $last['incoming_digest']);
		$this->assertSame([], $last['ignored'] ?? NULL);
		$this->assertSame(0, $last['ignored_count'] ?? NULL);
	}

	public function testEmptyRowsKeepIncomingAndAcceptedDigestsEqual(): void
	{
		$payload = self::cleanPayload();
		$payload['pfblockernglistsv4']['config'][1]                = '';
		$payload['pfblockernglistsv4']['config'][0]['row'][1]      = '';
		$this->receive($payload);

		$last = $this->last();
		$this->assertSame($last['accepted_digest'], $last['incoming_digest']);
		$this->assertSame([], $last['ignored'] ?? NULL);
	}

	public function testGappedRowKeysKeepIncomingAndAcceptedDigestsEqual(): void
	{
		$payload = self::cleanPayload();
		$second  = ['aliasname' => 'Beta', 'action' => 'Deny_Inbound', 'cron' => 'EveryDay', 'row' => [0 => self::feedRow()]];
		$payload['pfblockernglistsv4']['config'] = [0 => $payload['pfblockernglistsv4']['config'][0], 2 => $second];
		$this->receive($payload);

		$last = $this->last();
		$this->assertSame('changed', $last['outcome']);
		$this->assertSame([], $last['ignored'] ?? NULL, 'before-state: nothing was ignored');
		$this->assertSame($last['accepted_digest'], $last['incoming_digest'], 'row keys as sent must not split the digests');
	}

	public function testOverLongKeyIsRecordedAsAStarSegmentAndKeepsTheStateSmall(): void
	{
		$payload = self::cleanPayload();
		$payload['pfblockerng']['config'][0][str_repeat('a', 100000)] = 'x';
		$this->receive($payload);

		$this->assertSame(['installedpackages/pfblockerng/config/0/*'], $this->last()['ignored'] ?? NULL);
		$this->assertLessThan(65536, strlen($this->rawState()));
	}

	// ---- 2 ----------------------------------------------------------------------------

	public function testInjectedLocalLeavesAreIgnoredAndListedExactly(): void
	{
		$before = [];
		foreach (self::localSeeds() as $path => $seed) {
			$before[$path] = config_get_path($path);
			$this->assertSame($seed, $before[$path], "fixture: {$path} is seeded");
		}

		$this->receive(self::injectedPayload());

		foreach (self::localSeeds() as $path => $seed) {
			$this->assertSame($seed, config_get_path($path), "receiver-local {$path} must not change");
		}
		$this->assertNull(config_get_path('installedpackages/pfblockerng/hooks'), 'an injected hooks row must not be stored');
		$this->assertNull(config_get_path('installedpackages/pfblockerngglobal/widget-pfblockerng'), 'an injected widget key must not be stored');
		$this->assertSame('new', config_get_path('installedpackages/pfblockerng/config/0/pfb_keep'), 'the policy leaf still lands');

		$last = $this->last();
		$this->assertSame(self::expectedIgnored(), $last['ignored'] ?? NULL);
		$this->assertSame(count(self::injectedPaths()), $last['ignored_count'] ?? NULL);
		$this->assertArrayHasKey('incoming_digest', $last);
		$this->assertSame($this->state()['accepted_digest'], $last['accepted_digest'] ?? NULL);
		$this->assertNotSame($last['accepted_digest'] ?? NULL, $last['incoming_digest'], 'ignored leaves must split the digests');
	}

	// ---- 3 ----------------------------------------------------------------------------

	public function testNoInjectedValueReachesTheStateFileOrTheLog(): void
	{
		$payload = self::injectedPayload();
		$this->assertSame(
			count(self::injectedPaths()),
			substr_count(json_encode($payload, JSON_THROW_ON_ERROR), self::SENTINEL),
			'fixture: every injected leaf really carries a sentinel'
		);

		$this->receive($payload);

		$this->assertFileExists("{$this->dir}/pfb_sync_receive.json");
		$this->assertNotSame('', $this->rawState());
		$this->assertStringNotContainsString('LEAK_SENTINEL', $this->rawState());
		$this->assertNotSame('', $this->loggedText(), 'fixture: the receive logs a line');
		$this->assertStringNotContainsString('LEAK_SENTINEL', $this->loggedText());
	}

	// ---- 4 ----------------------------------------------------------------------------

	public function testHostileKeysAreRecordedAsAStarSegment(): void
	{
		$payload = self::cleanPayload();
		$payload['pfblockerngglobal']['Bad<Key>']        = 'x';
		$payload['pfblockerngsafesearch']                = ['a b' => 'y', 'safesearch_enable' => 'on'];
		$this->receive($payload);

		$last = $this->last();
		$this->assertSame(
			['installedpackages/pfblockerngglobal/*', 'installedpackages/pfblockerngsafesearch/*'],
			$last['ignored'] ?? NULL
		);
		$this->assertSame(2, $last['ignored_count'] ?? NULL);
		$this->assertStringNotContainsString('<', $this->rawState());
		$this->assertStringNotContainsString('Bad', $this->rawState());
		$this->assertStringNotContainsString('a b', $this->rawState());
	}

	// ---- 5 ----------------------------------------------------------------------------

	public function testIgnoredListIsCappedAtOneHundredButCountsAll(): void
	{
		$payload = self::cleanPayload();
		for ($n = 0; $n < 150; $n++) {
			$payload['pfblockerng']['config'][0][sprintf('zz_unknown_%03d', $n)] = 'x';
		}
		$this->receive($payload);

		$last = $this->last();
		$this->assertIsArray($last['ignored'] ?? NULL);
		$this->assertCount(100, $last['ignored']);
		$this->assertSame(150, $last['ignored_count'] ?? NULL);
		$this->assertSame('installedpackages/pfblockerng/config/0/zz_unknown_000', $last['ignored'][0]);
		$this->assertSame('installedpackages/pfblockerng/config/0/zz_unknown_099', $last['ignored'][99]);
	}

	// ---- 6 ----------------------------------------------------------------------------

	public function testRefusedReceiveRecordsNoDigestsAndKeepsThePreviousAcceptedOne(): void
	{
		$this->receive(self::cleanPayload());
		$accepted = $this->state()['accepted_digest'];
		$this->assertNotNull($accepted);

		$scope = self::injectedPayload();
		$scope['pfblockerngsync']['config'][0]['syncscope'] = 'all';
		$dup = self::injectedPayload();
		$dup['pfblockernglistsv4']['config'][1] = $dup['pfblockernglistsv4']['config'][0];

		foreach (['syncscope all' => $scope, 'duplicate aliasname' => $dup] as $why => $payload) {
			$this->receive($payload);
			$last = $this->last();
			$this->assertSame('refused', $last['outcome'], $why);
			$this->assertArrayNotHasKey('incoming_digest', $last, $why);
			$this->assertArrayNotHasKey('accepted_digest', $last, $why);
			$this->assertArrayNotHasKey('ignored', $last, $why);
			$this->assertArrayNotHasKey('ignored_count', $last, $why);
			$this->assertSame($accepted, $this->state()['accepted_digest'], $why);
		}
	}

	// ---- 7 ----------------------------------------------------------------------------

	public function testUnchangedRepeatReceiveRecordsTheSameDigestsAgain(): void
	{
		$this->receive(self::injectedPayload());
		$first = $this->last();
		$this->assertSame('changed', $first['outcome']);

		$this->receive(self::injectedPayload());
		$second = $this->last();
		$this->assertSame('unchanged', $second['outcome']);
		foreach (['incoming_digest', 'accepted_digest', 'ignored', 'ignored_count'] as $key) {
			$this->assertArrayHasKey($key, $second);
			$this->assertSame($first[$key], $second[$key], $key);
		}
	}

	// ---- 8 ----------------------------------------------------------------------------

	public function testAcceptedClearKeepsTheDigestsOfTheLastRecord(): void
	{
		$this->receive(self::injectedPayload());
		$last = $this->last();
		$this->assertArrayHasKey('incoming_digest', $last);

		pfb_sync_receive_accepted_clear($this->dir);

		$this->assertNull($this->state()['accepted_digest']);
		$kept = $this->last();
		$this->assertSame($last['incoming_digest'], $kept['incoming_digest'] ?? NULL);
		$this->assertSame($last['accepted_digest'] ?? NULL, $kept['accepted_digest'] ?? NULL);
		$this->assertSame($last['ignored'], $kept['ignored'] ?? NULL);
	}

	// ---- 9 ----------------------------------------------------------------------------

	public function testCorruptOrMissingStateIsReplacedWithAFreshRecord(): void
	{
		$this->assertFileDoesNotExist("{$this->dir}/pfb_sync_receive.json");
		file_put_contents("{$this->dir}/pfb_sync_receive.json", '{"accepted_digest": [1, 2');

		$this->receive(self::injectedPayload());

		$state = $this->state();
		$keys  = array_keys($state);
		sort($keys);
		$this->assertSame(['accepted_digest', 'last'], $keys, 'no prior apply or value may be synthesized');
		$this->assertSame(
			['time', 'outcome', 'incoming_digest', 'accepted_digest', 'ignored', 'ignored_count'],
			array_keys($this->last())
		);
		$this->assertNotNull($state['accepted_digest']);
	}

	public function testExtraKeysInTheLastRecordReadBackUnchanged(): void
	{
		$last = [
			'time' => 1, 'outcome' => 'changed', 'incoming_digest' => str_repeat('a', 64), 'accepted_digest' => str_repeat('b', 64),
			'ignored' => ['installedpackages/pfblockerng/hooks/row/0/script'], 'ignored_count' => 1, 'future_key' => ['nested' => 7],
		];
		file_put_contents(
			"{$this->dir}/pfb_sync_receive.json",
			json_encode(['accepted_digest' => str_repeat('b', 64), 'last' => $last], JSON_THROW_ON_ERROR)
		);

		$this->assertSame($last, $this->state()['last']);
		$this->assertSame(str_repeat('b', 64), $this->state()['accepted_digest']);
	}
}
