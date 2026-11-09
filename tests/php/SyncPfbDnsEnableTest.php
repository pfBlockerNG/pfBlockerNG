<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3770 — the pfB-DNS enable syncs like the DNSBL enable, and nothing else of pfB-DNS leaves the node.
 *
 * DNSBL runs only through pfB-DNS, so a receiver that gets DNSBL on without pfB-DNS on would hold DNSBL that blocks
 * nothing. The enable (`dns/pfb_dns`) therefore travels with the DNSBL enable: in scope `policy` as a policy leaf, in
 * the legacy scope `all` as the one leaf of pfblockerngdns that pfSense's HA handoff sends. Scope `lists` carries
 * neither. The saved Resolver snapshot, the listener interface lists and the transport settings are node-local in
 * every scope: every fixture below carries SENDER-... sentinels in them, so a leak shows in the failure diff.
 *
 * The XMLRPC replication targets of the legacy scope `all` use core's merge_installedpackages_section, which replaces a
 * sent installedpackages/<name> wholesale and calls no package hook: a one-leaf pfblockerngdns there would erase the
 * receiver's snapshot and listener lists. That transport therefore never sends pfblockerngdns.
 *
 * Every receive is applied the way core's xmlrpc.php does (config_set_path() of each returned path except
 * xmlrpc_recv_result), so the assertions read what the receiver would find stored.
 */
#[CoversFunction('pfblockerng_do_xmlrpc_sync')]
#[CoversFunction('pfblockerng_plugin_xmlrpc_send')]
#[CoversFunction('pfblockerng_plugin_xmlrpc_recv')]
#[CoversFunction('pfb_sync_policy_merge')]
#[CoversFunction('pfb_sync_legacy_digests')]
#[CoversFunction('pfb_sync_receive_suppressed')]
final class SyncPfbDnsEnableTest extends TestCase
{
	private const DNS   = 'installedpackages/pfblockerngdns/config/0';
	private const DNSBL = 'installedpackages/pfblockerngdnsblsettings/config/0';
	private const GATE  = 'installedpackages/pfblockerngsync/config/0/syncscope';

	private string $dir;
	private mixed $savedConfig;
	private mixed $savedPfb;

	protected function setUp(): void
	{
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$this->savedPfb    = $GLOBALS['pfb'] ?? NULL;

		$this->dir = sys_get_temp_dir() . '/pfb_sync_dns_enable_' . bin2hex(random_bytes(6));
		mkdir($this->dir, 0700);

		$GLOBALS['pfb']['dbdir']          = $this->dir;
		$GLOBALS['pfb']['log']            = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['pending_marker'] = "{$this->dir}/pfb_pending_changes";
		$GLOBALS['pfb_test_mwexec_bg']    = [];
		$GLOBALS['pfb_test_logger_calls'] = [];
		$GLOBALS['pfb_test_xmlrpc_calls'] = [];
		unset($GLOBALS['pfb_test_xmlrpc_connection']);
		pfb_sync_receive_changed(FALSE);
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
		unset($GLOBALS['pfb_test_mwexec_bg'], $GLOBALS['pfb_test_logger_calls'], $GLOBALS['pfb_test_xmlrpc_calls'], $GLOBALS['pfb_test_xmlrpc_connection']);
		pfb_sync_receive_changed(FALSE);
	}

	// ---- fixtures ----------------------------------------------------------------------

	/** @return array<string,string> a node's whole pfblockerngdns section: the enable beside its node-local keys */
	private static function dns(string $node, string $enable): array
	{
		return ['pfb_dns' => $enable, 'pfb_dns_saved' => "{$node}-SNAPSHOT", 'pfb_dns_interface' => "{$node}-IF",
			'pfb_dns_dot_interface' => "{$node}-DOT-IF", 'pfb_dns_doh_interface' => "{$node}-DOH-IF",
			'pfb_dns_doq_interface' => "{$node}-DOQ-IF", 'pfb_dns_sslcertref' => "{$node}-CERT", 'pfb_dns_name' => "{$node}-NAME"];
	}

	/** @return array<string,mixed> the whole config of a node */
	private static function node(string $node, string $enable, string $dnsbl, string $scope, string $transport): array
	{
		return [
			'installedpackages' => [
				'pfblockerngdnsblsettings' => ['config' => [0 => ['pfb_dnsbl' => $dnsbl]]],
				'pfblockerngdns'           => ['config' => [0 => self::dns($node, $enable)]],
				'pfblockerngdnssettings'   => ['config' => [0 => ['pfb_dns_doh' => 'on']]],
				'pfblockerngsafesearch'    => ['safesearch_enable' => 'on'],
				'pfblockerngsync'          => ['config' => [0 => ['syncscope' => $scope, 'varsynconchanges' => $transport]]],
			],
			'unbound' => ['active_interface' => "{$node}-UNBOUND-IF", 'custom_options' => "{$node}-UNBOUND-OPTIONS"],
		];
	}

	/**
	 * The installedpackages payload $sender would put on the wire for $scope over $transport: the XMLRPC
	 * replication targets call core's method, the pfSense HA sync hands paths to core, which sends their values.
	 *
	 * @return array{0:string,1:array<string,mixed>} [method, installedpackages payload]
	 */
	private function send(string $scope, string $transport, string $enable = 'on'): array
	{
		$GLOBALS['config']              = self::node('SENDER', $enable, 'on', $scope, $transport);
		$GLOBALS['pfb_test_xmlrpc_calls'] = [];

		if ($transport === 'manual') {
			pfblockerng_do_xmlrpc_sync('192.0.2.2', '443', 'https', 'admin', 'password', 5);
			$this->assertCount(1, $GLOBALS['pfb_test_xmlrpc_calls'], 'one request per target');
			[$method, $params] = $GLOBALS['pfb_test_xmlrpc_calls'][0];
			return [$method, $params['installedpackages'] ?? $params];
		}

		$payload = [];
		foreach (pfblockerng_plugin_xmlrpc_send() as $path) {
			array_set_path($payload, $path, array_get_path($GLOBALS['config'], $path, []));
		}
		return ['restore_config_section', $payload['installedpackages'] ?? []];
	}

	/** Switches this process to the receiving node and runs core's receive on $payload. @return array<string,mixed> */
	private function receive(array $payload, string $enable, string $dnsbl = '', string $scope = 'policy'): array
	{
		$GLOBALS['config'] = self::node('RECEIVER', $enable, $dnsbl, $scope, 'auto');

		$result = pfblockerng_plugin_xmlrpc_recv(['installedpackages' => $payload]);
		foreach ($result as $path => $value) {
			if ($path !== 'xmlrpc_recv_result') {
				config_set_path($path, $value);
			}
		}
		return $result;
	}

	// ---- R5: policy ---------------------------------------------------------------------

	/** @return iterable<string,array{string}> */
	public static function transports(): iterable
	{
		yield 'xmlrpc replication target' => ['manual'];
		yield 'pfSense HA sync' => ['auto'];
	}

	#[DataProvider('transports')]
	public function testPolicySyncMakesAReceiverWithPfbDnsOffStorePfbDnsOnWithoutMovingTheResolver(string $transport): void
	{
		[, $payload] = $this->send('policy', $transport);
		$this->assertSame('on', $payload['pfblockerngdnsblsettings']['config'][0]['pfb_dnsbl'] ?? NULL, 'vacuity guard: DNSBL policy is sent');
		$this->assertSame(['config' => [0 => ['pfb_dns' => 'on']]], $payload['pfblockerngdns'] ?? NULL, 'the enable is the only pfB-DNS leaf on the wire');
		$this->assertStringNotContainsString('SENDER-', serialize($payload), 'no node-local pfB-DNS value of the sender is on the wire');

		$GLOBALS['config'] = self::node('RECEIVER', '', '', 'policy', 'auto');
		$this->assertSame('', config_get_path(self::DNS . '/pfb_dns'), 'before-state: the receiver has pfB-DNS off');
		$this->assertSame('', config_get_path(self::DNSBL . '/pfb_dnsbl'), 'before-state: the receiver has DNSBL off');
		$unbound = $GLOBALS['config']['unbound'];

		$this->receive($payload, '');

		$this->assertSame('on', config_get_path(self::DNSBL . '/pfb_dnsbl'), 'DNSBL on arrived');
		$this->assertSame('on', config_get_path(self::DNS . '/pfb_dns'), 'and the pfB-DNS enable arrived with it');
		$this->assertSame(array_replace(self::dns('RECEIVER', ''), ['pfb_dns' => 'on']), config_get_path(self::DNS), 'every other pfB-DNS key is the receiver\'s own');
		$this->assertSame($unbound, $GLOBALS['config']['unbound'], 'a receive never moves the Resolver; the following Update does');
		$this->assertStringNotContainsString('SENDER-', serialize($GLOBALS['config']));
	}

	public function testReceivedEnableJoinsTheAcceptedAndIncomingDigestsAndLiftsSuppressionWhenEditedLocally(): void
	{
		[, $payload] = $this->send('policy', 'auto');
		$this->receive($payload, '');
		$this->assertSame('on', config_get_path(self::DNS . '/pfb_dns'), 'vacuity guard: the enable arrived');

		$state = pfb_sync_receive_state_read($this->dir);
		$this->assertNotNull($state['accepted_digest']);
		$this->assertSame($state['accepted_digest'], pfb_sync_policy_current_digest(), 'the accepted digest covers the received enable');
		$this->assertSame($state['accepted_digest'], $state['last']['incoming_digest'], 'no ignored leaf: the incoming digest reads the same payload');
		$this->assertTrue(pfb_sync_receive_suppressed(), 'a node whose policy still equals the received one does not echo it');

		config_set_path(self::DNS . '/pfb_dns_saved', 'RECEIVER-SNAPSHOT-MOVED');
		$this->assertTrue(pfb_sync_receive_suppressed(), 'the node-local snapshot is not policy');
		config_set_path(self::DNS . '/pfb_dns', '');
		$this->assertFalse(pfb_sync_receive_suppressed(), 'this node\'s own edit of the enable lifts the suppression');
	}

	// ---- R8: version skew ---------------------------------------------------------------

	public function testPolicyFromAnOlderSenderWithoutAnyPfbDnsSectionKeepsTheReceiversEnable(): void
	{
		$older = [
			'pfblockerngdnsblsettings' => ['config' => [0 => ['pfb_dnsbl' => 'on']]],
			'pfblockerngsafesearch'    => ['safesearch_enable' => 'on'],
			'pfblockerngsync'          => ['config' => [0 => ['syncscope' => 'policy']]],
		];
		$this->assertArrayNotHasKey('pfblockerngdns', $older);

		$this->receive($older, 'on');

		$this->assertSame('on', config_get_path(self::DNSBL . '/pfb_dnsbl'), 'vacuity guard: the older sender\'s DNSBL policy applied');
		$this->assertSame(self::dns('RECEIVER', 'on'), config_get_path(self::DNS), 'its pfB-DNS keys, the enable included, stay as they were');
	}

	public function testExplicitOffFromAnUpgradedSenderStillTurnsTheReceiverOff(): void
	{
		[, $payload] = $this->send('policy', 'manual', '');
		// Core's array_get_path() answers its default for '', so an explicit Off travels as [] (the merge reads [] as '').
		$this->assertSame(['config' => [0 => ['pfb_dns' => []]]], $payload['pfblockerngdns'] ?? NULL, 'the sender states Off explicitly');

		$GLOBALS['config'] = self::node('RECEIVER', 'on', 'on', 'policy', 'auto');
		$this->assertSame('on', config_get_path(self::DNS . '/pfb_dns'), 'before-state');

		$this->receive($payload, 'on', 'on');

		$this->assertSame(array_replace(self::dns('RECEIVER', 'on'), ['pfb_dns' => '']), config_get_path(self::DNS));
	}

	// ---- every scope: what pfblockerngdns goes on the wire -------------------------------

	/** @return iterable<string,array{string,string,?array<string,mixed>}> scope, transport, the pfblockerngdns section on the wire */
	public static function wire(): iterable
	{
		$leaf = ['config' => [0 => ['pfb_dns' => 'on']]];
		yield 'policy over replication targets' => ['policy', 'manual', $leaf];
		yield 'policy over HA sync'             => ['policy', 'auto', $leaf];
		yield 'all over HA sync'                => ['all', 'auto', $leaf];
		// merge_installedpackages_section replaces the section wholesale and calls no hook, so it cannot carry one leaf.
		yield 'all over replication targets'    => ['all', 'manual', NULL];
		yield 'lists over replication targets'  => ['lists', 'manual', NULL];
		yield 'lists over HA sync'              => ['lists', 'auto', NULL];
	}

	/** @param ?array<string,mixed> $expected */
	#[DataProvider('wire')]
	public function testNoScopeSendsMoreOfPfbDnsThanItsEnableAndOnlyWhereItCanBeSetAlone(string $scope, string $transport, ?array $expected): void
	{
		[, $payload] = $this->send($scope, $transport);

		$this->assertSame('on', $payload['pfblockerngsafesearch']['safesearch_enable'] ?? NULL, 'vacuity guard: the sender sent its sections');
		$this->assertSame($expected, $payload['pfblockerngdns'] ?? NULL);
		$this->assertStringNotContainsString('SENDER-SNAPSHOT', serialize($payload));
		$this->assertStringNotContainsString('SENDER-IF', serialize($payload));
		$this->assertStringNotContainsString('SENDER-DOT-IF', serialize($payload));
		$this->assertStringNotContainsString('SENDER-CERT', serialize($payload));
		$this->assertStringNotContainsString('SENDER-NAME', serialize($payload));
	}

	// ---- R6: lists ----------------------------------------------------------------------

	public function testListsScopeLeavesTheReceiversPfbDnsSectionByteIdentical(): void
	{
		[, $payload] = $this->send('lists', 'auto');
		$this->assertSame('auto', $payload['pfblockerngsync']['config'][0]['varsynconchanges'] ?? NULL, 'vacuity guard: a legacy payload the hook accepts');

		foreach (['on', ''] as $enable) {
			$GLOBALS['config'] = self::node('RECEIVER', $enable, '', 'lists', 'auto');
			$before = config_get_path(self::DNS);
			$this->receive($payload, $enable, '', 'lists');
			$this->assertSame($before, config_get_path(self::DNS), "the receiver's pfB-DNS section is untouched (enable '{$enable}')");
		}
	}

	// ---- R7: legacy scope 'all' over HA sync ---------------------------------------------

	/** @return iterable<string,array{string,string}> sender enable, receiver enable before */
	public static function allEnables(): iterable
	{
		yield 'on reaches a receiver with it off' => ['on', ''];
		yield 'off reaches a receiver with it on' => ['', 'on'];
	}

	#[DataProvider('allEnables')]
	public function testLegacyAllSetsTheReceiversEnableAndNothingElseOfItsPfbDnsSection(string $sender, string $receiver): void
	{
		[, $payload] = $this->send('all', 'auto', $sender);
		$this->assertSame(['config' => [0 => ['pfb_dns' => $sender === '' ? [] : $sender]]], $payload['pfblockerngdns'] ?? NULL, 'vacuity guard: only the enable is sent');
		$this->assertSame('auto', $payload['pfblockerngsync']['config'][0]['varsynconchanges'] ?? NULL, 'vacuity guard: a legacy payload the hook accepts');

		$GLOBALS['config'] = self::node('RECEIVER', $receiver, '', 'all', 'auto');
		$this->assertSame($receiver, config_get_path(self::DNS . '/pfb_dns'), 'before-state');
		$unbound = $GLOBALS['config']['unbound'];

		$this->receive($payload, $receiver, '', 'all');

		$this->assertSame(array_replace(self::dns('RECEIVER', $receiver), ['pfb_dns' => $sender]), config_get_path(self::DNS));
		$this->assertSame($unbound, $GLOBALS['config']['unbound'], 'a legacy receive never moves the Resolver');
		$this->assertStringNotContainsString('SENDER-SNAPSHOT', serialize($GLOBALS['config']));
	}

	public function testLegacyReceiveTakesOnlyTheEnableLeafOfAPfbDnsSection(): void
	{
		// A legacy payload that also names node-local pfB-DNS keys: only the enable may be set from it.
		$payload = [
			'pfblockerngsync'  => ['config' => [0 => ['varsynconchanges' => 'auto']]],
			'pfblockerngdns'   => ['config' => [0 => self::dns('EVIL', 'on')]],
		];
		$GLOBALS['config'] = self::node('RECEIVER', '', '', 'all', 'auto');
		$this->assertSame('', config_get_path(self::DNS . '/pfb_dns'), 'before-state');

		$result = $this->receive($payload, '', '', 'all');

		$this->assertSame(array_replace(self::dns('RECEIVER', ''), ['pfb_dns' => 'on']), config_get_path(self::DNS));
		$this->assertStringNotContainsString('EVIL-', serialize($GLOBALS['config']));
		$this->assertTrue($result['xmlrpc_recv_result'], 'the receive reports a change');
	}

	public function testLegacyAllWithTheSameEnableChangesNothing(): void
	{
		[, $payload] = $this->send('all', 'auto', 'on');
		$GLOBALS['config'] = self::node('RECEIVER', 'on', 'on', 'all', 'auto');
		$before = $GLOBALS['config']['installedpackages']['pfblockerngdns'];

		$result = $this->receive($payload, 'on', 'on', 'all');

		$this->assertArrayNotHasKey('installedpackages/pfblockerngdns', $result);
		$this->assertArrayNotHasKey(self::DNS . '/pfb_dns', $result);
		$this->assertSame($before, $GLOBALS['config']['installedpackages']['pfblockerngdns']);
	}

	public function testLegacyAllDigestMovesWithTheEnableAndIgnoresTheLocalKeys(): void
	{
		$GLOBALS['config'] = self::node('SENDER', 'on', 'on', 'all', 'auto');
		$first = pfb_sync_legacy_digests(['all', 'lists']);

		config_set_path(self::DNS . '/pfb_dns_saved', 'SENDER-SNAPSHOT-MOVED');
		config_set_path(self::DNS . '/pfb_dns_interface', 'SENDER-IF-MOVED');
		$this->assertSame($first, pfb_sync_legacy_digests(['all', 'lists']), 'node-local keys are not part of what the scope sends');

		config_set_path(self::DNS . '/pfb_dns', '');
		$second = pfb_sync_legacy_digests(['all', 'lists']);
		$this->assertNotSame($first['all'], $second['all'], 'an own edit of the enable lifts the suppression of a legacy all send');
		$this->assertSame($first['lists'], $second['lists'], 'lists never carried it');
	}
}
