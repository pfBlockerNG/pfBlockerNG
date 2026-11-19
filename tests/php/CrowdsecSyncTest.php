<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4071 -- XMLRPC sync carries exactly the CrowdSec settings marked policy, never the key (docs/specs/crowdsec-integration.md,
 * D2 and acceptance criterion 14).
 *
 * pfblockerngcrowdsec joins the sections of scope `policy` as a settings section (allowlist): its enable, LAPI URL and rule
 * settings travel, while the bouncer key, the log level and the interface choice stay on each node (each node registers its own
 * bouncer on the engine). The legacy scopes send whole sections, so they never carry pfblockerngcrowdsec at all. Every fixture
 * gives the sender SENDER-... sentinels in its local fields, so a leak shows in the failure diff.
 *
 * Every receive is applied the way core's xmlrpc.php does (config_set_path() of each returned path except xmlrpc_recv_result).
 */
#[CoversFunction('pfblockerng_do_xmlrpc_sync')]
#[CoversFunction('pfblockerng_plugin_xmlrpc_send')]
#[CoversFunction('pfblockerng_plugin_xmlrpc_recv')]
#[CoversFunction('pfb_sync_policy_projection')]
#[CoversFunction('pfb_sync_policy_merge')]
final class CrowdsecSyncTest extends TestCase
{
	private const CROWDSEC = 'installedpackages/pfblockerngcrowdsec/config/0';
	private const SENDER_KEY = 'SENDER-bouncer-KEY-0123456789';

	private string $dir;
	private mixed $savedConfig;
	private mixed $savedPfb;

	protected function setUp(): void
	{
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$this->savedPfb    = $GLOBALS['pfb'] ?? NULL;
		$this->dir = sys_get_temp_dir() . '/pfb_sync_crowdsec_' . bin2hex(random_bytes(6));
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
		rmdir_recursive($this->dir);
		$GLOBALS['config'] = $this->savedConfig;
		$GLOBALS['pfb'] = $this->savedPfb;
		unset($GLOBALS['pfb_test_mwexec_bg'], $GLOBALS['pfb_test_logger_calls'], $GLOBALS['pfb_test_xmlrpc_calls'], $GLOBALS['pfb_test_xmlrpc_connection']);
		pfb_sync_receive_changed(FALSE);
	}

	/** @return array<string,string> a node's CrowdSec section: its policy beside its own key, log level and interfaces */
	private static function crowdsec(string $node, string $enable = 'on'): array
	{
		return [
			'enable'               => $enable,
			'lapi_url'             => $node === 'SENDER' ? 'https://lapi.example.net:8080' : 'http://192.0.2.9:8080',
			'api_key'              => "{$node}-bouncer-KEY-0123456789",
			'log_level'            => $node === 'SENDER' ? 'debug' : 'error',
			'rules_all_interfaces' => '',
			'rules_interfaces'     => $node === 'SENDER' ? 'SENDER-IF' : 'RECEIVER-IF',
			'rules_log'            => $node === 'SENDER' ? 'on' : '',
			'rules_tag'            => "{$node}_TAG",
			'rule_v4'              => 'on',
			'rule_v6'              => $node === 'SENDER' ? '' : 'on',
		];
	}

	/** @return array<string,mixed> the whole config of a node */
	private static function node(string $node, string $scope, string $transport, ?array $crowdsec = NULL): array
	{
		$config = [
			'installedpackages' => [
				'pfblockerngdnsblsettings' => ['config' => [0 => ['pfb_dnsbl' => 'on']]],
				'pfblockerngsafesearch'    => ['safesearch_enable' => 'on'],
				'pfblockerngsync'          => ['config' => [0 => ['syncscope' => $scope, 'varsynconchanges' => $transport]]],
			],
		];
		$config['installedpackages']['pfblockerngcrowdsec'] = ['config' => [0 => $crowdsec ?? self::crowdsec($node)]];
		return $config;
	}

	/** @return array<string,mixed> the installedpackages payload the sender puts on the wire for $scope over $transport */
	private function send(string $scope, string $transport): array
	{
		$GLOBALS['config'] = self::node('SENDER', $scope, $transport);
		$GLOBALS['pfb_test_xmlrpc_calls'] = [];

		if ($transport === 'manual') {
			pfblockerng_do_xmlrpc_sync('192.0.2.2', '443', 'https', 'admin', 'password', 5);
			$this->assertCount(1, $GLOBALS['pfb_test_xmlrpc_calls'], 'one request per target');
			[, $params] = $GLOBALS['pfb_test_xmlrpc_calls'][0];
			return $params['installedpackages'] ?? $params;
		}
		$payload = [];
		foreach (pfblockerng_plugin_xmlrpc_send() as $path) {
			array_set_path($payload, $path, array_get_path($GLOBALS['config'], $path, []));
		}
		return $payload['installedpackages'] ?? [];
	}

	private function receive(array $payload): void
	{
		$GLOBALS['config'] = self::node('RECEIVER', 'policy', 'auto');
		$result = pfblockerng_plugin_xmlrpc_recv(['installedpackages' => $payload]);
		foreach ($result as $path => $value) {
			if ($path !== 'xmlrpc_recv_result') {
				config_set_path($path, $value);
			}
		}
	}

	/** @return iterable<string,array{string}> */
	public static function transports(): iterable
	{
		yield 'xmlrpc replication target' => ['manual'];
		yield 'pfSense HA sync' => ['auto'];
	}

	#[DataProvider('transports')]
	public function testPolicyScopeSendsExactlyThePolicySettingsAndNeverTheKey(string $transport): void
	{
		$payload = $this->send('policy', $transport);

		$this->assertSame('on', $payload['pfblockerngdnsblsettings']['config'][0]['pfb_dnsbl'] ?? NULL, 'vacuity guard: policy is sent');
		$sent = $payload['pfblockerngcrowdsec']['config'][0] ?? NULL;
		$this->assertIsArray($sent, 'the CrowdSec section is policy');
		ksort($sent);
		$this->assertSame(['enable', 'lapi_url', 'rule_v4', 'rule_v6', 'rules_log', 'rules_tag'], array_keys($sent),
			'the six policy settings and nothing else');
		$this->assertSame('https://lapi.example.net:8080', $sent['lapi_url']);
		$this->assertSame('SENDER_TAG', $sent['rules_tag']);
		$this->assertStringNotContainsString(self::SENDER_KEY, serialize($payload), 'the key is never on the wire');
		$this->assertStringNotContainsString('SENDER-IF', serialize($payload), 'nor the interfaces');
	}

	public function testAReceiverTakesThePolicyAndKeepsItsOwnKeyLogLevelAndInterfaces(): void
	{
		$payload = $this->send('policy', 'auto');
		$GLOBALS['config'] = self::node('RECEIVER', 'policy', 'auto');
		$this->assertSame(self::crowdsec('RECEIVER'), config_get_path(self::CROWDSEC), 'before-state');

		$this->receive($payload);

		$this->assertSame(array_replace(self::crowdsec('RECEIVER'), [
			'lapi_url'  => 'https://lapi.example.net:8080',
			'rules_log' => 'on',
			'rules_tag' => 'SENDER_TAG',
			'rule_v6'   => '',
		]), config_get_path(self::CROWDSEC));
		$this->assertStringNotContainsString(self::SENDER_KEY, serialize($GLOBALS['config']));
	}

	public function testAReceiverWithoutAKeyGetsTheEnableButNoKey(): void
	{
		$payload = $this->send('policy', 'manual');
		$GLOBALS['config'] = self::node('RECEIVER', 'policy', 'auto', []);

		$result = pfblockerng_plugin_xmlrpc_recv(['installedpackages' => $payload]);
		foreach ($result as $path => $value) {
			if ($path !== 'xmlrpc_recv_result') {
				config_set_path($path, $value);
			}
		}

		$this->assertSame('on', config_get_path(self::CROWDSEC . '/enable'), 'the enable arrived');
		$this->assertNull(config_get_path(self::CROWDSEC . '/api_key'), 'no key arrived with it');
		$GLOBALS['pfb']['enable'] = PfbToggle::On;
		$this->assertFalse(pfb_crowdsec_should_run(), 'so the bouncer does not run on this node');
	}

	/** @return iterable<string,array{string,string}> */
	public static function legacy(): iterable
	{
		foreach (['all', 'lists'] as $scope) {
			foreach (['manual', 'auto'] as $transport) {
				yield "{$scope} over {$transport}" => [$scope, $transport];
			}
		}
	}

	#[DataProvider('legacy')]
	public function testTheLegacyScopesNeverSendTheCrowdsecSection(string $scope, string $transport): void
	{
		$payload = $this->send($scope, $transport);

		$this->assertNotSame([], $payload, 'vacuity guard: the scope sends something');
		$this->assertArrayNotHasKey('pfblockerngcrowdsec', $payload);
		$this->assertStringNotContainsString(self::SENDER_KEY, serialize($payload));
	}

	public function testPolicyFromAnOlderSenderWithoutTheSectionLeavesTheReceiversSettings(): void
	{
		$older = [
			'pfblockerngdnsblsettings' => ['config' => [0 => ['pfb_dnsbl' => 'on']]],
			'pfblockerngsafesearch'    => ['safesearch_enable' => 'on'],
			'pfblockerngsync'          => ['config' => [0 => ['syncscope' => 'policy']]],
		];

		$this->receive($older);

		$this->assertSame(self::crowdsec('RECEIVER'), config_get_path(self::CROWDSEC));
	}
}
