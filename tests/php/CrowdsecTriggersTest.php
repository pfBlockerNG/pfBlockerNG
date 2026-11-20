<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4139 -- what starts, stops and reconfigures the CrowdSec bouncer (docs/specs/crowdsec-integration.md, D4 and its #4139
 * amendment).
 *
 * Only these apply the "should run" decision, each at the moment it happens:
 *   - the CrowdSec Settings save (pfb_crowdsec_save());
 *   - the General save of pfBlockerNG's master enable, and the wizard, which resets every setting;
 *   - an XMLRPC receive that changed the CrowdSec section or the master enable, in the receive request itself
 *     (plugin_xmlrpc_recv_done), in the policy scope and in the legacy `all` scope that carries the master enable;
 *   - the installer;
 *   - boot, through pfSense's own start of the rc script alone.
 * pfBlockerNG's update pass, in save mode or any other, never starts, stops or restarts the bouncer and never writes the rule hook's
 * registration. Each trigger but boot also writes that registration (pfSense's install loses it) and reloads the filter when it wrote
 * it while the bouncer should run.
 *
 * A CrowdSec save marks no pending changes: its page ends like the General save, with a save-mode pass that sends the change to the
 * peers (manual XMLRPC sync) and a write_config() whose HA sync carries it in the automatic mode.
 *
 * The pass, the pages, the wizard and the installer cannot run off-appliance, so their wiring is read from source. The receive and
 * pfb_crowdsec_resync() run for real; the bouncer's state is its config file, which exists exactly while the bouncer is applied on.
 */
#[CoversFunction('pfb_crowdsec_resync')]
#[CoversFunction('pfb_crowdsec_save')]
#[CoversFunction('pfblockerng_plugin_xmlrpc_recv')]
#[CoversFunction('pfblockerng_plugin_xmlrpc_recv_done')]
final class CrowdsecTriggersTest extends TestCase
{
	private const SRC = __DIR__ . '/../../src/usr/local';
	private const CROWDSEC = 'installedpackages/pfblockerngcrowdsec/config/0';
	private const GENERAL = 'installedpackages/pfblockerng/config/0';
	private const KEY = 'RECEIVER-bouncer-KEY-0123456789';

	private string $dir = '';
	private mixed $savedConfig;
	private mixed $savedPfb;

	protected function setUp(): void
	{
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$this->savedPfb = $GLOBALS['pfb'] ?? NULL;
		$this->dir = sys_get_temp_dir() . '/pfb_crowdsec_triggers_' . bin2hex(random_bytes(6));
		$this->assertTrue(mkdir("{$this->dir}/rc", 0700, TRUE));
		$GLOBALS['config'] = [];
		$GLOBALS['pfb'] = [
			'dbdir'           => $this->dir,
			'log'             => "{$this->dir}/pfblockerng.log",
			'pending_marker'  => "{$this->dir}/pfb_pending_changes",
			'crowdsec_config' => "{$this->dir}/pfb_crowdsec.json",
		];
		$GLOBALS['pfb_test_rcfile_dir'] = "{$this->dir}/rc";
		$GLOBALS['pfb_test_service_calls'] = [];
		$GLOBALS['pfb_test_service_running'] = ['pfb_crowdsec' => FALSE];
		$GLOBALS['pfb_test_filter_configure_calls'] = 0;
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_mwexec_bg'] = [];
		$GLOBALS['pfb_test_logger_calls'] = [];
		pfb_sync_receive_changed(FALSE);
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->dir);
		$GLOBALS['config'] = $this->savedConfig;
		$GLOBALS['pfb'] = $this->savedPfb;
		unset($GLOBALS['pfb_test_rcfile_dir'], $GLOBALS['pfb_test_service_calls'], $GLOBALS['pfb_test_service_running'],
			$GLOBALS['pfb_test_filter_configure_calls'], $GLOBALS['pfb_test_write_config_calls'], $GLOBALS['pfb_test_mwexec_bg'],
			$GLOBALS['pfb_test_logger_calls']);
		pfb_sync_receive_changed(FALSE);
	}

	private static function source(string $path): string
	{
		$text = file_get_contents(self::SRC . "/{$path}");
		self::assertIsString($text, "cannot read {$path}");
		return $text;
	}

	/** @return array<string,string> a CrowdSec section; $key is this node's own bouncer key */
	private static function crowdsec(string $enable, string $key = self::KEY): array
	{
		return ['enable' => $enable, 'lapi_url' => 'https://lapi.example.net:8080', 'api_key' => $key, 'log_level' => 'info',
			'rules_all_interfaces' => 'on', 'rules_interfaces' => '', 'rules_log' => '', 'rules_tag' => '', 'rule_v4' => 'on', 'rule_v6' => 'on'];
	}

	/** @return array<string,mixed> a node's whole config: master enable, CrowdSec section, sync settings */
	private static function node(string $master, string $crowdsec, string $scope = 'policy'): array
	{
		return ['installedpackages' => [
			'pfblockerng'              => ['config' => [0 => ['enable_cb' => $master]]],
			'pfblockerngdnsblsettings' => ['config' => [0 => ['pfb_dnsbl' => 'on']]],
			'pfblockerngsync'          => ['config' => [0 => ['syncscope' => $scope, 'varsynconchanges' => 'auto']]],
			'pfblockerngcrowdsec'      => ['config' => [0 => self::crowdsec($crowdsec)]],
		]];
	}

	/** The receiver at $before takes what a sender at $after sends in $scope, as core's xmlrpc.php does, then core's recv_done runs. */
	private function receive(array $before, array $after, string $scope = 'policy'): void
	{
		$GLOBALS['config'] = $after;
		$payload = [];
		foreach (pfblockerng_plugin_xmlrpc_send() as $path) {
			array_set_path($payload, $path, array_get_path($GLOBALS['config'], $path, []));
		}
		$this->assertNotSame([], $payload, "the sender sends something in scope {$scope}");

		$GLOBALS['config'] = $before;
		if ($scope !== 'policy') {
			// The legacy receive takes a payload only from a sender in the automatic mode, and writes what changed
			array_set_path($payload, 'installedpackages/pfblockerngsync/config/0/varsynconchanges', 'auto');
		}
		foreach (pfblockerng_plugin_xmlrpc_recv($payload) as $path => $value) {
			if ($path !== 'xmlrpc_recv_result') {
				config_set_path($path, $value);
			}
		}
		pfblockerng_plugin_xmlrpc_recv_done(NULL);
	}

	private function bouncerApplied(): bool
	{
		clearstatcache();
		return is_file($GLOBALS['pfb']['crowdsec_config']);
	}

	/** Apply the receiver's own state first, so that the receive is what changes it. */
	private function settle(array $config): void
	{
		$GLOBALS['config'] = $config;
		pfb_crowdsec_apply();
		$GLOBALS['pfb_test_service_running']['pfb_crowdsec'] = pfb_crowdsec_should_run();
	}

	// ---- the update pass never touches the bouncer ------------------------------------------------

	public function testTheUpdatePassNeverStartsStopsOrRestartsTheBouncerNorWritesItsRuleHook(): void
	{
		$pass = self::source('pkg/pfblockerng/pfblockerng_apply.inc');

		foreach (['pfb_crowdsec_apply(', 'pfb_crowdsec_resync(', 'pfb_crowdsec_register_rule_hook(', "_service('pfb_crowdsec')"] as $call) {
			$this->assertStringNotContainsString($call, $pass, "the update pass calls {$call}");
		}
	}

	// ---- each trigger applies it, at once -----------------------------------------------------------

	/** @return iterable<string, array{string, string, string}> source file, the call that ends its save, a call it must follow */
	public static function sourceTriggers(): iterable
	{
		yield 'General save (master enable)' => ['www/pfblockerng/pfblockerng_general.php', 'pfb_crowdsec_resync();', 'sync_package_pfblockerng();'];
		yield 'wizard (every setting reset)' => ['www/wizards/pfblockerng_wizard.inc', 'pfb_crowdsec_resync();', "write_config('pfBlockerNG: Default Wizard configuration saved');"];
		yield 'installer'                    => ['pkg/pfblockerng/pfblockerng_install.inc', 'pfb_crowdsec_resync();', "update_status(\"Applying the CrowdSec bouncer service...\");"];
	}

	#[DataProvider('sourceTriggers')]
	public function testEachTriggerOutsideTheSettingsAppliesTheBouncerOnceItsSettingsAreStored(string $file, string $call, string $after): void
	{
		$text = self::source($file);

		$this->assertSame(1, substr_count($text, $call), "{$file} calls {$call} once");
		$this->assertGreaterThan(strpos($text, $after), strpos($text, $call), "{$file}: {$call} comes after {$after}");
	}

	public function testTheCrowdsecSaveEndsWithTheSaveModePassThatSyncsLikeTheGeneralSave(): void
	{
		$page = self::source('www/pfblockerng/pfblockerng_crowdsec.php');

		$this->assertMatchesRegularExpression(
			'~pfb_crowdsec_save\(\$checked\[\'values\'\]\);\s*\$pfb\[\'save\'\] = TRUE;\s*sync_package_pfblockerng\(\);\s*header\(~',
			$page,
			'after its own apply, the save runs the save-mode pass (the General save\'s sync), then redirects'
		);
	}

	/** @return iterable<string, array{array<string,string>}> */
	public static function policyChanges(): iterable
	{
		yield 'enable'              => [['enable' => '']];
		yield 'LAPI URL'            => [['lapi_url' => 'http://192.0.2.7:8080']];
		yield 'log blocked packets' => [['rules_log' => 'on']];
		yield 'tag'                 => [['rules_tag' => 'cs']];
		yield 'IPv4 rules'          => [['rule_v4' => '']];
	}

	#[DataProvider('policyChanges')]
	public function testTheCrowdsecSaveMarksNoPendingChangesForAPolicySetting(array $change): void
	{
		config_set_path(self::GENERAL . '/enable_cb', 'on');
		config_set_path(self::CROWDSEC, self::crowdsec('on'));
		$this->assertFileDoesNotExist($GLOBALS['pfb']['pending_marker'], 'before-state: nothing is pending');

		pfb_crowdsec_save(array_replace(self::crowdsec('on'), $change));

		$this->assertFileDoesNotExist($GLOBALS['pfb']['pending_marker'], 'the save syncs at once: nothing waits for the next Update');
	}

	// ---- an XMLRPC receive applies it in the receive request --------------------------------------

	/** @return iterable<string, array{string, string, string, string, bool}> receiver master/CrowdSec, sender master/CrowdSec, applied after */
	public static function receives(): iterable
	{
		yield 'CrowdSec turned on'         => ['on', '', 'on', 'on', TRUE];
		yield 'CrowdSec turned off'        => ['on', 'on', 'on', '', FALSE];
		yield 'pfBlockerNG turned off'     => ['on', 'on', '', 'on', FALSE];
		yield 'pfBlockerNG turned on'      => ['', 'on', 'on', 'on', TRUE];
	}

	#[DataProvider('receives')]
	public function testAPolicyReceiveAppliesTheBouncerInTheReceiveRequest(string $rm, string $rc, string $sm, string $sc, bool $on): void
	{
		$this->settle(self::node($rm, $rc));
		$this->assertSame(!$on, $this->bouncerApplied(), 'before-state: the receiver is the other way round');

		$this->receive(self::node($rm, $rc), self::node($sm, $sc));

		$this->assertSame($on, $this->bouncerApplied(), 'applied by the receive itself, not by a later Update');
	}

	public function testALegacyReceiveOfTheMasterEnableAppliesTheBouncer(): void
	{
		// Given a receiver whose bouncer runs, in scope `all` (which never carries the CrowdSec section)
		$this->settle(self::node('on', 'on', 'all'));
		$this->assertTrue($this->bouncerApplied(), 'before-state: the bouncer runs');

		// When the sender turns pfBlockerNG off
		$this->receive(self::node('on', 'on', 'all'), self::node('', 'on', 'all'), 'all');

		// Then the bouncer is off at once
		$this->assertFalse($this->bouncerApplied());
	}

	public function testAReceiveThatChangesNeitherTheMasterEnableNorTheCrowdsecSectionLeavesTheBouncerAlone(): void
	{
		// Given a receiver whose bouncer should run but was never applied (no config file)
		$GLOBALS['config'] = self::node('on', 'on');
		$sender = self::node('on', 'on');
		$sender['installedpackages']['pfblockerngdnsblsettings']['config'][0]['pfb_dnsbl'] = '';
		$this->assertFalse($this->bouncerApplied(), 'before-state: not applied');

		// When a receive changes another section only
		$this->receive(self::node('on', 'on'), $sender);

		// Then the receive did not apply the bouncer
		$this->assertFalse($this->bouncerApplied(), 'only a change of the master enable or the CrowdSec section applies it');
		$this->assertSame([], $GLOBALS['pfb_test_service_calls']);
	}

	// ---- pfb_crowdsec_resync(): what each trigger outside the Settings runs ---------------------------

	public function testTheResyncRegistersTheRuleHookAndReloadsTheFilterWhileTheBouncerShouldRun(): void
	{
		$GLOBALS['config'] = self::node('on', 'on');
		$GLOBALS['config']['installedpackages']['package'] = [['configurationfile' => 'pfblockerng.xml']];
		$this->assertFalse($this->bouncerApplied(), 'before-state: not applied');

		pfb_crowdsec_resync();

		$this->assertSame('pfb_crowdsec_rules', config_get_path('installedpackages/package/0/filter_rule_function'));
		$this->assertTrue($this->bouncerApplied());
		$this->assertSame(1, $GLOBALS['pfb_test_filter_configure_calls'], 'one reload for the new rules');
	}

	public function testTheResyncOfAnUnchangedBouncerNeitherReloadsNorWrites(): void
	{
		$GLOBALS['config'] = self::node('on', 'on');
		$GLOBALS['config']['installedpackages']['package'] = [['configurationfile' => 'pfblockerng.xml', 'filter_rule_function' => 'pfb_crowdsec_rules']];
		$this->settle($GLOBALS['config']);
		$GLOBALS['pfb_test_write_config_calls'] = [];

		pfb_crowdsec_resync();

		$this->assertSame(0, $GLOBALS['pfb_test_filter_configure_calls']);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
	}
}
