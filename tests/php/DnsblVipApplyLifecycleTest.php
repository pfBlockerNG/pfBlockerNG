<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

define('PFB_VIP_APPLY_PFB_BASELINE', $GLOBALS['pfb']);

/**
 * issue #3539 — the real apply pass (sync_package_pfblockerng()) runs the web server / NAT / auto-VIP
 * lifecycle in the order that keeps the live DNSBL generation served:
 *
 *   - while demand has just ended and the web server still serves, the VIP, NAT and web server are NOT
 *     touched before the resolver reload; they are torn down after it, and only once pfb_dnsbl_converged();
 *   - empty web server ports abort the DNSBL pass only while a block answers with the VIP;
 *   - the port alias and the DNSBL floating rules exist only while a block answers with the VIP;
 *   - the boot / install resync serves (or tears down) through pfb_create_dnsbl() only for an enabled
 *     package with DNSBL on and the resolver on.
 *
 * The pass runs for real on a temp tree. Doubles: pfSense services (recorded), the resolver process (a
 * flag), the resolver start (suppressed by the bootstrap). The pass log is the clock: the line
 * "DNSBL update [ feed lines" is written once the resolver reload has finished.
 */
#[CoversFunction('sync_package_pfblockerng')]
#[CoversFunction('pfb_create_dnsbl')]
#[CoversFunction('pfb_manage_dnsbl_vip')]
final class DnsblVipApplyLifecycleTest extends TestCase
{
	private const DNSBL = 'installedpackages/pfblockerngdnsblsettings/config/0';
	private const RELOAD_DONE = 'DNSBL update [ feed lines';
	private const VIP_WRITE = 'pfBlockerNG: saving DNSBL auto-VIP changes';
	private const NAT_WRITE = 'pfBlockerNG: saving DNSBL changes';
	private const PORTS_ABORT = 'DNSBL Ports are not defined. Exiting';
	private const DNSBL_PROCESSING = 'Loading DNSBL SafeSearch...';
	private const USER_NAT = ['descr' => 'user rule', 'interface' => 'wan', 'target' => '10.0.0.9'];

	private string $dir;
	/** @var array<string,array{bool,mixed}> */
	private array $savedGlobals = [];
	/** @var list<array{string,string,bool}> [function, service, resolver reload already finished] */
	private array $serviceEvents = [];
	/** @var list<array{string,bool}> [write_config description, resolver reload already finished] */
	private array $configWrites = [];

	protected function setUp(): void
	{
		foreach (['pfb', 'config', 'g'] as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$this->dir = sys_get_temp_dir() . '/pfb_vip_apply_' . getmypid() . '_' . bin2hex(random_bytes(6));
		mkdir("{$this->dir}/deny", 0755, TRUE);
		$this->serviceEvents = [];
		$this->configWrites  = [];

		$GLOBALS['pfb_test_service_calls']    = [];
		$GLOBALS['pfb_test_file_notices']     = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_service_hook']       = function (string $function, string $service): void {
			$this->serviceEvents[] = [$function, $service, $this->reloadFinished()];
		};
		$GLOBALS['pfb_test_write_config_hook']  = function (string $description): void {
			$this->configWrites[] = [$description, $this->reloadFinished()];
		};
	}

	protected function tearDown(): void
	{
		foreach ($this->savedGlobals as $name => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
		$this->savedGlobals = [];
		unset(
			$GLOBALS['pfb_test_service_calls'], $GLOBALS['pfb_test_file_notices'], $GLOBALS['pfb_test_write_config_calls'],
			$GLOBALS['pfb_test_service_hook'], $GLOBALS['pfb_test_write_config_hook'], $GLOBALS['pfb_test_process_running']
		);
		rmdir_recursive($this->dir);
	}

	private function reloadFinished(): bool
	{
		return str_contains((string) @file_get_contents($GLOBALS['pfb']['log']), self::RELOAD_DONE);
	}

	private function passLog(): string
	{
		return (string) @file_get_contents($GLOBALS['pfb']['log']);
	}

	/**
	 * @param array{save?:bool,demand?:bool,rowState?:string,ports?:bool,enable?:bool,dnsbl?:bool,unbound?:bool,install?:bool,served?:bool,up?:bool} $o
	 *   save    GUI/resync save pass (no feed processing) vs a full update pass
	 *   demand  a group answers with the VIP (logging 'enabled'), else Null Blocking ('disabled_log')
	 *   rowState state of the group's one feed row ('Disabled' = the group has no blocking row)
	 *   served  the web server serves: marked VIP, DNSBL NAT, conf and certificate exist
	 *   up      the resolver process is running (so a finished reload is converged)
	 */
	private function arrange(array $o = []): void
	{
		$o += ['save' => TRUE, 'demand' => FALSE, 'rowState' => 'Enabled', 'ports' => TRUE, 'enable' => TRUE, 'dnsbl' => TRUE,
			'unbound' => TRUE, 'install' => FALSE, 'served' => FALSE, 'up' => TRUE];
		$dir = $this->dir;

		$GLOBALS['pfb'] = array_merge(PFB_VIP_APPLY_PFB_BASELINE, [
			'dbdir' => $dir, 'schedule_state_dir' => $dir, 'log' => "{$dir}/pfblockerng.log", 'errlog' => "{$dir}/error.log",
			'runlog' => "{$dir}/run.log", 'denydir' => "{$dir}/deny", 'dnsbldir' => $dir, 'dnsbl_conf' => "{$dir}/lighty.conf",
			'dnsbl_cert' => "{$dir}/cert.pem", 'chroot_cmd' => '/bin/echo', 'php' => PHP_BINARY, 'dnsbl_python_unmount' => FALSE,
			'install' => FALSE, 'domain_clear' => FALSE, 'save' => $o['save'], 'unbound_py_vip' => "{$dir}/pfb_py_vip",
		]);
		$GLOBALS['config'] = [];
		$GLOBALS['g']['varrun_path']          = $dir;
		$GLOBALS['g']['unbound_chroot_path']  = '/var/unbound';
		$GLOBALS['g']['pfblockerng_install']  = $o['install'];

		$gen   = 'installedpackages/pfblockerng/config/0';
		$ip    = 'installedpackages/pfblockerngipsettings/config/0';
		$dnsbl = self::DNSBL;
		foreach (['pfb_min' => '0', 'pfb_hour' => '0', 'pfb_dailystart' => '0', 'skipfeed' => '0', 'pfb_interval' => '24',
			'pfb_quiet_hours' => '', 'pfb_reuse' => '', 'enable_cb' => $o['enable'] ? 'on' : ''] as $key => $value) {
			config_set_path("{$gen}/{$key}", $value);
		}
		foreach (['suppression' => '', 'database_cc' => '', 'maxmind_locale' => 'en', 'asn_reporting' => 'disabled', 'asn_token' => '',
			'maxmind_account' => '', 'maxmind_key' => '', 'enable_dup' => '', 'enable_agg' => '', 'enable_float' => '', 'enable_log' => '',
			'killstates' => '', 'ip_placeholder' => '', 'inbound_deny_action' => '', 'outbound_deny_action' => '', 'pass_order' => '',
			'autorule_suffix' => ''] as $key => $value) {
			config_set_path("{$ip}/{$key}", $value);
		}
		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '8.8.8.8');
		config_set_path('installedpackages/pfblockerngblacklist/blacklist_enable', 'Disable');
		foreach (['enable_dedup', 'enable_pdup', 'enable_rep', 'et_update', 'ccwhite', 'ccblack', 'etblock', 'etmatch', 'p24_max_var',
			'p24_dmax_var', 'p24_pmax_var', 'ccexclude'] as $key) {
			config_set_path("installedpackages/pfblockerngreputation/config/0/{$key}", '');
		}
		foreach (['pfb_dnsvip4' => '_vipauto4', 'pfb_dnsvip6' => '', 'pfb_dnsport' => $o['ports'] ? '8081' : '',
			'pfb_dnsport_ssl' => $o['ports'] ? '8443' : '', 'top1m_enable' => '', 'top1m_count' => '', 'top1m_inclusion' => '',
			'pfb_cache' => '', 'pfb_py_reply' => '', 'pfb_regex' => '', 'pfb_regex_list' => '', 'pfb_cname' => '', 'tld_allow' => '',
			'pfb_py_nolog' => '', 'pfb_noaaaa' => '', 'pfb_noaaaa_list' => '', 'pfb_gp' => '', 'pfb_gp_bypass_list' => '',
			'pfb_dnsbl_rule' => 'on', 'tld_wildcard' => '', 'pfb_control' => '', 'whitelist' => '', 'dnsbl_allow_int' => 'lan'] as $key => $value) {
			config_set_path("{$dnsbl}/{$key}", $value);
		}
		PfbConfig::write('dnsbl/pfb_dnsbl', $o['dnsbl'] ? 'on' : '');
		PfbConfig::write('dnsbl/pfb_dnsvip_auto', 'on');
		PfbConfig::write('dnsbl/dnsbl_interface', 'opt1');
		if ($o['unbound']) {
			$GLOBALS['config']['unbound'] = ['enable' => ''];
		}
		config_set_path('installedpackages/pfblockernglistsv4/config', []);
		config_set_path('installedpackages/pfblockernglistsv6/config', []);

		// A refused connection, never a download, if a regression ever lets a full pass reach the feed.
		config_set_path('installedpackages/pfblockerngdnsbl/config', [[
			'aliasname' => 'T1', 'action' => 'unbound', 'order' => 'default', 'logging' => $o['demand'] ? 'enabled' : 'disabled_log',
			'row' => [['url' => 'http://127.0.0.1:9/list.txt', 'state' => $o['rowState'], 'header' => 'T1_a', 'format' => 'auto']],
		]]);
		config_set_path('virtualip/vip', [[
			'mode' => 'ipalias', 'interface' => 'opt1', 'type' => 'single', 'subnet' => '172.16.53.53', 'subnet_bits' => '32',
			'descr' => PFB_AUTO_VIP_DESCR_V4, 'uniqid' => 'auto4',
		]]);
		config_set_path('nat/rule', $o['served'] ? [self::USER_NAT, self::dnsblNatRow()] : [self::USER_NAT]);
		if ($o['served']) {
			file_put_contents($GLOBALS['pfb']['dnsbl_conf'], "serving\n");
			touch($GLOBALS['pfb']['dnsbl_cert']);
		}

		// The module is wired into the resolver; whether the resolver is up decides if a finished reload converged.
		file_put_contents("{$dir}/unbound.conf", "python-script: pfb_unbound.py\n");
		$GLOBALS['pfb_test_process_running']['unbound'] = self::resolverProcess($o['up']);
	}

	/** The resolver process double: never running, or running except while pfb_stop_start_unbound() restarts it (so a finished reload is converged). */
	private static function resolverProcess(bool $up): mixed
	{
		return $up
			? static function (): bool {
				foreach (debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS) as $frame) {
					if (($frame['function'] ?? '') === 'pfb_stop_start_unbound') {
						return FALSE;
					}
				}
				return TRUE;
			}
			: FALSE;
	}

	/** @return array<string,mixed> */
	private static function dnsblNatRow(): array
	{
		return [
			'source' => ['any' => ''], 'destination' => ['address' => '172.16.53.53', 'port' => '80'], 'protocol' => 'tcp',
			'target' => '127.0.0.1', 'local-port' => '8081', 'interface' => 'opt1', 'descr' => PFB_MANAGED_NAT_DESCR,
			'associated-rule-id' => 'pass', 'natreflection' => 'purenat',
		];
	}

	private function runPass(): void
	{
		// The restart branch link()s the real lighttpd binary, which the sandbox lacks.
		set_error_handler(static fn (int $no, string $message): bool => str_starts_with($message, 'link('));
		try {
			sync_package_pfblockerng();
		} finally {
			restore_error_handler();
		}
	}

	/** @return list<array<string,mixed>> */
	private function dnsblNat(): array
	{
		return array_values(array_filter(config_get_path('nat/rule', []), static fn (array $row): bool => ($row['descr'] ?? '') === PFB_MANAGED_NAT_DESCR));
	}

	/** @return list<array{string,string,bool}> */
	private function events(string $function, string $service = 'pfb_dnsbl'): array
	{
		return array_values(array_filter($this->serviceEvents, static fn (array $e): bool => $e[0] === $function && $e[1] === $service));
	}

	/** @return list<array{string,bool}> */
	private function lifecycleWrites(): array
	{
		return array_values(array_filter($this->configWrites, static fn (array $w): bool => in_array($w[0], [self::VIP_WRITE, self::NAT_WRITE], TRUE)));
	}

	private function assertServedStateIntact(): void
	{
		$this->assertSame([PFB_AUTO_VIP_DESCR_V4], array_column(config_get_path('virtualip/vip', []), 'descr'), 'the auto-VIP is still in config');
		$this->assertSame('_vipauto4', config_get_path(self::DNSBL . '/pfb_dnsvip4'), 'the stored VIP id still names it');
		$this->assertNotSame([], $this->dnsblNat(), 'the DNSBL NAT is still in config');
		$this->assertFileExists($GLOBALS['pfb']['dnsbl_conf']);
		$this->assertFileExists($GLOBALS['pfb']['dnsbl_cert']);
	}

	/**
	 * A full update pass, served web server, no group left (so no block answers with the VIP). The pass publishes the empty
	 * manifest, or fails to when $publish is FALSE (the raw generation directory cannot be staged).
	 */
	private function arrangeFullPass(bool $up, bool $publish): void
	{
		$this->arrange(['save' => FALSE, 'served' => TRUE, 'demand' => FALSE, 'up' => $up]);
		config_set_path('installedpackages/pfblockerngdnsbl/config', []);
		$this->publishTo($publish);
	}

	/** Point the manifest publication at the temp tree, or (when $publish is FALSE) at a raw directory that cannot be staged. */
	private function publishTo(bool $publish): void
	{
		$dir = $this->dir;
		$GLOBALS['pfb']['unbound_py_sources']      = "{$dir}/pfb_py_sources.json";
		$GLOBALS['pfb']['unbound_py_rawdir']       = $publish ? "{$dir}/pfb_py_raw" : "{$dir}/missing/pfb_py_raw";
		$GLOBALS['pfb']['unbound_py_top1m']        = "{$dir}/pfb_py_top1m.txt";
		$GLOBALS['pfb']['unbound_py_count']        = "{$dir}/pfb_py_count";
		$GLOBALS['pfb']['unbound_py_regex_count']  = "{$dir}/pfb_py_regex_count";
		$GLOBALS['pfb']['unbound_py_reject_stats'] = "{$dir}/pfb_py_reject_stats.json";
	}

	// ------------------------------------------------------------------------------------------
	// Generation hand-off
	// ------------------------------------------------------------------------------------------

	public function testEndedDemandTearsTheServedStateDownOnlyAfterTheNewGenerationIsLive(): void
	{
		// GIVEN a serving web server (marked VIP, NAT, conf, certificate) whose last VIP-answering group became Null Blocking,
		// and a resolver that is up
		$this->arrangeFullPass(TRUE, TRUE);
		$this->assertServedStateIntact();
		$this->assertFileDoesNotExist($GLOBALS['pfb']['unbound_py_sources'], 'before-state: no manifest published yet');

		// WHEN the apply pass runs
		$this->runPass();

		// THEN the pass published a new manifest and reloaded the resolver
		$this->assertFileExists($GLOBALS['pfb']['unbound_py_sources'], 'the pass published no manifest');
		$this->assertStringContainsString(self::RELOAD_DONE, $this->passLog());
		// AND the web server was stopped once, after that reload, and never restarted
		$stops = $this->events('stop_service');
		$this->assertCount(1, $stops, 'stop_service(pfb_dnsbl) calls');
		$this->assertTrue($stops[0][2], 'the web server was stopped before the reload finished');
		$this->assertSame([], $this->events('restart_service'));
		// AND the VIP and NAT were removed only after it as well
		$writes = $this->lifecycleWrites();
		$this->assertNotSame([], $writes, 'the teardown wrote no VIP/NAT change');
		foreach ($writes as [$description, $reloaded]) {
			$this->assertTrue($reloaded, "'{$description}' was written before the reload finished");
		}
		// AND the end state is fully torn down
		$this->assertSame([], array_column(config_get_path('virtualip/vip', []), 'descr'));
		$this->assertEmpty(config_get_path(self::DNSBL . '/pfb_dnsvip4'));
		$this->assertSame([self::USER_NAT], config_get_path('nat/rule'));
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dnsbl_conf']);
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dnsbl_cert']);
	}

	public function testEndedDemandTearsNothingDownWhileTheNewGenerationIsNotLive(): void
	{
		// GIVEN the same serving web server, but a resolver that is not running after the reload (not converged)
		$this->arrange(['served' => TRUE, 'demand' => FALSE, 'up' => FALSE]);
		$this->assertServedStateIntact();

		// WHEN the apply pass runs
		$this->runPass();

		// THEN the reload ran (the absence below is not vacuous)
		$this->assertStringContainsString(self::RELOAD_DONE, $this->passLog());
		// AND nothing was torn down, stopped, restarted or rewritten: the old generation keeps its VIP and web server
		$this->assertServedStateIntact();
		$this->assertSame([], $this->events('stop_service'));
		$this->assertSame([], $this->events('restart_service'));
		$this->assertSame([], $this->lifecycleWrites());
	}

	public function testAPassWithoutAConfTearsTheLeftOversDownAtOnce(): void
	{
		// GIVEN a save pass, no web server conf (nothing can be serving), no block answering with the VIP, a resolver that is
		// not up (no hold can be released), and a left-over DNSBL NAT rule beside the package's VIP
		$this->arrange(['save' => TRUE, 'served' => FALSE, 'demand' => FALSE, 'up' => FALSE]);
		config_set_path('nat/rule', [self::USER_NAT, self::dnsblNatRow()]);
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dnsbl_conf'], 'before-state: no conf');
		$this->assertNotSame([], $this->dnsblNat(), 'before-state: the DNSBL NAT exists');
		$this->assertNotSame([], config_get_path('virtualip/vip', []), 'before-state: the auto-VIP exists');

		// WHEN the apply pass runs
		$this->runPass();

		// THEN the pass reloaded and tore the left-overs down in the same pass: with no conf there is no generation to hold for
		$this->assertStringContainsString(self::RELOAD_DONE, $this->passLog());
		$this->assertSame([self::USER_NAT], config_get_path('nat/rule'));
		$this->assertSame([], array_column(config_get_path('virtualip/vip', []), 'descr'));
	}

	public function testASavePassWithoutAPublicationRecordKeepsHoldingEvenWhenTheResolverIsConverged(): void
	{
		// GIVEN the serving web server, no VIP demand, a resolver that is up (converged), a save pass, and no record of the
		// last published generation (an upgrade from before the record): that generation may still answer with the VIP
		$this->arrange(['save' => TRUE, 'served' => TRUE, 'demand' => FALSE, 'up' => TRUE]);
		$this->assertServedStateIntact();

		// WHEN the pass runs
		$this->runPass();

		// THEN the pass reloaded (the absence below is not vacuous) and nothing was torn down, stopped or rewritten
		$this->assertStringContainsString(self::RELOAD_DONE, $this->passLog());
		$this->assertServedStateIntact();
		$this->assertSame([], $this->events('stop_service'));
		$this->assertSame([], $this->lifecycleWrites());
	}

	public function testAFailedPublicationWithoutAPublicationRecordKeepsHoldingEvenWhenTheResolverIsConverged(): void
	{
		// GIVEN the serving web server, a full update pass whose manifest publication fails, no record of an earlier
		// generation, and a resolver that is up
		$this->arrangeFullPass(TRUE, FALSE);
		$this->assertServedStateIntact();

		// WHEN the pass runs
		$this->runPass();

		// THEN the publication did fail, and nothing was torn down, stopped or rewritten
		$this->assertTrue($GLOBALS['pfb']['dnsbl_publish_failed'], 'the manifest publication did not fail');
		$this->assertFileDoesNotExist($GLOBALS['pfb']['unbound_py_sources']);
		$this->assertServedStateIntact();
		$this->assertSame([], $this->events('stop_service'));
		$this->assertSame([], $this->lifecycleWrites());
	}

	public function testAPublishedGenerationThatIsNotLiveKeepsHolding(): void
	{
		// GIVEN the serving web server, a full update pass that publishes the empty manifest, and a resolver that is not up
		$this->arrangeFullPass(FALSE, TRUE);
		$this->assertServedStateIntact();

		// WHEN the pass runs
		$this->runPass();

		// THEN the manifest was published and the resolver reloaded, and still nothing was torn down, stopped or rewritten
		$this->assertFileExists($GLOBALS['pfb']['unbound_py_sources']);
		$this->assertStringContainsString(self::RELOAD_DONE, $this->passLog());
		$this->assertServedStateIntact();
		$this->assertSame([], $this->events('stop_service'));
		$this->assertSame([], $this->lifecycleWrites());
	}

	public function testALaterConvergedPassReleasesTheHoldOfAPublishedGenerationWithoutTheVip(): void
	{
		// GIVEN pass 1: a full pass publishes the generation without VIP answers while the resolver is not up, so it holds
		$this->arrangeFullPass(FALSE, TRUE);
		$this->runPass();
		$this->assertServedStateIntact();
		$this->assertSame([], $this->events('stop_service'), 'before-state: pass 1 held the web server');

		// WHEN pass 2 publishes nothing (a save pass) and the resolver has converged on that generation
		$GLOBALS['pfb']['save'] = TRUE;
		$GLOBALS['pfb_test_process_running']['unbound'] = self::resolverProcess(TRUE);
		$this->runPass();

		// THEN the live generation answers with no VIP, so the hold is released and the web server torn down
		$this->assertCount(1, $this->events('stop_service'), 'stop_service(pfb_dnsbl) calls');
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dnsbl_conf']);
		$this->assertSame([self::USER_NAT], config_get_path('nat/rule'));
		$this->assertSame([], array_column(config_get_path('virtualip/vip', []), 'descr'));
	}

	public function testAConvergedLaterPassKeepsHoldingWhileTheLiveGenerationAnswersWithTheVip(): void
	{
		// GIVEN pass 1: a full pass with a group answering with the VIP publishes that generation on a converged resolver
		$this->arrange(['save' => FALSE, 'served' => TRUE, 'demand' => TRUE, 'up' => TRUE]);
		$this->publishTo(TRUE);
		$this->runPass();
		$this->assertFileExists($GLOBALS['pfb']['unbound_py_sources'], 'before-state: pass 1 published the VIP generation');

		// WHEN pass 2 is a save pass after the group became Null Blocking: it publishes nothing, so the live generation is
		// still the one that answers with the VIP
		config_set_path('installedpackages/pfblockerngdnsbl/config/0/logging', 'disabled_log');
		$GLOBALS['pfb']['save'] = TRUE;
		$this->runPass();

		// THEN the web server keeps serving it
		$this->assertSame([], $this->events('stop_service'), 'pass 2 stopped the web server the live generation still needs');
		$this->assertFileExists($GLOBALS['pfb']['dnsbl_conf']);
	}

	public function testDemandKeepsServingThroughThePass(): void
	{
		// GIVEN the serving web server and a group that still answers with the VIP
		$this->arrange(['served' => TRUE, 'demand' => TRUE, 'up' => TRUE]);
		$this->assertServedStateIntact();

		// WHEN the apply pass runs
		$this->runPass();

		// THEN VIP, both port forwards and a freshly written conf are in place and the web server was not stopped
		$this->assertSame([PFB_AUTO_VIP_DESCR_V4], array_column(config_get_path('virtualip/vip', []), 'descr'));
		$this->assertSame(['80', '443'], array_map(static fn (array $row): string => $row['destination']['port'], $this->dnsblNat()));
		$this->assertSame(pfb_create_lighttpd(), file_get_contents($GLOBALS['pfb']['dnsbl_conf']));
		$this->assertFileExists($GLOBALS['pfb']['dnsbl_cert']);
		$this->assertSame([], $this->events('stop_service'));
		$this->assertNotSame([], $this->events('restart_service'), 'a changed conf restarts the web server');
	}

	// ------------------------------------------------------------------------------------------
	// Ports
	// ------------------------------------------------------------------------------------------

	public function testEmptyPortsAbortTheDnsblPassWhileABlockAnswersWithTheVip(): void
	{
		// GIVEN a full update pass, a group answering with the VIP, and no web server ports
		$this->arrange(['save' => FALSE, 'demand' => TRUE, 'ports' => FALSE]);

		// WHEN the pass runs
		$this->runPass();

		// THEN the DNSBL pass exits on the missing ports and never starts processing
		$this->assertStringContainsString(self::PORTS_ABORT, $this->passLog());
		$this->assertStringNotContainsString(self::DNSBL_PROCESSING, $this->passLog());
	}

	public function testEmptyPortsDoNotStopDnsblProcessingWithoutDemand(): void
	{
		// GIVEN a full update pass, a group with no blocking row (no VIP demand), and no web server ports
		$this->arrange(['save' => FALSE, 'demand' => FALSE, 'rowState' => 'Disabled', 'ports' => FALSE]);

		// WHEN the pass runs
		$this->runPass();

		// THEN DNSBL processing runs and the missing ports are not an error
		$this->assertStringContainsString(self::DNSBL_PROCESSING, $this->passLog());
		$this->assertStringNotContainsString(self::PORTS_ABORT, $this->passLog());
	}

	// ------------------------------------------------------------------------------------------
	// Port alias and floating rules
	// ------------------------------------------------------------------------------------------

	/** @return array<string,array{bool}> */
	public static function demandRows(): array
	{
		return ['a block answers with the VIP' => [TRUE], 'no block answers with the VIP' => [FALSE]];
	}

	#[DataProvider('demandRows')]
	public function testPortsAliasAndFloatingRulesExistOnlyWhileABlockAnswersWithTheVip(bool $demand): void
	{
		// GIVEN DNSBL with ports, an allowed interface, DNSBL floating rules on, and a group that does / does not answer with the VIP
		$this->arrange(['demand' => $demand]);

		// WHEN the apply pass runs
		$this->runPass();

		// THEN the DNSBL port alias and the ping + permit floating rules exist exactly when demand does
		$this->assertPortsAliasAndFloatingRules($demand, $demand ? 'demand' : 'no demand');
	}

	private function assertPortsAliasAndFloatingRules(bool $present, string $when): void
	{
		$aliases = array_column(config_get_path('aliases/alias', []), 'name');
		$rules   = array_column(config_get_path('filter/rule', []), 'descr');
		$this->assertSame($present, in_array('pfB_DNSBL_Ports', $aliases, TRUE), "{$when}: pfB_DNSBL_Ports alias: " . json_encode($aliases));
		$this->assertSame($present, in_array('pfB_DNSBL_Ping auto rule', $rules, TRUE), "{$when}: ping rule: " . json_encode($rules));
		$this->assertSame($present, in_array('pfB_DNSBL_Permit auto rule', $rules, TRUE), "{$when}: permit rule: " . json_encode($rules));
	}

	public function testPortsAliasAndFloatingRulesStayWhileTheServedGenerationIsHeldAndGoOnceItIsReleased(): void
	{
		// GIVEN pass 1: a serving web server and a group answering with the VIP -- the alias and both rules are written
		$this->arrange(['save' => TRUE, 'served' => TRUE, 'demand' => TRUE, 'up' => TRUE]);
		$this->runPass();
		$this->assertPortsAliasAndFloatingRules(TRUE, 'before-state, pass 1 with demand');

		// WHEN pass 2 finds the demand ended but the resolver is not converged: the old generation still answers with the VIP
		config_set_path('installedpackages/pfblockerngdnsbl/config/0/logging', 'disabled_log');
		$GLOBALS['pfb_test_process_running']['unbound'] = self::resolverProcess(FALSE);
		$this->runPass();

		// THEN the web server is held and so are the alias and rules that let clients reach it
		$this->assertFileExists($GLOBALS['pfb']['dnsbl_conf'], 'pass 2 did not hold the web server');
		$this->assertSame([], $this->events('stop_service'), 'pass 2 stopped the web server');
		$this->assertPortsAliasAndFloatingRules(TRUE, 'pass 2, demand ended and the resolver not converged');

		// WHEN pass 3 publishes the new generation and the resolver converges
		config_set_path('installedpackages/pfblockerngdnsbl/config', []);
		$GLOBALS['pfb']['save'] = FALSE;
		$this->publishTo(TRUE);
		$GLOBALS['pfb_test_process_running']['unbound'] = self::resolverProcess(TRUE);
		$this->runPass();

		// THEN the hold is released: the web server is torn down and the alias and rules are gone with it
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dnsbl_conf'], 'pass 3 did not release the hold');
		$this->assertPortsAliasAndFloatingRules(FALSE, 'pass 3, converged publish');
	}

	// ------------------------------------------------------------------------------------------
	// Boot / install resync
	// ------------------------------------------------------------------------------------------

	/** @return array<string,array{array<string,bool>,bool}> */
	public static function bootRows(): array
	{
		return [
			'package on, DNSBL on, resolver on' => [[], TRUE],
			'package off' => [['enable' => FALSE], FALSE],
			'DNSBL off' => [['dnsbl' => FALSE], FALSE],
			'resolver off' => [['unbound' => FALSE], FALSE],
		];
	}

	/** @param array<string,bool> $state */
	#[DataProvider('bootRows')]
	public function testBootResyncServesOnlyForAnEnabledPackageWithDnsblAndTheResolverOnAndOtherwiseTearsDownALeftOverServedState(array $state, bool $serves): void
	{
		// GIVEN the boot/install resync, a group answering with the VIP, and -- unless the web server may serve -- the
		// served state an older version left behind (conf, certificate, NAT, marked auto-VIP)
		$this->arrange($state + ['install' => TRUE, 'demand' => TRUE, 'served' => !$serves]);
		$this->assertCount($serves ? 0 : 1, $this->dnsblNat(), 'before-state: the DNSBL NAT is left over exactly when nothing may serve');
		$this->assertSame(!$serves, file_exists($GLOBALS['pfb']['dnsbl_conf']), 'before-state: the conf is left over exactly when nothing may serve');

		// WHEN the resync runs
		$this->runPass();

		// THEN the pass took the boot/install branch
		$this->assertStringContainsString('Sync terminated during boot process.', $this->passLog());
		// AND package, DNSBL and resolver all on serve (conf and NAT) -- anything else leaves no conf, certificate or NAT
		$this->assertCount($serves ? 2 : 0, $this->dnsblNat(), 'DNSBL NAT');
		$this->assertSame($serves, file_exists($GLOBALS['pfb']['dnsbl_conf']), 'web server conf');
		$this->assertSame($serves, file_exists($GLOBALS['pfb']['dnsbl_cert']), 'web server certificate');
		// AND the web server was stopped and the auto-VIP removed exactly when nothing may serve
		$this->assertCount($serves ? 0 : 1, $this->events('stop_service'), 'stop_service(pfb_dnsbl) calls');
		$this->assertSame($serves ? [PFB_AUTO_VIP_DESCR_V4] : [], array_column(config_get_path('virtualip/vip', []), 'descr'), 'auto-VIP');
	}

	public function testBootResyncLeavesAServingWebServerAloneWhileTheOnDiskGenerationMayStillAnswerWithTheVip(): void
	{
		// GIVEN the boot/install resync with a serving web server (its conf is on disk) whose demand ended while the box was off
		$this->arrange(['install' => TRUE, 'served' => TRUE, 'demand' => FALSE]);
		$this->assertServedStateIntact();

		// WHEN the resync runs
		$this->runPass();

		// THEN the pass took the boot branch and left VIP, NAT, conf and certificate alone: the next publishing pass tears down
		$this->assertStringContainsString('Sync terminated during boot process.', $this->passLog());
		$this->assertServedStateIntact();
		$this->assertSame([], $this->events('stop_service'));
		$this->assertSame([], $this->lifecycleWrites());
	}

	public function testBootResyncWithoutAConfRunsTheDemandRule(): void
	{
		// GIVEN the boot/install resync, no web server conf (nothing can be serving), no block answering with the VIP,
		// and a left-over DNSBL NAT rule beside the package's VIP
		$this->arrange(['install' => TRUE, 'served' => FALSE, 'demand' => FALSE]);
		config_set_path('nat/rule', [self::USER_NAT, self::dnsblNatRow()]);
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dnsbl_conf'], 'before-state: no conf');
		$this->assertNotSame([], $this->dnsblNat(), 'before-state: the DNSBL NAT exists');

		// WHEN the resync runs
		$this->runPass();

		// THEN the demand rule applied: the NAT and the package's VIP are gone
		$this->assertSame([self::USER_NAT], config_get_path('nat/rule'));
		$this->assertSame([], array_column(config_get_path('virtualip/vip', []), 'descr'));
	}

	public function testAnUnusableHeaderDoesNotServeButANormalizableHeaderAndAliasDo(): void
	{
		$this->arrange(['demand' => TRUE]);
		config_set_path('installedpackages/pfblockerngdnsbl/config/0/row/0/header', '!!!');
		$this->runPass();
		$this->assertSame('', config_get_path('installedpackages/pfblockerngdnsbl/config/0/row/0/header'), 'apply strips header punctuation');
		$this->assertFalse($GLOBALS['pfb']['dnsbl_vip_demand'], 'no consumable feed row');
		$this->assertFileDoesNotExist($GLOBALS['pfb']['dnsbl_conf']);

		config_set_path('installedpackages/pfblockerngdnsbl/config/0/aliasname', '!!!');
		config_set_path('installedpackages/pfblockerngdnsbl/config/0/row/0/header', 'T1-a!');
		$this->runPass();
		$this->assertSame('', config_get_path('installedpackages/pfblockerngdnsbl/config/0/aliasname'), 'apply permits the empty alias suffix of DNSBL_');
		$this->assertSame('T1a', config_get_path('installedpackages/pfblockerngdnsbl/config/0/row/0/header'));
		$this->assertTrue($GLOBALS['pfb']['dnsbl_vip_demand'], 'the normalized feed header is consumable');
		$this->assertFileExists($GLOBALS['pfb']['dnsbl_conf']);
	}

	public function testAReservedDnsblipRowIsLoadedToTheVipAndKeepsTheVipServing(): void
	{
		// GIVEN a full update pass whose only feed row carries the reserved DNSBLIP header: the resolver still loads that row
		// and logs it to the VIP, so the row must demand the VIP and a live web server exactly as any other header does
		$this->arrange(['save' => FALSE, 'demand' => TRUE]);
		$this->publishTo(TRUE);
		$feed = "{$this->dir}/dnsblip-feed.txt";
		file_put_contents($feed, "reservedprobe3539.example.com\n");
		config_set_path('installedpackages/pfblockerngdnsbl/config/0/row/0/url', $feed);
		config_set_path('installedpackages/pfblockerngdnsbl/config/0/row/0/header', 'DNSBLIP');

		// WHEN the apply pass runs
		$this->runPass();

		// THEN the manifest carries the DNSBLIP row as a feed that logs to the VIP
		$feeds   = json_decode((string) @file_get_contents($GLOBALS['pfb']['unbound_py_sources']), TRUE)['feeds'] ?? [];
		$dnsblip = array_values(array_filter($feeds, static fn (array $f): bool => ($f['feed'] ?? '') === 'DNSBLIP'));
		$this->assertCount(1, $dnsblip, 'the manifest carries the DNSBLIP feed');
		$this->assertSame('1', $dnsblip[0]['log_flag'] ?? NULL, 'the DNSBLIP feed logs to the VIP');
		// AND the row demands the VIP, so the marked auto-VIP, both port forwards and a live conf and certificate are in place
		$this->assertTrue($GLOBALS['pfb']['dnsbl_vip_demand'], 'the DNSBLIP row does not demand the VIP');
		$this->assertSame([PFB_AUTO_VIP_DESCR_V4], array_column(config_get_path('virtualip/vip', []), 'descr'));
		$this->assertSame(['80', '443'], array_map(static fn (array $row): string => $row['destination']['port'], $this->dnsblNat()));
		$this->assertFileExists($GLOBALS['pfb']['dnsbl_conf']);
		$this->assertFileExists($GLOBALS['pfb']['dnsbl_cert']);
	}

	public function testBootTeardownRemovesTheMarkedAutoVipAndKeepsAManualVipAtTheSameAddress(): void
	{
		// GIVEN the boot/install resync with the package off (nothing may serve), the served state an older version left behind,
		// and a manual VIP at the auto-VIP's address, listed first so a delete that ignores the marker would take it
		$this->arrange(['install' => TRUE, 'enable' => FALSE, 'demand' => TRUE, 'served' => TRUE]);
		config_set_path('virtualip/vip', array_merge([[
			'mode' => 'ipalias', 'interface' => 'opt1', 'type' => 'single', 'subnet' => '172.16.53.53', 'subnet_bits' => '32',
			'descr' => 'manual VIP', 'uniqid' => 'manual4',
		]], config_get_path('virtualip/vip', [])));
		$this->assertSame(['manual VIP', PFB_AUTO_VIP_DESCR_V4], array_column(config_get_path('virtualip/vip', []), 'descr'), 'before-state');

		// WHEN the resync runs
		$this->runPass();

		// THEN the pass took the boot branch, and only the marked auto-VIP is removed: the manual VIP stays at its address
		$this->assertStringContainsString('Sync terminated during boot process.', $this->passLog());
		$this->assertSame(['manual VIP' => '172.16.53.53'], array_column(config_get_path('virtualip/vip', []), 'subnet', 'descr'));
	}
}
