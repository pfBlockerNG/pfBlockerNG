<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyReadySeedTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3770 -- DNSBL runs only through pfB-DNS, so the only host of the DNSBL module is the DNS proxy while it owns the Resolver
 * and DNSBL is on. Unbound is never asked: not by the liveness predicate, the convergence verdict, the zero-downtime swap, nor the
 * tick retry -- whatever its process, its unbound.conf or the python keys in config.xml still say. Every "not hosted" row starts
 * from a legacy box that really runs Unbound with pfb_unbound.py wired (process up, conf and config.xml naming it), so a verdict
 * that still consults Unbound would answer the opposite and fail it. The texts say where DNSBL runs when pfB-DNS does not.
 */
#[CoversFunction('pfb_unbound_py_host_running')]
#[CoversFunction('pfb_dnsbl_converged')]
#[CoversFunction('pfb_dnsbl_apply_ledger_update')]
#[CoversFunction('pfb_dnsbl_apply_retry')]
#[CoversFunction('pfb_reload_unbound')]
#[CoversFunction('pfb_dns_proxy_unmoved_effect')]
#[CoversFunction('pfb_dns_status')]
final class DnsblHostIsPfbDnsOnlyTest extends TestCase
{
	use DnsProxyReadySeedTrait;

	private const PROXY_PIDFILE = '/var/run/pfb_dns_proxy.pid';
	private const SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';
	private const LEGACY_CONF = "server:\n\tmodule-config: \"python validator iterator\"\n\npython:\npython-script: pfb_unbound.py\n";

	private string $dir;
	private array $savedGlobals = [];

	protected function setUp(): void
	{
		foreach (['pfb', 'config', 'g'] as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$this->dir = sys_get_temp_dir() . '/pfb_dnsbl_host_pfbdns_' . getmypid() . '_' . uniqid();
		mkdir("{$this->dir}/dnsdir", 0777, TRUE);

		$GLOBALS['pfb'] = array_replace($GLOBALS['pfb'] ?? [], [
			'dnsbldir' => $this->dir,
			'dbdir' => $this->dir,
			'dnsbl_file' => "{$this->dir}/pfb_dnsbl",
			'dnsdir' => "{$this->dir}/dnsdir",
			'dnsbl_cache' => "{$this->dir}/pfb_py_cache.sqlite",
			'unbound_py_count' => "{$this->dir}/pfb_py_count",
			'unbound_py_sources' => "{$this->dir}/pfb_py_sources.json",
			'unbound_py_rawdir' => "{$this->dir}/pfb_py_raw",
			'unbound_py_reject_stats' => "{$this->dir}/pfb_py_reject_stats.json",
			'chroot_cmd' => '/bin/echo',
			'dnsbl_python_unmount' => FALSE,

			'dnsbl_cache_flush' => PfbToggle::Off,
			'enable' => PfbToggle::On,
			'dnsbl' => PfbToggle::On,
			'pfb_dns' => PfbToggle::On,	// requested: DNSBL runs only while pfB-DNS is on, so "not hosted" rows are about ownership, not the switch
			'unbound_state' => PfbToggle::On,
			'save' => TRUE,
			'dnsbl_tld_wildcard' => FALSE,
			'domain_update' => FALSE,
			'reuse_dnsbl' => '',
			'dnsbl_unlock' => "{$this->dir}/dnsbl_unlock",
			'keep' => PfbToggle::On,
			'install' => FALSE,
			'errlog' => "{$this->dir}/error.log",
			'log' => "{$this->dir}/pfblockerng.log",
			'php' => PHP_BINARY,
		]);
		$GLOBALS['config'] = [];
		$GLOBALS['g']['varrun_path'] = $this->dir;
		$GLOBALS['pfb_test_process_running'] = ['unbound' => FALSE];
		$GLOBALS['pfb_test_valid_pids'] = [];
		$GLOBALS['pfb_test_file_notices'] = [];
	}

	protected function tearDown(): void
	{
		$this->clearProxyFiles();
		foreach ($this->savedGlobals as $name => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
		$this->savedGlobals = [];
		unset(
			$GLOBALS['pfb_test_process_running'],
			$GLOBALS['pfb_test_valid_pids'],
			$GLOBALS['pfb_test_file_notices'],
			$GLOBALS['pfb_test_unbound_py_sentinel_published'],
			$GLOBALS['pfb_test_service_hook']
		);
		rmdir_recursive($this->dir);
	}

	/** config.xml as a pfB-DNS-On apply leaves it: a valid Resolver snapshot, so the proxy owns the Resolver. */
	private function pfbDnsOwnsTheResolver(): void
	{
		$keys = [];
		foreach (['active_interface' => 'lan', 'enablessl' => NULL, 'custom_options' => NULL] as $key => $value) {
			$keys[$key] = ['present' => $value !== NULL, 'value' => $value];
		}
		config_set_path(self::SAVED, base64_encode((string) json_encode($keys)));
	}

	/** A box as it was before this change: Unbound runs and loads pfb_unbound.py (process, unbound.conf and config.xml). */
	private function legacyUnboundLoadsTheModule(): void
	{
		$GLOBALS['config']['unbound'] = ['enable' => '', 'python' => 'on', 'python_script' => 'pfb_unbound'];
		file_put_contents("{$this->dir}/unbound.conf", self::LEGACY_CONF);
		$GLOBALS['pfb_test_process_running']['unbound'] = TRUE;
	}

	private function setProxyUp(bool $up): void
	{
		$GLOBALS['pfb_test_valid_pids'][self::PROXY_PIDFILE] = $up;
	}

	private function writeGenerations(int $sentinel, int $applied): void
	{
		file_put_contents("{$this->dir}/pfb_py_reload", "{$sentinel}\n");
		file_put_contents("{$this->dir}/pfb_py_reload.applied", "{$applied}\n");
	}

	private function sentinel(): int
	{
		return pfb_unbound_py_marker_generation("{$this->dir}/pfb_py_reload");
	}

	/** Unbound answers "up" everywhere except inside its own stop/start, which the double models as a clean restart. */
	private function unboundUpExceptDuringRestart(): void
	{
		$GLOBALS['pfb_test_process_running']['unbound'] = static function (): bool {
			foreach (debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS) as $frame) {
				if (($frame['function'] ?? '') === 'pfb_stop_start_unbound') {
					return FALSE;
				}
			}
			return TRUE;
		};
	}

	/** @return list<array<string,string>> the open DNSBL apply entries */
	private function openApplyEntries(): array
	{
		return pfb_sync_status_list_open($this->dir, 'dnsbl');
	}

	// -----------------------------------------------------------------------
	// The host predicates: pfB-DNS only
	// -----------------------------------------------------------------------

	/** @return array<string, array{bool}> proxy pid valid */
	public static function proxyPidRows(): array
	{
		return ['a dead proxy pid' => [FALSE], 'a stale live proxy pid that pfB-DNS does not own the Resolver for' => [TRUE]];
	}

	#[DataProvider('proxyPidRows')]
	public function testAnUnboundLoadingThePythonModuleIsNotAHostWhenPfbDnsDoesNotOwnTheResolver(bool $proxyUp): void
	{
		// Given DNSBL on, a legacy Unbound that is up with pfb_unbound.py wired, current generations, and no pfB-DNS ownership
		$this->legacyUnboundLoadsTheModule();
		$this->writeGenerations(3, 3);
		$this->setProxyUp($proxyUp);

		// Then nothing hosts the module: not live, not converged, and the apply entry says why
		$this->assertFalse(pfb_unbound_py_host_running(), 'Unbound is never the module host');
		$this->assertFalse(pfb_dnsbl_converged(), 'a wired, running Unbound does not converge DNSBL');
		$this->assertFalse(pfb_dnsbl_apply_ledger_update());
		$open = $this->openApplyEntries();
		$this->assertCount(1, $open);
		$this->assertStringContainsString('DNSBL is not blocking', $open[0]['message']);
		$this->assertStringContainsString('pfB-DNS is not active yet', $open[0]['message']);
		$this->assertStringContainsString('pfB-DNS status', $open[0]['message']);
		$this->assertStringNotContainsString('DNS > pfB-DNS', $open[0]['message'], 'pfB-DNS is already requested: no instruction to turn it on');
		$this->assertStringNotContainsString('pfb_unbound.py', $open[0]['message'], 'no word of an Unbound-hosted module');
	}

	public function testTheProxyOwningTheResolverWithDnsblOnAndRunningConvergesWhateverUnboundIs(): void
	{
		// Given pfB-DNS owning the Resolver, DNSBL on, the proxy up, and an Unbound that is down with a conf without the module
		$this->pfbDnsOwnsTheResolver();
		$this->writeGenerations(3, 3);
		$this->setProxyUp(TRUE);
		file_put_contents("{$this->dir}/unbound.conf", "server:\n\tmodule-config: \"validator iterator\"\n");

		// Then the proxy is the live host and DNSBL converges, closing the apply entry
		$this->assertTrue(pfb_unbound_py_host_running());
		$this->assertTrue(pfb_dnsbl_converged());
		$this->assertTrue(pfb_dnsbl_apply_ledger_update());
		$this->assertSame([], $this->openApplyEntries());
	}

	public function testAProxyThatOwnsTheResolverButIsDownKeepsTheProxyNamingMessageWhateverUnboundIs(): void
	{
		// Given pfB-DNS owning the Resolver with DNSBL on, the proxy down, and a legacy Unbound up and wired
		$this->pfbDnsOwnsTheResolver();
		$this->legacyUnboundLoadsTheModule();
		$this->writeGenerations(3, 3);
		$this->setProxyUp(FALSE);

		// Then it is not live nor converged, and the entry names the proxy, not the missing ownership
		$this->assertFalse(pfb_unbound_py_host_running());
		$this->assertFalse(pfb_dnsbl_apply_ledger_update());
		$open = $this->openApplyEntries();
		$this->assertCount(1, $open);
		$this->assertStringContainsString('the DNS proxy is not fully live', $open[0]['message']);
		$this->assertStringNotContainsString('pfB-DNS is not active', $open[0]['message']);
	}

	// -----------------------------------------------------------------------
	// The zero-downtime swap and the tick retry never target Unbound
	// -----------------------------------------------------------------------

	public function testADataUpdateTakesNoZeroDowntimeSwapWhenPfbDnsDoesNotHostEvenWithAnUnboundWiredToThePythonModule(): void
	{
		// Given DNSBL on, no pfB-DNS ownership, a legacy Unbound up with pfb_unbound.py in config.xml and unbound.conf, and a
		// watcher double that would apply any generation published
		file_put_contents($GLOBALS['pfb']['unbound_py_count'], "10\n");
		file_put_contents($GLOBALS['pfb']['unbound_py_sources'], '{"version":1,"config":{},"feeds":[]}');
		file_put_contents($GLOBALS['pfb']['unbound_py_reject_stats'], '[]');
		$this->legacyUnboundLoadsTheModule();
		$this->unboundUpExceptDuringRestart();
		$GLOBALS['pfb_test_unbound_py_sentinel_published'] = static function (string $path, int $generation): void {
			file_put_contents("{$path}.applied", "{$generation}\n");
		};
		$log = (string) $GLOBALS['pfb_test_unbound_start_log'];
		$starts = file_exists($log) ? count(file($log, FILE_IGNORE_NEW_LINES) ?: []) : 0;

		// When a data-only update reloads the Resolver
		pfb_reload_unbound('enabled', FALSE, TRUE);

		// Then no generation was published for an Unbound that does not host the module, and the restart path ran
		$this->assertFileDoesNotExist("{$this->dir}/pfb_py_reload", 'the sentinel was not flipped');
		$this->assertGreaterThan($starts, file_exists($log) ? count(file($log, FILE_IGNORE_NEW_LINES) ?: []) : 0, 'the restart path ran');
	}

	/** @return array<string, array{bool, int}> pfB-DNS owns the Resolver (the proxy is up), expected sentinel after the retry */
	public static function applyRetryRows(): array
	{
		return [
			'pfB-DNS hosts and runs: the stuck swap is re-published' => [TRUE, 6],
			'a legacy Unbound up and wired, no pfB-DNS: nothing hosts the module' => [FALSE, 5],
		];
	}

	#[DataProvider('applyRetryRows')]
	public function testTheTickRetryRepublishesTheSentinelOnlyForAHostingProxy(bool $owned, int $expected): void
	{
		$this->legacyUnboundLoadsTheModule();
		if ($owned) {
			$this->pfbDnsOwnsTheResolver();
			$this->setProxyUp(TRUE);
		}
		$this->writeGenerations(5, 3);

		pfb_dnsbl_apply_retry();

		$this->assertSame($expected, $this->sentinel());
	}

	// -----------------------------------------------------------------------
	// The texts: where DNSBL runs when pfB-DNS does not
	// -----------------------------------------------------------------------

	/** @return array<string, array{bool}> the saved copy of the Resolver's settings is invalid (recovery required) */
	public static function unmovedEffectRows(): array
	{
		return [
			'the Resolver is unchanged' => [FALSE],
			'recovery is required (an invalid saved copy)' => [TRUE],
		];
	}

	#[DataProvider('unmovedEffectRows')]
	public function testAnUnmovedTakeoverSaysDnsblDoesNotBlockWhenDnsblIsOn(bool $recovery): void
	{
		if ($recovery) {
			config_set_path(self::SAVED, '!!!truncated-snapshot!!!');
		}

		$on = pfb_dns_proxy_unmoved_effect(FALSE);

		$this->assertStringContainsString('DNSBL does not block until pfB-DNS is active', $on);
		$this->assertStringNotContainsString('DNS Resolver as before', $on, 'Unbound no longer hosts DNSBL');

		// And with DNSBL off the text says nothing about DNSBL
		$GLOBALS['pfb']['dnsbl'] = PfbToggle::Off;
		$off = pfb_dns_proxy_unmoved_effect(FALSE);
		$this->assertStringNotContainsString('DNSBL', $off);
		$this->assertStringContainsString('pfB-DNS is not active', $off);
	}

	public function testTheStatusOfAPfbDnsThatIsOnButNotMovedSaysDnsblDoesNotBlockWhenDnsblIsOn(): void
	{
		// Given pfB-DNS on, pfBlockerNG and the Resolver enabled, and nothing moved
		$GLOBALS['pfb']['pfb_dns'] = PfbToggle::On;

		$on = pfb_dns_status()['mode'];

		$this->assertStringContainsString('On, not active: the DNS Resolver has not been moved to the proxy', $on);
		$this->assertStringContainsString('DNSBL does not block until pfB-DNS is active', $on);
		$this->assertStringNotContainsString('with DNSBL if that is on', $on, 'the Resolver no longer serves DNSBL itself');

		// And with DNSBL off the status says nothing about DNSBL
		$GLOBALS['pfb']['dnsbl'] = PfbToggle::Off;
		$off = pfb_dns_status()['mode'];
		$this->assertStringContainsString('It serves clients itself', $off);
		$this->assertStringNotContainsString('DNSBL', $off);
	}
}
