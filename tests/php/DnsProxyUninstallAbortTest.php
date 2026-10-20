<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyCertificateFixtures.php';

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/support/ProcessRunner.php';

/**
 * issue #3515 -- a package removal must stop while pfB-DNS still holds the Resolver, and stopping must leave pfB-DNS working.
 *
 * When the Resolver cannot be put back (another config save holds the lock, config.xml cannot be re-read, or the proxy
 * outlived its stop), the Resolver stays moved and its snapshot is the only way back. The rest of the removal destroys
 * the recovery path: the pending-changes marker, the generated files and (Keep Settings off) the whole package config,
 * snapshot included, and pkg then deletes the proxy and observer code the moved Resolver depends on.
 *
 * pfSense ignores what the hook returns (rc.packages runs it through eval_once() and exits 0), and pkg(8) only logs a
 * failed DEINSTALL script and removes the files anyway; the one status that makes pkg abandon the removal is 3
 * (libpkg pkg_script_run_child()). So the hook returns FALSE and the package XML exits with PFB_PKG_REMOVAL_ABORT.
 *
 * But pfSense's delete_package_xml() has already done its own half of the removal when the hook starts, and persisted it:
 * it stopped each registered service (the DNS proxy, the DNSBL web server, the filter daemon), unlinked their rc scripts and
 * deleted their registrations and the menu entry. Aborting then leaves the package installed with the Resolver pointing
 * at a stopped proxy, nothing registered that could start it, and a retry that can never succeed (it finds no registered
 * service to stop, so the proxy survives its stop and the removal aborts again). So an abort also puts back what pfSense
 * took: the registrations (next to every other package's, never twice), the rc scripts, the running proxy in the mode
 * config.xml stores (not the uninstall's "pfBlockerNG is off" view), and only the other services config.xml says run.
 *
 * Each case runs the shipped hook in a private child process (support/PackageRemovalWorker.php) through the XML text that
 * pfSense evaluates, after a port of pfSense's own pre-hook half, and observes what survives ON DISK. The `none` case
 * proves the observations can fail: with the Resolver restored the same removal destroys them. The staged observer
 * files are removed by `pfblockerng.sh dnsbl_cache teardown`, an absolute path that cannot be sandboxed here: it comes
 * after the pending-changes clear this test observes.
 */
final class DnsProxyUninstallAbortTest extends TestCase
{
	/** The status pkg(8) treats as "stop, leave the package installed". */
	private const PKG_ABORT = 3;

	/** What the package registers, next to the two services of other packages the worker seeds. */
	private const OURS = ['pfb_dnsbl', 'pfb_dns_proxy', 'pfb_filter'];
	private const THEIRS = ['squid', 'zeek'];

	/** @var list<string> */
	private array $dirs = [];

	protected function tearDown(): void
	{
		foreach ($this->dirs as $dir) {
			rmdir_recursive($dir);
		}
		$this->dirs = [];
	}

	/**
	 * @param array<string,mixed> $scenario extra worker scenario keys: stored, permanent, unmigratedPolicy, lockAfterMove, marker and interface (a Resolver pfB-DNS never moved beside that stored marker), state (a directory a second run continues from)
	 * @return array{returned:bool,snapshot:bool,marker:string,interface:?string,sections:list<string>,services:list<string>,menus:list<string>,foreign:bool,pending:bool,dbCanary:bool,logCanary:bool,rawFeed:bool,manifest:bool,rcScript:bool,rcSameAsBaseline:bool,noModule:bool,iniSameAsBaseline:bool,ini:string,running:list<string>,events:list<string>,lockHeld:bool,notices:list<string>,writes:list<string>,exit:int,state:string}
	 */
	private function removal(string $failure, string $keep, array $scenario = []): array
	{
		$dir = sys_get_temp_dir() . '/pfb_removal_abort_' . bin2hex(random_bytes(6));
		mkdir($dir, 0700, TRUE);
		$this->dirs[] = $dir;
		$result = "{$dir}/result.json";
		$state = $scenario['state'] ?? "{$dir}/state";
		@mkdir($state, 0700, TRUE);
		$process = pfb_test_run_process([
			PHP_BINARY, __DIR__ . '/support/PackageRemovalWorker.php',
			(string) json_encode(['failure' => $failure, 'keep' => $keep, 'state' => $state, 'certificate' => DnsProxyCertificateFixtures::shared()] + $scenario), $result,
		], 120.0);
		$this->assertFileExists($result, "the worker reported nothing (exit {$process['exit']}): {$process['stderr']}");
		return ['exit' => $process['exit'], 'state' => $state]
			+ json_decode((string) file_get_contents($result), TRUE, 512, JSON_THROW_ON_ERROR);
	}

	/** @return array{rc:string,ini:string} what the last apply left behind while pfB-DNS served: the removal's before-state */
	private function baseline(string $state): array
	{
		return json_decode((string) file_get_contents("{$state}/baseline.json"), TRUE, 8, JSON_THROW_ON_ERROR);
	}

	/** @return array<string,array{string,string}> */
	public static function unrestorableResolver(): array
	{
		$cases = [];
		foreach (['lock' => 'config.xml is locked by another save', 'read' => 'config.xml cannot be re-read', 'survivor' => 'the proxy outlived its stop'] as $failure => $why) {
			foreach (['on' => 'Keep Settings on', 'off' => 'Keep Settings off'] as $keep => $label) {
				$cases["{$why}, {$label}"] = [$failure, $keep];
			}
		}
		return $cases;
	}

	#[DataProvider('unrestorableResolver')]
	public function testRemovalStopsWithPkgsAbortStatusAndKeepsEverythingTheMovedResolverNeeds(string $failure, string $keep): void
	{
		$removal = $this->removal($failure, $keep);

		$this->assertSame(self::PKG_ABORT, $removal['exit'], 'the package hook exits with the one status that makes pkg abandon the removal');
		$this->assertFalse($removal['returned'], 'and never returns into the rest of the removal');
		$this->assertTrue($removal['snapshot'], 'the Resolver snapshot is kept');
		$this->assertSame('lo0', $removal['interface'], 'the Resolver is untouched: still moved');
		$this->assertContains('pfblockerngdns', $removal['sections'], 'the section holding the snapshot is not wiped');
		$this->assertContains('pfblockerngipsettings', $removal['sections'], 'nor any other package section');
		$this->assertTrue($removal['pending'], 'the pending-changes marker, the first thing the teardown clears, is still there');
		$this->assertTrue($removal['dbCanary'], 'the package data directory is kept');
		$this->assertTrue($removal['logCanary'], 'so is the log directory');
		$this->assertTrue($removal['manifest'], 'so is the DNSBL manifest the proxy loads its blocklists from when it starts again');
		$this->assertTrue($removal['rawFeed'], 'and the raw feed the proxy reads its blocklists from, which the disable pass would tear down');
		$this->assertTrue($removal['rcScript'], 'the proxy\'s rc script is kept');
		$this->assertFalse($removal['lockHeld'], 'no config lock is left held');
		$this->assertNotSame([], array_filter($removal['notices'], static fn (string $notice): bool => str_contains($notice, 'removal was stopped')
			&& str_contains($notice, 'remove the package again')), 'the operator is told the removal stopped and what to do: ' . json_encode($removal['notices']));
	}

	#[DataProvider('unrestorableResolver')]
	public function testAbortPutsBackTheRegistrationPfSenseDeletedBeforeTheHookNextToEveryOtherPackages(string $failure, string $keep): void
	{
		$removal = $this->removal($failure, $keep);

		$this->assertSame(self::PKG_ABORT, $removal['exit'], 'before: the removal aborted');
		$services = $removal['services'];
		sort($services);
		$this->assertSame(['pfb_dns_proxy', 'pfb_dnsbl', 'pfb_filter', 'squid', 'zeek'], $services,
			'the package\'s three services are registered again, once each, and the other packages\' are all still there: ' . json_encode($removal['services']));
		$this->assertSame(1, count(array_keys($removal['menus'], 'Firewall:pfBlockerNG', TRUE)), 'its menu entry is back, once: ' . json_encode($removal['menus']));
		$this->assertTrue($removal['foreign'], 'another package\'s service and menu entry are untouched, field for field');
	}

	#[DataProvider('unrestorableResolver')]
	public function testAbortRestartsTheProxyThroughItsRegisteredServiceInTheModeConfigXmlStores(string $failure, string $keep): void
	{
		$removal = $this->removal($failure, $keep);

		$baseline = $this->baseline($removal['state']);
		$this->assertStringNotContainsString('--no-module', $baseline['rc'], 'before: pfB-DNS served with the DNSBL module');
		$this->assertSame(self::PKG_ABORT, $removal['exit'], 'before: the removal aborted');

		$this->assertContains('pfb_dns_proxy', $removal['running'], 'the proxy that answers the moved Resolver\'s clients is running');
		$starts = array_values(array_filter($removal['events'], static fn (string $event): bool => str_starts_with($event, 'start:pfb_dns_proxy')));
		$this->assertSame('start:pfb_dns_proxy', end($starts), 'the last start went through pfSense\'s service handler and found the proxy registered (the removal\'s own restart before the '
			. 'registration is ignored, which is the defect): ' . json_encode($removal['events']));
		$this->assertFalse($removal['noModule'], 'it hosts the DNSBL module config.xml says is on, not the uninstall\'s "pfBlockerNG is off" view');
		$this->assertTrue($removal['rcSameAsBaseline'], 'its rc script is the one the last apply wrote');
		$this->assertTrue($removal['iniSameAsBaseline'], 'and the module\'s ini is the one the last apply wrote: VIP and client logging as they were');
		$this->assertStringContainsString("dnsbl_ipv4\t= 10.10.10.1", $removal['ini'], 'the DNSBL VIP');
		$this->assertStringContainsString("python_reply\t= on", $removal['ini'], 'DNS reply logging');
	}

	#[DataProvider('unrestorableResolver')]
	public function testAbortStartsTheOtherServicesConfigXmlSaysRunAndTellsTheOperatorWhatWasRestored(string $failure, string $keep): void
	{
		$removal = $this->removal($failure, $keep);

		$this->assertSame(self::PKG_ABORT, $removal['exit'], 'before: the removal aborted');
		$this->assertContains('pfb_filter', $removal['running'], 'the filter daemon: pfBlockerNG is enabled');
		$this->assertContains('pfb_dnsbl', $removal['running'], 'the DNSBL web server: DNSBL is enabled');
		$this->assertEqualsCanonicalizing(['pfb_dns_proxy', 'pfb_filter', 'pfb_dnsbl', 'squid', 'zeek'], $removal['running'], 'and nothing else comes up');
		$this->assertNotSame([], array_filter($removal['notices'], static fn (string $notice): bool => str_contains($notice, 'removal was stopped')
			&& str_contains($notice, 'service entries were registered again') && str_contains($notice, 'DNS proxy is running')),
			'the notice says the removal stopped and that the registrations and the proxy are back: ' . json_encode($removal['notices']));
	}

	public function testAbortWritesTheModulesIniAgainFromTheStoredSettingsWhenItIsGone(): void
	{
		$removal = $this->removal('lock', 'on', ['iniGone' => TRUE]);

		$baseline = $this->baseline($removal['state']);
		$this->assertStringContainsString("python_control\t= on", $baseline['ini'], 'before: the module\'s control integration is on in config.xml');
		$this->assertStringContainsString("decisiondb_max\t= 777", $baseline['ini'], 'before: the decision cache cap the apply wrote');
		$this->assertSame(self::PKG_ABORT, $removal['exit'], 'before: the removal aborted');

		$this->assertTrue($removal['iniSameAsBaseline'], 'the ini is written again with what config.xml stores: VIP, logging and control as they were');
		$this->assertStringContainsString("python_enable\t= on", $removal['ini'], 'with the module enabled, not the removal\'s disabled view');
		$this->assertStringContainsString("dnsbl_ipv4\t= 10.10.10.1", $removal['ini']);
		$this->assertStringContainsString("decisiondb_max\t= 777", $removal['ini'], 'and the recovery writes that cap, not the default');
	}

	#[DataProvider('unrestorableResolver')]
	public function testAbortNeverStartsAnRcScriptBehindPfSensesBack(string $failure, string $keep): void
	{
		$removal = $this->removal($failure, $keep);

		$this->assertSame(self::PKG_ABORT, $removal['exit'], 'before: the removal aborted');
		$this->assertSame([], array_filter($removal['events'], static fn (string $event): bool => str_starts_with($event, 'direct start:')),
			'nothing is started by running its rc script: a proxy no registration can stop is one a retry can never remove');
	}

	/** @return array<string,array{string,list<string>}> */
	public static function whatConfigXmlSaysIsOn(): array
	{
		return [
			'DNSBL off: the proxy only forwards, there is no web server to start'            => ['dnsbl_off', ['pfb_dns_proxy', 'pfb_filter']],
			'pfBlockerNG off: the moved Resolver is still served, nothing else is started'   => ['disabled', ['pfb_dns_proxy']],
		];
	}

	/** @param list<string> $started */
	#[DataProvider('whatConfigXmlSaysIsOn')]
	public function testAbortStartsOnlyWhatTheStoredSettingsRequire(string $stored, array $started): void
	{
		$removal = $this->removal('lock', 'on', ['stored' => $stored]);

		$this->assertSame(self::PKG_ABORT, $removal['exit'], 'before: the removal aborted');
		$this->assertEqualsCanonicalizing(array_merge($started, self::THEIRS), $removal['running'], 'exactly the services the stored settings need run: ' . json_encode($removal['events']));
		$this->assertTrue($removal['noModule'], 'the proxy forwards only: DNSBL is not on in config.xml');
		$this->assertNotContains('start:pfb_dnsbl', $removal['events'], 'the DNSBL web server is not started');
		$this->assertEqualsCanonicalizing(array_merge(self::OURS, self::THEIRS), $removal['services'], 'the registrations come back whatever is on');
	}

	/** @return array<string,array{string}> */
	public static function recoveryThatCannotRun(): array
	{
		return ['config.xml stays locked' => ['lock'], 'config.xml stays unreadable' => ['read']];
	}

	#[DataProvider('recoveryThatCannotRun')]
	public function testAbortThatCannotRegisterTheServicesAgainSaysSoAndKeepsEveryFile(string $failure): void
	{
		$removal = $this->removal($failure, 'on', ['permanent' => TRUE]);

		$this->assertSame(self::PKG_ABORT, $removal['exit'], 'the removal still stops');
		$this->assertSame(self::THEIRS, $removal['services'], 'nothing was written into config.xml: the registrations stay as pfSense left them');
		$this->assertTrue($removal['foreign'], 'and the other packages\' entries are intact');
		$this->assertTrue($removal['snapshot'], 'the Resolver snapshot is kept');
		$this->assertTrue($removal['rcScript'], 'the proxy\'s rc script is back, so the operator can start it by hand');
		$this->assertTrue($removal['manifest'], 'the DNSBL manifest is kept');
		$this->assertNotContains('pfb_dns_proxy', $removal['running'], 'the proxy is not started behind a registration nothing can stop it through');
		$this->assertFalse($removal['lockHeld'], 'no config lock is left held');
		$text = implode("\n", $removal['notices']);
		$this->assertStringContainsString('could not be registered again', $text, 'the operator is told the recovery did not complete');
		$this->assertStringContainsString("{$removal['state']}/rc.d/pfb_dns_proxy.sh start", $text, 'and how to start the proxy by hand: its rc script, which is back');
		$this->assertStringNotContainsString('DNS proxy is running', $text, 'and is never told it is running');
	}

	public function testARecoveryThatThrowsStillStopsTheRemovalWithPkgsAbortStatus(): void
	{
		// An uncaught error would exit pkg's DEINSTALL script with a status other than 3, and pkg then deletes the package
		// files under the moved Resolver: the one thing the abort exists to prevent.
		$removal = $this->removal('lock', 'on', ['startThrows' => TRUE]);

		$this->assertSame(self::PKG_ABORT, $removal['exit'], 'the package hook still exits with the abort status');
		$this->assertFalse($removal['returned']);
		$this->assertTrue($removal['snapshot'], 'the Resolver snapshot is kept');
		$this->assertTrue($removal['manifest'], 'with the files');
		$this->assertFalse($removal['lockHeld'], 'and no config lock held');
		$text = implode("\n", $removal['notices']);
		$this->assertStringContainsString('start exploded', $text, 'the operator is told what stopped the recovery');
		$this->assertStringNotContainsString('DNS proxy is running', $text, 'and is never told the proxy is running');
	}

	public function testAbortWhoseProxyNeverComesUpDoesNotClaimItIsRunning(): void
	{
		$removal = $this->removal('lock', 'on', ['proxyWontStart' => TRUE]);

		$this->assertSame(self::PKG_ABORT, $removal['exit'], 'the removal still stops');
		$this->assertContains('start:pfb_dns_proxy', $removal['events'], 'the proxy was started through its registration');
		$this->assertNotContains('pfb_dns_proxy', $removal['running'], 'but nothing serves');
		$this->assertContains('pfb_dns_proxy', $removal['services'], 'the registration stays: a retry can stop whatever does come up');
		$text = implode("\n", $removal['notices']);
		$this->assertStringContainsString('the DNS proxy did not become ready', $text, 'the operator is told so');
		$this->assertStringContainsString("{$removal['state']}/rc.d/pfb_dns_proxy.sh start", $text, 'and how to start it by hand');
		$this->assertStringNotContainsString('DNS proxy is running', $text, 'and is never told it is running');
	}

	/** @return list<string> the worker's write_config() descriptions, the order the removal changed config.xml in */
	private function writes(array $removal): array
	{
		return array_map(static fn (string $write): string => str_replace('pfBlockerNG: ', '', $write), $removal['writes']);
	}

	/** @return array<string,array{mixed}> pfSense's write_config() answers for a write it did not make: FALSE (refused), -1 (config.xml not written) */
	public static function refusedWrites(): array
	{
		return ['the write is refused' => [FALSE], 'config.xml could not be written' => [-1]];
	}

	#[DataProvider('refusedWrites')]
	public function testARestoreThatConfigXmlDoesNotTakeStopsTheRemovalAndLeavesTheProxyServingTheMovedResolver(mixed $answer): void
	{
		// Given pfB-DNS serving with the DNSBL VIP, and a config.xml that does not take the write that puts the Resolver back
		$removal = $this->removal('none', 'on', ['refuseWrite' => ['match' => 'Restored the DNS Resolver', 'answer' => $answer]]);

		// When the removal runs: the restore is tried first, and refused
		$writes = $this->writes($removal);
		$this->assertContains('Restored the DNS Resolver settings the DNS proxy had moved', $writes, 'before: the restore was attempted: ' . json_encode($writes));

		// Then the removal stops with pkg's abort status, as for any Resolver that cannot be put back
		$this->assertSame(self::PKG_ABORT, $removal['exit'], 'the package hook exits with the one status that makes pkg abandon the removal: ' . json_encode($removal['notices']));
		$this->assertFalse($removal['returned'], 'and never returns into the rest of the removal');

		// ... config.xml still holds the moved Resolver and its snapshot, and nothing the proxy needs was torn down
		$this->assertTrue($removal['snapshot'], 'the Resolver snapshot is still stored');
		$this->assertSame('lo0', $removal['interface'], 'and the Resolver is still moved');
		$this->assertContains('pfblockerngdns', $removal['sections'], 'the section holding the snapshot is not wiped');
		$this->assertContains('pfblockerngipsettings', $removal['sections'], 'nor any other package section');
		$this->assertTrue($removal['pending'], 'the pending-changes marker is still there');
		$this->assertTrue($removal['manifest'], 'so is the DNSBL manifest the proxy loads its blocklists from');
		$this->assertTrue($removal['rawFeed'], 'and the raw feed');
		$this->assertTrue($removal['rcScript'], 'the proxy\'s rc script is kept');
		$this->assertFalse($removal['noModule'], 'and it hosts the DNSBL module, as the last apply wrote it');

		// ... the proxy answers, through the registration the abort put back
		$this->assertContains('pfb_dns_proxy', $removal['running'], 'the proxy that answers the moved Resolver\'s clients is running');
		$services = $removal['services'];
		sort($services);
		$this->assertSame(['pfb_dns_proxy', 'pfb_dnsbl', 'pfb_filter', 'squid', 'zeek'], $services, 'the package\'s services are registered again, once each: ' . json_encode($removal['services']));
		$this->assertFalse($removal['lockHeld'], 'no config lock is left held');

		// ... and the operator is told why the Resolver was not put back, and that the removal stopped
		$text = implode("\n", $removal['notices']);
		$this->assertStringContainsString('could not be written', $text, 'the DNS proxy notice names the refused write');
		$this->assertNotSame([], array_filter($removal['notices'], static fn (string $notice): bool => str_contains($notice, 'removal was stopped')
			&& str_contains($notice, 'remove the package again')), 'the removal notice says what to do: ' . json_encode($removal['notices']));
	}

	public function testARemovalThatStoppedOnARefusedRestoreFinishesOnceConfigXmlTakesTheWrite(): void
	{
		// Given a removal that stopped because config.xml did not take the restore's write
		$aborted = $this->removal('none', 'on', ['refuseWrite' => ['match' => 'Restored the DNS Resolver', 'answer' => FALSE]]);
		$this->assertSame(self::PKG_ABORT, $aborted['exit'], 'before: the removal stopped');
		$this->assertTrue($aborted['snapshot'], 'before: the snapshot is stored, so a retry has something to restore from');

		// When the operator removes the package again and config.xml takes the write
		$retry = $this->removal('none', 'on', ['state' => $aborted['state']]);

		// Then the removal goes through and the Resolver is back on the user's interfaces
		$this->assertSame(0, $retry['exit'], 'the retry removes the package: ' . json_encode($retry['notices']));
		$this->assertFalse($retry['snapshot']);
		$this->assertSame('lan,opt1', $retry['interface']);
		$this->assertSame(self::THEIRS, $retry['services']);
		$this->assertSame([], $retry['notices']);
	}

	/**
	 * The Resolver can be moved AGAIN inside the disable pass: the pass reads the DNSBL logging policy, which no apply has migrated
	 * yet, and the upgrade's pfb_global() re-reads enable_cb, turning the uninstall's disable off for the rest of the pass, so
	 * pfB-DNS is wanted again. This is the one way the restore after the pass has work to do.
	 */
	public function testRemovalWhosePassMovedTheResolverAgainStillGivesItBack(): void
	{
		$removal = $this->removal('none', 'on', ['unmigratedPolicy' => TRUE]);

		$writes = $this->writes($removal);
		$restored = array_search('Restored the DNS Resolver settings the DNS proxy had moved', $writes, TRUE);
		$moved = array_search('Moved the DNS Resolver onto loopback for the DNS proxy', $writes, TRUE);
		$this->assertNotFalse($restored, 'before: the restore ahead of the pass put the Resolver back: ' . json_encode($writes));
		$this->assertNotFalse($moved, 'before: the pass moved the Resolver again: ' . json_encode($writes));
		$this->assertLessThan($moved, $restored, 'in that order');

		$this->assertSame(0, $removal['exit'], 'the removal goes ahead: ' . json_encode($removal['notices']));
		$this->assertFalse($removal['snapshot'], 'nothing is left moved');
		$this->assertSame('lan,opt1', $removal['interface'], 'the Resolver is back on the user\'s interfaces');
		$this->assertSame(self::THEIRS, $removal['services'], 'and only other packages\' services remain registered');
		$this->assertEqualsCanonicalizing(self::THEIRS, $removal['running'], 'nothing of the package runs');
	}

	public function testAbortAfterThePassMovedTheResolverAgainKeepsPfbDnsFilteringWhenTheRestoreAfterItIsRefused(): void
	{
		// Given pfB-DNS serving with the DNSBL VIP, a DNSBL policy no apply has migrated, and another save that takes the config
		// lock the moment the disable pass moved the Resolver again, and holds it until the recovery announces itself.
		$removal = $this->removal('none', 'on', ['unmigratedPolicy' => TRUE, 'lockAfterMove' => TRUE]);

		// When the removal runs: the restore ahead of the pass succeeds, the pass moves the Resolver again, the restore after the pass is refused.
		$baseline = $this->baseline($removal['state']);
		$this->assertStringContainsString("dnsbl_ipv4\t= 10.10.10.1", $baseline['ini'], 'before: the DNSBL VIP is the blocking mechanism');
		$writes = $this->writes($removal);
		$restored = array_search('Restored the DNS Resolver settings the DNS proxy had moved', $writes, TRUE);
		$moved = array_search('Moved the DNS Resolver onto loopback for the DNS proxy', $writes, TRUE);
		$registered = array_search('registered the package menu and services again after an aborted removal', $writes, TRUE);
		$this->assertNotFalse($restored, 'before: the first restore put the Resolver back: ' . json_encode($writes));
		$this->assertNotFalse($moved, 'before: the pass moved the Resolver again: ' . json_encode($writes));
		$this->assertLessThan($moved, $restored, 'in that order');
		$this->assertSame(self::PKG_ABORT, $removal['exit'], 'the removal stops');
		$this->assertFalse($removal['returned']);
		$this->assertNotFalse($registered, 'and the recovery wrote the registrations back: ' . json_encode($writes));
		$this->assertLessThan($registered, $moved, 'after the pass');

		// Then the proxy answers the Resolver it holds, with the module and the lists it loads them from.
		$this->assertTrue($removal['snapshot'], 'the Resolver snapshot is kept');
		$this->assertSame('lo0', $removal['interface'], 'the Resolver is still moved to the proxy');
		$this->assertTrue($removal['manifest'], 'the DNSBL manifest the proxy loads is kept');
		$this->assertTrue($removal['rawFeed'], 'and the raw feed');
		$this->assertTrue($removal['rcScript'], 'the proxy\'s rc script is there');
		$this->assertFalse($removal['noModule'], 'and hosts the DNSBL module');
		$this->assertTrue($removal['rcSameAsBaseline'], 'exactly as the last apply wrote it');
		$this->assertTrue($removal['iniSameAsBaseline'], 'with the module\'s ini of the last apply: VIP and logging as they were');
		$this->assertContains('pfb_dns_proxy', $removal['running'], 'the proxy runs');
		$this->assertContains('pfb_dnsbl', $removal['running'], 'with the DNSBL web server');
		$services = $removal['services'];
		sort($services);
		$this->assertSame(['pfb_dns_proxy', 'pfb_dnsbl', 'pfb_filter', 'squid', 'zeek'], $services, 'the package\'s three services are registered again');
		$this->assertFalse($removal['lockHeld'], 'no config lock is left held');
		$this->assertNotSame([], array_filter($removal['notices'], static fn (string $notice): bool => str_contains($notice, 'removal was stopped')
			&& str_contains($notice, 'service entries were registered again') && str_contains($notice, 'DNS proxy is running')),
			'the operator is told the removal stopped and that the proxy is back: ' . json_encode($removal['notices']));
	}

	/** @return array<string,array{string}> */
	public static function keepSettings(): array
	{
		return ['Keep Settings on' => ['on'], 'Keep Settings off' => ['off']];
	}

	#[DataProvider('keepSettings')]
	public function testRemovalOfARestorableResolverStillTearsDownAndExitsCleanly(string $keep): void
	{
		$removal = $this->removal('none', $keep);

		$this->assertSame(0, $removal['exit'], 'a removal that restored the Resolver is not aborted');
		$this->assertTrue($removal['returned']);
		$this->assertFalse($removal['snapshot'], 'the snapshot was used and cleared');
		$this->assertNotSame('lo0', $removal['interface'], 'the Resolver is back on the user\'s interfaces');
		$this->assertFalse($removal['pending'], 'the teardown ran: the pending-changes marker is cleared');
		$this->assertFalse($removal['rcScript'], 'the proxy\'s rc script is removed');
		$this->assertFalse($removal['manifest'], 'and the DNSBL manifest, which nothing hosts any more');
		$this->assertFalse($removal['rawFeed'], 'and the raw feed it was read from');
		$this->assertSame($keep === 'on', $removal['dbCanary'], 'the data directory goes only with Keep Settings off');
		$this->assertSame($keep === 'on', $removal['logCanary'], 'so does the log directory');
		$this->assertSame($keep === 'on', in_array('pfblockerngipsettings', $removal['sections'], TRUE), 'and the package config sections');
		$this->assertSame(self::THEIRS, $removal['services'], 'pfSense\'s deletion of the package\'s registrations stands: only other packages\' remain');
		$this->assertSame([], array_filter($removal['menus'], static fn (string $menu): bool => str_contains($menu, 'pfBlockerNG')), 'and its menu entry');
		$this->assertEqualsCanonicalizing(self::THEIRS, $removal['running'], 'nothing of the package runs');
		$this->assertSame([], array_filter($removal['events'], static fn (string $event): bool => str_starts_with($event, 'start:') && !str_ends_with($event, ':ignored')),
			'and nothing was started: a start aimed at an unregistered service is ignored by pfSense and is not one');
		$this->assertSame([], $removal['notices'], 'no notice: nothing went wrong');
	}

	/** @return array<string,array{string,string}> a stored marker that is no snapshot, and the Keep Settings choice */
	public static function unconfirmedMarkers(): array
	{
		$cases = [];
		foreach (['the single character 0' => '0', 'the text of an interrupted write' => '!!!truncated-snapshot!!!'] as $label => $marker) {
			foreach (['on' => 'Keep Settings on', 'off' => 'Keep Settings off'] as $keep => $choice) {
				$cases["{$label}, {$choice}"] = [$marker, $keep];
			}
		}
		return $cases;
	}

	#[DataProvider('unconfirmedMarkers')]
	public function testRemovalStopsWhenTheSavedStateCannotBeConfirmedAndErasesNeitherTheMarkerNorTheSettings(string $marker, string $keep): void
	{
		// Given a Resolver pfB-DNS was never shown to have moved (no block of ours) and a stored marker that is no snapshot
		$removal = $this->removal('none', $keep, ['marker' => $marker]);

		// Then the removal stops with pkg's abort status before anything is torn down, and the marker is exactly as stored
		$this->assertSame(self::PKG_ABORT, $removal['exit'], 'the package hook exits with the one status that makes pkg abandon the removal');
		$this->assertFalse($removal['returned'], 'and never returns into the rest of the removal');
		$this->assertSame($marker, $removal['marker'], 'the stored marker is kept verbatim, Keep Settings or not');
		$this->assertSame('lo0', $removal['interface'], 'the Resolver is untouched');
		$this->assertContains('pfblockerngdns', $removal['sections'], 'the section holding the marker is not wiped');
		$this->assertContains('pfblockerngipsettings', $removal['sections'], 'nor any other package section');
		$this->assertTrue($removal['pending'], 'the pending-changes marker, the first thing the teardown clears, is still there');
		$this->assertTrue($removal['dbCanary'], 'the package data directory is kept');
		$this->assertTrue($removal['rawFeed'], 'and the raw feed the disable pass would tear down');
		$this->assertTrue($removal['rcScript'], 'the proxy\'s rc script is kept');
		$texts = array_filter($removal['notices'], static fn (string $notice): bool => str_contains($notice, 'removal was stopped'));
		$this->assertNotSame([], $texts, 'the operator is told the removal stopped: ' . json_encode($removal['notices']));
		foreach ($texts as $text) {
			$this->assertStringContainsString('cannot be confirmed', $text);
			$this->assertStringNotContainsString('the DNS proxy is running', $text);
		}
	}

	#[DataProvider('keepSettings')]
	public function testRemovalOfALoopbackOnlyResolverWithAnEmptyMarkerStillGoesThrough(string $keep): void
	{
		// Given a Resolver that has always sat on loopback: no block of ours and an empty marker
		$removal = $this->removal('none', $keep, ['marker' => '']);

		// Then nothing was moved, so the removal is not stopped and tears down as for any Resolver
		$this->assertSame(0, $removal['exit'], 'a removal with nothing to restore is not aborted: ' . json_encode($removal['notices']));
		$this->assertTrue($removal['returned']);
		$this->assertSame('', $removal['marker']);
		$this->assertFalse($removal['pending'], 'the teardown ran: the pending-changes marker is cleared');
		$this->assertFalse($removal['rcScript'], 'the proxy\'s rc script is removed');
		$this->assertSame($keep === 'on', in_array('pfblockerngipsettings', $removal['sections'], TRUE), 'the package config sections go only with Keep Settings off');
	}

	public function testRetryAfterTheLockIsReleasedRemovesThePackageForRealAndGivesTheResolverBack(): void
	{
		// Given pfB-DNS serving with the DNSBL VIP and client logging, and a removal that aborted on a locked config.xml.
		$aborted = $this->removal('lock', 'on');
		$state = $aborted['state'];
		$baseline = $this->baseline($state);
		$this->assertStringContainsString("dnsbl_ipv4\t= 10.10.10.1", $baseline['ini'], 'before: the DNSBL VIP is the blocking mechanism');
		$this->assertStringContainsString("python_reply\t= on", $baseline['ini'], 'before: clients\' DNS replies are logged');
		$this->assertSame(self::PKG_ABORT, $aborted['exit'], 'the first removal aborted');
		$this->assertContains('pfb_dns_proxy', $aborted['running'], 'and left the proxy answering');
		$this->assertTrue($aborted['iniSameAsBaseline'], 'with the VIP blocking mechanism and the logging as they were');
		$this->assertTrue($aborted['rcSameAsBaseline']);

		// When the operator removes the package again, the lock now free.
		$retry = $this->removal('none', 'on', ['state' => $state]);

		// Then the removal succeeds: pfSense stops the proxy through the registration the abort put back, the Resolver is
		// restored, and what pfSense deletes this time stays deleted.
		$this->assertContains('stop:pfb_dns_proxy', $retry['events'], 'pfSense found the proxy registered and stopped it');
		$this->assertSame(0, $retry['exit'], 'the retry removes the package: ' . json_encode($retry['notices']));
		$this->assertTrue($retry['returned']);
		$this->assertFalse($retry['snapshot']);
		$this->assertSame('lan,opt1', $retry['interface'], 'the Resolver is back on the user\'s interfaces');
		$this->assertNotContains('pfb_dns_proxy', $retry['running']);
		$this->assertFalse($retry['rcScript']);
		$this->assertSame(self::THEIRS, $retry['services']);
		$this->assertSame([], $retry['notices']);
	}
}
