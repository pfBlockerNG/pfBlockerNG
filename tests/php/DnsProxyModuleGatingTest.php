<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyCertificateFixtures.php';
require_once __DIR__ . '/ConfigXmlDiskTrait.php';

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- while the experimental DNS proxy is on, the proxy hosts pfb_unbound.py and Unbound runs only the inert
 * observer; every path that turns the proxy off (toggle, the setup wizard's reset, the package's own uninstall pass) hands the
 * Resolver back exactly as it was. issue #3770 -- the proxy is the only host: Unbound never loads pfb_unbound.py, proxy on or
 * off (UnboundNeverHostsDnsblModuleTest holds the every-mode matrix).
 *
 * Seams under test: pfb_unbound_python() (config.xml python keys + the Resolver move),
 * pfb_unbound_dnsbl() (the unbound.conf patch), the wizard's reset step and the apply pass's
 * mode computation. The moved state is seeded by hand in the restore rows, so they pin the documented snapshot format and not just the writer's own round trip.
 *
 * Both seams follow the EFFECTIVE takeover (a valid moved-Resolver snapshot), never the requested toggle: while the
 * snapshot exists Unbound runs the observer; a takeover that does not happen (move refused, config.xml locked or unreadable)
 * leaves Unbound with no pfBlockerNG python at all, with a notice that says pfB-DNS is not active, and DNSBL off gives Unbound nothing.
 */
final class DnsProxyModuleGatingTest extends TestCase
{
	use ConfigXmlDiskTrait;

	private const BLOCK = "server:\n# pfBlockerNG DNS proxy\nport: 5354\ninterface: 127.0.0.1@5353\ninterface: ::1@5353\n"
		. "proxy-protocol-port: 5353\nedns-buffer-size: 1432\n# end pfBlockerNG DNS proxy";
	private const SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';
	private const DNSBL = 'installedpackages/pfblockerngdnsblsettings/config/0';
	private const PFB_DNS = 'installedpackages/pfblockerngdns/config/0';

	private string $tmp;
	private bool $hadPfb = FALSE;
	private bool $hadConfig = FALSE;
	private bool $hadG = FALSE;
	private array $originalPfb = [];
	private array $originalConfig = [];
	private array $originalG = [];

	protected function setUp(): void
	{
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->hadConfig = array_key_exists('config', $GLOBALS);
		$this->hadG = array_key_exists('g', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		$this->originalConfig = $GLOBALS['config'] ?? [];
		$this->originalG = $GLOBALS['g'] ?? [];
		$GLOBALS['config'] = [];
		$GLOBALS['g']['unbound_chroot_path'] = '/var/unbound';
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_unbound_configure_calls'] = [];
		$GLOBALS['pfb_test_unbound_configure_resolver'] = [];
		$GLOBALS['pfb_test_file_notices'] = [];
		$this->tmp = sys_get_temp_dir() . '/pfb_dns_proxy_gate_' . uniqid('', TRUE);
		mkdir($this->tmp, 0777, TRUE);
		$GLOBALS['pfb'] = array_merge($this->originalPfb, [
			'logdir'          => $this->tmp,
			'log'             => "{$this->tmp}/pfb.log",
			'errlog'          => "{$this->tmp}/pfb.err",
			'dnsbldir'        => $this->tmp,
			'unbound_py_conf' => "{$this->tmp}/pfb_unbound.ini",
			'unbound_py_wh'   => "{$this->tmp}/pfb_whitelist.txt",
			'unbound_py_sources' => "{$this->tmp}/pfb_sources.json",
		]);
		unset($GLOBALS['pfb']['dnsbl_python_unmount']);
		$this->useMountState(TRUE);
		$this->seedPackageConfig(FALSE);
		DnsProxyCertificateFixtures::seedResolver($this->tmp);
	}

	protected function tearDown(): void
	{
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		if ($this->hadConfig) {
			$GLOBALS['config'] = $this->originalConfig;
		} else {
			unset($GLOBALS['config']);
		}
		if ($this->hadG) {
			$GLOBALS['g'] = $this->originalG;
		} else {
			unset($GLOBALS['g']);
		}
		unset($GLOBALS['pfb_test_write_config_calls'], $GLOBALS['pfb_test_unbound_configure_calls'], $GLOBALS['pfb_test_unbound_configure_resolver'],
			$GLOBALS['pfb_test_valid_pids'], $GLOBALS['pfb_test_file_notices'], $GLOBALS['pfb_test_try_lock_fail'], $GLOBALS['pfb_test_lock_held'],
			$GLOBALS['pfb_test_config_read_fails'], $GLOBALS['pfb_test_write_config_hook'], $GLOBALS['pfb_test_write_config_result'],
			$GLOBALS['pfb_test_config_read_hook'], $GLOBALS['pfb_test_config_read_calls'], $GLOBALS['pfb_test_config_read_lock_held']);
		rmdir_recursive($this->tmp);
	}

	/** Answers the mount probe pfb_unbound_python() runs: "already mounted", or "nothing mounted". */
	private function useMountState(bool $mounted): void
	{
		$out = $mounted ? "printf '%s\\n' mounted" : 'exit 0';
		file_put_contents("{$this->tmp}/grep_double", "#!/bin/sh\n{$out}\n");
		chmod("{$this->tmp}/grep_double", 0755);
		$GLOBALS['pfb']['grep'] = "{$this->tmp}/grep_double";
	}

	private function seedPackageConfig(bool $proxy): void
	{
		PfbConfig::writeSectionSystem('installedpackages/pfblockerng/config/0', [
			'pfb_min' => '0', 'pfb_hour' => '0', 'pfb_dailystart' => '0', 'skipfeed' => '0', 'enable_cb' => 'on',
		]);
		PfbConfig::writeSectionSystem('installedpackages/pfblockerngipsettings/config/0', [
			'suppression' => '', 'database_cc' => '', 'asn_token' => '', 'maxmind_account' => '',
			'maxmind_key' => '', 'maxmind_locale' => 'en', 'asn_reporting' => 'disabled',
		]);
		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '8.8.8.8');
		PfbConfig::writeSectionSystem(self::DNSBL, [
			'pfb_dnsvip4' => '', 'pfb_dnsvip6' => '', 'pfb_dnsport' => '8081', 'pfb_dnsport_ssl' => '8443',
			'top1m_enable' => '', 'pfb_py_reply' => '', 'pfb_regex' => '', 'pfb_regex_list' => '',
			'pfb_cname' => '', 'tld_allow' => '', 'tld_wildcard' => '',
			'pfb_gp' => '', 'pfb_gp_bypass_list' => '', 'whitelist' => '', 'pfb_py_nolog' => '', 'pfb_noaaaa' => '', 'pfb_noaaaa_list' => '',
			'pfb_dnsbl' => '', 'pfb_dnsvip_auto' => '', 'dnsbl_interface' => 'lo0',
		]);
		PfbConfig::writeSectionSystem(self::PFB_DNS, ['pfb_dns' => $proxy ? 'on' : '']);
		$GLOBALS['pfb']['dnsbl_tld_wildcard'] = '';
		$GLOBALS['pfb']['dnsbl_control'] = PfbToggle::Off;
		$GLOBALS['pfb']['dnsbl_control_legacy'] = PfbToggle::Off;
	}

	private function setProxy(bool $on): void
	{
		PfbConfig::writeSystem('dns/pfb_dns', $on ? PfbToggle::On : PfbToggle::Off);
	}

	/** The user's Resolver before the proxy touched it: DoT on, two LAN interfaces, own options. */
	private static function originalResolver(): array
	{
		return [
			'enable'           => '',
			'dnssec'           => '',
			'sslcertref'       => 'cert123',
			'tlsport'          => '853',
			'port'             => '53',
			'active_interface' => 'lan,opt1',
			'enablessl'        => '',
			'custom_options'   => base64_encode("do-ip6: no\nprefetch: yes"),
		];
	}

	/** The same Resolver as the proxy leaves it: still on port 53, on loopback, our block appended. */
	private static function movedResolver(): array
	{
		$moved = self::originalResolver();
		$moved['active_interface'] = 'lo0';
		unset($moved['enablessl']);
		$moved['custom_options'] = base64_encode("do-ip6: no\nprefetch: yes\n" . self::BLOCK);
		return $moved;
	}

	private static function snapshotOfOriginal(): string
	{
		$original = self::originalResolver();
		$keys = [];
		foreach (['active_interface', 'enablessl', 'custom_options'] as $key) {
			$keys[$key] = ['present' => TRUE, 'value' => $original[$key]];
		}
		return base64_encode((string) json_encode($keys));
	}

	/** Seed config.xml exactly as a proxy-On apply leaves it: moved Resolver, marker, no python keys. */
	private function seedMovedResolver(): void
	{
		$GLOBALS['config']['unbound'] = self::movedResolver();
		config_set_path(self::SAVED, self::snapshotOfOriginal());
	}

	/** The marker as stored (raw leaf: the on-disk location is part of the contract), '' when absent. */
	private function savedRaw(): string
	{
		return (string) config_get_path(self::SAVED, '');
	}

	private static function sorted(array $unbound): array
	{
		ksort($unbound);
		return $unbound;
	}

	/** @param array<string,string> $extra keys the restored Resolver legitimately gains on top of the original */
	private function assertResolverRestored(string $why, array $extra = []): void
	{
		$this->assertSame(self::sorted(self::originalResolver() + $extra), self::sorted(config_get_path('unbound')), $why);
		$this->assertSame('', $this->savedRaw(), "{$why}: marker cleared");
	}

	private function pythonModuleKeysSet(): bool
	{
		return config_path_enabled('unbound', 'python')
			&& config_get_path('unbound/python_script') === 'pfb_unbound'
			&& config_get_path('unbound/python_order') === 'pre_validator';
	}

	private function configureCalls(): array
	{
		return $GLOBALS['pfb_test_unbound_configure_calls'] ?? [];
	}

	/** The `unbound` section as config.xml held it when services_unbound_configure() ran (exactly once). */
	private function resolverWhenConfigured(): array
	{
		$seen = $GLOBALS['pfb_test_unbound_configure_resolver'] ?? [];
		$this->assertCount(1, $seen, 'unbound.conf regenerated exactly once');
		return $seen[0];
	}

	private function pfbLog(): string
	{
		return (string) @file_get_contents($GLOBALS['pfb']['log']);
	}

	// -----------------------------------------------------------------------
	// G1 -- pfB-DNS off: Unbound is given no python and the Resolver is left alone
	// -----------------------------------------------------------------------

	public function testPfbDnsOffGivesUnboundNoPythonAndLeavesTheResolverAlone(): void
	{
		// Given pfB-DNS off and a Resolver without python.
		$GLOBALS['config']['unbound'] = self::originalResolver();
		$this->assertFalse(config_path_enabled('unbound', 'python'), 'before: no python keys');

		// When DNSBL is applied.
		pfb_unbound_python('enabled');

		// Then Unbound is not given the DNSBL module (the proxy is its only host), the Resolver is untouched and nothing regenerated unbound.conf.
		$this->assertFalse(config_path_enabled('unbound', 'python'));
		$this->assertFalse($this->pythonModuleKeysSet());
		$this->assertSame(self::sorted(self::originalResolver()), self::sorted(config_get_path('unbound')));
		$this->assertSame('', $this->savedRaw());
		$this->assertSame([], $this->configureCalls());
	}

	// -----------------------------------------------------------------------
	// G2 -- proxy on: module out of Unbound, Resolver moved
	// -----------------------------------------------------------------------

	public function testProxyOnKeepsTheModuleOutOfUnboundMovesTheResolverAndRegeneratesOnce(): void
	{
		// Given the proxy on and a Resolver that still loads the module.
		$this->setProxy(TRUE);
		$GLOBALS['config']['unbound'] = self::originalResolver() + [
			'python' => '', 'python_order' => 'pre_validator', 'python_script' => 'pfb_unbound',
		];
		$this->assertTrue($this->pythonModuleKeysSet(), 'before: the module is in Unbound');
		$this->assertNotSame('lo0', config_get_path('unbound/active_interface'), 'before: the Resolver is not moved');

		// When DNSBL is applied.
		$changed = pfb_unbound_python('enabled');

		// Then a restart is signalled, the module keys are gone and the Resolver is moved ...
		$this->assertTrue($changed);
		$this->assertFalse($this->pythonModuleKeysSet(), 'Unbound does not load the module the proxy hosts');
		$this->assertSame('pfb_upstream_observer', config_get_path('unbound/python_script'), 'it runs the inert observer instead');
		$this->assertSame('53', config_get_path('unbound/port'), 'the listen port stays: the firewall resolves through it');
		$this->assertSame('lo0', config_get_path('unbound/active_interface'));
		$this->assertNotSame('', $this->savedRaw());

		// ... unbound.conf is regenerated from config.xml exactly once, without restarting DHCP ...
		$this->assertSame([FALSE], $this->configureCalls());
		$this->assertSame('lo0', $this->resolverWhenConfigured()['active_interface'], 'unbound.conf is rendered from the moved Resolver');
		$this->assertSame('pfb_upstream_observer', $this->resolverWhenConfigured()['python_script'], 'with the module keys already out');

		// ... and the module's own inputs are still produced, because the proxy loads the module from them.
		$this->assertFileExists($GLOBALS['pfb']['unbound_py_conf']);
		$this->assertFileExists($GLOBALS['pfb']['unbound_py_wh']);
	}

	public function testProxyOnTakesUnboundsPythonSlotForTheObserverAsTheModuleDoes(): void
	{
		// Given the proxy on and a Resolver running the admin's own python module.
		$this->setProxy(TRUE);
		$GLOBALS['config']['unbound'] = self::originalResolver() + [
			'python' => '', 'python_order' => 'pre_validator', 'python_script' => 'mymodule',
		];

		// When DNSBL is applied.
		pfb_unbound_python('enabled');

		// Then Unbound's one python slot goes to the observer, exactly as it goes to pfb_unbound.py with the toggle
		// off: pfSense's Unbound start hook (the boot-time DNS) is looked up from that one script name.
		$this->assertSame([TRUE, 'pre_validator', 'pfb_upstream_observer'], $this->pythonKeys());
	}

	public function testProxyOnAppliedAgainRegeneratesNothingAndSignalsNoRestart(): void
	{
		// Given the proxy on and one pass already applied.
		$this->setProxy(TRUE);
		$GLOBALS['config']['unbound'] = self::originalResolver();
		$this->assertTrue(pfb_unbound_python('enabled'), 'first pass moves the Resolver and writes the ini');
		$this->assertCount(1, $this->configureCalls());

		// When the next pass finds everything already in place.
		$changed = pfb_unbound_python('enabled');

		// Then it is a steady state: no restart signal and no further regeneration.
		$this->assertFalse($changed);
		$this->assertCount(1, $this->configureCalls());
	}

	public function testMountsHappenOnlyWhenTheObserverGoesIntoUnbound(): void
	{
		// Given nothing mounted; pfB-DNS on with its move accepted first, to prove this harness reaches the mount code.
		$this->useMountState(FALSE);
		$this->setProxy(TRUE);
		$GLOBALS['config']['unbound'] = self::originalResolver();
		pfb_unbound_python('enabled');
		$this->assertStringContainsString('Mounting: /usr/local/bin', $this->pfbLog(), 'before: the observer goes into Unbound with mounts');

		// When pfB-DNS is on but its move is refused (Listen Port 5353) and DNSBL is off: nothing owns the Resolver, so no python
		// script at all
		@unlink($GLOBALS['pfb']['log']);
		config_set_path(self::SAVED, '');
		$GLOBALS['config']['unbound'] = ['port' => '5353'] + self::originalResolver();
		pfb_unbound_python('disabled');

		// Then Unbound is not given python's mounts ...
		$this->assertStringNotContainsString('Mounting:', $this->pfbLog());

		// ... and with DNSBL on the same refused move changes nothing: Unbound never loads the module, so it needs none
		@unlink($GLOBALS['pfb']['log']);
		pfb_unbound_python('enabled');
		$this->assertStringNotContainsString('Mounting:', $this->pfbLog(), 'the DNSBL module does not go into Unbound');
	}

	public function testProxyOnDoesNotFlagThePythonMountsForUnmounting(): void
	{
		$this->setProxy(TRUE);
		$GLOBALS['config']['unbound'] = self::originalResolver();

		pfb_unbound_python('enabled');

		$this->assertArrayNotHasKey('dnsbl_python_unmount', $GLOBALS['pfb'], 'only a DNSBL-disabled pass unmounts');
	}

	// -----------------------------------------------------------------------
	// G3 -- every way out restores the Resolver and gives the module back
	// -----------------------------------------------------------------------

	public function testDnsblDisabledWhilePfbDnsIsOnKeepsTheResolverMovedAndTheInertObserverInUnbound(): void
	{
		// Given pfB-DNS on and a moved Resolver whose Unbound runs the observer, and DNSBL gets disabled.
		$this->setProxy(TRUE);
		$this->seedMovedResolver();
		foreach (self::OBSERVER_KEYS as $key => $value) {
			config_set_path("unbound/{$key}", $value);
		}
		$snapshot = $this->savedRaw();

		// When the disabled pass runs.
		$changed = pfb_unbound_python('disabled');

		// Then pfB-DNS keeps serving: nothing is restored or regenerated, the observer stays in Unbound
		// (it is what lets pfSense's Unbound start hook bring pfB-DNS up at boot) and its mounts are not unmounted.
		$this->assertFalse($changed);
		$this->assertSame('lo0', config_get_path('unbound/active_interface'));
		$this->assertSame($snapshot, $this->savedRaw());
		$this->assertSame([TRUE, 'pre_validator', 'pfb_upstream_observer'], $this->pythonKeys());
		$this->assertSame([], $this->configureCalls());
		$this->assertArrayNotHasKey('dnsbl_python_unmount', $GLOBALS['pfb'], 'the observer still needs the python mounts');
	}

	public function testPfbDnsOnWithDnsblOffMovesTheResolverAndGivesUnboundTheInertObserver(): void
	{
		// Given nothing mounted, pfB-DNS on and an untouched Resolver, and DNSBL off.
		$this->useMountState(FALSE);
		$this->setProxy(TRUE);
		$GLOBALS['config']['unbound'] = self::originalResolver();

		// When the disabled pass runs (DNSBL is off: the pass that used to only tear DNSBL down).
		$changed = pfb_unbound_python('disabled');

		// Then the Resolver is moved, Unbound gets the observer and its mounts, and no DNSBL input is produced.
		$this->assertTrue($changed);
		$this->assertSame('lo0', config_get_path('unbound/active_interface'));
		$this->assertNotSame('', $this->savedRaw());
		$this->assertSame([TRUE, 'pre_validator', 'pfb_upstream_observer'], $this->pythonKeys());
		$this->assertSame([FALSE], $this->configureCalls());
		$this->assertSame('pfb_upstream_observer', $this->resolverWhenConfigured()['python_script']);
		$this->assertStringContainsString('Mounting: /usr/local/bin', $this->pfbLog());
		$this->assertStringContainsString('Mounting: /usr/local/lib', $this->pfbLog());
		$this->assertArrayNotHasKey('dnsbl_python_unmount', $GLOBALS['pfb']);
		$this->assertFileDoesNotExist($GLOBALS['pfb']['unbound_py_conf'], 'DNSBL off: the module ini is not produced');
	}

	public function testPfbDnsOnWithDnsblOffAppliedAgainSignalsNothing(): void
	{
		// Given pfB-DNS on, DNSBL off and one pass already applied.
		$this->setProxy(TRUE);
		$GLOBALS['config']['unbound'] = self::originalResolver();
		$this->assertTrue(pfb_unbound_python('disabled'));

		// When the next pass finds everything in place.
		$changed = pfb_unbound_python('disabled');

		// Then it is a steady state.
		$this->assertFalse($changed);
		$this->assertCount(1, $this->configureCalls());
	}

	public function testPfbDnsOnWithTheResolverDisabledPutsItBack(): void
	{
		// Given pfB-DNS on and a moved Resolver, and the admin disables the Resolver itself (nothing left to front).
		$this->setProxy(TRUE);
		$this->seedMovedResolver();
		config_del_path('unbound/enable');

		// When the pass runs with no mode (DNSBL on, Resolver disabled).
		$changed = pfb_unbound_python('');

		// Then the Resolver is back as the user had it (its own enable flag stays absent) and the snapshot is cleared.
		$expected = self::originalResolver();
		unset($expected['enable']);
		$this->assertTrue($changed);
		$this->assertSame(self::sorted($expected), self::sorted(config_get_path('unbound')));
		$this->assertSame('', $this->savedRaw());
		$this->assertSame([FALSE], $this->configureCalls());
	}

	public function testPfBlockerNgDisabledPutsTheResolverBackWhateverPfbDnsSays(): void
	{
		// Given a moved Resolver, the toggle on, and pfBlockerNG itself disabled.
		$this->setProxy(TRUE);
		PfbConfig::writeSystem('gen/enable_cb', PfbToggle::Off);
		$this->seedMovedResolver();
		$this->assertSame('lo0', config_get_path('unbound/active_interface'), 'before: moved');

		// When the disabled pass runs.
		pfb_unbound_python('disabled');

		// Then the Resolver is back, the observer is not given to Unbound, unbound.conf was regenerated once.
		$this->assertResolverRestored('pfBlockerNG disabled');
		$this->assertFalse($this->pythonModuleKeysSet());
		$this->assertFalse(config_path_enabled('unbound', 'python'));
		$this->assertSame([FALSE], $this->configureCalls());
		$this->assertSame('lan,opt1', $this->resolverWhenConfigured()['active_interface'], 'unbound.conf is rendered from the restored Resolver');
		$this->assertTrue($GLOBALS['pfb']['dnsbl_python_unmount'], 'the disabled pass schedules the unmount');
	}

	public function testPfbDnsOffAndDnsblDisabledPutsTheResolverBackAndSchedulesTheUnmount(): void
	{
		// Given a moved Resolver and the admin turned pfB-DNS off while DNSBL is off.
		$this->seedMovedResolver();
		$this->setProxy(FALSE);

		// When the disabled pass runs.
		pfb_unbound_python('disabled');

		// Then the Resolver is back, no python keys remain, and the python mounts are scheduled for unmounting.
		$this->assertResolverRestored('toggle off, DNSBL off');
		$this->assertFalse($this->pythonModuleKeysSet());
		$this->assertSame([FALSE], $this->configureCalls());
		$this->assertTrue($GLOBALS['pfb']['dnsbl_python_unmount']);
	}

	public function testRestoringTheResolverAloneSignalsAnUnboundRestart(): void
	{
		// Given a disabled pass on an untouched Resolver: nothing to change, no restart signal.
		$GLOBALS['config']['unbound'] = self::originalResolver();
		$this->assertFalse(pfb_unbound_python('disabled'), 'before: a plain disabled pass signals nothing');

		// When the same pass has to hand a moved Resolver back.
		$this->seedMovedResolver();
		$changed = pfb_unbound_python('disabled');

		// Then the restore itself is the restart signal (no python keys or mounts were involved).
		$this->assertTrue($changed);
		$this->assertResolverRestored('restore signal');
	}

	public function testProxyTurnedOffRestoresTheResolverAndGivesUnboundNoPython(): void
	{
		// Given a moved Resolver, then the admin unticks the toggle.
		$this->seedMovedResolver();
		$this->setProxy(FALSE);
		$this->assertFalse($this->pythonModuleKeysSet(), 'before: the module is out of Unbound');

		// When DNSBL is applied.
		$changed = pfb_unbound_python('enabled');

		// Then the Resolver is back and unbound.conf was regenerated once, still with no python script: Unbound never gets the module.
		$this->assertTrue($changed);
		$this->assertResolverRestored('toggle off');
		$this->assertFalse(config_path_enabled('unbound', 'python'));
		$this->assertSame([FALSE], $this->configureCalls());
		$this->assertSame('lan,opt1', $this->resolverWhenConfigured()['active_interface'], 'unbound.conf is rendered from the restored Resolver');
		$this->assertSame('', $this->resolverWhenConfigured()['python_script'] ?? '', 'with no python script');
	}

	public function testAnAbandonedRestoreKeepsTheModuleOutOfUnboundWhileTheProxyStillHostsIt(): void
	{
		// Given the admin unticked the toggle, but the proxy outlived its stop so the restore is abandoned
		$this->seedMovedResolver();
		$this->setProxy(FALSE);
		$GLOBALS['pfb_test_valid_pids'] = [PFB_DNS_PROXY_PIDFILE => TRUE];
		$this->assertFalse($this->pythonModuleKeysSet(), 'before: the module is out of Unbound');

		// When DNSBL is applied
		pfb_unbound_python('enabled');

		// Then the Resolver is still moved and Unbound is not given the module the proxy still hosts
		$this->assertSame('lo0', config_get_path('unbound/active_interface'));
		$this->assertNotSame('', $this->savedRaw(), 'the snapshot is kept for the retry');
		$this->assertFalse($this->pythonModuleKeysSet(), 'no module keys in Unbound while the proxy hosts the module');
		$this->assertSame([], $this->configureCalls());
		$this->assertStringNotContainsString('Mounting:', $this->pfbLog());
	}

	// -----------------------------------------------------------------------
	// G4 -- pfb_unbound_dnsbl() patches unbound.conf by the snapshot, not by the mode alone
	// -----------------------------------------------------------------------

	private function writeUnboundConf(string $conf): void
	{
		file_put_contents("{$this->tmp}/unbound.conf", $conf);
		@unlink("{$this->tmp}/unbound.tmp");
	}

	private function patchedConf(): string
	{
		return (string) @file_get_contents("{$this->tmp}/unbound.tmp");
	}

	private const CONF_WITH_MODULE = "server:\n\tinterface: 127.0.0.1\n\tmodule-config: \"python validator iterator\"\n\npython:\npython-script: pfb_unbound.py\n";
	private const CONF_WITHOUT_MODULE = "server:\n\tinterface: 127.0.0.1\n\tmodule-config: \"validator iterator\"\n";

	public function testUnboundConfSwapsTheModuleForTheObserverWhileASnapshotExists(): void
	{
		// Given a conf that loads the module and a snapshot (the proxy owns the module).
		$this->seedMovedResolver();
		$this->writeUnboundConf(self::CONF_WITH_MODULE);
		$this->assertStringContainsString('python-script: pfb_unbound.py', self::CONF_WITH_MODULE);

		// When the enabled pass patches it.
		$changed = pfb_unbound_dnsbl('enabled');

		// Then the module is out and the inert observer is the one python script, forwarding or not.
		$this->assertTrue($changed);
		$patched = $this->patchedConf();
		$this->assertSame(1, substr_count($patched, 'python-script:'));
		$this->assertStringContainsString('python-script: pfb_upstream_observer.py', $patched);
		$this->assertStringNotContainsString('pfb_unbound.py', $patched);
		$this->assertStringContainsString('interface: 127.0.0.1', $patched, 'unrelated lines survive');
	}

	public function testUnboundConfGainsNoModuleWithoutASnapshot(): void
	{
		// Given a conf without the module and no snapshot (pfB-DNS off).
		$this->writeUnboundConf(self::CONF_WITHOUT_MODULE);
		$this->assertStringNotContainsString('python', self::CONF_WITHOUT_MODULE);

		// When the enabled pass looks at it.
		$changed = pfb_unbound_dnsbl('enabled');

		// Then nothing is patched in: Unbound never loads the module.
		$this->assertFalse($changed);
		$this->assertSame('', $this->patchedConf());
	}

	public function testToggleOnWithALostMarkerOnAMovedResolverGivesUnboundTheObserverNotTheModule(): void
	{
		// Given pfB-DNS on and DNSBL on, a Resolver that still carries our block, the marker lost, and the module loaded:
		// pfb_dns_proxy_resolver() refuses (it will not snapshot moved values as the previous ones), the block marks it as ours.
		$this->setProxy(TRUE);
		$this->enableDnsbl();
		$GLOBALS['config']['unbound'] = self::movedResolver() + [
			'python' => '', 'python_order' => 'pre_validator', 'python_script' => 'pfb_unbound',
		];
		$this->assertSame('', $this->savedRaw(), 'before: no snapshot');
		$this->writeUnboundConf(self::CONF_WITH_MODULE);

		// When both seams run.
		pfb_unbound_python('enabled');
		$changed = pfb_unbound_dnsbl('enabled');

		// Then the refusal stored no snapshot, and Unbound runs the inert observer: the matcher is not loaded beside our block
		$this->assertSame('', $this->savedRaw(), 'the refusal stored no snapshot');
		$this->assertSame('pfb_upstream_observer', config_get_path('unbound/python_script'), 'config.xml runs the observer');
		$this->assertTrue($changed, 'unbound.conf is patched from the module to the observer');
		$this->assertStringContainsString('pfb_upstream_observer', $this->patchedConf(), 'unbound.conf observer');
		$this->assertStringNotContainsString('pfb_unbound.py', $this->patchedConf(), 'unbound.conf no matcher');
	}

	/** @return array<string,array{string}> a stored marker that is no snapshot */
	public static function unconfirmedMarkers(): array
	{
		return [
			'the single character 0'           => ['0'],
			'the text of an interrupted write' => ['!!!truncated-snapshot!!!'],
			'base64 of text that is not JSON'  => [base64_encode('not json')],
		];
	}

	#[DataProvider('unconfirmedMarkers')]
	public function testToggleOnWithAMarkerThatIsNoSnapshotAndNoBlockGivesUnboundNeitherTheModuleNorTheObserver(string $marker): void
	{
		// Given pfB-DNS on and DNSBL on, an ordinary Resolver (no block of ours) and a stored marker that is no snapshot: a
		// corrupted value is no evidence that pfB-DNS owns the Resolver, so there is no observer, and Unbound never gets the module
		$this->setProxy(TRUE);
		$this->enableDnsbl();
		$GLOBALS['config']['unbound'] = self::originalResolver();
		config_set_path(self::SAVED, $marker);
		$this->writeUnboundConf(self::CONF_WITHOUT_MODULE);

		// When both seams run
		pfb_unbound_python('enabled');
		$changed = pfb_unbound_dnsbl('enabled');

		// Then the move was refused, the marker is kept, and Unbound is given no python script at all
		$this->assertSame($marker, $this->savedRaw(), 'the marker is kept verbatim');
		$this->assertSame('lan,opt1', config_get_path('unbound/active_interface'), 'the Resolver was not moved');
		$this->assertFalse(config_path_enabled('unbound', 'python'), 'config.xml names no python script');
		$this->assertFalse($changed, 'unbound.conf has nothing to patch');
		$this->assertSame('', $this->patchedConf());
		$this->assertFalse(pfb_dns_proxy_hosts_module(), 'the proxy hosts no module for a Resolver it was never shown to own');
	}

	public function testDisabledPassStillRemovesTheModuleWithoutASnapshot(): void
	{
		// Today's behaviour: mode 'disabled' strips the module whether or not a snapshot exists.
		$this->writeUnboundConf(self::CONF_WITH_MODULE);

		$changed = pfb_unbound_dnsbl('disabled');

		$this->assertTrue($changed);
		$this->assertStringNotContainsString('python', $this->patchedConf());
	}

	public function testDnsblVipStaysInUnboundForAnEnabledPassEvenWithASnapshot(): void
	{
		// Given a conf listening on the DNSBL VIP, and a snapshot.
		config_set_path('virtualip/vip', [['uniqid' => 'abc', 'subnet' => '10.10.10.1']]);
		PfbConfig::writeSystem('dnsbl/pfb_dnsvip4', '_vipabc');
		$this->seedMovedResolver();
		$conf = "server:\n\tinterface: 127.0.0.1\n\tinterface: 10.10.10.1\n\tmodule-config: \"validator iterator\"\n";

		// Before-state: a DISABLED pass removes that VIP line.
		$this->writeUnboundConf($conf);
		$this->assertTrue(pfb_unbound_dnsbl('disabled'));
		$this->assertStringNotContainsString('10.10.10.1', $this->patchedConf(), 'before: disabled removes the VIP');

		// When an ENABLED pass patches the same conf.
		$this->writeUnboundConf($conf . "python:\npython-script: pfb_unbound.py\n");
		pfb_unbound_dnsbl('enabled');

		// Then the VIP line stays: only the module decision follows the snapshot.
		$this->assertStringContainsString('interface: 10.10.10.1', $this->patchedConf());
	}

	public function testModuleFilesAreStagedWhileTheModuleOrAnyPythonScriptIsInUnbound(): void
	{
		// The staging exec targets an absolute appliance path with no test seam, so the decision
		// is pinned in the source: the proxy imports the staged module, and Unbound's boot hook
		// (pfb_upstream_observer_include.inc) must stay staged while the observer is in Unbound.
		$ref = new ReflectionFunction('pfb_unbound_dnsbl');
		$body = implode('', array_slice(
			(array) file((string) $ref->getFileName()),
			$ref->getStartLine() - 1,
			$ref->getEndLine() - $ref->getStartLine() + 1
		));

		$this->assertMatchesRegularExpression(
			"/if \\(\\\$mode == 'enabled' \\|\\| \\\$script !== NULL\\) \\{\\s*(?:\\/\\/[^\\n]*\\n\\s*)*exec\\('[^']*dnsbl_cache stage/",
			$body,
			'staging must follow the mode or the script Unbound is given, never tear down under a snapshot'
		);
	}

	// -----------------------------------------------------------------------
	// F1 -- forwarding mode: Unbound runs the upstream-block observer, never pfb_unbound.py
	// -----------------------------------------------------------------------

	private const CONF_WITH_OBSERVER = "server:\n\tinterface: 127.0.0.1\n\tmodule-config: \"python validator iterator\"\n\npython:\npython-script: pfb_upstream_observer.py\n";
	private const OBSERVER_KEYS = ['python' => '', 'python_order' => 'pre_validator', 'python_script' => 'pfb_upstream_observer'];
	private const MODULE_KEYS = ['python' => '', 'python_order' => 'pre_validator', 'python_script' => 'pfb_unbound'];

	/** The python keys Unbound's config.xml carries, as [enabled, order, script]. */
	private function pythonKeys(): array
	{
		return [config_path_enabled('unbound', 'python'), config_get_path('unbound/python_order', ''), config_get_path('unbound/python_script', '')];
	}

	private function setForwarding(bool $on): void
	{
		if ($on) {
			config_set_path('unbound/forwarding', '');
		} else {
			config_del_path('unbound/forwarding');
		}
	}

	public function testProxyOnWithForwardingGivesUnboundTheObserverInPlaceOfTheModule(): void
	{
		// Given the proxy on, the Resolver forwarding, and Unbound still loading the module.
		$this->setProxy(TRUE);
		$GLOBALS['config']['unbound'] = self::originalResolver() + self::MODULE_KEYS;
		$this->setForwarding(TRUE);
		$this->assertTrue($this->pythonModuleKeysSet(), 'before: the module is in Unbound');

		// When DNSBL is applied.
		$changed = pfb_unbound_python('enabled');

		// Then Unbound's python keys name the observer (the proxy hosts the module) and unbound.conf is rendered from them.
		$this->assertTrue($changed);
		$this->assertSame([TRUE, 'pre_validator', 'pfb_upstream_observer'], $this->pythonKeys());
		$this->assertFalse($this->pythonModuleKeysSet(), 'pfb_unbound is not the python script');
		$this->assertSame('lo0', config_get_path('unbound/active_interface'), 'the Resolver is moved');
		$this->assertSame('pfb_upstream_observer', $this->resolverWhenConfigured()['python_script'], 'unbound.conf is rendered with the observer');
	}

	public function testProxyOnWithoutForwardingStillGivesUnboundTheInertObserver(): void
	{
		// Given pfB-DNS on, a moved Resolver that is recursing (not forwarding), and no python keys yet.
		$this->setProxy(TRUE);
		$this->seedMovedResolver();
		$this->setForwarding(FALSE);
		$this->assertFalse(config_path_enabled('unbound', 'python'));

		// When DNSBL is applied.
		$changed = pfb_unbound_python('enabled');

		// Then Unbound is given the observer anyway: it stays inert without a report socket, and it is what
		// lets pfSense's Unbound start hook bring pfB-DNS up at boot, forwarding or not.
		$this->assertTrue($changed);
		$this->assertSame([TRUE, 'pre_validator', 'pfb_upstream_observer'], $this->pythonKeys());
		$this->assertSame('lo0', config_get_path('unbound/active_interface'), 'the Resolver stays moved');
	}

	public function testTurningTheProxyOffTakesTheObserverKeysOutAndPutsNothingInTheirPlace(): void
	{
		// Given a moved Resolver running the observer, then the admin unticks the toggle.
		$this->seedMovedResolver();
		foreach (self::OBSERVER_KEYS as $key => $value) {
			config_set_path("unbound/{$key}", $value);
		}
		$this->setForwarding(TRUE);
		$this->setProxy(FALSE);

		// When DNSBL is applied.
		$this->assertTrue(pfb_unbound_python('enabled'));

		// Then the Resolver is back and Unbound loads no python script: not the observer, and not pfb_unbound.py in its place.
		$this->assertResolverRestored('toggle off', ['forwarding' => '', 'python_order' => '', 'python_script' => '']);
		$this->assertFalse(config_path_enabled('unbound', 'python'));
		$this->assertFalse($this->pythonModuleKeysSet());
	}

	public function testPfbDnsOffAndDnsblDisabledTakesTheObserverKeysOut(): void
	{
		// Given the observer keys and a moved Resolver, the toggle off and DNSBL disabled.
		$this->setProxy(FALSE);
		$this->seedMovedResolver();
		foreach (self::OBSERVER_KEYS as $key => $value) {
			config_set_path("unbound/{$key}", $value);
		}
		$this->setForwarding(TRUE);

		// When the disabled pass runs.
		pfb_unbound_python('disabled');

		// Then the Resolver is restored and neither the module nor the observer remains in Unbound.
		$this->assertFalse(config_path_enabled('unbound', 'python'));
		$this->assertSame('', config_get_path('unbound/python_script'));
		$this->assertSame('', $this->savedRaw());
	}

	public function testAnAbandonedRestoreKeepsTheObserverWhileTheProxyStillHostsTheModule(): void
	{
		// Given the admin unticked the toggle, but the proxy outlived its stop so the restore is abandoned.
		$this->seedMovedResolver();
		$this->setProxy(FALSE);
		$this->setForwarding(TRUE);
		$GLOBALS['pfb_test_valid_pids'] = [PFB_DNS_PROXY_PIDFILE => TRUE];

		// When DNSBL is applied.
		pfb_unbound_python('enabled');

		// Then the Resolver is still moved and Unbound runs the observer, not the module the proxy hosts.
		$this->assertNotSame('', $this->savedRaw(), 'the snapshot is kept for the retry');
		$this->assertSame([TRUE, 'pre_validator', 'pfb_upstream_observer'], $this->pythonKeys());
	}

	public function testAMoveTheResolverRefusedTakesTheLegacyDnsblModuleOutOfUnboundAndGivesItNoObserver(): void
	{
		// Given pfB-DNS on and DNSBL on with the Resolver forwarding, a Resolver whose Listen Port the proxy cannot work with
		// (the move is refused), still loading the DNSBL module an older version put in.
		$this->setProxy(TRUE);
		$this->enableDnsbl();
		$GLOBALS['config']['unbound'] = ['port' => '5353'] + self::originalResolver() + self::MODULE_KEYS;
		$this->setForwarding(TRUE);

		// When DNSBL is applied.
		pfb_unbound_python('enabled');

		// Then nothing was moved, so nothing fronts the Resolver: the module is out of Unbound and the observer is not given instead.
		$this->assertSame('', $this->savedRaw());
		$this->assertSame([FALSE, '', ''], $this->pythonKeys());
	}

	// -----------------------------------------------------------------------
	// G6 -- a pfB-DNS takeover that does not happen leaves Unbound with no pfBlockerNG python
	// -----------------------------------------------------------------------

	/** DNSBL on as the apply pass sees it (the auto-created VIP keeps pfb_global() from force-disabling it). */
	private function enableDnsbl(): void
	{
		PfbConfig::writeSystem('dnsbl/pfb_dnsbl', PfbToggle::On);
		PfbConfig::writeSystem('dnsbl/pfb_dnsvip_auto', PfbToggle::On);
	}

	/** @return array<string,array{string}> why pfB-DNS could not take the Resolver over, with the toggle on */
	public static function takeoverFailures(): array
	{
		return [
			'Listen Port 5353'                          => ['port5353'],
			'Listen Port 5354'                          => ['port5354'],
			'own loopback interface line in Custom Options' => ['interface'],
			'own port: line in Custom Options'          => ['port'],
			'Resolver value that cannot be stored'      => ['unstorable'],
			'config.xml locked by another save'         => ['lock'],
			'config.xml cannot be re-read'              => ['read'],
		];
	}

	/** Seed the Resolver the cause needs: still on its own interfaces and loading the module, unless the cause is a moved look. */
	private function seedTakeoverFailure(string $cause): void
	{
		$resolver = self::originalResolver() + self::MODULE_KEYS;
		switch ($cause) {
			case 'port5353':
				$resolver['port'] = '5353';
				break;
			case 'port5354':
				$resolver['port'] = '5354';
				break;
			case 'interface':
				$resolver['custom_options'] = base64_encode("do-ip6: no\ninterface: 127.0.0.1@5353");
				break;
			case 'port':
				$resolver['custom_options'] = base64_encode("server:\nport: 5300");
				break;
			case 'unstorable':
				$resolver['enablessl'] = ['not', 'a', 'scalar'];
				break;
			case 'lock':
				$GLOBALS['pfb_test_try_lock_fail'] = TRUE;
				break;
			case 'read':
				$GLOBALS['pfb_test_config_read_fails'] = TRUE;
				break;
		}
		$GLOBALS['config']['unbound'] = $resolver;
		$this->setForwarding(TRUE);
	}

	/** @return list<string> */
	private function notices(): array
	{
		return array_column($GLOBALS['pfb_test_file_notices'] ?? [], 'notice');
	}

	#[DataProvider('takeoverFailures')]
	public function testATakeoverThatDoesNotHappenTakesTheLegacyDnsblModuleOutOfUnboundInBothSeams(string $cause): void
	{
		// Given pfB-DNS on and DNSBL on, Unbound still loading the module an older version put in, and a takeover that cannot happen
		$this->setProxy(TRUE);
		$this->enableDnsbl();
		$this->seedTakeoverFailure($cause);
		$before = config_get_path('unbound');
		$this->writeUnboundConf(self::CONF_WITH_MODULE);

		// When both seams run
		pfb_unbound_python('enabled');
		$changed = pfb_unbound_dnsbl('enabled');

		// Then nothing was moved or snapshotted, and the module is out of both: no observer, no module
		$this->assertSame('', $this->savedRaw(), 'no snapshot');
		$this->assertSame($before['active_interface'], config_get_path('unbound/active_interface'), 'the Resolver was not touched');
		$this->assertSame([FALSE, '', ''], $this->pythonKeys(), 'config.xml names no python script');
		$this->assertSame([], $this->configureCalls(), 'nothing changed the Resolver, so nothing regenerated unbound.conf');
		$this->assertTrue($changed, 'unbound.conf is patched to drop the module');
		$patched = $this->patchedConf();
		$this->assertStringNotContainsString('python-script', $patched);
		$this->assertStringNotContainsString('module-config: "python', $patched);

		// ... and the operator is told that pfB-DNS is not active and that DNSBL does not block until it is
		$notices = $this->notices();
		$this->assertCount(1, $notices, 'one notice');
		$this->assertStringContainsString('pfB-DNS is not active', $notices[0]);
		$this->assertStringContainsString('DNSBL does not block until pfB-DNS is active', $notices[0]);
		$this->assertStringNotContainsString('DNSBL blocks nothing', $notices[0]);
	}

	#[DataProvider('takeoverFailures')]
	public function testATakeoverThatDoesNotHappenLeavesAnUnboundThatLacksPythonWithoutIt(string $cause): void
	{
		// Given the same failure, but Unbound loads no python (a first apply with pfB-DNS on)
		$this->setProxy(TRUE);
		$this->enableDnsbl();
		$this->seedTakeoverFailure($cause);
		foreach (['python', 'python_order', 'python_script'] as $key) {
			config_del_path("unbound/{$key}");
		}
		$this->writeUnboundConf(self::CONF_WITHOUT_MODULE);
		$this->assertFalse($this->pythonModuleKeysSet(), 'before: no module keys');

		// When both seams run
		pfb_unbound_python('enabled');
		$changed = pfb_unbound_dnsbl('enabled');

		// Then DNSBL does not put the module into Unbound, in config.xml or unbound.conf, and gives it no observer either
		$this->assertSame([FALSE, '', ''], $this->pythonKeys(), 'config.xml gains no python script');
		$this->assertFalse($changed);
		$this->assertSame('', $this->patchedConf());
		$this->assertSame('', $this->savedRaw());
	}

	/** @return array<string,array{string}> */
	public static function takeoverFailuresWithDnsblOff(): array
	{
		return ['Listen Port' => ['port5353'], 'config.xml locked' => ['lock']];
	}

	#[DataProvider('takeoverFailuresWithDnsblOff')]
	public function testATakeoverThatDoesNotHappenWithDnsblOffGivesUnboundNothingAndSaysSo(string $cause): void
	{
		// Given pfB-DNS on and DNSBL off, a failed takeover and a Resolver carrying no python keys
		$this->setProxy(TRUE);
		$this->seedTakeoverFailure($cause);
		foreach (['python', 'python_order', 'python_script'] as $key) {
			config_del_path("unbound/{$key}");
		}

		// When the disabled-DNSBL pass runs
		pfb_unbound_python('disabled');

		// Then nothing is injected, and the notice claims no DNSBL
		$this->assertFalse(config_path_enabled('unbound', 'python'));
		$this->assertSame('', $this->savedRaw());
		$notices = $this->notices();
		$this->assertCount(1, $notices);
		$this->assertStringContainsString('pfB-DNS is not active', $notices[0]);
		$this->assertStringNotContainsString('DNSBL', $notices[0]);
	}

	#[DataProvider('takeoverFailures')]
	public function testATakeoverThatDoesNotHappenLeavesThePythonSlotAnAdminModuleHeldAlone(string $cause): void
	{
		// Given pfB-DNS on, DNSBL on, a failed takeover, and a Resolver that has the python slot taken by the admin's own module
		$this->setProxy(TRUE);
		$this->enableDnsbl();
		$this->seedTakeoverFailure($cause);
		config_set_path('unbound/python_script', 'mymodule');

		// When DNSBL is applied
		pfb_unbound_python('enabled');

		// Then the admin's module keeps the one python slot: the DNSBL module never takes it, and neither does the observer
		$this->assertSame([TRUE, 'pre_validator', 'mymodule'], $this->pythonKeys());
	}

	public function testAStableTakeoverWhoseReassertionCannotTakeTheLockKeepsTheObserverAndNoSecondModule(): void
	{
		// Given pfB-DNS on and DNSBL on, the Resolver already moved (a snapshot), and another save holding the config lock
		$this->setProxy(TRUE);
		$this->enableDnsbl();
		$this->seedMovedResolver();
		$this->setForwarding(TRUE);
		$GLOBALS['pfb_test_try_lock_fail'] = TRUE;
		$snapshot = $this->savedRaw();
		$this->writeUnboundConf(self::CONF_WITH_MODULE);

		// When both seams run
		pfb_unbound_python('enabled');
		pfb_unbound_dnsbl('enabled');

		// Then the proxy keeps the Resolver and the module: Unbound runs the observer, never the module as well
		$this->assertSame($snapshot, $this->savedRaw(), 'the snapshot is untouched');
		$this->assertSame([TRUE, 'pre_validator', 'pfb_upstream_observer'], $this->pythonKeys());
		$patched = $this->patchedConf();
		$this->assertSame(1, substr_count($patched, 'python-script:'));
		$this->assertStringContainsString('python-script: pfb_upstream_observer.py', $patched);
		$this->assertStringNotContainsString('pfb_unbound.py', $patched);
		$notices = $this->notices();
		$this->assertCount(1, $notices);
		$this->assertStringContainsString('The DNS proxy keeps serving the DNS Resolver as it was moved', $notices[0]);
		$this->assertStringNotContainsString('DNSBL does not block', $notices[0], 'the proxy hosts the module');
	}

	public function testAnAcceptedTakeoverStillGivesUnboundTheObserverNotTheModuleAndRaisesNoNotice(): void
	{
		// Given pfB-DNS on and DNSBL on, and a Resolver the proxy can take over
		$this->setProxy(TRUE);
		$this->enableDnsbl();
		$GLOBALS['config']['unbound'] = self::originalResolver() + self::MODULE_KEYS;
		$this->setForwarding(TRUE);
		$this->writeUnboundConf(self::CONF_WITH_MODULE);

		// When both seams run
		pfb_unbound_python('enabled');
		pfb_unbound_dnsbl('enabled');

		// Then the effective takeover (the snapshot) decides: observer in both seams, module in neither, no notice
		$this->assertNotSame('', $this->savedRaw(), 'before: the takeover happened');
		$this->assertSame([TRUE, 'pre_validator', 'pfb_upstream_observer'], $this->pythonKeys());
		$this->assertStringNotContainsString('pfb_unbound.py', $this->patchedConf());
		$this->assertSame([], $this->notices());
	}

	public function testTheObserverGetsTheModuleMountsOnlyWhenItGoesIntoUnbound(): void
	{
		// Given nothing mounted, the proxy on and the Resolver forwarding.
		$this->useMountState(FALSE);
		$this->setProxy(TRUE);
		$GLOBALS['config']['unbound'] = self::originalResolver();
		$this->setForwarding(TRUE);

		// When DNSBL is applied.
		pfb_unbound_python('enabled');

		// Then Unbound is given the python bin and lib mounts the observer needs inside its chroot.
		$this->assertStringContainsString('Mounting: /usr/local/bin', $this->pfbLog());
		$this->assertStringContainsString('Mounting: /usr/local/lib', $this->pfbLog());
	}

	public function testUnboundConfGainsTheObserverWhileASnapshotExistsAndForwardingIsOn(): void
	{
		// Given a conf without any python module, a snapshot (the proxy owns the module) and forwarding.
		$this->seedMovedResolver();
		$this->setForwarding(TRUE);
		$this->writeUnboundConf(self::CONF_WITHOUT_MODULE);

		// When the enabled pass patches it.
		$changed = pfb_unbound_dnsbl('enabled');

		// Then the python module and the observer script block are added, and pfb_unbound.py is not.
		$this->assertTrue($changed);
		$patched = $this->patchedConf();
		$this->assertStringContainsString('module-config: "python validator iterator"', $patched);
		$this->assertStringContainsString("python:\npython-script: pfb_upstream_observer.py", $patched);
		$this->assertStringNotContainsString('pfb_unbound.py', $patched);
	}

	public function testUnboundConfSwapsTheModuleForTheObserverWhenTheProxyTakesOver(): void
	{
		// Given a conf that loads pfb_unbound.py, then a snapshot appears with forwarding on.
		$this->seedMovedResolver();
		$this->setForwarding(TRUE);
		$this->writeUnboundConf(self::CONF_WITH_MODULE);

		// When the enabled pass patches it.
		$this->assertTrue(pfb_unbound_dnsbl('enabled'));

		// Then exactly the observer is the python script and the python module stays in the chain.
		$patched = $this->patchedConf();
		$this->assertSame(1, substr_count($patched, 'python-script:'));
		$this->assertStringContainsString('python-script: pfb_upstream_observer.py', $patched);
		$this->assertStringNotContainsString('pfb_unbound.py', $patched);
		$this->assertStringContainsString('module-config: "python validator iterator"', $patched);
	}

	public function testUnboundConfDropsTheObserverWhenTheProxyIsGone(): void
	{
		// Given a conf that loads the observer and no snapshot (the proxy is off, the Resolver restored).
		$this->writeUnboundConf(self::CONF_WITH_OBSERVER);

		// When the enabled pass patches it.
		$this->assertTrue(pfb_unbound_dnsbl('enabled'));

		// Then no python script remains: pfb_unbound.py is not put in the observer's place.
		$patched = $this->patchedConf();
		$this->assertStringNotContainsString('python-script', $patched);
		$this->assertStringNotContainsString('pfb_unbound.py', $patched);
		$this->assertStringNotContainsString('pfb_upstream_observer', $patched);
	}

	public function testUnboundConfKeepsTheObserverWhenForwardingIsOff(): void
	{
		// Given a conf that loads the observer, a snapshot, and a Resolver that does not forward.
		$this->seedMovedResolver();
		$this->setForwarding(FALSE);
		$this->writeUnboundConf(self::CONF_WITH_OBSERVER);

		// When the enabled pass looks at it.
		$changed = pfb_unbound_dnsbl('enabled');

		// Then the inert observer stays: nothing is rewritten.
		$this->assertFalse($changed);
		$this->assertSame('', $this->patchedConf());
	}

	public function testUnboundConfWithTheObserverAlreadyInPlaceIsLeftAlone(): void
	{
		// Given the steady state: snapshot, forwarding, the observer already wired.
		$this->seedMovedResolver();
		$this->setForwarding(TRUE);
		$this->writeUnboundConf(self::CONF_WITH_OBSERVER);

		// When the enabled pass looks at it.
		$changed = pfb_unbound_dnsbl('enabled');

		// Then nothing is rewritten.
		$this->assertFalse($changed);
		$this->assertSame('', $this->patchedConf());
	}

	public function testDisabledPassKeepsTheObserverInUnboundConfWhileASnapshotExists(): void
	{
		// Given a conf that loads the observer and a snapshot (pfB-DNS on, DNSBL off).
		$this->seedMovedResolver();
		$this->writeUnboundConf(self::CONF_WITH_OBSERVER);

		// When the disabled pass looks at it.
		$changed = pfb_unbound_dnsbl('disabled');

		// Then nothing is rewritten: pfB-DNS still needs the observer's boot hook.
		$this->assertFalse($changed);
		$this->assertSame('', $this->patchedConf());
	}

	public function testDisabledPassGivesUnboundTheObserverWhilePfbDnsIsOn(): void
	{
		// Given a snapshot and a conf with no python module at all (DNSBL was off when pfB-DNS moved the Resolver).
		$this->seedMovedResolver();
		$this->writeUnboundConf(self::CONF_WITHOUT_MODULE);

		// When the disabled pass patches it.
		$this->assertTrue(pfb_unbound_dnsbl('disabled'));

		// Then the observer is added as the one python script.
		$patched = $this->patchedConf();
		$this->assertStringContainsString('module-config: "python validator iterator"', $patched);
		$this->assertStringContainsString("python:\npython-script: pfb_upstream_observer.py", $patched);
	}

	public function testDisabledPassStripsTheObserverFromUnboundConfWithoutASnapshot(): void
	{
		// Given a conf that still loads the observer and no snapshot (pfB-DNS is gone).
		$this->writeUnboundConf(self::CONF_WITH_OBSERVER);

		// When the disabled pass patches it.
		$this->assertTrue(pfb_unbound_dnsbl('disabled'));

		// Then no python module remains.
		$this->assertStringNotContainsString('python', $this->patchedConf());
	}

	// -----------------------------------------------------------------------
	// W1 -- the setup wizard's reset
	// -----------------------------------------------------------------------

	public function testWizardResetRestoresTheResolverBeforeItSweepsThePackageConfig(): void
	{
		// Given a moved Resolver whose snapshot lives in the package config the wizard is about to sweep.
		$this->setProxy(TRUE);
		$this->seedMovedResolver();
		$this->assertSame('lo0', config_get_path('unbound/active_interface'), 'before: moved');
		$this->assertNotSame('', $this->savedRaw(), 'before: snapshot present');

		// When the wizard runs its capture-and-sweep step (the region ends at the sweep itself).
		$source = (string) file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/wizards/pfblockerng_wizard.inc');
		$start = strpos($source, "\t\$pfb_general_schedule = PfbConfig::readSection('installedpackages/pfblockerng/config/0');");
		$sweep = "\n\tpfb_remove_config_settings();";
		$end = $start === FALSE ? FALSE : strpos($source, $sweep, $start);
		$this->assertTrue($start !== FALSE && $end !== FALSE, 'test bootstrap: wizard capture/sweep region found');
		eval(substr($source, (int) $start, (int) $end + strlen($sweep) - (int) $start));

		// Then the Resolver is back as the user had it, and the package config really was swept.
		$this->assertSame(self::sorted(self::originalResolver()), self::sorted(config_get_path('unbound')));
		$this->assertSame([], config_get_path('installedpackages', []));
	}

	/** Runs the wizard's capture-and-sweep step of step4_submitphpaction() (a `return` ends it early); returns its $input_errors. */
	private function runWizardReset(): array
	{
		$input_errors = [];
		$source = (string) file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/wizards/pfblockerng_wizard.inc');
		$start = strpos($source, "\t\$pfb_general_schedule = PfbConfig::readSection('installedpackages/pfblockerng/config/0');");
		$sweep = "\n\tpfb_remove_config_settings();";
		$end = $start === FALSE ? FALSE : strpos($source, $sweep, $start);
		$this->assertTrue($start !== FALSE && $end !== FALSE, 'test bootstrap: wizard capture/sweep region found');
		eval(substr($source, (int) $start, (int) $end + strlen($sweep) - (int) $start));
		return $input_errors;
	}

	/** @return array<string,array{string}> why the Resolver could not be put back */
	public static function failedRestores(): array
	{
		return [
			'the proxy outlives its stop'       => ['proxy alive'],
			'another save holds the config lock' => ['config locked'],
		];
	}

	#[DataProvider('failedRestores')]
	public function testWizardResetStopsBeforeTheSweepAndKeepsTheSnapshotWhenTheResolverCannotBePutBack(string $why): void
	{
		// Given a moved Resolver whose restore cannot complete
		$this->setProxy(TRUE);
		$this->seedMovedResolver();
		if ($why === 'proxy alive') {
			$GLOBALS['pfb_test_valid_pids'] = [PFB_DNS_PROXY_PIDFILE => TRUE];
		} else {
			$GLOBALS['pfb_test_try_lock_fail'] = TRUE;
		}
		$moved = self::sorted(config_get_path('unbound'));
		$snapshot = $this->savedRaw();
		$this->assertNotSame('', $snapshot, 'before: snapshot present');

		// When the wizard runs its reset
		$errors = $this->runWizardReset();

		// Then it reports the failure and stops: the Resolver, the snapshot and the package config are all untouched
		$this->assertCount(1, $errors, 'one input error');
		$this->assertStringContainsString('DNS proxy', $errors[0]);
		$this->assertStringContainsString('Resolver', $errors[0]);
		$this->assertSame($snapshot, $this->savedRaw(), 'the snapshot is kept for the next attempt');
		$this->assertSame($moved, self::sorted(config_get_path('unbound')), 'the Resolver is left as it is');
		$this->assertNotSame([], config_get_path('installedpackages', []), 'the package config was not swept');
	}

	public function testWizardResetSweepsWhenThereIsNoMovedResolverToPutBack(): void
	{
		// Given an untouched Resolver: pfb_dns_proxy_resolver(FALSE) returns FALSE because there is nothing to do
		$GLOBALS['config']['unbound'] = self::originalResolver();
		$this->assertSame('', $this->savedRaw(), 'before: no snapshot');
		$this->assertNotSame([], config_get_path('installedpackages', []), 'before: the package config exists');

		// When the wizard runs its reset
		$errors = $this->runWizardReset();

		// Then a FALSE that means "nothing to restore" is not a failure: the sweep ran
		$this->assertSame([], $errors);
		$this->assertSame([], config_get_path('installedpackages', []));
		$this->assertSame(self::sorted(self::originalResolver()), self::sorted(config_get_path('unbound')));
	}

	// -----------------------------------------------------------------------
	// U1 -- the package's own uninstall pass
	// -----------------------------------------------------------------------

	/**
	 * The apply pass's own mode and pfB-DNS decisions (pfblockerng_apply.inc), run against the real pfb_global().
	 *
	 * @return array{string,bool} $mode, and what the apply hands pfb_unbound_python() as $dns_wanted
	 */
	private function applyDecisionsFor(bool $install): array
	{
		$GLOBALS['pfb']['install'] = $install;
		pfb_global();
		$source = (string) file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc');
		$from = "\t\$pfbupdate = \$pfbpython = FALSE;\n\t// \$mode must be a defined string";
		$until = "\n\n\t// [ ADR-13 ] Provision (or remove)";
		$start = strpos($source, $from);
		$end = $start === FALSE ? FALSE : strpos($source, $until, $start);
		$this->assertTrue($start !== FALSE && $end !== FALSE, 'test bootstrap: apply mode region found');
		$mode = NULL;
		$pfb_dns_wanted = NULL;
		$pfb = &$GLOBALS['pfb'];
		eval(substr($source, (int) $start, (int) $end - (int) $start));
		return [(string) $mode, (bool) $pfb_dns_wanted];
	}

	public function testUninstallDisablePassRestoresTheResolver(): void
	{
		// Given pfBlockerNG fully on with a moved Resolver: on its own, the apply pass runs 'enabled' and wants pfB-DNS.
		PfbConfig::writeSystem('gen/enable_cb', PfbToggle::On);
		PfbConfig::writeSystem('dnsbl/pfb_dnsbl', PfbToggle::On);
		PfbConfig::writeSystem('dnsbl/pfb_dnsvip_auto', PfbToggle::On);
		$this->setProxy(TRUE);
		$this->seedMovedResolver();
		$this->assertSame(['enabled', TRUE], $this->applyDecisionsFor(FALSE), 'before: a normal pass is enabled');
		$this->assertSame('lo0', config_get_path('unbound/active_interface'), 'before: moved');

		// When pfblockerng_php_pre_deinstall_command()'s flag turns the pass into a disable pass.
		[$mode, $wanted] = $this->applyDecisionsFor(TRUE);

		// Then the pass is 'disabled' and pfB-DNS is not wanted, although config.xml (which pfb_unbound_python() re-reads
		// and which still has pfBlockerNG on) says otherwise: its Unbound step hands the Resolver back.
		$this->assertSame(['disabled', FALSE], [$mode, $wanted]);
		pfb_unbound_python($mode, $wanted);
		$this->assertResolverRestored('uninstall disable pass');
		$this->assertFalse(config_path_enabled('unbound', 'python'));
	}

	/** @return array<string,array{PfbToggle,PfbToggle,string,bool}> the pfBlockerNG enable, the pfB-DNS enable, the apply's $mode, and whether it wants pfB-DNS */
	public static function parentSwitchStates(): array
	{
		return [
			'pfBlockerNG on, pfB-DNS on' => [PfbToggle::On, PfbToggle::On, 'enabled', TRUE],
			'pfBlockerNG off, pfB-DNS on' => [PfbToggle::Off, PfbToggle::On, 'disabled', FALSE],
			'pfBlockerNG on, pfB-DNS off' => [PfbToggle::On, PfbToggle::Off, 'disabled', FALSE],
		];
	}

	/**
	 * issue #3770: pfB-DNS is a parent switch of DNSBL, as the pfBlockerNG enable is: DNSBL stored On with either one off runs the
	 * apply exactly as DNSBL off does, so the DNSBL pipeline is torn down (and pfB-DNS is wanted only while both are on).
	 */
	#[DataProvider('parentSwitchStates')]
	public function testTheApplyRunsDisabledForDnsblStoredOnWheneverAParentSwitchOfItIsOff(PfbToggle $enable, PfbToggle $pfbDns, string $mode, bool $wanted): void
	{
		// Given DNSBL stored On, the Resolver enabled, and the parent switches as the row says
		PfbConfig::writeSystem('gen/enable_cb', $enable);
		PfbConfig::writeSystem('dnsbl/pfb_dnsbl', PfbToggle::On);
		PfbConfig::writeSystem('dnsbl/pfb_dnsvip_auto', PfbToggle::On);
		$this->setProxy($pfbDns === PfbToggle::On);
		$GLOBALS['config']['unbound'] = self::originalResolver();

		// When the apply decides its mode, then it is DNSBL's pipeline that is on, or off, exactly as the switches say
		$this->assertSame([$mode, $wanted], $this->applyDecisionsFor(FALSE));
	}

	/** @return array<string,array{string}> the DNSBL mode the apply runs with */
	public static function dnsblModes(): array
	{
		return ['DNSBL on' => ['enabled'], 'DNSBL off' => ['disabled']];
	}

	/**
	 * Our block with no snapshot still marks the Resolver as the proxy's: Unbound neither loads the DNSBL matcher, which would
	 * filter for a proxy that cannot serve and double-filter once it can, nor drops the inert observer.
	 */
	#[DataProvider('dnsblModes')]
	public function testAnOrphanedResolverKeepsTheMatcherOutOfUnboundAndTheObserverIn(string $mode): void
	{
		// Given pfB-DNS is on, the Resolver carries our block and no snapshot survives
		$this->setProxy(TRUE);
		$GLOBALS['config']['unbound'] = self::movedResolver();
		config_set_path(self::SAVED, '');

		// When the module is applied
		pfb_unbound_python($mode);

		// Then Unbound runs the observer, never the matcher
		$this->assertSame('pfb_upstream_observer', config_get_path('unbound/python_script'));
	}

	// -----------------------------------------------------------------------
	// The write that removes Unbound's python settings: refused is not removed
	// -----------------------------------------------------------------------

	/** The observer's python keys as the proxy-On apply gave them to Unbound, beside the moved Resolver. */
	private function seedObserverInUnbound(): void
	{
		$this->seedMovedResolver();
		config_set_path('unbound/python', '');
		config_set_path('unbound/python_order', 'pre_validator');
		config_set_path('unbound/python_script', 'pfb_upstream_observer');
	}

	private function pfbLogs(): string
	{
		return (string) @file_get_contents($GLOBALS['pfb']['log']) . (string) @file_get_contents($GLOBALS['pfb']['errlog']);
	}

	public function testTheDisabledPassRemovesTheObserverAndSchedulesTheUnmountWhenConfigXmlTakesTheWrite(): void
	{
		// Given the observer in Unbound beside a moved Resolver, pfB-DNS off and DNSBL disabled
		$this->seedObserverInUnbound();
		$this->setProxy(FALSE);
		$this->configXmlOnDisk();
		$this->assertSame('pfb_upstream_observer', $this->onDisk('unbound/python_script'), 'before: config.xml names the observer');

		// When the disabled pass runs and config.xml takes every write
		pfb_unbound_python('disabled');

		// Then the settings are gone from config.xml, and the python mounts are scheduled for unmounting
		$this->assertNull($this->onDisk('unbound/python'), 'no python key remains in config.xml');
		$this->assertSame('', $this->onDisk('unbound/python_script'));
		$this->assertTrue($GLOBALS['pfb']['dnsbl_python_unmount']);
	}

	#[DataProvider('refusedWrites')]
	public function testTheDisabledPassWhoseRemovalOfTheObserverConfigXmlRefusesKeepsItStoredAndUnmountsNothing(mixed $answer): void
	{
		// Given the same state, and a config.xml that refuses the write that removes the python settings (it takes the Resolver's restore)
		$this->seedObserverInUnbound();
		$this->setProxy(FALSE);
		$this->configXmlOnDisk($answer, 'Removing DNSBL Unbound python');
		$this->assertSame('pfb_upstream_observer', $this->onDisk('unbound/python_script'), 'before: config.xml names the observer');

		// When the disabled pass runs
		pfb_unbound_python('disabled');

		// Then the Resolver is back, and the settings are still stored, here and in config.xml: Unbound keeps its script
		$this->assertSame('lan,opt1', $this->onDisk('unbound/active_interface'), 'the restore was written');
		$this->assertSame('pfb_upstream_observer', $this->onDisk('unbound/python_script'), 'config.xml still names the observer');
		$this->assertSame('pfb_upstream_observer', config_get_path('unbound/python_script'), 'and this process holds the stored settings');
		$this->assertTrue(config_path_enabled('unbound', 'python'));

		// ... the python mounts the observer needs are not scheduled for unmounting ...
		$this->assertEmpty($GLOBALS['pfb']['dnsbl_python_unmount'] ?? NULL, 'Unbound still loads the script, so its libraries stay mounted');

		// ... and the log says the settings were not removed, not that they were
		$this->assertStringContainsString('could not be written', $this->pfbLogs());
	}

	// -----------------------------------------------------------------------
	// A removal of Unbound's python settings that config.xml refused: unbound.conf and the staged scripts follow config.xml
	// -----------------------------------------------------------------------

	/** The Resolver back on its own interfaces, with the python settings config.xml still stores for $script (the removal's write was refused). */
	private function seedStoredPython(string $script): void
	{
		$GLOBALS['config']['unbound'] = self::originalResolver() + ['python' => '', 'python_order' => 'pre_validator', 'python_script' => $script];
		$this->setProxy(FALSE);
	}

	/** @return array<string,array{string,string,string}> stored script, the unbound.conf that loads it, and the line that names it there */
	public static function storedScripts(): array
	{
		return [
			'the proxy\'s observer' => ['pfb_upstream_observer', self::CONF_WITH_OBSERVER, 'python-script: pfb_upstream_observer.py'],
			'the DNSBL module'      => ['pfb_unbound', self::CONF_WITH_MODULE, 'python-script: pfb_unbound.py'],
		];
	}

	#[DataProvider('storedScripts')]
	public function testARemovalPassKeepsInUnboundConfTheScriptConfigXmlStillNamesWhenItCouldNotRemoveIt(string $script, string $conf, string $line): void
	{
		// Given Unbound loading a script and the Resolver back on its own interfaces; the removal pass runs with no DNSBL mode
		$this->seedStoredPython($script);
		$this->writeUnboundConf($conf);
		touch("{$this->tmp}/{$script}.py"); // the script is in the chroot, as staged

		// Before: when config.xml took the removal of the python settings, the pass takes the script out of unbound.conf
		$GLOBALS['pfb']['python_removal_failed'] = FALSE;
		$this->assertTrue(pfb_unbound_dnsbl(''), 'before: the script is patched out');
		$this->assertStringNotContainsString($line, $this->patchedConf(), 'before: the patch removes it');

		// When config.xml refused that removal: it still names the script, so unbound.conf and the staged scripts must too
		$this->writeUnboundConf($conf);
		$GLOBALS['pfb']['python_removal_failed'] = TRUE;
		$changed = pfb_unbound_dnsbl('');

		// Then nothing is patched out of unbound.conf (the staged files follow the script Unbound is given: no teardown)
		$this->assertFalse($changed, 'unbound.conf is left as it is');
		$this->assertSame('', $this->patchedConf(), 'no patched copy is written');
		$this->assertStringContainsString($line, (string) file_get_contents("{$this->tmp}/unbound.conf"), 'it still loads the script');
	}

	public function testARefusedRemovalDoesNotKeepInUnboundConfAScriptThatIsGoneFromTheChroot(): void
	{
		// Given config.xml still naming the DNSBL module after a refused removal and unbound.conf loading it, with the script gone from
		// the chroot (a RAM-disk reboot: no package stages pfb_unbound.py any more)
		$this->seedStoredPython('pfb_unbound');
		$this->writeUnboundConf(self::CONF_WITH_MODULE);
		$GLOBALS['pfb']['python_removal_failed'] = TRUE;
		$this->assertFileDoesNotExist("{$this->tmp}/pfb_unbound.py", 'before: the script is not in the chroot');

		// When the pass patches unbound.conf
		$changed = pfb_unbound_dnsbl('');

		// Then the script is patched out: Unbound does not start from a conf whose python-script is missing, and DNS would be down
		$this->assertTrue($changed, 'unbound.conf is patched');
		$this->assertStringNotContainsString('python-script', $this->patchedConf());
		$this->assertStringNotContainsString('module-config: "python', $this->patchedConf());
		$this->assertStringContainsString('module-config: "validator iterator"', $this->patchedConf(), 'the rest of the conf stays');
	}

	public function testAFailedRemovalDoesNotKeepAScriptThatIsNotOurs(): void
	{
		// Given a stored python script of another package, our observer lines in unbound.conf, and the failed-removal flag set
		$this->seedStoredPython('someone_elses_script');
		$this->writeUnboundConf(self::CONF_WITH_OBSERVER);
		$GLOBALS['pfb']['python_removal_failed'] = TRUE;

		// When the pass patches unbound.conf
		$changed = pfb_unbound_dnsbl('');

		// Then only what config.xml names is kept: our observer is patched out as for any removal
		$this->assertTrue($changed);
		$this->assertStringNotContainsString('pfb_upstream_observer.py', $this->patchedConf());
		$this->assertStringNotContainsString('someone_elses_script', $this->patchedConf(), 'a python script that is not pfBlockerNG\'s is never kept or added to unbound.conf, whatever config.xml stores');
	}
}
