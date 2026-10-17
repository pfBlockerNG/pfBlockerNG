<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- while the experimental DNS proxy is on, the proxy hosts pfb_unbound.py and
 * Unbound must NOT load it; every path that turns the proxy off (toggle, DNSBL disabled, the
 * setup wizard's reset, the package's own uninstall pass) hands the Resolver and the module
 * back exactly as they were.
 *
 * Seams under test: pfb_unbound_python() (config.xml python keys + the Resolver move),
 * pfb_unbound_dnsbl() (the unbound.conf patch), the wizard's reset step and the apply pass's
 * mode computation. The moved state is seeded by hand in the restore rows, so they pin the
 * documented snapshot format and not just the writer's own round trip.
 */
final class DnsProxyModuleGatingTest extends TestCase
{
	private const LINE = 'proxy-protocol-port: 5353';
	private const SAVED = 'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dns_proxy_saved';
	private const DNSBL = 'installedpackages/pfblockerngdnsblsettings/config/0';

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
			'unbound_py_module_src' => ["{$this->tmp}/absent_a.py", "{$this->tmp}/absent_b.py"],
			'unbound_py_module_applied' => "{$this->tmp}/pfb_py_module.applied",
		]);
		unset($GLOBALS['pfb']['dnsbl_python_unmount']);
		$this->useMountState(TRUE);
		$this->seedPackageConfig(FALSE);
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
		unset($GLOBALS['pfb_test_write_config_calls'], $GLOBALS['pfb_test_unbound_configure_calls'], $GLOBALS['pfb_test_unbound_configure_resolver']);
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
			'pfb_min' => '0', 'pfb_hour' => '0', 'pfb_dailystart' => '0', 'skipfeed' => '0',
		]);
		PfbConfig::writeSectionSystem('installedpackages/pfblockerngipsettings/config/0', [
			'suppression' => '', 'database_cc' => '', 'asn_token' => '', 'maxmind_account' => '',
			'maxmind_key' => '', 'maxmind_locale' => 'en', 'asn_reporting' => 'disabled',
		]);
		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '8.8.8.8');
		PfbConfig::writeSectionSystem(self::DNSBL, [
			'pfb_dnsvip4' => '', 'pfb_dnsvip6' => '', 'pfb_dnsport' => '8081', 'pfb_dnsport_ssl' => '8443',
			'top1m_enable' => '', 'pfb_cache' => '', 'pfb_py_reply' => '', 'pfb_regex' => '', 'pfb_regex_list' => '',
			'pfb_cname' => '', 'tld_allow' => '', 'tld_wildcard' => '',
			'pfb_gp' => '', 'pfb_gp_bypass_list' => '', 'whitelist' => '', 'pfb_py_nolog' => '', 'pfb_noaaaa' => '', 'pfb_noaaaa_list' => '',
			'pfb_dnsbl' => '', 'pfb_dnsvip_auto' => '', 'dnsbl_interface' => 'lo0',
			'pfb_dns_proxy' => $proxy ? 'on' : '',
		]);
		$GLOBALS['pfb']['dnsbl_tld_wildcard'] = '';
		$GLOBALS['pfb']['dnsbl_control'] = PfbToggle::Off;
		$GLOBALS['pfb']['dnsbl_control_legacy'] = PfbToggle::Off;
	}

	private function setProxy(bool $on): void
	{
		PfbConfig::writeSystem('dnsbl/pfb_dns_proxy', $on ? PfbToggle::On : PfbToggle::Off);
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

	/** The same Resolver as the proxy leaves it. */
	private static function movedResolver(): array
	{
		$moved = self::originalResolver();
		$moved['port'] = '5353';
		$moved['active_interface'] = 'lo0';
		unset($moved['enablessl']);
		$moved['custom_options'] = base64_encode(self::LINE . "\ndo-ip6: no\nprefetch: yes");
		return $moved;
	}

	private static function snapshotOfOriginal(): string
	{
		$original = self::originalResolver();
		$keys = [];
		foreach (['port', 'active_interface', 'enablessl', 'custom_options'] as $key) {
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
	// G1 -- proxy off: exactly today's behaviour
	// -----------------------------------------------------------------------

	public function testProxyOffPutsTheModuleIntoUnboundAndLeavesTheResolverAlone(): void
	{
		// Given the proxy off and a Resolver without the module.
		$GLOBALS['config']['unbound'] = self::originalResolver();
		$this->assertFalse($this->pythonModuleKeysSet(), 'before: no module keys');

		// When DNSBL is applied.
		pfb_unbound_python('enabled');

		// Then the module keys are set, the Resolver is untouched and nothing regenerated unbound.conf.
		$this->assertTrue($this->pythonModuleKeysSet());
		$unbound = config_get_path('unbound');
		unset($unbound['python'], $unbound['python_order'], $unbound['python_script']);
		$this->assertSame(self::sorted(self::originalResolver()), self::sorted($unbound));
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
		$this->assertSame('53', config_get_path('unbound/port'), 'before: the Resolver is not moved');

		// When DNSBL is applied.
		$changed = pfb_unbound_python('enabled');

		// Then a restart is signalled, the module keys are gone and the Resolver is moved ...
		$this->assertTrue($changed);
		$this->assertFalse(config_path_enabled('unbound', 'python'));
		$this->assertSame('', config_get_path('unbound/python_script'));
		$this->assertSame('5353', config_get_path('unbound/port'));
		$this->assertSame('lo0', config_get_path('unbound/active_interface'));
		$this->assertNotSame('', $this->savedRaw());

		// ... unbound.conf is regenerated from config.xml exactly once, without restarting DHCP ...
		$this->assertSame([FALSE], $this->configureCalls());
		$this->assertSame('5353', $this->resolverWhenConfigured()['port'], 'unbound.conf is rendered from the moved Resolver');
		$this->assertArrayNotHasKey('python', $this->resolverWhenConfigured(), 'with the module keys already out');

		// ... and the module's own inputs are still produced, because the proxy loads the module from them.
		$this->assertFileExists($GLOBALS['pfb']['unbound_py_conf']);
		$this->assertFileExists($GLOBALS['pfb']['unbound_py_wh']);
	}

	public function testProxyOnLeavesAUsersOwnPythonModuleKeysAlone(): void
	{
		// Given the proxy on and a Resolver running the admin's own python module.
		$this->setProxy(TRUE);
		$GLOBALS['config']['unbound'] = self::originalResolver() + [
			'python' => '', 'python_order' => 'pre_validator', 'python_script' => 'mymodule',
		];

		// When DNSBL is applied.
		pfb_unbound_python('enabled');

		// Then the module keys are not ours to remove.
		$this->assertTrue(config_path_enabled('unbound', 'python'));
		$this->assertSame('mymodule', config_get_path('unbound/python_script'));
		$this->assertSame('pre_validator', config_get_path('unbound/python_order'));
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

	public function testMountsHappenOnlyWhenTheModuleGoesIntoUnbound(): void
	{
		// Given nothing mounted; the proxy off first, to prove this harness reaches the mount code.
		$this->useMountState(FALSE);
		$GLOBALS['config']['unbound'] = self::originalResolver();
		pfb_unbound_python('enabled');
		$this->assertStringContainsString('Mounting: /usr/local/bin', $this->pfbLog(), 'before: proxy off mounts');

		// When the proxy is on.
		@unlink($GLOBALS['pfb']['log']);
		$this->setProxy(TRUE);
		$GLOBALS['config']['unbound'] = self::originalResolver();
		pfb_unbound_python('enabled');

		// Then Unbound is not given the module's mounts.
		$this->assertStringNotContainsString('Mounting:', $this->pfbLog());
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

	public function testDnsblDisabledRestoresTheResolverAndKeepsTheModuleOut(): void
	{
		// Given a moved Resolver (the toggle stays on; DNSBL is what gets disabled).
		$this->setProxy(TRUE);
		$this->seedMovedResolver();
		$this->assertSame('5353', config_get_path('unbound/port'), 'before: moved');

		// When the disabled pass runs.
		pfb_unbound_python('disabled');

		// Then the Resolver is back, the module keys are absent, unbound.conf was regenerated once.
		$this->assertResolverRestored('disabled pass');
		$this->assertFalse($this->pythonModuleKeysSet());
		$this->assertSame([FALSE], $this->configureCalls());
		$this->assertSame('53', $this->resolverWhenConfigured()['port'], 'unbound.conf is rendered from the restored Resolver');
		$this->assertArrayNotHasKey('python', $this->resolverWhenConfigured(), 'with the module keys out');
		$this->assertTrue($GLOBALS['pfb']['dnsbl_python_unmount'], 'the disabled pass still schedules the unmount');
	}

	public function testAnUndefinedModeRestoresTheResolverToo(): void
	{
		// Given a moved Resolver and a pass whose mode is '' (DNSBL on, Resolver disabled).
		$this->setProxy(TRUE);
		$this->seedMovedResolver();

		pfb_unbound_python('');

		$this->assertResolverRestored("mode ''");
		$this->assertSame([FALSE], $this->configureCalls());
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

	public function testProxyTurnedOffRestoresTheResolverAndPutsTheModuleBack(): void
	{
		// Given a moved Resolver, then the admin unticks the toggle.
		$this->seedMovedResolver();
		$this->setProxy(FALSE);
		$this->assertFalse($this->pythonModuleKeysSet(), 'before: the module is out of Unbound');

		// When DNSBL is applied.
		$changed = pfb_unbound_python('enabled');

		// Then the Resolver is back, the module keys are set again and unbound.conf was regenerated once.
		$this->assertTrue($changed);
		$this->assertResolverRestored('toggle off', ['python' => '', 'python_order' => 'pre_validator', 'python_script' => 'pfb_unbound']);
		$this->assertTrue($this->pythonModuleKeysSet());
		$this->assertSame([FALSE], $this->configureCalls());
		$this->assertSame('53', $this->resolverWhenConfigured()['port'], 'unbound.conf is rendered from the restored Resolver');
		$this->assertSame('pfb_unbound', $this->resolverWhenConfigured()['python_script'], 'with the module keys back');
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

	public function testUnboundConfLosesTheModuleWhileASnapshotExists(): void
	{
		// Given a conf that loads the module and a snapshot (the proxy owns the module).
		$this->seedMovedResolver();
		$this->writeUnboundConf(self::CONF_WITH_MODULE);
		$this->assertStringContainsString('python-script: pfb_unbound.py', self::CONF_WITH_MODULE);

		// When the enabled pass patches it.
		$changed = pfb_unbound_dnsbl('enabled');

		// Then the module is removed from Unbound's module chain and its script block is gone.
		$this->assertTrue($changed);
		$patched = $this->patchedConf();
		$this->assertStringContainsString('module-config: "validator iterator"', $patched);
		$this->assertStringNotContainsString('python', $patched);
		$this->assertStringContainsString('interface: 127.0.0.1', $patched, 'unrelated lines survive');
	}

	public function testUnboundConfGainsTheModuleWithoutASnapshot(): void
	{
		// Given a conf without the module and no snapshot (proxy off).
		$this->writeUnboundConf(self::CONF_WITHOUT_MODULE);
		$this->assertStringNotContainsString('python', self::CONF_WITHOUT_MODULE);

		// When the enabled pass patches it.
		$changed = pfb_unbound_dnsbl('enabled');

		// Then the module and its script block are added.
		$this->assertTrue($changed);
		$patched = $this->patchedConf();
		$this->assertStringContainsString('module-config: "python validator iterator"', $patched);
		$this->assertStringContainsString("python:\npython-script: pfb_unbound.py", $patched);
	}

	public function testToggleOnWithALostMarkerOnAMovedResolverKeepsTheModuleOutOfBothSeams(): void
	{
		// Given the toggle on, a Resolver that already looks moved, the marker lost, and a python key set the
		// move cannot take over: pfb_dns_proxy_resolver() refuses, and the owner rule still holds.
		$this->setProxy(TRUE);
		$GLOBALS['config']['unbound'] = self::movedResolver() + [
			'python' => '', 'python_order' => 'pre_validator', 'python_script' => 'pfb_unbound',
		];
		$this->assertSame('', $this->savedRaw(), 'before: no snapshot');
		$this->writeUnboundConf(self::CONF_WITH_MODULE);

		// When both seams run.
		pfb_unbound_python('enabled');
		$changed = pfb_unbound_dnsbl('enabled');

		// Then the move was refused (nothing snapshotted) yet neither seam hands Unbound the module.
		$this->assertSame('', $this->savedRaw(), 'the refusal stored no snapshot');
		$this->assertFalse($this->pythonModuleKeysSet(), 'config.xml python keys');
		$this->assertTrue($changed, 'unbound.conf was rewritten');
		$this->assertStringNotContainsString('python', $this->patchedConf(), 'unbound.conf module');
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

	public function testModuleFilesAreStagedByModeNotBySnapshot(): void
	{
		// The staging exec targets an absolute appliance path with no test seam, so the decision
		// is pinned in the source: the proxy imports the staged module, so it must stay staged.
		$ref = new ReflectionFunction('pfb_unbound_dnsbl');
		$body = implode('', array_slice(
			(array) file((string) $ref->getFileName()),
			$ref->getStartLine() - 1,
			$ref->getEndLine() - $ref->getStartLine() + 1
		));

		$this->assertMatchesRegularExpression(
			"/if \\(\\\$mode == 'enabled'\\) \\{\\s*(?:\\/\\/[^\\n]*\\n\\s*)*exec\\('[^']*dnsbl_cache stage/",
			$body,
			'staging must follow the mode, not whether a snapshot exists'
		);
	}

	// -----------------------------------------------------------------------
	// W1 -- the setup wizard's reset
	// -----------------------------------------------------------------------

	public function testWizardResetRestoresTheResolverBeforeItSweepsThePackageConfig(): void
	{
		// Given a moved Resolver whose snapshot lives in the package config the wizard is about to sweep.
		$this->setProxy(TRUE);
		$this->seedMovedResolver();
		$this->assertSame('5353', config_get_path('unbound/port'), 'before: moved');
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

	// -----------------------------------------------------------------------
	// U1 -- the package's own uninstall pass
	// -----------------------------------------------------------------------

	/** The apply pass's own mode computation (pfblockerng_apply.inc), run against the real pfb_global(). */
	private function applyModeFor(bool $install): string
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
		$pfb = &$GLOBALS['pfb'];
		eval(substr($source, (int) $start, (int) $end - (int) $start));
		return (string) $mode;
	}

	public function testUninstallDisablePassRestoresTheResolver(): void
	{
		// Given pfBlockerNG fully on with a moved Resolver: on its own, the apply pass runs 'enabled'.
		PfbConfig::writeSystem('gen/enable_cb', PfbToggle::On);
		PfbConfig::writeSystem('dnsbl/pfb_dnsbl', PfbToggle::On);
		PfbConfig::writeSystem('dnsbl/pfb_dnsvip_auto', PfbToggle::On);
		$this->setProxy(TRUE);
		$this->seedMovedResolver();
		$this->assertSame('enabled', $this->applyModeFor(FALSE), 'before: a normal pass is enabled');
		$this->assertSame('5353', config_get_path('unbound/port'), 'before: moved');

		// When pfblockerng_php_pre_deinstall_command()'s flag turns the pass into a disable pass.
		$mode = $this->applyModeFor(TRUE);

		// Then the pass is 'disabled', and its Unbound step hands the Resolver back.
		$this->assertSame('disabled', $mode);
		pfb_unbound_python($mode);
		$this->assertResolverRestored('uninstall disable pass');
	}
}
