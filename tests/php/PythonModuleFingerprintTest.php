<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #3125 -- the DNSBL module fingerprint drives a Resolver restart signal.
 *
 * pfb_unbound_py_module_fingerprint() digests the SHIPPED python module pair
 * (sha256 concat, pfb_unbound.py first, no separator); pfb_unbound_python('enabled')
 * signals a restart whenever the applied marker (pfb_py_module.applied, written by
 * the python module at init) trims to anything else -- and stays silent when the
 * marker matches. The PARITY_FP literal is pinned identically in
 * tests/test_module_fingerprint.py; a digest-recipe change in either language
 * fails one of the two pins.
 */
final class PythonModuleFingerprintTest extends TestCase
{
	private const PARITY_FP = 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb'
		. '3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d';
	private const EMPTY_FP = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
		. 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

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
		$this->tmp = sys_get_temp_dir() . '/pfb_py_module_' . uniqid('', TRUE);
		mkdir($this->tmp, 0777, TRUE);
		$GLOBALS['pfb'] = array_merge($this->originalPfb, [
			'logdir'          => $this->tmp,
			'log'             => "{$this->tmp}/pfb.log",
			'errlog'          => "{$this->tmp}/pfb.err",
			'dnsbldir'        => $this->tmp,
			'unbound_py_conf' => "{$this->tmp}/pfb_unbound.ini",
			'unbound_py_wh'   => "{$this->tmp}/pfb_whitelist.txt",
			'unbound_py_sources' => "{$this->tmp}/pfb_sources.json",
			'unbound_py_module_src' => [
				"{$this->tmp}/pfb_unbound.py",
				"{$this->tmp}/pfb_dnsbl_regex_rules.py",
			],
			'unbound_py_module_applied' => "{$this->tmp}/pfb_py_module.applied",
		]);
		// The mount validate in pfb_unbound_python() is appliance runtime (nullfs);
		// this double answers "already mounted" so the return value reflects ONLY the
		// ini/whitelist/module compares, exactly the steady state these rows assume.
		file_put_contents("{$this->tmp}/mounted_grep", "#!/bin/sh\nprintf '%s\\n' mounted\n");
		chmod("{$this->tmp}/mounted_grep", 0755);
		$GLOBALS['pfb']['grep'] = "{$this->tmp}/mounted_grep";
		$this->seedConfig();
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
		rmdir_recursive($this->tmp);
	}

	private function seedConfig(): void
	{
		$gen = 'installedpackages/pfblockerng/config/0';
		$ip = 'installedpackages/pfblockerngipsettings/config/0';
		$dnsbl = 'installedpackages/pfblockerngdnsblsettings/config/0';
		PfbConfig::writeSectionSystem($gen, ['pfb_min' => '0', 'pfb_hour' => '0', 'pfb_dailystart' => '0', 'skipfeed' => '0']);
		PfbConfig::writeSectionSystem($ip, [
			'suppression' => '', 'database_cc' => '', 'asn_token' => '', 'maxmind_account' => '',
			'maxmind_key' => '', 'maxmind_locale' => 'en', 'asn_reporting' => 'disabled',
		]);
		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '8.8.8.8');
		PfbConfig::writeSectionSystem($dnsbl, [
			'pfb_dnsvip4' => '', 'pfb_dnsvip6' => '', 'pfb_dnsport' => '8081', 'pfb_dnsport_ssl' => '8443',
			'top1m_enable' => '', 'pfb_cache' => '', 'pfb_py_reply' => '', 'pfb_regex' => '', 'pfb_regex_list' => '',
			'pfb_cname' => '', 'tld_allow' => '', 'tld_wildcard' => '',
			'pfb_gp' => '', 'pfb_gp_bypass_list' => '', 'whitelist' => '', 'pfb_py_nolog' => '', 'pfb_noaaaa' => '', 'pfb_noaaaa_list' => '',
			'pfb_dnsbl' => '', 'pfb_dnsvip_auto' => '', 'dnsbl_interface' => 'lo0',
		]);
		$GLOBALS['pfb']['dnsbl_tld_wildcard'] = '';
		$GLOBALS['pfb']['dnsbl_control'] = PfbToggle::Off;
		$GLOBALS['pfb']['dnsbl_control_legacy'] = PfbToggle::Off;
	}

	private function shipFiles(string $a = 'a', string $b = 'b'): void
	{
		file_put_contents($GLOBALS['pfb']['unbound_py_module_src'][0], $a);
		file_put_contents($GLOBALS['pfb']['unbound_py_module_src'][1], $b);
	}

	private function markerPath(): string
	{
		return $GLOBALS['pfb']['unbound_py_module_applied'];
	}

	// -----------------------------------------------------------------------
	// pfb_unbound_py_module_fingerprint() -- direct contract
	// -----------------------------------------------------------------------

	public function testFingerprintTwoFilesMatchesParityLiteral(): void
	{
		// H1: for file bytes "a" and "b" the digest is the cross-language constant.
		$this->shipFiles();
		$this->assertSame(self::PARITY_FP, pfb_unbound_py_module_fingerprint($GLOBALS['pfb']['unbound_py_module_src']));
	}

	public function testFingerprintUnreadableOrMissingPathIsFalse(): void
	{
		// H2: any unreadable member poisons the whole fingerprint -> FALSE, so an
		// unreadable shipped file never fakes a restart signal. The missing-path
		// shape runs under every uid; the chmod'd shape only when permissions bite.
		$this->shipFiles();
		$missing = "{$this->tmp}/absent.py";
		$this->assertFalse(pfb_unbound_py_module_fingerprint([$missing, $GLOBALS['pfb']['unbound_py_module_src'][1]]));

		if (function_exists('posix_getuid') && posix_getuid() === 0) {
			return;
		}
		$locked = "{$this->tmp}/locked.py";
		file_put_contents($locked, 'secret');
		chmod($locked, 0000);
		try {
			$this->assertFalse(pfb_unbound_py_module_fingerprint([$locked, $GLOBALS['pfb']['unbound_py_module_src'][1]]));
		} finally {
			chmod($locked, 0644);
		}
	}

	// -----------------------------------------------------------------------
	// pfb_unbound_python('enabled') -- the restart signal
	// -----------------------------------------------------------------------

	public function testMarkerAbsentSignalsRestartAndLogs(): void
	{
		// H3: absent marker (fresh stage the running module never recorded) = drift.
		$this->shipFiles();
		$this->assertTrue(pfb_unbound_python('enabled'));
		$log = (string) file_get_contents($GLOBALS['pfb']['log']);
		$this->assertStringContainsString('DNSBL Unbound python module changed -- Resolver restart required', $log);
	}

	public function testMarkerMatchingFingerprintConvergesToFalse(): void
	{
		// H4: call 1 writes the ini + whitelist (returns TRUE, before-state); with the
		// marker already equal, call 2 has NOTHING left to signal -> FALSE.
		$this->shipFiles();
		file_put_contents($this->markerPath(), self::PARITY_FP . "\n");
		$this->assertTrue(pfb_unbound_python('enabled'), 'first call must write ini + whitelist (before-state)');
		$this->assertFalse(pfb_unbound_python('enabled'));
	}

	public function testMarkerHoldingDifferentFingerprintKeepsSignaling(): void
	{
		// H5: a stale-but-wellformed marker (module changed since) = drift, again.
		$this->shipFiles();
		file_put_contents($this->markerPath(), str_repeat('f', 128) . "\n");
		$this->assertTrue(pfb_unbound_python('enabled'));
		$this->assertTrue(pfb_unbound_python('enabled'));
	}

	public function testUnreadableShippedFileSuppressesSignal(): void
	{
		// H6: fingerprint FALSE = nothing to compare -> NO signal (second call FALSE),
		// even though the marker is absent. False alarm beats restart, never the reverse.
		$this->shipFiles();
		$GLOBALS['pfb']['unbound_py_module_src'][0] = "{$this->tmp}/absent.py";
		$this->assertTrue(pfb_unbound_python('enabled'), 'first call still writes ini + whitelist (before-state)');
		$this->assertFalse(pfb_unbound_python('enabled'));
	}

	public function testDisabledModeNeverSignals(): void
	{
		// H7: the module compare lives ONLY in the enabled branch.
		$this->shipFiles();
		$this->assertFalse(pfb_unbound_python('disabled'));
	}

	public function testMarkerSurroundingWhitespaceStillMatches(): void
	{
		// H8: the marker is read trim()'d -- the writer's trailing newline (plus any
		// stray padding) must not fake a drift.
		$this->shipFiles();
		file_put_contents($this->markerPath(), '  ' . self::PARITY_FP . "  \n");
		$this->assertTrue(pfb_unbound_python('enabled'), 'first call writes ini + whitelist (before-state)');
		$this->assertFalse(pfb_unbound_python('enabled'));
	}

	public function testMarkerJunkIsDifferentNeverCrashes(): void
	{
		// Hostile (brief S5): a junk marker -- 128 non-hex chars, or 10 MB of it --
		// is just "different" (restart signal); never parsed as anything else.
		$this->shipFiles();
		file_put_contents($this->markerPath(), str_repeat('z', 128));
		$this->assertTrue(pfb_unbound_python('enabled'));

		file_put_contents($this->markerPath(), str_repeat('x', 10 * 1024 * 1024));
		$this->assertTrue(pfb_unbound_python('enabled'));
	}

	public function testEmptiedShippedFilesStillFingerprintAsString(): void
	{
		// Hostile (brief S5): emptied shipped files fingerprint to the sha256-of-empty
		// pair -- still a string, still compares normally, no special case.
		$this->shipFiles('', '');
		$this->assertSame(self::EMPTY_FP, pfb_unbound_py_module_fingerprint($GLOBALS['pfb']['unbound_py_module_src']));
	}
}
