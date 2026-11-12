<?php

declare(strict_types=1);

require_once __DIR__ . '/support/PfbFlockClockFixture.php';

use PHPUnit\Framework\TestCase;

/**
 * issue #3896 -- the retired DNSBL module (pfb_unbound.py), the regex rules it imports and its mount hook
 * (pfb_unbound_include.inc) leave Unbound's chroot on the FIRST Update after unbound.conf stops naming the module, and never
 * while the conf Unbound next starts from still names it (#3838: a missing python-script fails the start, so DNS is down).
 *
 * The pass runs as on the appliance: pfb_unbound_dnsbl() stages the chroot and patches unbound.conf into unbound.tmp, then
 * pfb_update_unbound() moves the patch into place and restarts Unbound, rolling the conf back when the start fails. Only the
 * appliance boundaries are doubled: `pfblockerng.sh dnsbl_cache` runs the real script against this test's chroot, and the
 * Unbound start reports the outcome each row names.
 */
final class DnsblRetiredModuleFirstPassTest extends TestCase
{
	private const RETIRED = ['pfb_unbound.py', 'pfb_dnsbl_regex_rules.py', 'pfb_unbound_include.inc'];
	private const LEGACY_CONF = "server:\n\tinterface: 127.0.0.1\n\tmodule-config: \"python validator iterator\"\n\npython:\npython-script: pfb_unbound.py\n";
	private const PFB_KEYS = [
		'dnsbldir', 'dbdir', 'dnsbl_file', 'dnsdir', 'dnsbl_cache', 'unbound_py_count', 'unbound_py_sources',
		'unbound_py_rawdir', 'unbound_py_reject_stats', 'chroot_cmd', 'dnsbl_python_unmount', 'dnsbl_cache_flush',
		'enable', 'dnsbl', 'pfb_dns', 'save', 'dnsbl_tld_wildcard', 'domain_update', 'reuse_dnsbl', 'dnsbl_unlock', 'keep',
		'install', 'errlog', 'log', 'python_removal_failed',
	];

	private string $dir;
	private string $chroot;
	private array $savedPfb = [];
	private array $savedConfig = [];
	private array $savedG = [];
	/** @var array<string,mixed> the apply pass's state: pfb_unbound_dnsbl() rereads config.xml through pfb_global(), the pass then runs on this */
	private array $pass = [];

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_retired_first_pass_' . bin2hex(random_bytes(6));
		$this->chroot = "{$this->dir}/chroot";
		foreach (['chroot', 'pkg', 'db', 'dnsdir'] as $sub) {
			mkdir("{$this->dir}/{$sub}", 0777, TRUE);
		}
		foreach (self::PFB_KEYS as $key) {
			$this->savedPfb[$key] = [array_key_exists($key, $GLOBALS['pfb'] ?? []), $GLOBALS['pfb'][$key] ?? NULL];
		}
		$this->savedConfig = $GLOBALS['config'] ?? [];
		$this->savedG = $GLOBALS['g'] ?? [];

		$this->pass = [
			'dnsbldir' => $this->chroot,
			'dbdir' => "{$this->dir}/db",
			'dnsbl_file' => "{$this->dir}/db/pfb_dnsbl",
			'dnsdir' => "{$this->dir}/dnsdir",
			'dnsbl_cache' => "{$this->dir}/db/pfb_py_cache.sqlite",
			'unbound_py_count' => "{$this->chroot}/pfb_py_count",
			'unbound_py_sources' => "{$this->chroot}/pfb_py_sources.json",
			'unbound_py_rawdir' => "{$this->chroot}/pfb_py_raw",
			'unbound_py_reject_stats' => "{$this->chroot}/pfb_py_reject_stats.json",
			'chroot_cmd' => "{$this->dir}/unbound-control",
			'dnsbl_python_unmount' => FALSE,
			'dnsbl_cache_flush' => PfbToggle::Off,
			'enable' => PfbToggle::On,
			'dnsbl' => PfbToggle::On,
			'pfb_dns' => PfbToggle::On,
			'save' => TRUE,
			'dnsbl_tld_wildcard' => FALSE,
			'domain_update' => FALSE,
			'reuse_dnsbl' => '',
			'dnsbl_unlock' => "{$this->dir}/db/dnsbl_unlock",
			'keep' => PfbToggle::On,
			'install' => FALSE,
			'errlog' => "{$this->dir}/error.log",
			'log' => "{$this->dir}/pfblockerng.log",
		];
		$GLOBALS['pfb'] = array_replace($GLOBALS['pfb'], $this->pass);
		$GLOBALS['g']['varrun_path'] = $this->dir;
		$GLOBALS['g']['unbound_chroot_path'] = $this->chroot;
		$GLOBALS['pfb_test_process_running'] = ['unbound' => TRUE];
		file_put_contents($GLOBALS['pfb']['chroot_cmd'], "#!/bin/sh\nexit 0\n");
		chmod($GLOBALS['pfb']['chroot_cmd'], 0755);
		file_put_contents($GLOBALS['pfb']['unbound_py_sources'], '{"version":1,"config":{},"feeds":[]}');

		// The package's current mount hook, which a kept module gets restaged from.
		file_put_contents("{$this->dir}/pkg/pfb_unbound_include.inc", 'INC-PACKAGE');
		// The real dnsbl_cache, pointed at this chroot and package directory.
		$source = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.sh';
		file_put_contents("{$this->dir}/pfblockerng.sh", "#!/bin/sh\nPFB_SOURCED=1\n. " . escapeshellarg($source) . "\n"
			. 'pfbchroot=' . escapeshellarg($this->chroot) . "\n"
			. 'pfbpkgdir=' . escapeshellarg("{$this->dir}/pkg") . "\n"
			. 'pfbdb=' . escapeshellarg("{$this->dir}/db") . "\n"
			. 'dnsbl_cache "$2"' . "\n");
		chmod("{$this->dir}/pfblockerng.sh", 0755);
	}

	protected function tearDown(): void
	{
		foreach ($this->savedPfb as $key => [$existed, $value]) {
			if ($existed) {
				$GLOBALS['pfb'][$key] = $value;
			} else {
				unset($GLOBALS['pfb'][$key]);
			}
		}
		$GLOBALS['config'] = $this->savedConfig;
		$GLOBALS['g'] = $this->savedG;
		unset($GLOBALS['pfb_test_process_running']);
		rmdir_recursive($this->dir);
	}

	/**
	 * An upgraded box: Unbound's conf loads pfb_unbound.py and the chroot still holds the module, its rules and its mount hook.
	 * config.xml holds what this pass's removal of Unbound's python settings left: cleared, or still the module when it was refused.
	 */
	private function seedUpgradedBox(bool $removalRefused): void
	{
		$GLOBALS['config']['unbound'] = $removalRefused
			? ['enable' => '', 'python' => '', 'python_order' => 'pre_validator', 'python_script' => 'pfb_unbound']
			: ['enable' => '', 'python_script' => ''];
		$GLOBALS['pfb']['python_removal_failed'] = $removalRefused;
		file_put_contents("{$this->chroot}/unbound.conf", self::LEGACY_CONF);
		foreach (self::RETIRED as $file) {
			file_put_contents("{$this->chroot}/{$file}", 'OLD');
		}
	}

	/**
	 * One DNSBL Update, its staging run through the real dnsbl_cache; each Unbound start reports the next of $starts.
	 *
	 * @param list<int> $starts the exit status of each Unbound start, in order
	 */
	private function runOnePass(array $starts): void
	{
		$namespace = (new PfbFlockClockFixture())->loadChain(['pfb_unbound_dnsbl', 'pfb_update_unbound', 'pfb_reload_unbound']);
		$GLOBALS['pfb_test_retired_pass'] = ['script' => "{$this->dir}/pfblockerng.sh", 'starts' => $starts];
		eval(<<<PHP
			namespace {$namespace};
			function exec(string \$command, &\$output = NULL, &\$result_code = NULL) {
				\$command = str_replace('/usr/local/pkg/pfblockerng/pfblockerng.sh', \\escapeshellarg(\$GLOBALS['pfb_test_retired_pass']['script']), \$command);
				return \\exec(\$command, \$output, \$result_code);
			}
			function pfb_stop_start_unbound(): array {
				\$retval = array_shift(\$GLOBALS['pfb_test_retired_pass']['starts']) ?? 0;
				return ['start_completed' => TRUE, 'retval' => \$retval, 'result' => []];
			}
			PHP);

		set_error_handler(static function (int $severity, string $message): bool {
			return $severity === E_NOTICE && str_contains($message, 'tempnam(): file created in the system');
		});
		try {
			($namespace . '\\pfb_unbound_dnsbl')('enabled');
			$GLOBALS['pfb'] = array_replace($GLOBALS['pfb'], $this->pass);
			($namespace . '\\pfb_update_unbound')('enabled', TRUE, TRUE);
		} finally {
			restore_error_handler();
			unset($GLOBALS['pfb_test_retired_pass']);
		}
	}

	/** @return array<string,bool> each retired file, and whether it is in the chroot */
	private function retiredInChroot(): array
	{
		$state = [];
		foreach (self::RETIRED as $file) {
			$state[$file] = file_exists("{$this->chroot}/{$file}");
		}
		return $state;
	}

	private function confNamesModule(): bool
	{
		return str_contains((string) file_get_contents("{$this->chroot}/unbound.conf"), 'python-script: pfb_unbound.py');
	}

	public function testAPassThatTakesTheModuleOutOfUnboundConfRemovesTheRetiredFilesTheSamePass(): void
	{
		// Given an upgraded box whose removal of Unbound's python settings went through, still loading the module before the pass
		$this->seedUpgradedBox(FALSE);
		$this->assertTrue($this->confNamesModule(), 'before: unbound.conf loads the module');
		$this->assertSame(array_fill_keys(self::RETIRED, TRUE), $this->retiredInChroot(), 'before: the retired files are in the chroot');

		// When one Update runs and Unbound starts from the patched conf
		$this->runOnePass([0]);

		// Then Unbound's conf no longer names the module, and none of the retired files is left after this one pass
		$this->assertFalse($this->confNamesModule(), 'the pass took the module out of unbound.conf');
		$this->assertSame(array_fill_keys(self::RETIRED, FALSE), $this->retiredInChroot(), 'the retired files leave on the first pass');
	}

	public function testARefusedRemovalKeepsTheModuleItsRulesAndItsMountHook(): void
	{
		// Given an upgraded box whose removal of Unbound's python settings config.xml refused
		$this->seedUpgradedBox(TRUE);

		// When one Update runs
		$this->runOnePass([0]);

		// Then the conf Unbound starts from still loads the module, so the module, its rules and its current mount hook all stay
		$this->assertTrue($this->confNamesModule(), 'before the verdict: unbound.conf still loads the module');
		$this->assertSame(array_fill_keys(self::RETIRED, TRUE), $this->retiredInChroot(), 'nothing the module needs is removed');
		$this->assertSame('INC-PACKAGE', file_get_contents("{$this->chroot}/pfb_unbound_include.inc"), 'the mount hook is the package copy');
	}

	public function testAStartThatRollsTheConfBackKeepsTheFilesTheRestoredConfLoads(): void
	{
		// Given an upgraded box whose removal went through, and an Unbound that fails to start from the patched conf
		$this->seedUpgradedBox(FALSE);

		// When one Update runs: the failed start restores the previous conf, and Unbound starts from it
		$this->runOnePass([1, 0]);

		// Then that restored conf loads the module again, so nothing it needs is removed
		$this->assertTrue($this->confNamesModule(), 'before the verdict: the previous conf, which loads the module, is back');
		$this->assertSame(array_fill_keys(self::RETIRED, TRUE), $this->retiredInChroot(), 'nothing the restored conf loads is removed');
	}
}
