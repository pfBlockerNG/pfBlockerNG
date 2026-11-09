<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyCertificateFixtures.php';

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3770 -- DNSBL runs only through pfB-DNS: Unbound never loads pfb_unbound.py, whatever the DNSBL mode, the Resolver's
 * ownership or the apply pass's pfB-DNS answer. Unbound may run the inert upstream observer, and only while pfB-DNS owns the
 * Resolver. Both seams are exercised in the order the apply pass runs them: pfb_unbound_python() (config.xml python keys), then
 * pfb_unbound_dnsbl() (the unbound.conf patch). Every row starts from a legacy box that really loads pfb_unbound.py (config.xml
 * and unbound.conf), or from a fresh box that loads nothing, so a "never" is asserted against a start that could fail it.
 */
final class UnboundNeverHostsDnsblModuleTest extends TestCase
{
	private const SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';
	private const DNSBL = 'installedpackages/pfblockerngdnsblsettings/config/0';
	private const BLOCK = "server:\n# pfBlockerNG DNS proxy\nport: 5354\ninterface: 127.0.0.1@5353\ninterface: ::1@5353\n"
		. "proxy-protocol-port: 5353\nedns-buffer-size: 1432\n# end pfBlockerNG DNS proxy";
	private const LEGACY_KEYS = ['python' => '', 'python_order' => 'pre_validator', 'python_script' => 'pfb_unbound'];
	private const LEGACY_CONF = "server:\n\tinterface: 127.0.0.1\n\tmodule-config: \"python validator iterator\"\n\npython:\npython-script: pfb_unbound.py\n";
	private const FRESH_CONF = "server:\n\tinterface: 127.0.0.1\n\tmodule-config: \"validator iterator\"\n";

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
		$this->tmp = sys_get_temp_dir() . '/pfb_unbound_no_module_' . uniqid('', TRUE);
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
		// Answers the mount probe pfb_unbound_python() runs: nothing mounted.
		file_put_contents("{$this->tmp}/grep_double", "#!/bin/sh\nexit 0\n");
		chmod("{$this->tmp}/grep_double", 0755);
		$GLOBALS['pfb']['grep'] = "{$this->tmp}/grep_double";
		$this->seedPackageConfig();
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
			$GLOBALS['pfb_test_file_notices']);
		rmdir_recursive($this->tmp);
	}

	private function seedPackageConfig(): void
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
		$GLOBALS['pfb']['dnsbl_tld_wildcard'] = '';
		$GLOBALS['pfb']['dnsbl_control'] = PfbToggle::Off;
		$GLOBALS['pfb']['dnsbl_control_legacy'] = PfbToggle::Off;
	}

	/** The user's Resolver before pfB-DNS touched it. */
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

	/** The same Resolver as pfB-DNS leaves it: on loopback, our block appended. */
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

	/**
	 * Seed the Resolver the row starts from, and the unbound.conf pfSense generated from it.
	 *
	 * @param string $start 'no snapshot' (pfB-DNS never moved it), 'valid snapshot' (pfB-DNS owns it), 'move refused' (Listen Port 5353: pfB-DNS cannot take it)
	 */
	private function seedBox(bool $legacy, string $start, bool $wanted): void
	{
		$resolver = match ($start) {
			'no snapshot'    => self::originalResolver(),
			'valid snapshot' => self::movedResolver(),
			'move refused'   => ['port' => '5353'] + self::originalResolver(),
		};
		$GLOBALS['config']['unbound'] = $legacy ? $resolver + self::LEGACY_KEYS : $resolver;
		if ($start === 'valid snapshot') {
			config_set_path(self::SAVED, self::snapshotOfOriginal());
		}
		PfbConfig::writeSystem('dns/pfb_dns', $wanted ? PfbToggle::On : PfbToggle::Off);
		file_put_contents("{$this->tmp}/unbound.conf", $legacy ? self::LEGACY_CONF : self::FRESH_CONF);
		@unlink("{$this->tmp}/unbound.tmp");
	}

	/** The unbound.conf Unbound will load: the patched copy when the pass wrote one, else the generated file. */
	private function loadedConf(): string
	{
		$patched = "{$this->tmp}/unbound.tmp";
		return (string) file_get_contents(file_exists($patched) ? $patched : "{$this->tmp}/unbound.conf");
	}

	/** @return list<string> the script names of every `python-script:` line */
	private static function scriptLines(string $conf): array
	{
		preg_match_all('/^python-script:\s*(\S+)/m', $conf, $matches);
		return $matches[1];
	}

	/** @return array<string,array{bool,string,string,bool}> legacy box, DNSBL mode, the Resolver the pass starts from, the apply's pfB-DNS answer */
	public static function combinations(): array
	{
		$rows = [];
		foreach ([TRUE, FALSE] as $legacy) {
			foreach (['enabled', 'disabled'] as $mode) {
				foreach (['no snapshot', 'valid snapshot', 'move refused'] as $start) {
					foreach ([TRUE, FALSE] as $wanted) {
						$rows[($legacy ? 'legacy' : 'fresh') . " box, DNSBL {$mode}, Resolver: {$start}, pfB-DNS " . ($wanted ? 'wanted' : 'not wanted')]
							= [$legacy, $mode, $start, $wanted];
					}
				}
			}
		}
		return $rows;
	}

	#[DataProvider('combinations')]
	public function testUnboundNeverLoadsThePfbUnboundModuleInAnyMode(bool $legacy, string $mode, string $start, bool $wanted): void
	{
		// Given the box, with the proof that a legacy one really loads pfb_unbound.py today
		$this->seedBox($legacy, $start, $wanted);
		if ($legacy) {
			$this->assertSame('pfb_unbound', config_get_path('unbound/python_script'), 'before: config.xml names the module');
			$this->assertSame(['pfb_unbound.py'], self::scriptLines($this->loadedConf()), 'before: unbound.conf loads the module');
		}

		// When the apply pass runs both Unbound seams
		pfb_unbound_python($mode, $wanted);
		pfb_unbound_dnsbl($mode);

		// Then neither config.xml nor the unbound.conf Unbound loads names pfb_unbound
		$conf = $this->loadedConf();
		$this->assertNotSame('pfb_unbound', config_get_path('unbound/python_script'), 'config.xml does not name the module');
		$this->assertStringNotContainsString('pfb_unbound.py', $conf, 'unbound.conf does not load the module');

		// ... only the observer, and only while pfB-DNS owns the Resolver; with nothing owned Unbound runs no pfBlockerNG python
		if (pfb_dns_proxy_owns_resolver()) {
			$this->assertSame('pfb_upstream_observer', config_get_path('unbound/python_script'));
			$this->assertSame(['pfb_upstream_observer.py'], self::scriptLines($conf));
		} else {
			$this->assertFalse(config_path_enabled('unbound', 'python'), 'no python keys in config.xml');
			$this->assertSame([], self::scriptLines($conf), 'no python script in unbound.conf');
			$this->assertStringNotContainsString('module-config: "python', $conf, 'no python module in the chain');
		}
	}

	/** @return array<string,array{bool,string}> legacy box, DNSBL mode */
	public static function ownedRows(): array
	{
		$rows = [];
		foreach ([TRUE, FALSE] as $legacy) {
			foreach (['enabled', 'disabled'] as $mode) {
				$rows[($legacy ? 'legacy' : 'fresh') . " box, DNSBL {$mode}"] = [$legacy, $mode];
			}
		}
		return $rows;
	}

	#[DataProvider('ownedRows')]
	public function testWhilePfbDnsOwnsTheResolverUnboundIsGivenTheObserver(bool $legacy, string $mode): void
	{
		// Given pfB-DNS wanted, with the Resolver it already moved (control: the assertions above can see a python-script line)
		$this->seedBox($legacy, 'valid snapshot', TRUE);

		// When the apply pass runs both Unbound seams
		pfb_unbound_python($mode, TRUE);
		pfb_unbound_dnsbl($mode);

		// Then config.xml and unbound.conf both give Unbound the observer, whatever the DNSBL mode
		$this->assertSame([TRUE, 'pre_validator', 'pfb_upstream_observer'], [
			config_path_enabled('unbound', 'python'), config_get_path('unbound/python_order'), config_get_path('unbound/python_script'),
		]);
		$this->assertSame(['pfb_upstream_observer.py'], self::scriptLines($this->loadedConf()));
	}
}
