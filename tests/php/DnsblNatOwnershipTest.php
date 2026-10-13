<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3488 — a NAT rule is pfBlockerNG-owned only when its descr is EXACTLY
 * PFB_MANAGED_NAT_DESCR (or carries the pfB_ prefix). A user rule whose descr merely contains
 * 'pfB DNSBL' (e.g. 'my pfB DNSBL test') is never rebuilt on enable and never removed on disable.
 */
#[CoversFunction('pfb_create_dnsbl')]
#[CoversFunction('pfb_is_managed_obj')]
final class DnsblNatOwnershipTest extends TestCase
{
	/** A user rule whose descr only contains the marker; every field is distinctive so any rewrite shows. */
	private const USER_ROW = [
		'source' => ['any' => ''], 'destination' => ['address' => '198.51.100.7', 'port' => '8080'], 'protocol' => 'tcp',
		'target' => '10.9.8.7', 'local-port' => '8888', 'interface' => 'lan', 'descr' => 'my pfB DNSBL test',
		'associated-rule-id' => 'pass', 'created' => ['time' => '1700000000', 'username' => 'admin@192.0.2.1'],
	];
	private const PLAIN_ROW = ['descr' => 'user rule', 'interface' => 'wan', 'target' => '10.0.0.9'];
	/** The package's own rule from a previous apply, now stale. */
	private const STALE_ROW = [
		'source' => ['any' => ''], 'destination' => ['address' => '192.0.2.1', 'port' => '80'], 'protocol' => 'tcp',
		'target' => '127.0.0.1', 'local-port' => '1', 'interface' => 'STALE_IFACE', 'descr' => 'pfB DNSBL - DO NOT EDIT',
		'associated-rule-id' => 'pass',
	];

	private string $dir;
	private mixed $savedConfig;
	private mixed $savedPfb;

	protected function setUp(): void
	{
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$this->savedPfb    = $GLOBALS['pfb'] ?? NULL;
		$this->dir         = sys_get_temp_dir() . '/pfb_dnsbl_nat_' . bin2hex(random_bytes(6));
		mkdir($this->dir, 0700);

		$GLOBALS['pfb_test_file_notices']       = [];
		$GLOBALS['pfb_test_logger_calls']       = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
	}

	protected function tearDown(): void
	{
		foreach (scandir($this->dir) ?: [] as $entry) {
			if ($entry !== '.' && $entry !== '..') {
				unlink("{$this->dir}/{$entry}");
			}
		}
		rmdir($this->dir);
		if ($this->savedConfig === NULL) {
			unset($GLOBALS['config']);
		} else {
			$GLOBALS['config'] = $this->savedConfig;
		}
		if ($this->savedPfb === NULL) {
			unset($GLOBALS['pfb']);
		} else {
			$GLOBALS['pfb'] = $this->savedPfb;
		}
		unset($GLOBALS['pfb_test_file_notices'], $GLOBALS['pfb_test_logger_calls'], $GLOBALS['pfb_test_write_config_calls'], $GLOBALS['pfb_test_vip_list']);
	}

	/**
	 * The minimum a manual-mode, valid-VIP DNSBL needs for pfb_create_dnsbl() to reach the NAT
	 * generation off-appliance (same seed as SyncCopiedObjectsTest::seedNatWriter), with the
	 * three NAT rows under test in config.
	 */
	private function seedConfig(): void
	{
		global $pfb;

		$GLOBALS['config'] = [];
		$pfb['dbdir']      = $this->dir;
		$pfb['dnsbl_conf'] = "{$this->dir}/lighty.conf";
		$pfb['dnsbl_cert'] = "{$this->dir}/cert.pem";
		touch($pfb['dnsbl_cert']);

		$gen   = 'installedpackages/pfblockerng/config/0';
		$ip    = 'installedpackages/pfblockerngipsettings/config/0';
		$dnsbl = 'installedpackages/pfblockerngdnsblsettings/config/0';
		foreach (['pfb_min' => '0', 'pfb_hour' => '0', 'pfb_dailystart' => '0', 'skipfeed' => '0'] as $key => $value) {
			config_set_path("{$gen}/{$key}", $value);
		}
		foreach (['suppression' => '', 'database_cc' => '', 'maxmind_locale' => 'en', 'asn_reporting' => 'disabled', 'asn_token' => '', 'maxmind_account' => '', 'maxmind_key' => ''] as $key => $value) {
			config_set_path("{$ip}/{$key}", $value);
		}
		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '8.8.8.8');
		foreach ([
			'pfb_dnsvip6' => '', 'pfb_dnsport' => '8081', 'pfb_dnsport_ssl' => '8443', 'top1m_enable' => '', 'pfb_cache' => '',
			'pfb_py_reply' => '', 'pfb_regex' => '', 'pfb_regex_list' => '', 'pfb_cname' => '', 'tld_allow' => '', 'pfb_py_nolog' => '',
			'pfb_noaaaa' => '', 'pfb_noaaaa_list' => '', 'pfb_gp' => '', 'pfb_gp_bypass_list' => '', 'pfb_dnsvip4' => '_vip_test_valid',
		] as $key => $value) {
			config_set_path("{$dnsbl}/{$key}", $value);
		}
		$GLOBALS['g']['unbound_chroot_path'] ??= '/var/unbound';
		PfbConfig::write('dnsbl/pfb_dnsbl', 'on');
		PfbConfig::write('dnsbl/pfb_dnsvip_auto', '');
		PfbConfig::write('dnsbl/dnsbl_interface', 'opt-double');
		$GLOBALS['pfb_test_vip_list'] = ['_vip_test_valid' => '203.0.113.10'];
		config_set_path('virtualip/vip', [['uniqid' => '_test_valid', 'subnet' => '203.0.113.10']]);

		config_set_path('nat/rule', [self::PLAIN_ROW, self::USER_ROW, self::STALE_ROW]);
	}

	public function testEnabledApplyKeepsAUserRuleWhoseDescrOnlyContainsTheMarker(): void
	{
		// GIVEN a user rule whose descr contains 'pfB DNSBL', next to a stale package rule
		$this->seedConfig();
		$this->assertContains(self::USER_ROW, config_get_path('nat/rule'), 'before-state: the user rule is in config');
		$this->assertContains(self::STALE_ROW, config_get_path('nat/rule'), 'before-state: the stale package rule is in config');

		// WHEN DNSBL is applied enabled (the restart branch link()s the real lighttpd binary, which the sandbox lacks)
		set_error_handler(static fn (int $no, string $message): bool => str_starts_with($message, 'link('));
		try {
			pfb_create_dnsbl('enabled');
		} finally {
			restore_error_handler();
		}

		// THEN the user rules survive byte-identical and in order, ahead of the generated rows
		$nat = config_get_path('nat/rule');
		$this->assertSame([self::PLAIN_ROW, self::USER_ROW], array_slice($nat, 0, 2));
		// AND exactly the two generated rows (HTTP + HTTPS) carry the package descr; the stale row is replaced
		$this->assertCount(4, $nat);
		$this->assertSame([2, 3], array_keys(array_filter(array_column($nat, 'descr'), static fn (string $descr): bool => $descr === PFB_MANAGED_NAT_DESCR)));
		$this->assertSame(['80', '443'], array_map(static fn (array $row): string => $row['destination']['port'], array_slice($nat, 2)));
		$this->assertNotContains('STALE_IFACE', array_column($nat, 'interface'));
	}

	public function testDisabledApplyKeepsAUserRuleWhoseDescrOnlyContainsTheMarker(): void
	{
		// GIVEN the same rules
		$this->seedConfig();
		$this->assertContains(self::USER_ROW, config_get_path('nat/rule'), 'before-state: the user rule is in config');

		// WHEN DNSBL is applied disabled
		pfb_create_dnsbl('disabled');

		// THEN only the package rule is removed; the user rules survive byte-identical and in order
		$this->assertSame([self::PLAIN_ROW, self::USER_ROW], config_get_path('nat/rule'));
	}

	/** @return array<string,array{string,bool}> */
	public static function descrs(): array
	{
		return [
			'the exact NAT descr'              => ['pfB DNSBL - DO NOT EDIT', TRUE],
			'the VIP marker (pfB_ prefix)'     => ['pfB_AUTO_VIP_v4', TRUE],
			'any pfB_ prefix'                  => ['pfB_X', TRUE],
			'empty'                            => ['', FALSE],
			'contains the marker'              => ['my pfB DNSBL test', FALSE],
			'the bare legacy prefix'           => ['pfB DNSBL', FALSE],
			'trailing space'                   => ['pfB DNSBL - DO NOT EDIT ', FALSE],
			'leading text'                     => ['x pfB DNSBL - DO NOT EDIT', FALSE],
			'suffixed'                         => ['pfB DNSBL - DO NOT EDIT (copy)', FALSE],
			'case differs'                     => ['pfb dnsbl - do not edit', FALSE],
		];
	}

	#[DataProvider('descrs')]
	public function testOwnershipIsTheExactNatDescrOrThePfbPrefix(string $descr, bool $owned): void
	{
		$this->assertSame($owned, pfb_is_managed_obj($descr));
	}
}
