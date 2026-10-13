<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsblNatWriterSeedTrait.php';

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
	use DnsblNatWriterSeedTrait;

	/** A user rule whose descr only contains the marker; every field is distinctive so any rewrite shows. */
	private const USER_ROW = [
		'source' => ['any' => ''], 'destination' => ['address' => '198.51.100.7', 'port' => '8080'], 'protocol' => 'tcp',
		'target' => '10.9.8.7', 'local-port' => '8888', 'interface' => 'lan', 'descr' => 'my pfB DNSBL test',
		'associated-rule-id' => 'pass', 'created' => ['time' => '1700000000', 'username' => 'admin@192.0.2.1'],
	];
	private const PLAIN_ROW = ['descr' => 'user rule', 'interface' => 'wan', 'target' => '10.0.0.9'];
	/** A user copy of the package rule: the suffix makes it the user's, not the package's. */
	private const COPY_ROW = ['descr' => 'pfB DNSBL - DO NOT EDIT (copy)', 'interface' => 'lan', 'target' => '10.1.1.1'];
	/** Another pfBlockerNG feature's NAT: owned, but never the DNSBL writer's to rebuild. */
	private const REDIRECT_ROW = ['descr' => 'pfB_DNS_Redirect_lan_v4', 'interface' => 'lan', 'target' => '127.0.0.1'];
	/** The rows no DNSBL apply may touch, in config order. */
	private const KEPT_ROWS = [self::PLAIN_ROW, self::USER_ROW, self::COPY_ROW, self::REDIRECT_ROW];
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

	public function testEnabledApplyKeepsAUserRuleWhoseDescrOnlyContainsTheMarker(): void
	{
		// GIVEN user rules resembling the package descr and another feature's NAT, next to a stale package rule
		$this->seedDnsblNatWriter($this->dir, [...self::KEPT_ROWS, self::STALE_ROW]);
		$this->assertContains(self::USER_ROW, config_get_path('nat/rule'), 'before-state: the user rule is in config');
		$this->assertContains(self::STALE_ROW, config_get_path('nat/rule'), 'before-state: the stale package rule is in config');

		// WHEN DNSBL is applied enabled
		$this->applyDnsblEnabled();

		// THEN the rules it does not own survive byte-identical and in order, ahead of the generated rows
		$nat = config_get_path('nat/rule');
		$this->assertSame(self::KEPT_ROWS, array_slice($nat, 0, 4));
		// AND exactly the two generated rows (HTTP + HTTPS) carry the package descr; the stale row is replaced
		$this->assertCount(6, $nat);
		$this->assertSame([4, 5], array_keys(array_filter(array_column($nat, 'descr'), static fn (string $descr): bool => $descr === PFB_MANAGED_NAT_DESCR)));
		$this->assertSame(['80', '443'], array_map(static fn (array $row): string => $row['destination']['port'], array_slice($nat, 4)));
		$this->assertNotContains('STALE_IFACE', array_column($nat, 'interface'));
	}

	public function testDisabledApplyKeepsAUserRuleWhoseDescrOnlyContainsTheMarker(): void
	{
		// GIVEN the same rules after an enabled apply, so the copied-object detector holds recorded state
		$this->seedDnsblNatWriter($this->dir, [...self::KEPT_ROWS, self::STALE_ROW]);
		$this->applyDnsblEnabled();
		$this->assertSame(self::KEPT_ROWS, array_slice(config_get_path('nat/rule'), 0, 4), 'before-state: the user rules are in config');
		$this->assertCount(6, config_get_path('nat/rule'), 'before-state: the generated package rules are in config');

		// WHEN DNSBL is applied disabled
		pfb_create_dnsbl('disabled');

		// THEN only the package rules are removed; the others survive byte-identical and in order
		$this->assertSame(self::KEPT_ROWS, config_get_path('nat/rule'));
		// AND the detector compared only the package rules, so a user rule never reads as an unexpected copy
		$this->assertSame([], pfb_sync_copied_read($this->dir)['findings']);
		$this->assertSame([], $GLOBALS['pfb_test_file_notices']);
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
