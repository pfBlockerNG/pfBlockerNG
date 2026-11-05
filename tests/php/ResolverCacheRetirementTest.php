<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_run_migrations')]
#[CoversFunction('pfb_install_registry_writeback')]
final class ResolverCacheRetirementTest extends TestCase
{
	private const DNSBL = 'installedpackages/pfblockerngdnsblsettings/config/0';
	private string $dir;
	private array $originalPfb;
	private array $savedGlobals = [];

	protected function setUp(): void
	{
		foreach (['config', 'pfb_test_write_config_calls', 'pfb_test_file_notices'] as $key) {
			if (array_key_exists($key, $GLOBALS)) {
				$this->savedGlobals[$key] = $GLOBALS[$key];
			}
		}
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_file_notices'] = [];
		$this->originalPfb = $GLOBALS['pfb'];
		$this->dir = sys_get_temp_dir() . '/pfb-cache-retirement-' . bin2hex(random_bytes(8));
		mkdir($this->dir, 0700);
		$GLOBALS['pfb']['dbdir'] = $this->dir;
	}

	protected function tearDown(): void
	{
		foreach (glob($this->dir . '/*') ?: [] as $file) {
			unlink($file);
		}
		rmdir($this->dir);
		$GLOBALS['pfb'] = $this->originalPfb;
		foreach (['config', 'pfb_test_write_config_calls', 'pfb_test_file_notices'] as $key) {
			if (array_key_exists($key, $this->savedGlobals)) {
				$GLOBALS[$key] = $this->savedGlobals[$key];
			} else {
				unset($GLOBALS[$key]);
			}
		}
	}

	/** @return iterable<string,array{array<string,string>,string}> */
	public static function storedSettings(): iterable
	{
		foreach (['absent' => [], 'on' => ['pfb_cache' => 'on'], 'empty' => ['pfb_cache' => '']] as $name => $legacy) {
			foreach (['on', ''] as $flush) {
				yield $name . '-flush-' . ($flush === '' ? 'off' : 'on') => [$legacy, $flush];
			}
		}
	}

	#[DataProvider('storedSettings')]
	public function testUpgradeRetiresOnlyCurrentResolverCacheSetting(array $legacy, string $flush): void
	{
		$current = $legacy + ['pfb_cache_flush' => $flush, 'pfb_dnsbl' => 'on', 'unrelated' => 'preserve-me'];
		config_set_path(self::DNSBL, ['pfb_cache' => 'on', 'pfb_cache_flush' => 'on']);
		$this->assertTrue(pfb_settings_family_save('3.3'));
		$snapshot = file_get_contents($this->dir . '/settings-3.3.xml');
		config_set_path(self::DNSBL, $current);
		pfb_run_migrations();
		pfb_install_registry_writeback([self::DNSBL => config_get_path(self::DNSBL)]);
		$first = config_get_path(self::DNSBL);
		$this->assertArrayNotHasKey('pfb_cache', $first, 'the obsolete current setting survives upgrade');
		$this->assertSame($flush, $first['pfb_cache_flush'], 'Clear Resolver Cache must retain its stored choice');
		$this->assertSame('preserve-me', $first['unrelated']);

		$this->assertSame($snapshot, file_get_contents($this->dir . '/settings-3.3.xml'), 'the saved 3.3 family must remain byte-identical');
		pfb_run_migrations();
		pfb_install_registry_writeback([self::DNSBL => config_get_path(self::DNSBL)]);
		$this->assertSame($first, config_get_path(self::DNSBL), 'a repeated upgrade must not recreate the retired setting');
	}
}
