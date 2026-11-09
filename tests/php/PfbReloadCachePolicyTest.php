<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_reload_unbound')]
final class PfbReloadCachePolicyTest extends TestCase
{
	private string $dir;
	private array $savedPfb = [];
	private array $savedG = [];
	private mixed $savedConfig;
	private bool $hadConfig;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_reload_cache_policy_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);
		foreach (['dnsbldir', 'dbdir', 'dnsbl_file', 'unbound_py_count', 'unbound_py_sources', 'enable', 'dnsbl',
			'unbound_py_rawdir', 'chroot_cmd', 'dnsbl_python_unmount', 'log', 'errlog'] as $key) {
			$this->savedPfb[$key] = array_key_exists($key, $GLOBALS['pfb'] ?? []) ? $GLOBALS['pfb'][$key] : FALSE;
		}
		$this->savedG['varrun_path'] = array_key_exists('varrun_path', $GLOBALS['g'] ?? [])
			? $GLOBALS['g']['varrun_path'] : FALSE;
		$this->hadConfig = array_key_exists('config', $GLOBALS);
		$this->savedConfig = $GLOBALS['config'] ?? NULL;

		$GLOBALS['pfb']['dnsbldir']               = $this->dir;
		$GLOBALS['pfb']['dbdir']                  = $this->dir;
		$GLOBALS['pfb']['dnsbl_file']             = "{$this->dir}/dnsbl_file";
		$GLOBALS['pfb']['unbound_py_count']       = "{$this->dir}/unbound_py_count";
		$GLOBALS['pfb']['unbound_py_sources']     = "{$this->dir}/pfb_py_sources.json";
		$GLOBALS['pfb']['unbound_py_rawdir']      = "{$this->dir}/pfb_py_raw";
		$GLOBALS['pfb']['chroot_cmd']             = "{$this->dir}/chroot-control-recorder";
		$GLOBALS['pfb']['dnsbl_python_unmount']   = FALSE;
		$GLOBALS['pfb']['log']                    = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog']                 = "{$this->dir}/error.log";
		$GLOBALS['g']['varrun_path']              = $this->dir;
		$GLOBALS['pfb']['enable']                 = $GLOBALS['pfb']['dnsbl'] = PfbToggle::On;
		// pfB-DNS owns the Resolver and is up: the DNS proxy hosts the module, Unbound never does (issue #3770)
		$GLOBALS['config'] ??= [];
		config_set_path('installedpackages/pfblockerngdns/config/0/pfb_dns_saved', base64_encode((string) json_encode([
			'active_interface' => ['present' => TRUE, 'value' => 'lan'],
			'enablessl' => ['present' => FALSE, 'value' => NULL],
			'custom_options' => ['present' => FALSE, 'value' => NULL],
		])));
		$GLOBALS['pfb_test_valid_pids']           = ['/var/run/pfb_dns_proxy.pid' => TRUE];
		$GLOBALS['pfb_test_process_running']      = ['unbound' => TRUE];
	}

	protected function tearDown(): void
	{
		foreach ($this->savedPfb as $key => $value) {
			if ($value === FALSE) {
				unset($GLOBALS['pfb'][$key]);
			} else {
				$GLOBALS['pfb'][$key] = $value;
			}
		}
		foreach ($this->savedG as $key => $value) {
			if ($value === FALSE) {
				unset($GLOBALS['g'][$key]);
			} else {
				$GLOBALS['g'][$key] = $value;
			}
		}
		if ($this->hadConfig) {
			$GLOBALS['config'] = $this->savedConfig;
		} else {
			unset($GLOBALS['config']);
		}
		unset($GLOBALS['pfb_test_process_running'], $GLOBALS['pfb_test_valid_pids']);
		foreach (glob("{$this->dir}/*") ?: [] as $file) {
			@unlink($file);
		}
		@rmdir($this->dir);
	}

	public function testGenericReloadDoesNotIssueBulkFullCacheFlush(): void
	{
		file_put_contents($GLOBALS['pfb']['unbound_py_count'], '10');
		file_put_contents($GLOBALS['pfb']['unbound_py_sources'], '{"feeds":[]}');
		file_put_contents("{$this->dir}/pfb_py_reload.applied", "1\n");

		$commands = "{$this->dir}/control-commands.log";
		$marker = escapeshellarg("{$this->dir}/pfb_py_reload.applied");
		file_put_contents(
			$GLOBALS['pfb']['chroot_cmd'],
			"#!/bin/sh\nprintf '%s|applied=%s\\n' \"\$*\" \"\$(cat {$marker})\" >> " . escapeshellarg($commands) . "\n"
		);
		chmod($GLOBALS['pfb']['chroot_cmd'], 0755);

		$calls = 0;
		$GLOBALS['pfb_test_valid_pids']['/var/run/pfb_dns_proxy.pid'] = function () use (&$calls): bool {
			$calls++;
			return $calls <= 2;
		};

		$swapped = pfb_reload_unbound('enabled', FALSE, TRUE);

		$this->assertSame(2, $calls, 'generic reload must use the no-restart success path');
		$this->assertTrue($swapped, 'successful applied-generation swap must return TRUE');
		$this->assertFileDoesNotExist(
			$commands,
			'generic reload must leave full-cache policy to its bulk caller'
		);
	}
}
