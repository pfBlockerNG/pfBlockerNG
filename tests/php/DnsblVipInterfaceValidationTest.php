<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_manage_dnsbl_vip() — PFBL-01 interface-name boundary. $interface (the stored
 * dnsbl_interface, a \w-only pfSense friendly name) is a singular required
 * parameter: a value failing pfb_filter(PFB_FILTER_WORD) must ABORT the whole run —
 * logged, with NO config write — while a valid name passes the boundary unchanged
 * and the function proceeds exactly as before.
 *
 * Scenario: VIP management with a validated vs a rejected interface name
 *   Background:
 *     Given config holds no marked DNSBL VIP and auto-create is off
 *       (so a run that passes validation is a no-change pass: no write_config)
 *   Case A (valid):   When mode 'enabled' runs with interface 'lo0'
 *                     Then no rejection is logged and config is untouched
 *   Case B (invalid): When mode 'enabled' runs with a non-\w interface value
 *                     Then a rejection log line is written, write_config is never
 *                     called, and config is byte-identical (abort before any write)
 *
 * The full create/delete lifecycle remains lint + live-smoke territory (ADR-13);
 * this pins only the validation boundary added by PFBL-01.
 */
#[CoversFunction('pfb_manage_dnsbl_vip')]
final class DnsblVipInterfaceValidationTest extends TestCase
{
	private string $tmp;
	private array $savedPfbKeys = [];
	private array $hadPfbKeys = [];
	private bool $hadConfig = false;
	private array $savedConfig = [];

	protected function setUp(): void
	{
		$this->tmp = sys_get_temp_dir() . '/pfb_vip_' . uniqid('', true);
		mkdir($this->tmp, 0777, true);

		// Fresh per-test log targets + the inputs pfb_manage_dnsbl_vip reads from $pfb.
		foreach (['log', 'errlog', 'dnsbl_vip_auto', 'dnsbl_iface', 'dnsblconfig'] as $key) {
			$this->hadPfbKeys[$key]   = array_key_exists($key, $GLOBALS['pfb'] ?? []);
			$this->savedPfbKeys[$key] = $GLOBALS['pfb'][$key] ?? null;
		}
		$GLOBALS['pfb']['log']    = "{$this->tmp}/log";
		$GLOBALS['pfb']['errlog'] = "{$this->tmp}/errlog";

		// Auto-create OFF, no marked VIP, resolver absent: a run that passes the
		// validation boundary walks both family delete-branches, finds nothing to do
		// and returns without writing config.
		$GLOBALS['pfb']['dnsbl_vip_auto'] = '';
		$GLOBALS['pfb']['dnsblconfig']    = [];

		$this->hadConfig = array_key_exists('config', $GLOBALS);
		$this->savedConfig = $GLOBALS['config'] ?? [];
		$GLOBALS['config'] = [
			'virtualip' => ['vip' => []],
			'installedpackages' => [
				'pfblockerngdnsblsettings' => ['config' => [0 => []]],
			],
		];

		$GLOBALS['pfb_test_write_config_calls'] = [];
	}

	protected function tearDown(): void
	{
		foreach ($this->savedPfbKeys as $key => $value) {
			if ($this->hadPfbKeys[$key]) {
				$GLOBALS['pfb'][$key] = $value;
			} else {
				unset($GLOBALS['pfb'][$key]);
			}
		}
		if ($this->hadConfig) {
			$GLOBALS['config'] = $this->savedConfig;
		} else {
			unset($GLOBALS['config']);
		}
		unset($GLOBALS['pfb_test_write_config_calls']);
		rmdir_recursive($this->tmp);
	}

	private function logContents(): string
	{
		$path = $GLOBALS['pfb']['log'];
		return file_exists($path) ? (string) file_get_contents($path) : '';
	}

	public function testValidInterfacePassesTheBoundaryWithoutRejection(): void
	{
		// Given a legal friendly interface name and an empty log
		$GLOBALS['pfb']['dnsbl_iface'] = 'lo0';
		$this->assertSame('', $this->logContents(), 'log must start empty');

		// When the lifecycle manager runs
		pfb_manage_dnsbl_vip('enabled');

		// Then no rejection is logged and the no-change pass writes no config
		$this->assertStringNotContainsString('failed validation', $this->logContents());
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'],
			'a no-change pass must not call write_config');
	}

	public function testRejectedInterfaceAbortsBeforeAnyConfigWrite(): void
	{
		// Given a non-\w interface value and an empty log
		$GLOBALS['pfb']['dnsbl_iface'] = 'igb1.100; ls';
		$configBefore = $GLOBALS['config'];
		$this->assertSame('', $this->logContents(), 'log must start empty');

		// When the lifecycle manager runs
		pfb_manage_dnsbl_vip('enabled');

		// Then the rejection is observable in the log (function name + encoded value) ...
		$log = $this->logContents();
		$this->assertStringContainsString('pfb_manage_dnsbl_vip', $log);
		$this->assertStringContainsString('failed validation', $log);
		$this->assertStringContainsString(htmlspecialchars('igb1.100; ls'), $log);

		// ... and the run aborted with no config write of any kind.
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'],
			'an aborted run must never call write_config');
		$this->assertSame($configBefore, $GLOBALS['config'], 'config must be untouched');
	}

	public function testRejectedInterfaceAlsoAbortsTheDisabledPath(): void
	{
		// The delete branch ('disabled') runs the same singular-parameter boundary:
		// both lifecycle modes must abort on a rejected interface name.
		$GLOBALS['pfb']['dnsbl_iface'] = 'lo0 && reboot';
		$this->assertSame('', $this->logContents(), 'log must start empty');

		pfb_manage_dnsbl_vip('disabled');

		$this->assertStringContainsString('failed validation', $this->logContents());
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
	}
}
