<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class PfbDnsAppliedStatusMixedCaseTest extends TestCase
{
	public function testActualGoCasePreservingAdvertisementIsAcceptedWithoutChangingItsTarget(): void
	{
		$saved = [$GLOBALS['pfb'], $GLOBALS['config'] ?? NULL, $GLOBALS['pfb_test_valid_pids'] ?? []];
		$dir = sys_get_temp_dir() . '/pfb-applied-case-' . uniqid();
		mkdir($dir);
		$process = NULL;
		$pipes = [];
		try {
			$GLOBALS['pfb']['dns_proxy_pidfile'] = "{$dir}/pid";
			$GLOBALS['pfb']['dns_proxy_ready'] = "{$dir}/ready";
			$GLOBALS['pfb']['dns_proxy_ctl'] = "{$dir}/ctl";
			$GLOBALS['pfb']['pfb_dns'] = $GLOBALS['pfb']['enable'] = PfbToggle::On;
			$GLOBALS['pfb_test_valid_pids']["{$dir}/pid"] = TRUE;
			file_put_contents("{$dir}/pid", "4242\n");
			file_put_contents("{$dir}/ready", "4242\n");
			$GLOBALS['config'] = [];
			PfbConfig::write('dns/pfb_dns_saved', base64_encode((string) json_encode([
				'active_interface' => ['present' => TRUE, 'value' => 'lan'],
				'enablessl' => ['present' => FALSE, 'value' => NULL],
				'custom_options' => ['present' => FALSE, 'value' => NULL],
			])));
			// Captured from the real Go control handler; only PID/executable identify the PHP harness instead of the Go test process.
			$wire = (string) file_get_contents(__DIR__ . '/support/AppliedStatusMixedCase.wire');
			$process = proc_open([PHP_BINARY, __DIR__ . '/support/AppliedStatusControlServer.php', "{$dir}/ctl", "{$dir}/frames", base64_encode($wire)],
				[0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
			$this->assertIsResource($process);
			$this->assertSame("ready\n", fgets($pipes[1]));
			$status = pfb_dns_status();
			$this->assertSame('dns.example', $status['name'], 'Case-preserving DNS target must not make valid applied state unavailable');
			$this->assertSame('matched', $status['ddr']['rows'][0]['state']);
			$this->assertStringContainsString('dot DNS.example:43405', $status['ddr']['rows'][0]['reason']);
			$this->assertStringContainsString('dot DNS.example:43405', pfb_dns_status_panel($status));
			$this->assertSame("fffffffa\n", file_get_contents("{$dir}/frames"));
		} finally {
			foreach ($pipes as $pipe) {
				fclose($pipe);
			}
			if (is_resource($process)) {
				proc_close($process);
			}
			[$GLOBALS['pfb'], $GLOBALS['config'], $GLOBALS['pfb_test_valid_pids']] = $saved;
			rmdir_recursive($dir);
		}
	}
}
