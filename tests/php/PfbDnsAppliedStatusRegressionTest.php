<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PfbDnsAppliedStatusRegressionTest extends TestCase
{
	private string $dir;
	private array $globals = [];
	private array $files = [];
	private array $servers = [];

	protected function setUp(): void
	{
		foreach (['pfb', 'g', 'config', 'pfb_test_valid_pids'] as $key) {
			$this->globals[$key] = $GLOBALS[$key] ?? NULL;
		}
		foreach ([$GLOBALS['pfb_test_ps_output'], $GLOBALS['pfb_test_sockstat_output'], $GLOBALS['pfb_test_sockstat_status'], PFB_DNS_PROXY_RCFILE] as $file) {
			$this->files[$file] = is_file($file) ? file_get_contents($file) : FALSE;
		}
		$this->dir = sys_get_temp_dir() . '/pfb-applied-consumer-' . uniqid();
		mkdir($this->dir);
		$GLOBALS['g']['varrun_path'] = $this->dir;
		$GLOBALS['pfb']['dns_proxy_pidfile'] = "{$this->dir}/pid";
		$GLOBALS['pfb']['dns_proxy_ready'] = "{$this->dir}/ready";
		$GLOBALS['pfb']['dns_proxy_ctl'] = "{$this->dir}/ctl";
		$GLOBALS['pfb']['dns_proxy_activation_failed'] = "{$this->dir}/failed";
		$GLOBALS['pfb']['pfb_dns'] = $GLOBALS['pfb']['enable'] = PfbToggle::On;
		$GLOBALS['pfb_test_valid_pids']["{$this->dir}/pid"] = TRUE;
		$GLOBALS['pfb_test_valid_pids']["{$this->dir}/unbound.pid"] = TRUE;
		file_put_contents("{$this->dir}/pid", "4242\n");
		file_put_contents("{$this->dir}/ready", "4242\n");
		file_put_contents("{$this->dir}/unbound.pid", "5151\n");
		file_put_contents($GLOBALS['pfb_test_ps_output'], '');
		file_put_contents($GLOBALS['pfb_test_sockstat_output'],
			"USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS\n"
			. "unbound unbound 5151 3 tcp4 127.0.0.1:5353 *:*\n"
			. "unbound unbound 5151 4 udp4 127.0.0.1:5353 *:*\n");
		file_put_contents($GLOBALS['pfb_test_sockstat_status'], "0\n");
		@unlink(PFB_DNS_PROXY_RCFILE);
		$GLOBALS['config'] = [];
		PfbConfig::write('dns/pfb_dns_saved', base64_encode((string) json_encode([
			'active_interface' => ['present' => TRUE, 'value' => 'lan'],
			'enablessl' => ['present' => FALSE, 'value' => NULL],
			'custom_options' => ['present' => FALSE, 'value' => NULL],
		])));
		PfbConfig::write('dns/pfb_dns_name', 'saved.example.com');
	}

	protected function tearDown(): void
	{
		foreach ($this->servers as [$process, $pipes]) {
			foreach ($pipes as $pipe) {
				fclose($pipe);
			}
			proc_close($process);
		}
		foreach ($this->files as $file => $content) {
			if ($content === FALSE) {
				@unlink($file);
			} else {
				file_put_contents($file, $content);
			}
		}
		foreach ($this->globals as $key => $value) {
			$GLOBALS[$key] = $value;
		}
		rmdir_recursive($this->dir);
	}

	private static function snapshot(int $count = 1): array
	{
		$listeners = $advertisements = [];
		for ($number = 1; $number <= $count; $number++) {
			$host = "192.0.2.{$number}";
			$listeners[] = ['kind' => 'udp+tcp', 'address' => "{$host}:53", 'state' => 'listening', 'reason' => ''];
			$advertisements[$host] = ['records' => [], 'additional' => []];
		}
		return [
			'version' => 1, 'pid' => 4242, 'executable' => PFB_DNS_PROXY_DIR . '/bin/freebsd-amd64/pfb-dns',
			'ready' => TRUE, 'upstream' => '127.0.0.1:5353', 'dns_name' => 'applied.example.com',
			'listeners' => $listeners, 'name_answers' => (object) [], 'ddr' => FALSE,
			'advertisements' => (object) $advertisements,
		];
	}

	private function serve(string $wire): string
	{
		$socket = $GLOBALS['pfb']['dns_proxy_ctl'];
		$record = "{$this->dir}/frames";
		$process = proc_open([PHP_BINARY, __DIR__ . '/support/AppliedStatusControlServer.php', $socket, $record, base64_encode($wire)],
			[0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
		$this->assertIsResource($process);
		$this->assertSame("ready\n", fgets($pipes[1]));
		$this->servers[] = [$process, $pipes];
		return $record;
	}

	public function testLongAppliedSnapshotSuppliesDnsNameWhenProcessArgvEndsBeforeTheName(): void
	{
		$argv = '4242 ' . PFB_DNS_PROXY_DIR . '/bin/freebsd-amd64/pfb-dns --upstream 127.0.0.1:5353'
		    . str_repeat(' --listen 192.0.2.1', 200);
		$truncated = substr($argv, 0, 2048);
		$this->assertSame(2048, strlen($truncated));
		$this->assertStringNotContainsString('--dns-name', $truncated);
		file_put_contents($GLOBALS['pfb_test_ps_output'], "{$truncated}\n");
		$wire = json_encode(self::snapshot(150), JSON_THROW_ON_ERROR) . "\nok\n";
		$this->assertGreaterThan(2048, strlen($wire));
		$record = $this->serve($wire);
		$status = pfb_dns_status();
		$this->assertSame('applied.example.com', $status['name'], 'Applied name must survive truncated argv and differing saved intent');
		$this->assertSame('Running', $status['service']);
		$this->assertSame("fffffffa\n", file_get_contents($record), 'One applied exchange must feed overview, upstream proof and DDR');
		$this->assertStringContainsString('>applied.example.com<', pfb_dns_status_panel($status));
	}

	public static function staleProcessEvidence(): array
	{
		return [
			'argv absent' => [''],
			'argv stale' => ['4242 ' . PFB_DNS_PROXY_DIR . '/bin/freebsd-amd64/pfb-dns --upstream 127.0.0.1:5354'],
		];
	}

	#[DataProvider('staleProcessEvidence')]
	public function testUpstreamProofUsesAppliedEndpointDespiteMissingOrStaleArgvAndRc(string $argv): void
	{
		file_put_contents($GLOBALS['pfb_test_ps_output'], $argv === '' ? '' : "{$argv}\n");
		file_put_contents(PFB_DNS_PROXY_RCFILE, '#!/bin/sh' . "\n/usr/sbin/daemon " . PFB_DNS_PROXY_DIR
		    . "/pfb_dns.sh --listen 127.0.0.1 --upstream 127.0.0.1:5354\n");
		$this->serve(json_encode(self::snapshot(), JSON_THROW_ON_ERROR) . "\nok\n");
		$this->assertTrue(pfb_dns_proxy_upstream_ready(), 'Live Unbound owns applied5353, not stale argv/rc5354');
		$this->assertSame('Running', pfb_dns_status()['service']);
	}

	public function testUnavailableAppliedSnapshotRendersUnavailableInsteadOfNoneOrSavedName(): void
	{
		$this->serve("error: unavailable\n");
		$status = pfb_dns_status();
		$this->assertNull($status['name'], 'Unavailable runtime evidence is not an intentionally absent DNS Name');
		$html = pfb_dns_status_panel($status);
		$this->assertStringContainsString('>Unavailable<', $html);
		$this->assertStringNotContainsString('>None<', $html);
		$this->assertStringNotContainsString('saved.example.com', $html);
	}
}
