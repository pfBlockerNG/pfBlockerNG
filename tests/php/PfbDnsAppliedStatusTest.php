<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PfbDnsAppliedStatusTest extends TestCase
{
	private string $dir;
	private array $saved;
	private array $servers = [];

	protected function setUp(): void
	{
		$this->saved = [];
		foreach (['pfb', 'config', 'pfb_test_valid_pids'] as $key) {
			$this->saved[$key] = $GLOBALS[$key] ?? NULL;
		}
		$this->dir = sys_get_temp_dir() . '/pfb-applied-' . uniqid();
		mkdir($this->dir);
		$GLOBALS['pfb']['dns_proxy_pidfile'] = "{$this->dir}/pid";
		$GLOBALS['pfb']['dns_proxy_ready'] = "{$this->dir}/ready";
		$GLOBALS['pfb']['dns_proxy_ctl'] = "{$this->dir}/ctl";
		$GLOBALS['pfb']['dns_proxy_activation_failed'] = "{$this->dir}/failed";
		$GLOBALS['pfb']['pfb_dns'] = $GLOBALS['pfb']['enable'] = PfbToggle::On;
		$GLOBALS['pfb_test_valid_pids']["{$this->dir}/pid"] = TRUE;
		file_put_contents("{$this->dir}/pid", "4242\n");
		file_put_contents("{$this->dir}/ready", "4242\n");
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
			fclose($pipes[0]);
			fclose($pipes[1]);
			fclose($pipes[2]);
			proc_close($process);
		}
		foreach ($this->saved as $key => $value) {
			$GLOBALS[$key] = $value;
		}
		rmdir_recursive($this->dir);
	}

	private static function snapshot(): array
	{
		return [
			'version' => 1, 'pid' => 4242,
			'executable' => PFB_DNS_PROXY_DIR . '/bin/freebsd-amd64/pfb-dns',
			'ready' => TRUE, 'upstream' => '127.0.0.1:5353', 'dns_name' => 'applied.example.com',
			'listeners' => [
				['kind' => 'udp+tcp', 'address' => '192.0.2.1:53', 'state' => 'listening', 'reason' => ''],
				['kind' => 'udp+tcp', 'address' => '[2001:db8::1]:53', 'state' => 'listening', 'reason' => ''],
				['kind' => 'dot', 'address' => '192.0.2.1:853', 'state' => 'refused', 'reason' => 'Address in use'],
			],
			'name_answers' => (object) ['192.0.2.1' => ['a' => [], 'aaaa' => []]], 'ddr' => TRUE,
			'advertisements' => (object) [
				'192.0.2.1' => ['records' => [
					['priority' => 1, 'target' => 'applied.example.com', 'alpn' => 'h2', 'port' => 443, 'hint' => '192.0.2.1', 'path' => '/dns-query{?dns}'],
				], 'additional' => ['192.0.2.1']],
				'2001:db8::1' => ['records' => [], 'additional' => []],
			],
		];
	}

	private function serve(string $wire): string
	{
		$socket = $GLOBALS['pfb']['dns_proxy_ctl'];
		@unlink($socket);
		$record = "{$this->dir}/frames" . count($this->servers);
		$process = proc_open([PHP_BINARY, __DIR__ . '/support/AppliedStatusControlServer.php', $socket, $record, base64_encode($wire)],
			[0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
		$this->assertIsResource($process);
		$this->assertSame("ready\n", fgets($pipes[1]));
		$this->servers[] = [$process, $pipes];
		return $record;
	}

	private function read(): ?array
	{
		$this->assertTrue(function_exists('pfb_dns_proxy_applied_status'), 'Applied-state status reader is missing; argv is not a status snapshot');
		return pfb_dns_proxy_applied_status(NULL, 0.2);
	}

	private static function wire(array $snapshot): string
	{
		return json_encode($snapshot, JSON_THROW_ON_ERROR) . "\nok\n";
	}

	public function testSnapshotKeepsAppliedNameOwnedNodataAndActualAdvertisementsInOneExchange(): void
	{
		$record = $this->serve(self::wire(self::snapshot()));
		$status = $this->read();
		$this->assertSame('applied.example.com', $status['dns_name']);
		$this->assertSame(['a' => [], 'aaaa' => []], $status['name_answers']['192.0.2.1']);
		$this->assertArrayNotHasKey('2001:db8::1', $status['name_answers']);
		$this->assertSame(443, $status['advertisements']['192.0.2.1']['records'][0]['port']);
		$this->assertSame("fffffffa\n", file_get_contents($record));
	}

	public static function malformed(): iterable
	{
		foreach (['', "ok\n", "error: denied\n", "{}\nok\n", "[]\nok\n", "null\nok\n", "{\nok\n", "\xff\nok\n", str_repeat('x', 65537) . "\nok\n"] as $index => $wire) {
			yield "wire {$index}" => [$wire];
		}
		$valid = self::snapshot();
		foreach (['version' => 2, 'pid' => 4243, 'executable' => '/usr/bin/other', 'ready' => FALSE, 'upstream' => 'localhost:53', 'dns_name' => "bad\nname"] as $key => $value) {
			$bad = $valid;
			$bad[$key] = $value;
			yield $key => [self::wire($bad)];
		}
		foreach (array_diff_key($valid, ['upstream' => TRUE]) as $key => $_) {
			$bad = $valid;
			unset($bad[$key]);
			yield "missing {$key}" => [self::wire($bad)];
			$bad = $valid;
			$bad[$key] = NULL;
			yield "null {$key}" => [self::wire($bad)];
		}
		// An absent upstream is valid (testAnAbsentUpstreamIsAValidOptionalFieldAndTheRestOfTheSnapshotIsKept); a present one must be canonical.
		foreach ([NULL, TRUE, FALSE, 7] as $value) {
			$bad = $valid;
			$bad['upstream'] = $value;
			yield 'present upstream ' . json_encode($value) => [self::wire($bad)];
		}
		foreach (['192.0.2.1:0', '192.0.2.1:65536', '192.0.2.1:053', '[2001:0db8::1]:53', '[::ffff:192.0.2.1]:53', '[fe80::1%em0]:53'] as $endpoint) {
			$bad = $valid;
			$bad['listeners'][0]['address'] = $endpoint;
			yield $endpoint => [self::wire($bad)];
		}
		$bad = $valid;
		$bad['listeners'][] = $bad['listeners'][0];
		yield 'duplicate listener' => [self::wire($bad)];
		$bad = $valid;
		$bad['name_answers'] = [];
		yield 'map as list' => [self::wire($bad)];
		$bad = $valid;
		$bad['advertisements'] = (object) ['192.0.2.1' => ['records' => [['priority' => TRUE]], 'additional' => []]];
		yield 'forged record' => [self::wire($bad)];
		yield 'truncated' => [substr(self::wire($valid), 0, -1)];
		yield 'trailing' => [self::wire($valid) . 'extra'];
	}

	#[DataProvider('malformed')]
	public function testInvalidOrIncompleteStatusFailsClosed(string $wire): void
	{
		$this->serve($wire);
		$this->assertNull($this->read());
	}

	public static function embeddedNulAddresses(): iterable
	{
		// inet_pton() throws ValueError on NUL: each address field must reject it before the native call.
		$bad = self::snapshot();
		$bad['upstream'] = "127.0.0.1\0:5353";
		yield 'upstream' => [self::wire($bad)];
		$bad = self::snapshot();
		$bad['listeners'][0]['address'] = "192.0.2.1\0:53";
		yield 'listener' => [self::wire($bad)];
		$bad = self::snapshot();
		$bad['name_answers'] = (object) ["192.0.2.1\0" => ['a' => [], 'aaaa' => []]];
		yield 'name answer key' => [self::wire($bad)];
		$bad = self::snapshot();
		$bad['name_answers'] = (object) ['192.0.2.1' => ['a' => ["192.0.2.9\0"], 'aaaa' => []]];
		yield 'A value' => [self::wire($bad)];
		$bad = self::snapshot();
		$bad['name_answers'] = (object) ['192.0.2.1' => ['a' => [], 'aaaa' => ["2001:db8::9\0"]]];
		yield 'AAAA value' => [self::wire($bad)];
		$bad = self::snapshot();
		$bad['advertisements']->{'192.0.2.1'}['records'][0]['hint'] = "192.0.2.1\0";
		yield 'record hint' => [self::wire($bad)];
		$bad = self::snapshot();
		$bad['advertisements']->{'192.0.2.1'}['additional'] = ["192.0.2.1\0"];
		yield 'additional address' => [self::wire($bad)];
	}

	#[DataProvider('embeddedNulAddresses')]
	public function testEmbeddedNulInAddressFieldFailsClosed(string $wire): void
	{
		$this->serve($wire);
		$this->assertNull($this->read());
	}

	public function testAnAbsentUpstreamIsAValidOptionalFieldAndTheRestOfTheSnapshotIsKept(): void
	{
		$data = self::snapshot();
		unset($data['upstream']);
		$this->serve(self::wire($data));
		$status = $this->read();
		$this->assertNotNull($status, 'the upstream is optional: a snapshot without one is valid');
		$this->assertArrayNotHasKey('upstream', $status);
		$this->assertSame('applied.example.com', $status['dns_name']);
		$this->assertSame(['a' => [], 'aaaa' => []], $status['name_answers']['192.0.2.1']);
	}

	public function testDeadOrMismatchedReadyMarkerNeverReadsTheSocket(): void
	{
		$record = $this->serve(self::wire(self::snapshot()));
		$GLOBALS['pfb_test_valid_pids']["{$this->dir}/pid"] = FALSE;
		$this->assertNull($this->read());
		$GLOBALS['pfb_test_valid_pids']["{$this->dir}/pid"] = TRUE;
		file_put_contents("{$this->dir}/ready", "4243\n");
		$this->assertNull($this->read());
		$this->assertFileDoesNotExist($record);
	}

	public function testLongAppliedInventoryIsNotTruncatedLikeArgv(): void
	{
		$snapshot = self::snapshot();
		for ($n = 2; $n < 150; $n++) {
			$ip = "192.0.2.{$n}";
			$snapshot['listeners'][] = ['kind' => 'udp+tcp', 'address' => "{$ip}:53", 'state' => 'listening', 'reason' => ''];
			$snapshot['advertisements']->{$ip} = ['records' => [], 'additional' => []];
		}
		$this->assertGreaterThan(2048, strlen(self::wire($snapshot)));
		$this->serve(self::wire($snapshot));
		$this->assertCount(151, $this->read()['listeners']);
	}

	public function testStatusSharesItsAppliedSnapshotWithDdrAndPreservesUnavailableVersusAbsentName(): void
	{
		$record = $this->serve(self::wire(self::snapshot()));
		$this->read(); // Require the new surface before invoking old status's unrelated startup paths on RED.
		file_put_contents($record, '');
		$status = pfb_dns_status();
		$this->assertSame('applied.example.com', $status['name']);
		$this->assertSame('matched', $status['ddr']['rows'][0]['state']);
		$this->assertSame("fffffffa\n", file_get_contents($record), 'overview, upstream proof and DDR must share one exchange');
		$empty = self::snapshot();
		$empty['dns_name'] = '';
		$empty['ddr'] = FALSE;
		$empty['advertisements'] = (object) ['192.0.2.1' => ['records' => [], 'additional' => []], '2001:db8::1' => ['records' => [], 'additional' => []]];
		$this->serve(self::wire($empty));
		$this->assertSame('', pfb_dns_status()['name']);
		$this->assertStringContainsString('>None<', pfb_dns_status_panel(pfb_dns_status()));
		$this->serve("error: unavailable\n");
		$this->assertNull(pfb_dns_status()['name']);
		$this->assertStringContainsString('>Unavailable<', pfb_dns_status_panel(pfb_dns_status()));
	}

	public function testDdrUsesAppliedRecordsNotSavedIntentAndDoesNotProbeDns(): void
	{
		$this->serve(self::wire(self::snapshot()));
		$snapshot = $this->read();
		$status = pfb_dns_ddr_status($snapshot);
		$this->assertSame(['matched', 'no_transport'], array_column($status['rows'], 'state'));
		$this->assertStringContainsString('NODATA', $status['rows'][0]['reason']);
		$this->assertStringContainsString('forwarded', $status['rows'][1]['reason']);
		$this->assertStringContainsString('applied.example.com', pfb_dns_status_panel(pfb_dns_status()));
	}
}
