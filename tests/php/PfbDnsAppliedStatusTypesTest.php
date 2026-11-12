<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PfbDnsAppliedStatusTypesTest extends TestCase
{
	private string $dir;
	private array $saved;
	private mixed $process = NULL;
	private array $pipes = [];

	protected function setUp(): void
	{
		$this->saved = [$GLOBALS['pfb'], $GLOBALS['pfb_test_valid_pids'] ?? []];
		$this->dir = sys_get_temp_dir() . '/pfb-applied-types-' . uniqid();
		mkdir($this->dir);
		foreach (['dns_proxy_pidfile' => 'pid', 'dns_proxy_ready' => 'ready', 'dns_proxy_ctl' => 'ctl'] as $key => $file) {
			$GLOBALS['pfb'][$key] = "{$this->dir}/{$file}";
		}
		file_put_contents("{$this->dir}/pid", "4242\n");
		file_put_contents("{$this->dir}/ready", "4242\n");
		$GLOBALS['pfb_test_valid_pids']["{$this->dir}/pid"] = TRUE;
	}

	protected function tearDown(): void
	{
		foreach ($this->pipes as $pipe) {
			fclose($pipe);
		}
		if (is_resource($this->process)) {
			proc_close($this->process);
		}
		[$GLOBALS['pfb'], $GLOBALS['pfb_test_valid_pids']] = $this->saved;
		rmdir_recursive($this->dir);
	}

	private static function snapshot(): array
	{
		return [
			'version' => 1, 'pid' => 4242, 'executable' => PFB_DNS_PROXY_DIR . '/bin/freebsd-amd64/pfb-dns',
			'ready' => TRUE, 'upstream' => '[::1]:65535', 'dns_name' => 'xn--bcher-kva.example.com', 'ddr' => TRUE,
			'listeners' => [
				['kind' => 'udp+tcp', 'address' => '0.0.0.0:1', 'state' => 'listening', 'reason' => ''],
				['kind' => 'udp+tcp', 'address' => '[::]:65535', 'state' => 'listening', 'reason' => ''],
				['kind' => 'dot', 'address' => '192.0.2.1:853', 'state' => 'listening', 'reason' => ''],
			],
			'name_answers' => (object) ['192.0.2.1' => ['a' => ['192.0.2.1'], 'aaaa' => ['2001:db8::1']]],
			'advertisements' => (object) [
				'0.0.0.0' => ['records' => [], 'additional' => []],
				'::' => ['records' => [], 'additional' => []],
				'192.0.2.1' => ['records' => [
					['priority' => 2, 'target' => 'xn--bcher-kva.example.com', 'alpn' => 'dot', 'port' => 853, 'hint' => '192.0.2.1', 'path' => ''],
				], 'additional' => ['192.0.2.1']],
			],
		];
	}

	private function ask(array $snapshot): ?array
	{
		$wire = json_encode($snapshot, JSON_THROW_ON_ERROR | JSON_PRESERVE_ZERO_FRACTION) . "\nok\n";
		$this->process = proc_open([PHP_BINARY, __DIR__ . '/support/AppliedStatusControlServer.php',
			$GLOBALS['pfb']['dns_proxy_ctl'], "{$this->dir}/frames", base64_encode($wire)],
			[0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $this->pipes);
		$this->assertIsResource($this->process);
		$this->assertSame("ready\n", fgets($this->pipes[1]));
		return pfb_dns_proxy_applied_status(NULL, 0.2);
	}

	public function testWildcardInventoryPunycodeDualFamilyAndBoundaryPortsAreValid(): void
	{
		$status = $this->ask(self::snapshot());
		$this->assertNotNull($status);
		$this->assertSame(['0.0.0.0:1', '[::]:65535', '192.0.2.1:853'], array_column($status['listeners'], 'address'));
		$this->assertSame(['records' => [], 'additional' => []], $status['advertisements']['::']);
		$this->assertSame(['a' => ['192.0.2.1'], 'aaaa' => ['2001:db8::1']], $status['name_answers']['192.0.2.1']);
	}

	/** @return iterable<string,array{array<string,mixed>,Closure(array<string,mixed>):mixed,mixed}> issue #3849: a snapshot with one address in another numeric spelling of its bytes, where it is read back, and PHP's spelling of it */
	public static function addressesInAnotherNumericSpelling(): iterable
	{
		$data = self::snapshot();
		$data['name_answers']->{'192.0.2.1'}['a'] = ['::ffff:192.0.2.1'];
		yield 'an IPv4-mapped IPv6 address is an A answer as its IPv4 address' => [$data, static fn (array $status): mixed => $status['name_answers']['192.0.2.1']['a'], ['192.0.2.1']];
		$data = self::snapshot();
		$data['name_answers']->{'192.0.2.1'}['aaaa'] = ['2001:0db8::1'];
		yield 'an IPv6 address with a zero-padded group is an AAAA answer without it' => [$data, static fn (array $status): mixed => $status['name_answers']['192.0.2.1']['aaaa'], ['2001:db8::1']];
		$data = self::snapshot();
		$data['advertisements']->{'192.0.2.1'}['records'][0]['hint'] = '::ffff:192.0.2.1';
		yield 'an IPv4-mapped hint is the IPv4 address of its local' => [$data, static fn (array $status): mixed => $status['advertisements']['192.0.2.1']['records'][0]['hint'], '192.0.2.1'];
		$data = self::snapshot();
		$data['name_answers'] = (object) ['::ffff:192.0.2.1' => $data['name_answers']->{'192.0.2.1'}];
		yield 'an IPv4-mapped local that is the only key of the name answers is keyed by its IPv4 address' => [$data, static fn (array $status): mixed => array_keys($status['name_answers']), ['192.0.2.1']];
	}

	/** @param Closure(array<string,mixed>):mixed $read */
	#[DataProvider('addressesInAnotherNumericSpelling')]
	public function testAnAddressInAnotherNumericSpellingOfItsBytesIsReadAsPhpsSpellingOfThem(array $snapshot, Closure $read, mixed $expected): void
	{
		$status = $this->ask($snapshot);

		$this->assertNotNull($status, 'the same bytes in another numeric spelling are a valid snapshot');
		$this->assertSame($expected, $read($status));
	}

	public static function hostileTypes(): iterable
	{
		foreach (['version', 'pid', 'executable', 'upstream', 'dns_name', 'listeners', 'name_answers', 'advertisements'] as $field) {
			$data = self::snapshot();
			$data[$field] = TRUE;
			yield "boolean {$field}" => [$data];
		}
		foreach (['version' => '1', 'pid' => 4242.0, 'ready' => 1, 'ddr' => 1, 'listeners' => (object) [],
		    'name_answers' => [], 'advertisements' => []] as $field => $value) {
			$data = self::snapshot();
			$data[$field] = $value;
			yield "wrong type {$field}" => [$data];
		}
		foreach (['kind', 'address', 'state', 'reason'] as $field) {
			$data = self::snapshot();
			$data['listeners'][0][$field] = TRUE;
			yield "boolean listener {$field}" => [$data];
		}
		foreach ([TRUE, (object) [], ['192.0.2.1', '192.0.2.2'], [TRUE], ['2001:db8::1'], ['192.000.2.1']] as $index => $value) {
			$data = self::snapshot();
			$data['name_answers']->{'192.0.2.1'}['a'] = $value;
			yield "invalid A family {$index}" => [$data];
		}
		foreach ([TRUE, (object) [], [TRUE], ['192.0.2.1'], ['fe80::1%em0']] as $index => $value) {
			$data = self::snapshot();
			$data['name_answers']->{'192.0.2.1'}['aaaa'] = $value;
			yield "invalid AAAA family {$index}" => [$data];
		}
		foreach (['priority', 'target', 'alpn', 'port', 'hint', 'path'] as $field) {
			$data = self::snapshot();
			$data['advertisements']->{'192.0.2.1'}['records'][0][$field] = TRUE;
			yield "boolean advertisement {$field}" => [$data];
		}
		foreach (['priority' => '2', 'port' => 0, 'target' => "bad\";touch example", 'hint' => '::ffff:192.0.2.2', 'path' => "\nforged"] as $field => $value) {
			$data = self::snapshot();
			$data['advertisements']->{'192.0.2.1'}['records'][0][$field] = $value;
			yield "invalid advertisement {$field}" => [$data];
		}
		foreach (['records', 'additional'] as $field) {
			foreach ([TRUE, (object) [], [TRUE]] as $index => $value) {
				$data = self::snapshot();
				$data['advertisements']->{'192.0.2.1'}[$field] = $value;
				yield "invalid advertisement {$field} {$index}" => [$data];
			}
		}
		foreach (['192.000.2.1', 'fe80::1%em0'] as $local) {
			$data = self::snapshot();
			$data['name_answers']->$local = ['a' => [], 'aaaa' => []];
			yield "invalid local {$local}" => [$data];
		}
		// issue #3849: another spelling of the address of a local the snapshot already keys is that local again, not a new one
		$data = self::snapshot();
		$data['name_answers']->{'::ffff:192.0.2.1'} = ['a' => [], 'aaaa' => []];
		yield 'a mapped local that repeats the name-answer key 192.0.2.1' => [$data];
		$data = self::snapshot();
		$data['ddr'] = FALSE;
		yield 'disabled DDR with records' => [$data];
		$data = self::snapshot();
		$data['advertisements']->{'192.0.2.1'}['additional'] = ['192.0.2.1', '192.0.2.1'];
		yield 'duplicate additional' => [$data];
		$data = self::snapshot();
		unset($data['advertisements']->{'::'});
		yield 'missing bound local advertisement' => [$data];
		$data = self::snapshot();
		$data['advertisements']->{'203.0.113.1'} = ['records' => [], 'additional' => []];
		yield 'unowned advertisement local' => [$data];
		$data = self::snapshot();
		$data['advertisements']->{'192.0.2.1'}['records'] = [];
		yield 'no advertisement cannot carry additional answers' => [$data];
	}

	#[DataProvider('hostileTypes')]
	public function testNestedTypesAndAddressesFailClosed(array $snapshot): void
	{
		$this->assertNull($this->ask($snapshot));
	}

	#[DataProvider('responseLimits')]
	public function testCompleteStatusUsesTheSharedWireCap(int $length, bool $accepted): void
	{
		$data = self::snapshot();
		$data['listeners'][] = ['kind' => 'doq', 'address' => '192.0.2.2:853', 'state' => 'refused', 'reason' => ''];
		$base = strlen(json_encode($data, JSON_THROW_ON_ERROR) . "\nok\n");
		$data['listeners'][3]['reason'] = str_repeat('x', $length - $base);
		$this->assertSame($length, strlen(json_encode($data, JSON_THROW_ON_ERROR) . "\nok\n"));
		$this->assertSame($accepted, $this->ask($data) !== NULL);
	}

	public static function responseLimits(): array
	{
		return [[65536, TRUE], [65537, FALSE]];
	}
}
