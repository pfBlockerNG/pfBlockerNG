<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3848 -- the gateway's applied status carries `degraded`: what pfB-DNS started without, as a list of {part, reason}. The reader
 * (pfb_dns_proxy_applied_status()) takes an absent field as no degraded part (a gateway older than the field), keeps each row as its
 * part and its one-line reason in the order given, and fails closed -- the whole status is unavailable -- on anything the contract
 * does not allow: not a list, a row that is not {part, reason}, a part outside the closed set, a part twice, or a reason that is
 * empty, longer than 300 bytes or carries a control character.
 */
#[CoversFunction('pfb_dns_proxy_applied_status')]
final class PfbDnsAppliedStatusDegradedTest extends TestCase
{
	private const PARTS = ['dnsbl', 'dnsbl_settings', 'dns_name', 'ddr', 'tls_certificate', 'acl', 'statistics', 'observer'];

	private string $dir;
	private array $saved;
	private array $servers = [];

	protected function setUp(): void
	{
		$this->saved = [];
		foreach (['pfb', 'config', 'pfb_test_valid_pids'] as $key) {
			$this->saved[$key] = $GLOBALS[$key] ?? NULL;
		}
		$this->dir = sys_get_temp_dir() . '/pfb-applied-degraded-' . uniqid();
		mkdir($this->dir);
		$GLOBALS['pfb']['dns_proxy_pidfile'] = "{$this->dir}/pid";
		$GLOBALS['pfb']['dns_proxy_ready'] = "{$this->dir}/ready";
		$GLOBALS['pfb']['dns_proxy_ctl'] = "{$this->dir}/ctl";
		$GLOBALS['pfb_test_valid_pids']["{$this->dir}/pid"] = TRUE;
		file_put_contents("{$this->dir}/pid", "4242\n");
		file_put_contents("{$this->dir}/ready", "4242\n");
		$GLOBALS['config'] = [];
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

	/** @return array<string,mixed> a valid version-1 status with no listener and no DDR: nothing in it but what `degraded` is judged on */
	private static function snapshot(): array
	{
		return [
			'version' => 1, 'pid' => 4242,
			'executable' => PFB_DNS_PROXY_DIR . '/bin/freebsd-amd64/pfb-dns',
			'ready' => TRUE, 'upstream' => '127.0.0.1:5353', 'dns_name' => '',
			'listeners' => [], 'name_answers' => (object) [], 'ddr' => FALSE, 'advertisements' => (object) [],
		];
	}

	/** The gateway answers the status verb with $status; what the reader makes of it. */
	private function read(array $status): ?array
	{
		$socket = $GLOBALS['pfb']['dns_proxy_ctl'];
		@unlink($socket);
		$process = proc_open(
			[PHP_BINARY, __DIR__ . '/support/AppliedStatusControlServer.php', $socket, "{$this->dir}/frames" . count($this->servers), base64_encode(json_encode($status, JSON_THROW_ON_ERROR) . "\nok\n")],
			[0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
			$pipes
		);
		$this->assertIsResource($process);
		$this->assertSame("ready\n", fgets($pipes[1]));
		$this->servers[] = [$process, $pipes];

		return pfb_dns_proxy_applied_status(NULL, 0.2);
	}

	/** @param list<mixed> $degraded */
	private function readWith(mixed $degraded): ?array
	{
		return $this->read(['degraded' => $degraded] + self::snapshot());
	}

	public function testAnAbsentDegradedFieldIsNoDegradedPartAndTheRestOfTheStatusIsKept(): void
	{
		// Given a gateway older than the field
		$status = $this->read(self::snapshot());

		// Then the status is valid and nothing is degraded
		$this->assertNotNull($status, 'an absent field is valid');
		$this->assertSame([], $status['degraded']);
		$this->assertSame('127.0.0.1:5353', $status['upstream']);
	}

	public function testAnEmptyDegradedListIsNoDegradedPart(): void
	{
		$status = $this->readWith([]);

		$this->assertNotNull($status);
		$this->assertSame([], $status['degraded']);
	}

	/** @return array<string,array{string}> */
	public static function parts(): array
	{
		return array_combine(self::PARTS, array_map(static fn (string $part): array => [$part], self::PARTS));
	}

	#[DataProvider('parts')]
	public function testEachPartOfTheClosedSetIsKeptWithItsReason(string $part): void
	{
		$status = $this->readWith([['part' => $part, 'reason' => 'the reason of one line']]);

		$this->assertNotNull($status, "{$part} is in the closed set");
		$this->assertSame([['part' => $part, 'reason' => 'the reason of one line']], $status['degraded']);
	}

	public function testEveryPartIsKeptInTheOrderTheGatewayGaveIt(): void
	{
		$rows = array_map(static fn (string $part): array => ['part' => $part, 'reason' => "reason of {$part}"], self::PARTS);

		$status = $this->readWith($rows);

		$this->assertSame($rows, $status['degraded'] ?? NULL);
	}

	public function testARowIsKeptAsItsPartAndItsReasonOnly(): void
	{
		$status = $this->readWith([['part' => 'ddr', 'reason' => 'no usable name', 'extra' => 'dropped']]);

		$this->assertSame([['part' => 'ddr', 'reason' => 'no usable name']], $status['degraded'] ?? NULL);
	}

	public function testAReasonOfExactly300BytesIsKept(): void
	{
		$reason = str_repeat('é', 150);
		$this->assertSame(300, strlen($reason), 'before: the reason is 300 bytes, 150 characters');

		$status = $this->readWith([['part' => 'acl', 'reason' => $reason]]);

		$this->assertSame($reason, $status['degraded'][0]['reason'] ?? NULL);
	}

	/** @return array<string,array{mixed}> a degraded field or row the contract does not allow */
	public static function invalid(): array
	{
		$row = ['part' => 'dnsbl', 'reason' => 'boot timeout'];

		return [
			'null' => [NULL],
			'a string' => ['dnsbl'],
			'a number' => [1],
			'an object holding a row' => [(object) ['0' => $row]],
			'an empty object' => [(object) []],
			'a row that is a string' => [['dnsbl']],
			'a row that is a list' => [[['dnsbl', 'boot timeout']]],
			'a row without a part' => [[['reason' => 'boot timeout']]],
			'a row without a reason' => [[['part' => 'dnsbl']]],
			'a null part' => [[['part' => NULL, 'reason' => 'x']]],
			'a numeric part' => [[['part' => 1, 'reason' => 'x']]],
			'an unknown part' => [[['part' => 'modules', 'reason' => 'x']]],
			'a part in another case' => [[['part' => 'DNSBL', 'reason' => 'x']]],
			'a part twice' => [[$row, ['part' => 'acl', 'reason' => 'x'], $row]],
			'a part twice with another reason' => [[$row, ['part' => 'dnsbl', 'reason' => 'another']]],
			'a null reason' => [[['part' => 'dnsbl', 'reason' => NULL]]],
			'a numeric reason' => [[['part' => 'dnsbl', 'reason' => 7]]],
			'an empty reason' => [[['part' => 'dnsbl', 'reason' => '']]],
			'a reason over 300 bytes' => [[['part' => 'dnsbl', 'reason' => str_repeat('x', 301)]]],
			'a reason over 300 bytes in multibyte characters' => [[['part' => 'dnsbl', 'reason' => str_repeat('é', 151)]]],
			'a newline in the reason' => [[['part' => 'dnsbl', 'reason' => "boot\ntimeout"]]],
			'a tab in the reason' => [[['part' => 'dnsbl', 'reason' => "boot\ttimeout"]]],
			'a NUL in the reason' => [[['part' => 'dnsbl', 'reason' => "boot\0timeout"]]],
			'DEL in the reason' => [[['part' => 'dnsbl', 'reason' => "boot\x7ftimeout"]]],
			'a zero-width space in the reason' => [[['part' => 'dnsbl', 'reason' => "boot\u{200b}timeout"]]],
		];
	}

	#[DataProvider('invalid')]
	public function testAnInvalidDegradedFieldMakesTheWholeStatusUnavailable(mixed $degraded): void
	{
		$this->assertNull($this->readWith($degraded));
	}
}
