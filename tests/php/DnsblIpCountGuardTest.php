<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** IPv4 and IPv6 sidecars each expose a safe count and positive log decision. */
final class DnsblIpCountGuardTest extends TestCase
{
	private const APPLY = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';
	private string $dir;

	public static function setUpBeforeClass(): void
	{
		require_once dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';
	}

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_ip_count_' . getmypid() . '_' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir($this->dir, 0700, TRUE));
	}

	protected function tearDown(): void
	{
		foreach (glob("{$this->dir}/*") ?: [] as $path) {
			is_dir($path) ? @rmdir($path) : @unlink($path);
		}
		@rmdir($this->dir);
	}

	/** @return array<string, array{string, string}> */
	public static function sidecarSeams(): array
	{
		return [
			'IPv4' => ['pfb_dnsbl_ipv4_count_decision', 'feed_v4.ip'],
			'IPv6' => ['pfb_dnsbl_ipv6_count_decision', 'feed_v6.ip'],
		];
	}

	#[DataProvider('sidecarSeams')]
	public function testEachSidecarReturnsCountAndPositiveDecision(string $seam, string $name): void
	{
		$path = "{$this->dir}/{$name}";
		$this->assertNotFalse(file_put_contents($path, "one\ntwo\n"));

		$this->assertSame(['count' => 2, 'loggable' => TRUE], $seam($path));
	}

	#[DataProvider('sidecarSeams')]
	public function testEachSidecarCountsAnUnterminatedLastLine(string $seam, string $name): void
	{
		$path = "{$this->dir}/{$name}";
		$this->assertNotFalse(file_put_contents($path, "one\ntwo"));
		$this->assertSame(['count' => 2, 'loggable' => TRUE], $seam($path));
	}

	#[DataProvider('sidecarSeams')]
	public function testEachSidecarTurnsReadFailureIntoNonLoggableZero(string $seam, string $name): void
	{
		$path = "{$this->dir}/{$name}";
		$this->assertTrue(mkdir($path, 0700));

		$this->assertSame(['count' => 0, 'loggable' => FALSE], $seam($path));
	}

	#[DataProvider('sidecarSeams')]
	public function testEachSidecarSkipsLogForEmptyFile(string $seam, string $name): void
	{
		$path = "{$this->dir}/{$name}";
		$this->assertNotFalse(file_put_contents($path, ''));

		$this->assertSame(['count' => 0, 'loggable' => FALSE], $seam($path));
	}

	/** #993: the live sync/download/firewall monolith is unsafe off-appliance; comments are stripped. */
	public function testSyncPassDispatchesBothDistinctSidecarDecisions(): void
	{
		$source = php_strip_whitespace(self::APPLY);
		$start = strpos($source, 'function sync_package_pfblockerng(');
		$this->assertNotFalse($start);
		$sync = substr($source, $start);
		foreach (self::sidecarSeams() as [$seam]) {
			$this->assertSame(1, substr_count($sync, "{$seam}("), "sync pass must dispatch {$seam} exactly once");
		}
	}
}
