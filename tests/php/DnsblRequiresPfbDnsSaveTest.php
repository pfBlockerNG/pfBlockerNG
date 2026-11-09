<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

require_once __DIR__ . '/support/ProcessRunner.php';

/**
 * issue #3770 -- DNSBL runs only through pfB-DNS, so the two pages refuse the saves that would break that:
 *   - the DNSBL page refuses DNSBL On while config.xml holds pfB-DNS Off or nothing;
 *   - the pfB-DNS page refuses pfB-DNS Off while config.xml holds DNSBL On.
 * Both decide on what config.xml holds under the config lock (the fresh read), not on the copy the request loaded, and
 * a refusal writes nothing and sends no redirect: the form comes back with the error and what was submitted.
 *
 * Each save runs in a child process (support/DnsblSaveWorker.php and support/DnsSaveWorker.php: the page's real save code
 * over the doubles), because a saved page ends with exit().
 */
final class DnsblRequiresPfbDnsSaveTest extends TestCase
{
	private const DNS = 'installedpackages/pfblockerngdns/config/0';
	private const DNSBL = 'installedpackages/pfblockerngdnsblsettings/config/0';

	/** @return array<string,mixed> the worker's result: disk, before, events, lockHeld, inputErrors, pendingMarked, returned, ... */
	private function runWorker(string $worker, string $scenario): array
	{
		$dir = sys_get_temp_dir() . '/pfb_dnsbl_requires_pfb_dns_' . bin2hex(random_bytes(6));
		mkdir($dir, 0700, TRUE);
		$result = "{$dir}/result.json";
		try {
			$process = pfb_test_run_process([PHP_BINARY, __DIR__ . "/support/{$worker}.php", $scenario, $result], 60.0);
			$this->assertFileExists($result, "the worker reported nothing (exit {$process['exit']}): {$process['stderr']}");
			return json_decode((string) file_get_contents($result), TRUE, 512, JSON_THROW_ON_ERROR);
		} finally {
			@unlink($result);
			@rmdir($dir);
		}
	}

	private static function at(array $config, string $path): mixed
	{
		foreach (explode('/', $path) as $key) {
			if (!is_array($config) || !array_key_exists($key, $config)) {
				return NULL;
			}
			$config = $config[$key];
		}
		return $config;
	}

	/** @param array<string,mixed> $result */
	private function assertRefusedWithNothingWritten(array $result): void
	{
		$this->assertSame($result['before'], $result['disk'], 'config.xml is what it was before the save');
		$this->assertNotContains('write', array_column($result['events'], 0), 'write_config() was never called');
		$this->assertFalse($result['pendingMarked'], 'a refused save marks no pending change');
		$this->assertFalse($result['lockHeld'], 'the config lock is released');
		$this->assertTrue($result['returned'], 'the page renders the error instead of exiting through its redirect');
	}

	/** @return array<string,array{string}> pfB-DNS is not On in config.xml when the DNSBL save takes the lock */
	public static function pfbDnsNotOn(): array
	{
		return [
			'pfB-DNS stored Off' => ['pfb_dns_off'],
			'pfB-DNS never stored' => ['pfb_dns_absent'],
			'pfB-DNS turned Off since this request loaded it' => ['pfb_dns_turned_off_meanwhile'],
		];
	}

	#[DataProvider('pfbDnsNotOn')]
	public function testSavingDnsblOnWhilePfbDnsIsNotOnIsRefusedAndWritesNothing(string $scenario): void
	{
		// Given pfB-DNS is not On in config.xml, and a DNSBL form that posts DNSBL On with a changed port
		$result = $this->runWorker('DnsblSaveWorker', $scenario);
		$this->assertNotSame('on', self::at($result['before'], self::DNS . '/pfb_dns'), 'before: pfB-DNS is not On');
		$this->assertNotSame('on', self::at($result['before'], self::DNSBL . '/pfb_dnsbl'), 'before: DNSBL is not On');

		// Then the form comes back with one error that names pfB-DNS and where it is turned on, as submitted
		$this->assertCount(1, $result['inputErrors'], 'one input error');
		$this->assertStringContainsString('pfB-DNS', $result['inputErrors'][0]);
		$this->assertStringContainsString('DNS > pfB-DNS', $result['inputErrors'][0]);
		$this->assertSame('8082', $result['postedPort'], 'the form re-displays the submitted port');

		// and nothing was saved: neither DNSBL On nor the port
		$this->assertRefusedWithNothingWritten($result);
	}

	public function testSavingDnsblOnWhilePfbDnsIsOnIsSaved(): void
	{
		// Given pfB-DNS On and DNSBL not On in config.xml
		$result = $this->runWorker('DnsblSaveWorker', 'pfb_dns_on');
		$this->assertSame('on', self::at($result['before'], self::DNS . '/pfb_dns'), 'before: pfB-DNS is On');
		$this->assertNotSame('on', self::at($result['before'], self::DNSBL . '/pfb_dnsbl'), 'before: DNSBL is not On');

		// Then the save goes through
		$this->assertSame([], $result['inputErrors']);
		$this->assertSame('on', self::at($result['disk'], self::DNSBL . '/pfb_dnsbl'), 'DNSBL is saved On');
		$this->assertSame('8082', self::at($result['disk'], self::DNSBL . '/pfb_dnsport'), 'with the posted port');
		$this->assertTrue($result['pendingMarked'], 'and applies on the next Update');
		$this->assertFalse($result['returned'], 'through the redirect');
	}

	public function testSavingDnsblOffWhilePfbDnsIsOffIsSaved(): void
	{
		// Given pfB-DNS Off in config.xml, and a DNSBL form that posts DNSBL Off with a changed port
		$result = $this->runWorker('DnsblSaveWorker', 'pfb_dns_off_dnsbl_off');
		$this->assertSame('', self::at($result['before'], self::DNS . '/pfb_dns'), 'before: pfB-DNS is Off');
		$this->assertSame('8081', self::at($result['before'], self::DNSBL . '/pfb_dnsport'), 'before: the old port');

		// Then the save goes through: only turning DNSBL on needs pfB-DNS
		$this->assertSame([], $result['inputErrors']);
		$this->assertSame('', self::at($result['disk'], self::DNSBL . '/pfb_dnsbl'), 'DNSBL is saved Off');
		$this->assertSame('8082', self::at($result['disk'], self::DNSBL . '/pfb_dnsport'), 'with the posted port');
	}

	/** @return array<string,array{string}> DNSBL is On in config.xml when the pfB-DNS save takes the lock */
	public static function dnsblOn(): array
	{
		return [
			'DNSBL stored On' => ['dnsbl_on'],
			'DNSBL turned On since this request loaded it' => ['dnsbl_turned_on_meanwhile'],
		];
	}

	#[DataProvider('dnsblOn')]
	public function testSavingPfbDnsOffWhileDnsblIsOnIsRefusedAndWritesNothing(string $scenario): void
	{
		// Given DNSBL and pfB-DNS On in config.xml, and a pfB-DNS form that posts pfB-DNS Off (the checkbox unticked)
		$result = $this->runWorker('DnsSaveWorker', $scenario);
		$this->assertSame('on', self::at($result['before'], self::DNSBL . '/pfb_dnsbl'), 'before: DNSBL is On');
		$this->assertSame('on', self::at($result['before'], self::DNS . '/pfb_dns'), 'before: pfB-DNS is On');

		// Then the form comes back with one error that names DNSBL and where it is turned off, with the box as submitted
		$this->assertCount(1, $result['inputErrors'], 'one input error');
		$this->assertStringContainsString('DNSBL', $result['inputErrors'][0]);
		$this->assertStringContainsString('DNS > DNSBL', $result['inputErrors'][0]);
		$this->assertSame('', $result['pfbDnsShown'], 'the form re-displays the submitted, unticked box');

		// and pfB-DNS is still On in config.xml, nothing else written
		$this->assertSame('on', self::at($result['disk'], self::DNS . '/pfb_dns'), 'pfB-DNS stays On');
		$this->assertRefusedWithNothingWritten($result);
	}

	public function testSavingPfbDnsOnWhileDnsblIsOnIsSaved(): void
	{
		// Given DNSBL On in config.xml and a form that posts pfB-DNS On
		$result = $this->runWorker('DnsSaveWorker', 'dnsbl_on_pfb_dns_on');
		$this->assertSame('on', self::at($result['before'], self::DNSBL . '/pfb_dnsbl'), 'before: DNSBL is On');

		// Then the save goes through
		$this->assertSame([], $result['inputErrors']);
		$this->assertSame('on', self::at($result['disk'], self::DNS . '/pfb_dns'), 'pfB-DNS is saved On');
		$this->assertTrue($result['pendingMarked'], 'and applies on the next Update');
		$this->assertFalse($result['returned'], 'through the redirect');
	}

	public function testSavingPfbDnsOffWhileDnsblIsOffIsSaved(): void
	{
		// Given pfB-DNS On and DNSBL Off in config.xml, and a form that posts pfB-DNS Off
		$result = $this->runWorker('DnsSaveWorker', 'dnsbl_off');
		$this->assertSame('on', self::at($result['before'], self::DNS . '/pfb_dns'), 'before: pfB-DNS is On');
		$this->assertSame('', self::at($result['before'], self::DNSBL . '/pfb_dnsbl'), 'before: DNSBL is Off');

		// Then the save goes through: only a DNSBL that is On keeps pfB-DNS from being turned off
		$this->assertSame([], $result['inputErrors']);
		$this->assertSame('', self::at($result['disk'], self::DNS . '/pfb_dns'), 'pfB-DNS is saved Off');
		$this->assertTrue($result['pendingMarked'], 'and applies on the next Update');
	}
}
