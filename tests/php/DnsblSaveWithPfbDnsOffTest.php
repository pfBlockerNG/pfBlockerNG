<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/support/ProcessRunner.php';

/**
 * issue #3770 -- pfB-DNS is the parent switch of DNSBL, as the pfBlockerNG enable is of everything: DNSBL stored On with
 * pfB-DNS Off is a state like DNSBL On with pfBlockerNG Off (DNSBL does not run), never a refused save.
 *   - the DNSBL page stores DNSBL On while config.xml holds pfB-DNS Off or nothing, and leaves the pfB-DNS enable as it found it;
 *   - the pfB-DNS form (on DNS > General) stores pfB-DNS Off while config.xml holds DNSBL On, and leaves the DNSBL enable as it found it.
 * Either save is as posted, marks the change pending for the next Update and ends through its redirect.
 *
 * Each save runs in a child process (support/DnsblSaveWorker.php and support/DnsSaveWorker.php: the page's real save code over
 * the doubles), because a saved page ends with exit().
 */
final class DnsblSaveWithPfbDnsOffTest extends TestCase
{
	private const DNS = 'installedpackages/pfblockerngdns/config/0';
	private const DNSBL = 'installedpackages/pfblockerngdnsblsettings/config/0';

	/** @return array<string,mixed> the worker's result: disk, before, events, lockHeld, inputErrors, pendingMarked, returned, ... */
	private function runWorker(string $worker, string $scenario): array
	{
		$dir = sys_get_temp_dir() . '/pfb_dnsbl_save_pfb_dns_off_' . bin2hex(random_bytes(6));
		mkdir($dir, 0700, TRUE);
		$result = "{$dir}/result.json";
		try {
			$process = pfb_test_run_process([PHP_BINARY, __DIR__ . "/support/{$worker}.php", $scenario, $result], 60.0);
			$this->assertFileExists($result, "the worker reported nothing (exit {$process['exit']}): {$process['stderr']}");
			$this->assertStringNotContainsString('worker:', $process['stdout'] . $process['stderr'], 'the worker found the save code it runs');
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

	/** @return array<string,array{string}> pfB-DNS is not On in config.xml when the DNSBL page saves DNSBL On */
	public static function pfbDnsNotOn(): array
	{
		return [
			'pfB-DNS stored Off' => ['pfb_dns_off'],
			'pfB-DNS never stored' => ['plain'],
		];
	}

	#[DataProvider('pfbDnsNotOn')]
	public function testSavingDnsblOnWhilePfbDnsIsNotOnIsStoredAsPosted(string $scenario): void
	{
		// Given pfB-DNS is not On in config.xml, DNSBL is not On either, and a DNSBL form that posts DNSBL On with a changed port
		$result = $this->runWorker('DnsblSaveWorker', $scenario);
		$this->assertNotSame('on', self::at($result['before'], self::DNS . '/pfb_dns'), 'before: pfB-DNS is not On');
		$this->assertNotSame('on', self::at($result['before'], self::DNSBL . '/pfb_dnsbl'), 'before: DNSBL is not On');
		$this->assertNotSame('8082', self::at($result['before'], self::DNSBL . '/pfb_dnsport'), 'before: not the posted port');

		// Then the save goes through with no error: DNSBL On and the posted port are stored
		$this->assertSame([], $result['inputErrors']);
		$this->assertSame('on', self::at($result['disk'], self::DNSBL . '/pfb_dnsbl'), 'DNSBL is saved On');
		$this->assertSame('8082', self::at($result['disk'], self::DNSBL . '/pfb_dnsport'), 'with the posted port');

		// and the pfB-DNS enable is exactly what it was: a save of DNSBL never moves it
		$this->assertSame(self::at($result['before'], self::DNS . '/pfb_dns'), self::at($result['disk'], self::DNS . '/pfb_dns'));

		// and it applies on the next Update, through the redirect, with the lock released
		$this->assertTrue($result['pendingMarked'], 'marked pending');
		$this->assertFalse($result['returned'], 'ends through the redirect');
		$this->assertFalse($result['lockHeld'], 'the config lock is released');
	}

	public function testSavingPfbDnsOffWhileDnsblIsOnIsStoredAsPosted(): void
	{
		// Given DNSBL and pfB-DNS On in config.xml, and a pfB-DNS form that posts pfB-DNS Off (the checkbox unticked)
		$result = $this->runWorker('DnsSaveWorker', 'dnsbl_on');
		$this->assertSame('on', self::at($result['before'], self::DNSBL . '/pfb_dnsbl'), 'before: DNSBL is On');
		$this->assertSame('on', self::at($result['before'], self::DNS . '/pfb_dns'), 'before: pfB-DNS is On');

		// Then the save goes through with no error: pfB-DNS is stored Off
		$this->assertSame([], $result['inputErrors']);
		$this->assertSame('', self::at($result['disk'], self::DNS . '/pfb_dns'), 'pfB-DNS is saved Off');

		// and the DNSBL enable is exactly what it was: a save of pfB-DNS never moves it
		$this->assertSame('on', self::at($result['disk'], self::DNSBL . '/pfb_dnsbl'), 'DNSBL stays On');

		// and it applies on the next Update, through the redirect, with the lock released
		$this->assertTrue($result['pendingMarked'], 'marked pending');
		$this->assertFalse($result['returned'], 'ends through the redirect');
		$this->assertFalse($result['lockHeld'], 'the config lock is released');
	}
}
