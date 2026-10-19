<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/support/ProcessRunner.php';

/**
 * issue #3515 -- the pfB-DNS page saves its toggle and its DNS Reply Logging preference, and write_config() writes the
 * whole copy of config.xml the request read when it started. An apply's Resolver move (snapshot, moved interface) that
 * landed in between would be overwritten with the values this request loaded.
 *
 * The page takes the config lock the apply's Resolver move takes, reads config.xml afresh under it, writes its own leaves
 * and holds the lock through write_config():
 *   - the move the apply made survives a pfB-DNS save, and the posted toggle and preference are saved;
 *   - a lock that stays taken, or a failed fresh read, is an input error: nothing is written;
 *   - a config.xml write that throws still releases the lock.
 *
 * The save runs in a child process (support/DnsSaveWorker.php: the page's real save code over the doubles), because the
 * page ends with exit().
 */
final class DnsSettingsSaveRaceTest extends TestCase
{
	private const DNS = 'installedpackages/pfblockerngdns/config/0';
	private const DNSBL = 'installedpackages/pfblockerngdnsblsettings/config/0';
	private const SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';

	/** @return array{disk:array,events:list<list<string>>,lockHeld:bool,inputErrors:list<string>} */
	private function runScenario(string $scenario): array
	{
		$dir = sys_get_temp_dir() . '/pfb_dns_save_race_' . bin2hex(random_bytes(6));
		mkdir($dir, 0700, TRUE);
		$result = "{$dir}/result.json";
		try {
			$process = pfb_test_run_process([PHP_BINARY, __DIR__ . '/support/DnsSaveWorker.php', $scenario, $result], 60.0);
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

	public function testASaveThatStartedBeforeAnAppliesMoveKeepsTheMoveAndItsSnapshotAndSavesTheToggleAndPreference(): void
	{
		$result = $this->runScenario('interleave');

		$this->assertSame([], $result['inputErrors'], 'the posted form is valid');
		$this->assertSame('', self::at($result['disk'], self::DNS . '/pfb_dns'), 'the toggle is saved as posted: Off');
		$this->assertSame('', self::at($result['disk'], self::DNSBL . '/pfb_py_reply'), 'the logging preference is saved in the same save');
		$this->assertSame('lo0', self::at($result['disk'], 'unbound/active_interface'), 'the Resolver move the apply made is kept');
		$this->assertNotSame('', (string) self::at($result['disk'], self::SAVED), 'and so is its snapshot');
		$this->assertFalse($result['lockHeld'], 'the lock is released');
	}

	public function testALockThatStaysTakenIsAnInputErrorThatSavesNothing(): void
	{
		$result = $this->runScenario('lock_taken');

		$this->assertCount(1, $result['inputErrors']);
		$this->assertSame('on', self::at($result['disk'], self::DNS . '/pfb_dns'), 'nothing posted was saved');
		$this->assertNotContains('write', array_map(static fn (array $event): string => $event[0], $result['events']));
		$this->assertFalse($result['lockHeld']);
	}

	public function testAFailedFreshReadIsAnInputErrorThatSavesNothingAndReleasesTheLock(): void
	{
		$result = $this->runScenario('read_fails');

		$this->assertCount(1, $result['inputErrors']);
		$this->assertSame('on', self::at($result['disk'], self::DNS . '/pfb_dns'), 'nothing posted was saved');
		$this->assertNotContains('write', array_map(static fn (array $event): string => $event[0], $result['events']));
		$this->assertFalse($result['lockHeld']);
	}

	public function testAWriteThatThrowsStillReleasesTheConfigLock(): void
	{
		$result = $this->runScenario('write_throws');

		$this->assertFalse($result['lockHeld'], 'the lock is released even when config.xml cannot be written');
	}
}
