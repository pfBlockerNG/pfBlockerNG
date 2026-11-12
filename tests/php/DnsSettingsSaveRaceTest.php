<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

require_once __DIR__ . '/support/ProcessRunner.php';

/**
 * issue #3515 -- DNS > General saves the pfB-DNS toggle and its listener settings, DNS Reply Logging and the Resolver addresses with its one
 * "Save DNS settings" button (issue #3856), while write_config() writes the whole copy of config.xml the request read when it started.
 * An apply's Resolver move (snapshot, moved interface) that landed in between would be overwritten with the values this request loaded.
 *
 * The page takes the config lock the apply's Resolver move takes, reads config.xml afresh under it, writes its own leaves
 * and holds the lock through its one write_config():
 *   - the move the apply made survives the save, and both parts of the posted form are saved: the pfB-DNS toggle and DNS Reply Logging;
 *   - a lock that stays taken, or a failed fresh read, is an input error: nothing is written;
 *   - a config.xml write that throws still releases the lock.
 *   - a failed save re-displays what the form submitted, both its parts, not what is stored;
 *
 * The save runs in a child process (support/DnsSaveWorker.php: the page's real save code over the doubles), because the
 * page ends with exit(). Its default form turns pfB-DNS Off to On and DNS Reply Logging On to Off.
 */
final class DnsSettingsSaveRaceTest extends TestCase
{
	private const DNS = 'installedpackages/pfblockerngdns/config/0';
	private const DNSBL = 'installedpackages/pfblockerngdnsblsettings/config/0';
	private const SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';
	private const SAVE = '[pfBlockerNG] save DNS settings';

	/** @return array{disk:array,before:array,events:list<list<string>>,lockHeld:bool,inputErrors:list<string>} */
	private function runScenario(string $scenario): array
	{
		$dir = sys_get_temp_dir() . '/pfb_dns_save_race_' . bin2hex(random_bytes(6));
		mkdir($dir, 0700, TRUE);
		$result = "{$dir}/result.json";
		try {
			$process = pfb_test_run_process([PHP_BINARY, __DIR__ . '/support/DnsSaveWorker.php', $scenario, $result], 60.0);
			$this->assertFileExists($result, "the worker reported nothing (exit {$process['exit']}): {$process['stderr']}");
			$this->assertStringNotContainsString('worker:', $process['stdout'] . $process['stderr'], 'the worker found the save code it runs on DNS General');
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

	/** The before-state of every save here: pfB-DNS Off and DNS Reply Logging On, so that the posted On and Off are both changes. */
	private function assertStoredBefore(array $result): void
	{
		$this->assertSame('', self::at($result['before'], self::DNS . '/pfb_dns'), 'before: pfB-DNS is Off');
		$this->assertSame('on', self::at($result['before'], self::DNSBL . '/pfb_py_reply'), 'before: DNS Reply Logging is On');
	}

	public function testASaveKeepsTheMoveAndItsSnapshotAndSavesBothPartsOfTheForm(): void
	{
		$result = $this->runScenario('interleave');

		$this->assertStoredBefore($result);
		$this->assertSame([], $result['inputErrors'], 'the posted form is valid');
		$this->assertSame([self::SAVE], $result['writes'], 'one write_config() for both parts');
		$this->assertSame('on', self::at($result['disk'], self::DNS . '/pfb_dns'), 'the pfB-DNS part is saved as posted: On');
		$this->assertSame('', self::at($result['disk'], self::DNSBL . '/pfb_py_reply'), 'the DNS General part is saved as posted: Off');
		$this->assertSame('lo0', self::at($result['disk'], 'unbound/active_interface'), 'the Resolver move the apply made is kept');
		$this->assertNotSame('', (string) self::at($result['disk'], self::SAVED), 'and so is its snapshot');
		$this->assertFalse($result['lockHeld'], 'the lock is released');
	}

	public function testALockThatStaysTakenIsAnInputErrorThatSavesNothing(): void
	{
		$result = $this->runScenario('lock_taken');

		$this->assertStoredBefore($result);
		$this->assertCount(1, $result['inputErrors']);
		$this->assertSame('', self::at($result['disk'], self::DNS . '/pfb_dns'), 'nothing posted was saved: pfB-DNS stays Off');
		$this->assertSame('on', self::at($result['disk'], self::DNSBL . '/pfb_py_reply'), 'nothing posted was saved: DNS Reply Logging stays On');
		$this->assertSame([], $result['writes']);
		$this->assertNotContains('write', array_map(static fn (array $event): string => $event[0], $result['events']));
		$this->assertFalse($result['lockHeld']);
	}

	public function testAFailedFreshReadIsAnInputErrorThatSavesNothingAndReleasesTheLock(): void
	{
		$result = $this->runScenario('read_fails');

		$this->assertStoredBefore($result);
		$this->assertCount(1, $result['inputErrors']);
		$this->assertSame('', self::at($result['disk'], self::DNS . '/pfb_dns'), 'nothing posted was saved: pfB-DNS stays Off');
		$this->assertSame('on', self::at($result['disk'], self::DNSBL . '/pfb_py_reply'), 'nothing posted was saved: DNS Reply Logging stays On');
		$this->assertSame([], $result['writes']);
		$this->assertNotContains('write', array_map(static fn (array $event): string => $event[0], $result['events']));
		$this->assertFalse($result['lockHeld']);
	}

	public function testAWriteThatThrowsStillReleasesTheConfigLock(): void
	{
		$result = $this->runScenario('write_throws');

		$this->assertFalse($result['lockHeld'], 'the lock is released even when config.xml cannot be written');
	}

	private const LOCK_ERROR = 'DNS: another save of the pfSense configuration is in progress, so these settings were not saved. Save again in a moment.';
	private const WRITE_ERROR = 'DNS: the configuration could not be written, so these settings were not saved. Save again in a moment.';

	/** @return array<string,array{string,string}> the failed saves (the lock stays taken, the fresh read fails, pfSense refuses the write) and the one error each shows */
	public static function failedSaves(): array
	{
		return [
			'the config lock stays taken'     => ['lock_taken', self::LOCK_ERROR],
			'the fresh config.xml read fails' => ['read_fails', self::LOCK_ERROR],
			'pfSense refuses the write'       => ['write_refused', self::WRITE_ERROR],
			'config.xml file write fails'      => ['write_failed', self::WRITE_ERROR],
		];
	}

	#[DataProvider('failedSaves')]
	public function testAFailedSaveRedisplaysWhatBothPartsOfTheFormSubmittedNotWhatIsStored(string $scenario, string $error): void
	{
		// Given pfB-DNS Off and DNS Reply Logging On stored, and a form that posts pfB-DNS On and DNS Reply Logging Off (the checkbox absent)
		$result = $this->runScenario($scenario);
		$this->assertStoredBefore($result);

		// Then the save is an input error naming why, the form comes back with what it submitted, and nothing was saved
		$this->assertSame([$error], $result['inputErrors'], 'before: the save failed');
		$this->assertSame('', $result['reply'], 'the form re-displays the preference it submitted, not the stored one');
		$this->assertSame('on', $result['pconfig']['pfb_dns'] ?? NULL, 'and the pfB-DNS enable it submitted');
		$this->assertSame('', self::at($result['disk'], self::DNS . '/pfb_dns'), 'config.xml keeps pfB-DNS Off');
		$this->assertSame('on', self::at($result['disk'], self::DNSBL . '/pfb_py_reply'), 'and the stored preference');
		$this->assertFalse($result['pendingMarked'], 'a failed save marks no pending change');
		$this->assertTrue($result['returned'], 'a failed save renders its errors instead of exiting through a redirect');
	}

	public function testAFailedListenerAdvertisementWriteIsAnInputErrorEvenWhenThePageWriteSucceeds(): void
	{
		$result = $this->runScenario('advert_write_fails');

		$this->assertContains('pfBlockerNG: saving DNS listener advertisements', $result['writes'], 'the advertisement write was attempted');
		$this->assertNotSame([], $result['inputErrors'], 'the operator is told the save failed');
		$this->assertTrue($result['returned'], 'the page renders its error instead of redirecting');
		$this->assertFalse($result['pendingMarked'], 'a failed save marks no pending change');
		$this->assertSame(0, $result['unboundCalls'], 'Unbound is not regenerated for a save that failed');
	}
}
