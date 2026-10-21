<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/support/ProcessRunner.php';

/**
 * issue #3515 -- the DNSBL page saves its whole section, and write_config() writes the whole copy of config.xml the request
 * read when it started. A pfB-DNS page save (DNS Reply Logging Off) or an apply's Resolver move (snapshot, moved
 * interface) that landed in between would therefore be overwritten with the values this request loaded.
 *
 * The DNSBL save takes the same config lock as those writers (pfb_dns_config_lock()), reads config.xml afresh under it,
 * applies the posted DNSBL fields to that fresh section and holds the lock through write_config():
 *   - the user's privacy choice (logging Off), the moved Resolver and its snapshot survive an unrelated DNSBL save, while
 *     the fields the user posted (a port, the block page) are saved;
 *   - a lock that stays taken, or a failed fresh read, is an input error: nothing is written and nothing stays locked.
 *
 * The save runs in a child process (support/DnsblSaveWorker.php: the page's real save code over the doubles), because the
 * page ends with exit().
 */
final class DnsblSettingsSaveRaceTest extends TestCase
{
	private const DNSBL = 'installedpackages/pfblockerngdnsblsettings/config/0';
	private const SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';

	/** @return array{disk:array,events:list<list<string>>,lockHeld:bool,inputErrors:list<string>} */
	private function runScenario(string $scenario): array
	{
		$dir = sys_get_temp_dir() . '/pfb_dnsbl_save_race_' . bin2hex(random_bytes(6));
		mkdir($dir, 0700, TRUE);
		$result = "{$dir}/result.json";
		try {
			$process = pfb_test_run_process([PHP_BINARY, __DIR__ . '/support/DnsblSaveWorker.php', $scenario, $result], 60.0);
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

	public function testASaveThatStartedBeforeAPrivacyChoiceAndAMoveDoesNotOverwriteThem(): void
	{
		// Given a DNSBL save that loaded reply logging On, then a pfB-DNS save of Off and a Resolver move landed on disk
		$result = $this->runScenario('interleave');

		// Then the unrelated posted fields were saved ...
		$this->assertSame('8082', self::at($result['disk'], self::DNSBL . '/pfb_dnsport'), 'the posted DNSBL port is saved');
		$this->assertSame('dnsbl_alt.php', self::at($result['disk'], self::DNSBL . '/dnsbl_webpage'), 'so is the block page chosen on the form');
		// ... and nothing the other writers saved was put back
		$this->assertSame('', self::at($result['disk'], self::DNSBL . '/pfb_py_reply'), 'the user\'s Off for DNS Reply Logging stays Off');
		$this->assertSame('lo0', self::at($result['disk'], 'unbound/active_interface'), 'the moved Resolver stays moved');
		$this->assertNotEmpty(self::at($result['disk'], self::SAVED), 'and its snapshot is kept');
	}

	public function testASaveWritesTheEightPostedPolicyFieldsToDiskInTheirStoredForm(): void
	{
		// Given a save that posts a value different from the seeded one for every DNSBL policy field
		$result = $this->runScenario('interleave');

		// Then each is on disk in its stored form (the page's pfb_dnsbl_policy_from_post() mapping)
		$stored = [
			'global_log'             => 'nxdomain',
			'global_log_mode'        => 'override',
			'pfb_regex'              => 'on',
			'pfb_regex_list'         => base64_encode('a.*'),
			'pfb_idn'                => 'confusable',
			'tld_allow'              => 'on',
			'tld_wildcard'           => 'on',
			'tld_wildcard_blacklist' => base64_encode('zip'),
		];
		foreach ($stored as $key => $value) {
			$this->assertSame($value, self::at($result['disk'], self::DNSBL . "/{$key}"), "the saved {$key}");
		}
	}

	public function testTheConfigLockIsTakenBeforeTheFreshReadAndHeldThroughTheWrite(): void
	{
		$result = $this->runScenario('interleave');

		$this->assertSame(['try_lock', 'read', 'write', 'unlock'], array_map(static fn (array $event): string => $event[0], $result['events']),
			'lock, fresh read under it, one write, then release');
		$this->assertSame('pfb_dns_config', $result['events'][0][1], 'the lock the pfB-DNS page and the Resolver move take');
		$this->assertFalse($result['lockHeld'], 'released');
	}

	public function testALockThatStaysTakenIsAnInputErrorThatSavesNothing(): void
	{
		$result = $this->runScenario('lock_taken');

		$this->assertCount(1, $result['inputErrors'], 'the form comes back with one error');
		$this->assertStringContainsString('another save', $result['inputErrors'][0]);
		$this->assertSame([['try_lock', 'pfb_dns_config', 10]], $result['events'], 'only the bounded attempt: no read, no write');
		$this->assertSame('', self::at($result['disk'], self::DNSBL . '/pfb_py_reply'), 'what the other writer saved is untouched');
		$this->assertNotSame('8082', self::at($result['disk'], self::DNSBL . '/pfb_dnsport'), 'nothing posted was saved');
	}

	public function testAFailedFreshReadIsAnInputErrorThatSavesNothingAndReleasesTheLock(): void
	{
		$result = $this->runScenario('read_fails');

		$this->assertCount(1, $result['inputErrors']);
		$this->assertSame(['try_lock', 'unlock'], array_map(static fn (array $event): string => $event[0], $result['events']),
			'locked, the read failed, released, never written');
		$this->assertFalse($result['lockHeld']);
		$this->assertNotSame('8082', self::at($result['disk'], self::DNSBL . '/pfb_dnsport'), 'nothing posted was saved');
	}

	public function testAWriteThatThrowsStillReleasesTheConfigLock(): void
	{
		$result = $this->runScenario('write_throws');

		$this->assertFalse($result['lockHeld'], 'the lock is released even when config.xml cannot be written');
	}
}
