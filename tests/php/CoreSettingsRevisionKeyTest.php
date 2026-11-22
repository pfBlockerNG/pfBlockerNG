<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3937 (Codex on PR #3942): Core shows the adapter's revision to every API client, and the projected settings it is taken over
 * hold feed credentials. The revision is keyed with a random per-box key only root can read, so it never confirms a guessed
 * credential, while any change of the settings, a credential included, still moves it (the conflict check depends on that).
 */
#[CoversFunction('pfb_core_settings_revision')]
final class CoreSettingsRevisionKeyTest extends TestCase
{
	private string $dir;
	private ?string $priorKey;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_core_revkey_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->dir, 0700));
		$this->priorKey = $GLOBALS['pfb']['core_revision_key'] ?? NULL;
		$GLOBALS['pfb']['core_revision_key'] = "{$this->dir}/one.key";
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb']['core_revision_key'] = $this->priorKey;
		rmdir_recursive($this->dir);
	}

	/** Settings with one feed whose credentials are $credentials. @return array<string, mixed> */
	private static function settings(string $credentials): array
	{
		return ['dns' => ['control' => FALSE], 'feeds/ipv4' => ['groups' => [['name' => 'G', 'feeds' => [
			['header' => 'F', 'url' => 'https://example.org/f', 'credentials' => $credentials],
		]]]]];
	}

	public function testTheSameSettingsUnderTwoKeysGiveTwoRevisions(): void
	{
		$one = pfb_core_settings_revision(self::settings('user:s3cret'));
		$this->assertSame($one, pfb_core_settings_revision(self::settings('user:s3cret')), 'one key: equal settings, equal revision');
		$GLOBALS['pfb']['core_revision_key'] = "{$this->dir}/two.key";
		$this->assertNotSame($one, pfb_core_settings_revision(self::settings('user:s3cret')), 'another key gives another revision');
	}

	public function testACredentialChangeStillMovesTheRevision(): void
	{
		$this->assertNotSame(pfb_core_settings_revision(self::settings('user:s3cret')), pfb_core_settings_revision(self::settings('user:other')));
	}

	public function testTheRevisionIsNotTheUnkeyedHashOfTheSettingsWithTheRightCredential(): void
	{
		$settings = self::settings('user:s3cret');
		$unkeyed = (int) hexdec(substr(hash('sha256', (string) json_encode($settings, JSON_INVALID_UTF8_SUBSTITUTE)), 0, 13)) ?: 1;
		$this->assertNotSame($unkeyed, pfb_core_settings_revision($settings), 'a guess checked offline against the revision would confirm it');
	}

	public function testTheKeyIsCreatedOnceRandomAndReadableByItsOwnerOnly(): void
	{
		$key = "{$this->dir}/one.key";
		$this->assertFileDoesNotExist($key);
		$first = pfb_core_settings_revision(self::settings(''));
		$this->assertFileExists($key);
		$this->assertSame(32, strlen((string) file_get_contents($key)), 'a 256-bit key');
		$this->assertSame('0600', sprintf('%04o', fileperms($key) & 0777));
		$bytes = file_get_contents($key);
		$this->assertSame($first, pfb_core_settings_revision(self::settings('')), 'the key is kept: the revision stays');
		$this->assertSame($bytes, file_get_contents($key));
	}

	/**
	 * Issue #4199: a create killed after the file appeared and before its 32 bytes were written left an empty or short key, and
	 * every revision then threw until the file was removed by hand. Such a key was never published whole, so it is replaced.
	 */
	#[\PHPUnit\Framework\Attributes\DataProvider('interruptedKeys')]
	public function testAKeyLeftShortByAnInterruptedCreateIsReplacedByAWholeOne(string $left): void
	{
		$key = "{$this->dir}/one.key";
		file_put_contents($key, $left);

		$revision = pfb_core_settings_revision(self::settings(''));

		$bytes = (string) file_get_contents($key);
		$this->assertSame(32, strlen($bytes), 'a whole 256-bit key replaces the short one');
		$this->assertSame('0600', sprintf('%04o', fileperms($key) & 0777));
		$this->assertSame($revision, pfb_core_settings_revision(self::settings('')), 'the new key is kept');
		$this->assertSame(['one.key'], array_values(array_diff(scandir($this->dir), ['.', '..', 'one.key.lock'])), 'no staged file is left');
	}

	/** @return array<string, array{string}> */
	public static function interruptedKeys(): array
	{
		return ['empty' => [''], 'half written' => [str_repeat("\x01", 16)]];
	}

	/**
	 * Issue #4199: a staged key a killed create left beside the key is never published, so the next create removes it; the
	 * lock file that serialises creates stays.
	 */
	public function testAStagedKeyAKilledCreateLeftIsRemovedByTheNextCreate(): void
	{
		$staged = "{$this->dir}/one.key.new";
		file_put_contents($staged, str_repeat("\x03", 32));

		pfb_core_settings_revision(self::settings(''));

		$this->assertFileDoesNotExist($staged);
		$this->assertSame(32, strlen((string) file_get_contents("{$this->dir}/one.key")));
	}

	/** Issue #4199: a key longer than 32 bytes is no interrupted create, so it is not replaced: the revision refuses it. */
	public function testAKeyLongerThanAWholeOneIsRefusedNotReplaced(): void
	{
		$key = "{$this->dir}/one.key";
		$bytes = str_repeat("\x04", 32) . "\n";
		file_put_contents($key, $bytes);

		$refusal = '';
		try {
			pfb_core_settings_revision(self::settings(''));
		} catch (RuntimeException $e) {
			$refusal = $e->getMessage();
		}
		$this->assertStringContainsString('cannot read the settings revision key', $refusal, 'a 33-byte key must be refused');
		$this->assertSame($bytes, file_get_contents($key), 'the key is left as it was');
	}

	/**
	 * Run $call in $n forked children released together once all are forked; each sends back what it returned (or "ERR:" and
	 * the message) and dies without running shutdown handlers. @return string[]
	 */
	private static function inChildren(int $n, callable $call): array
	{
		$pairs = $pids = [];
		for ($i = 0; $i < $n; $i++) {
			$pairs[$i] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
			$pid = pcntl_fork();
			if ($pid === 0) {
				pcntl_alarm(30);	// a child left waiting (no start signal, a stuck lock) dies without running shutdown handlers
				fread($pairs[$i][1], 1);	// the start signal
				try {
					$out = (string) $call();
				} catch (Throwable $e) {
					$out = 'ERR:' . $e->getMessage();
				}
				fwrite($pairs[$i][1], $out);
				posix_kill(posix_getpid(), SIGKILL);
			}
			$pids[$i] = $pid;
		}
		foreach ($pairs as $pair) {
			fwrite($pair[0], 'g');
		}
		$outs = [];
		foreach ($pids as $i => $pid) {
			fclose($pairs[$i][1]);
			$outs[$i] = (string) stream_get_contents($pairs[$i][0]);
			pcntl_waitpid($pid, $status);
		}
		return $outs;
	}

	/** Issue #4199: first callers that race to create the key all get the one key that was published, never one each. */
	public function testFirstCallersRacingToCreateTheKeyAllGetThePublishedOne(): void
	{
		if (!function_exists('pcntl_fork') || !function_exists('posix_kill')) {
			$this->markTestSkipped('pcntl and posix are required to race separate processes.');
		}
		for ($round = 0; $round < 20; $round++) {
			$GLOBALS['pfb']['core_revision_key'] = $key = "{$this->dir}/race{$round}.key";

			$outs = self::inChildren(8, static fn (): string => bin2hex(pfb_core_revision_key()));

			$this->assertSame(array_fill(0, 8, bin2hex((string) file_get_contents($key))), $outs, "round {$round}: every caller returns the published key");
		}
	}

	/** Issue #4199: a create that cannot write the whole key throws as a write failure and publishes nothing, staged or not. */
	public function testACreateThatCannotWriteTheWholeKeyThrowsAndLeavesNoKey(): void
	{
		if (!function_exists('pcntl_fork') || !function_exists('posix_setrlimit')) {
			$this->markTestSkipped('pcntl and posix are required to limit a separate process\'s file size.');
		}
		$key = "{$this->dir}/one.key";

		$outs = self::inChildren(1, static function (): string {
			pcntl_signal(SIGXFSZ, SIG_IGN);
			posix_setrlimit(POSIX_RLIMIT_FSIZE, 16, 16);	// the staged key gets 16 of its 32 bytes
			return bin2hex(pfb_core_revision_key());
		});

		$this->assertSame("ERR:cannot write the settings revision key {$key}", $outs[0]);
		$this->assertSame(['one.key.lock'], array_values(array_diff(scandir($this->dir), ['.', '..'])), 'no key and no staged key');
	}
}
