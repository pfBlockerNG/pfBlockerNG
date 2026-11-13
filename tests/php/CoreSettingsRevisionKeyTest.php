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
}
