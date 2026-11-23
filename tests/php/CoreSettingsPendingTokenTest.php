<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4031 (docs/specs/go-updater-pipeline.md §8.6): the settings adapter's read answers the pending-changes token beside the
 * settings, as `platform.pendingToken`, taken before the settings are read as sync_package_pfblockerng() takes it at its start. The
 * Core Updater hands it back unread and the Outpost apply settles exactly that token, so a change marked while the Update ran stays
 * pending. The token is opaque: carried whole or the read refused whole, never altered or truncated.
 */
#[CoversFunction('pfb_core_settings_backend')]
#[CoversFunction('pfb_core_settings_serve')]
final class CoreSettingsPendingTokenTest extends TestCase
{
	private array $priorConfig;
	private array $priorPfb;
	private string $dir;
	private string $marker;

	protected function setUp(): void
	{
		$this->priorConfig = $GLOBALS['config'] ?? [];
		$this->priorPfb = $GLOBALS['pfb'];
		$this->dir = sys_get_temp_dir() . '/pfb_core_pending_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->dir, 0700));
		$GLOBALS['config'] = [];
		$this->marker = "{$this->dir}/pending";
		$GLOBALS['pfb']['pending_marker'] = $this->marker;
		$GLOBALS['pfb']['dbdir'] = $this->dir;
		$GLOBALS['pfb']['core_revision_key'] = "{$this->dir}/core_revision.key";
		$GLOBALS['pfb']['log'] = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$this->dir}/error.log";
		$GLOBALS['pfb']['runlog'] = '';
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_lock_events'] = [];
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = $this->priorConfig;
		$GLOBALS['pfb'] = $this->priorPfb;
		unset($GLOBALS['pfb_test_write_config_calls'], $GLOBALS['pfb_test_lock_events'], $GLOBALS['pfb_test_lock_held']);
		rmdir_recursive($this->dir);
	}

	/** @return array<string, mixed> the adapter's read; $interfaces runs while the settings are being read */
	private function read(?callable $interfaces = NULL): array
	{
		return pfb_core_settings_backend(['version' => 1, 'op' => 'read'], "{$this->dir}/node_exporter", $interfaces ?? static fn(): array => []);
	}

	public function testWithoutAMarkerTheReadAnswersNoToken(): void
	{
		$reply = $this->read();

		$this->assertArrayHasKey('settings', $reply, json_encode($reply));
		$this->assertSame(['pendingToken' => NULL, 'pendingApply' => FALSE], $reply['platform'] ?? 'no platform member', 'no marker, no token, nothing pending');
		$this->assertFileDoesNotExist($this->marker, 'a read creates no marker');
		$this->assertSame([], $GLOBALS['pfb_test_lock_events'], 'a read takes no lock');
	}

	public function testTheReadAnswersTheMarkersTokenAndLeavesTheMarkerAlone(): void
	{
		file_put_contents($this->marker, '0123456789abcdef');

		$reply = $this->read();

		$this->assertSame(['pendingToken' => '0123456789abcdef', 'pendingApply' => TRUE], $reply['platform'] ?? 'no platform member');
		$this->assertSame('0123456789abcdef', file_get_contents($this->marker), 'the marker is as it was');
		$this->assertFileDoesNotExist("{$this->marker}.applied", 'a read settles nothing');
	}

	public function testAnEmptyMarkerIsVersionedFirstAsThePassDoes(): void
	{
		touch($this->marker);

		$token = $this->read()['platform']['pendingToken'] ?? 'no token';

		$this->assertMatchesRegularExpression('/^[0-9a-f]{16}$/D', (string) $token, 'the token pfb_pending_changes_token() gives an empty marker');
		$this->assertSame($token, file_get_contents($this->marker), 'the marker holds the token the read answered');
	}

	public function testTheTokenIsTakenBeforeTheSettingsAreRead(): void
	{
		file_put_contents($this->marker, 'before-the-read');
		config_set_path('installedpackages/pfblockernglistsv4/config/0', ['aliasname' => 'G', 'action' => 'Deny_Both', 'cron' => 'Never', 'srcint' => 'em0']);
		$marked = FALSE;

		// the interface lookup runs while the groups are projected
		$reply = $this->read(function () use (&$marked): array {
			file_put_contents($this->marker, 'marked-meanwhile');	// a save lands while the settings are being read
			$marked = TRUE;
			return ['em0' => '192.0.2.1'];
		});

		$this->assertTrue($marked, 'the settings read ran the seam');
		$this->assertSame('before-the-read', $reply['platform']['pendingToken'] ?? 'no token',
			'the token of before the read: settling it leaves the change marked meanwhile pending');
	}

	public function testTheRevisionDoesNotDependOnTheToken(): void
	{
		$none = $this->read()['revision'];
		file_put_contents($this->marker, 'one');
		$one = $this->read()['revision'];
		file_put_contents($this->marker, 'two');

		$this->assertSame($none, $one, 'a token appearing moves no revision');
		$this->assertSame($one, $this->read()['revision'], 'a token changing moves no revision');
	}

	public function testPendingApplyFollowsTheMarkerAndTheApplyWithoutMovingTheRevision(): void
	{
		$none = $this->read();
		$this->assertFalse($none['platform']['pendingApply'] ?? NULL, 'before-state: nothing pending');

		pfb_mark_pending_changes();
		$marked = $this->read();
		$this->assertTrue($marked['platform']['pendingApply'] ?? NULL, 'a change marked waits for an apply');
		$this->assertSame($none['revision'], $marked['revision'], 'pending state is no setting: the revision stays');

		pfb_settle_pending_changes($marked['platform']['pendingToken']);
		$settled = $this->read();
		$this->assertFalse($settled['platform']['pendingApply'] ?? NULL, 'the apply took it');
		$this->assertSame($none['revision'], $settled['revision']);
	}

	public function testAWriteReplyCarriesNoPlatform(): void
	{
		file_put_contents($this->marker, 'tok');
		$read = $this->read();

		$reply = pfb_core_settings_backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $read['settings']],
			"{$this->dir}/node_exporter", static fn(): array => []);

		$this->assertSame(['version' => 1, 'revision' => $read['revision']], $reply, 'only a read answers the token');
	}

	/** @return array<string, array{0: string}> */
	public static function hostileTokens(): array
	{
		return [
			'one mebibyte'       => [str_repeat('a', 1048576)],
			'control characters' => ["a\x01b\nc\td\"e\\f\x7f"],
			'a NUL'              => ["a\0b"],
			'multibyte text'     => ['tökén-✓'],
		];
	}

	#[DataProvider('hostileTokens')]
	public function testAHostileTokenIsCarriedWholeThroughTheServedReply(string $token): void
	{
		file_put_contents($this->marker, $token);

		$reply = json_decode(pfb_core_settings_serve('{"version":1,"op":"read"}'), TRUE, 512, JSON_THROW_ON_ERROR);

		$this->assertArrayHasKey('settings', $reply, 'the read answered ' . json_encode(array_keys($reply)));
		$carried = $reply['platform']['pendingToken'] ?? NULL;
		$this->assertSame(strlen($token), strlen((string) $carried), 'the token is not truncated');
		$this->assertTrue($token === $carried, 'the token is carried byte for byte');
	}

	public function testATokenThatIsNotUtf8RefusesTheReadWholeAndLeavesTheMarkerAlone(): void
	{
		file_put_contents($this->marker, "ab\xff\xfecd");

		$reply = json_decode(pfb_core_settings_serve('{"version":1,"op":"read"}'), TRUE, 512, JSON_THROW_ON_ERROR);

		$this->assertSame('unavailable', $reply['error']['code'] ?? NULL, 'JSON cannot carry it unaltered: ' . json_encode(array_keys($reply)));
		$this->assertArrayNotHasKey('settings', $reply, 'no settings beside a token that was not carried');
		$this->assertArrayNotHasKey('platform', $reply, 'no substituted or partial token');
		$this->assertSame("ab\xff\xfecd", file_get_contents($this->marker), 'the marker is as it was');
	}
}
