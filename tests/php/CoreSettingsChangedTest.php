<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3924: Core reads `settings/dns` through the settings adapter, so the Outpost only tells Core when config.xml may have
 * changed (the Core method `SettingsChanged`), through pfb_core_settings_changed():
 *   - forced (a page save, after write_config()): always notifies Core;
 *   - unforced (the tick): asks Core's revision (GetSettings) and notifies only when it is not the revision config.xml projects,
 *     so a restore, a revert or an HA receive reaches Core by the next tick and a quiet tick costs one cheap call;
 *   - NULL when Core was told (or already agrees), else the reason: logged once per outage and kept in
 *     $pfb['core_settings_failed'] (DNS General shows it) until a notice succeeds. A failed notice is retried by the next tick.
 */
#[CoversFunction('pfb_core_settings_changed')]
final class CoreSettingsChangedTest extends TestCase
{
	private array $priorConfig;
	private array $priorPfb;
	private string $dir;
	/** @var list<array{0: string, 1: array}> every call the fake Core got: method, params */
	private array $calls = [];

	protected function setUp(): void
	{
		$this->priorConfig = $GLOBALS['config'] ?? [];
		$this->priorPfb = $GLOBALS['pfb'];
		$this->dir = sys_get_temp_dir() . '/pfb_core_changed_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->dir, 0700));
		$GLOBALS['config'] = [];
		$GLOBALS['pfb']['core_settings_failed'] = "{$this->dir}/core_settings_failed";
		$GLOBALS['pfb']['log'] = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$this->dir}/error.log";
		$GLOBALS['pfb']['runlog'] = '';
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = $this->priorConfig;
		$GLOBALS['pfb'] = $this->priorPfb;
		rmdir_recursive($this->dir);
	}

	/** @return array{status: int, body: array, error: null} */
	private static function ok(array $body): array
	{
		return ['status' => 200, 'body' => $body, 'error' => NULL];
	}

	/** @return array{status: int, body: array, error: null} */
	private static function refused(int $status, string $code, string $message): array
	{
		return ['status' => $status, 'body' => ['error' => ['code' => $code, 'message' => $message]], 'error' => NULL];
	}

	/** @return array{status: int, body: null, error: string} */
	private static function down(string $why): array
	{
		return ['status' => 0, 'body' => NULL, 'error' => $why];
	}

	/** @return array{status: int, body: array, error: null} Core's GetSettings answer at $revision */
	private static function held(int $revision): array
	{
		return self::ok(['initialized' => TRUE, 'revision' => $revision, 'projections' => []]);
	}

	/** The revision config.xml projects now: what Core's adapter answers for a read (issue #3937: all of its projections). */
	private static function projected(): int
	{
		return pfb_core_settings_backend(['version' => 1, 'op' => 'read'])['revision'];
	}

	/**
	 * A Core that answers $replies[method] (a reply, or a callable taking the params) and records every call in $this->calls.
	 *
	 * @param array<string, array|callable> $replies
	 */
	private function core(array $replies): callable
	{
		$this->calls = [];
		return function (string $method, array $params = []) use ($replies): array {
			$this->calls[] = [$method, $params];
			$this->assertArrayHasKey($method, $replies, "unexpected Core call {$method}");
			$reply = $replies[$method];
			return is_callable($reply) ? $reply($params) : $reply;
		};
	}

	/** @return list<string> */
	private function methods(): array
	{
		return array_column($this->calls, 0);
	}

	private function logged(string $text): int
	{
		return substr_count((string) @file_get_contents("{$this->dir}/pfblockerng.log"), $text);
	}

	public function testAForcedNoticeAlwaysTellsCoreWithoutAskingItsRevision(): void
	{
		$core = $this->core(['SettingsChanged' => self::held(7)]);

		$this->assertNull(pfb_core_settings_changed($core, TRUE));

		$this->assertSame([['SettingsChanged', []]], $this->calls, 'a page save notifies at once: no GetSettings, no parameters');
		$this->assertFileDoesNotExist("{$this->dir}/core_settings_failed");
	}

	public function testATickThatFindsCoreAtTheProjectedRevisionAsksOnlyItsRevision(): void
	{
		$core = $this->core(['GetSettings' => self::held(self::projected())]);

		$this->assertNull(pfb_core_settings_changed($core));

		$this->assertSame([['GetSettings', ['projectionIds' => ['dns']]]], $this->calls);
	}

	public function testATickTellsCoreWhenConfigXmlMovedPastTheRevisionCoreHolds(): void
	{
		// Given Core at the revision config.xml projected a moment ago
		$held = self::projected();
		$core = $this->core(['GetSettings' => self::held($held), 'SettingsChanged' => self::held(self::projected())]);
		$this->assertNull(pfb_core_settings_changed($core), 'before-state: Core agrees');
		$this->assertSame(['GetSettings'], $this->methods());

		// When config.xml changes with no page and no save path (a restore, a history revert, an HA receive)
		config_set_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_psl_allow_private', 'on');
		$core = $this->core(['GetSettings' => self::held($held), 'SettingsChanged' => self::held(self::projected())]);

		// Then the next tick tells Core
		$this->assertNull(pfb_core_settings_changed($core));
		$this->assertSame(['GetSettings', 'SettingsChanged'], $this->methods());
		$this->assertNotSame($held, self::projected(), 'the change moved the projection');
	}

	public function testATickTellsCoreWhenOnlyAFeedGroupChangedInConfigXml(): void
	{
		// Given Core at the revision the adapter answers for a config.xml with one IPv4 group
		$group = 'installedpackages/pfblockernglistsv4/config/0';
		config_set_path($group, ['aliasname' => 'Spam', 'action' => 'Deny_Inbound', 'cron' => 'Never',
			'row' => [['format' => 'auto', 'state' => 'Enabled', 'url' => 'https://example.org/drop.txt', 'header' => 'Drop']]]);
		$held = self::projected();
		$core = $this->core(['GetSettings' => self::held($held)]);
		$this->assertNull(pfb_core_settings_changed($core), 'before-state: Core agrees');
		$this->assertSame(['GetSettings'], $this->methods());

		// When only the group's feed source changes (the DNS settings stay as they are)
		$dns = pfb_core_dns_settings();
		config_set_path("{$group}/row/0/url", 'https://example.org/edrop.txt');
		$this->assertSame($dns, pfb_core_dns_settings());
		$core = $this->core(['GetSettings' => self::held($held), 'SettingsChanged' => self::held(self::projected())]);

		// Then the next tick tells Core: the revision it compares is the one of every projection the adapter answers
		$this->assertNull(pfb_core_settings_changed($core));
		$this->assertSame(['GetSettings', 'SettingsChanged'], $this->methods());
	}

	public function testATickReportsCoreBeingDownWithoutTellingItAndCoreComingBackClearsIt(): void
	{
		// Given Core down
		$reason = 'the Core API did not answer: connection refused';
		$core = $this->core(['GetSettings' => self::down($reason)]);

		// When two ticks fail
		$this->assertSame($reason, pfb_core_settings_changed($core));
		$this->assertSame($reason, pfb_core_settings_changed($core));

		// Then the reason is kept, one line was logged for the outage, and Core was not asked to read
		$this->assertSame(['GetSettings', 'GetSettings'], $this->methods());
		$this->assertSame($reason, file_get_contents("{$this->dir}/core_settings_failed"));
		$this->assertSame(1, $this->logged($reason), 'one log line per outage');

		// When Core is back and agrees
		$core = $this->core(['GetSettings' => self::held(self::projected())]);
		$this->assertNull(pfb_core_settings_changed($core));

		// Then the failure is gone, and the next outage is logged again
		$this->assertFileDoesNotExist("{$this->dir}/core_settings_failed");
		$core = $this->core(['GetSettings' => self::down($reason)]);
		pfb_core_settings_changed($core);
		$this->assertSame(2, $this->logged($reason), 'a new outage logs again');
	}

	/** @return array<string, array{0: array, 1: list<string>}> a Core's answer to SettingsChanged and the words the reason must carry */
	public static function failedNotices(): array
	{
		return [
			'Core down'              => [self::down('the Core API did not answer: connection refused'), ['did not answer', 'connection refused']],
			'unavailable'            => [self::refused(503, 'unavailable', 'the settings backend failed: timed out after 10s'), ['503', 'unavailable', 'timed out after 10s']],
			'an internal error'      => [self::refused(500, 'internal', 'boom'), ['500', 'internal', 'boom']],
			'a Core without it'      => [self::refused(404, 'not_found', 'no such method: SettingsChanged'), ['404', 'not_found', 'SettingsChanged']],
		];
	}

	/** @param list<string> $words */
	#[DataProvider('failedNotices')]
	public function testAFailedNoticeIsTheReasonKeptForDnsGeneralAndLoggedOnce(array $reply, array $words): void
	{
		$core = $this->core(['SettingsChanged' => $reply]);

		$reason = pfb_core_settings_changed($core, TRUE);
		pfb_core_settings_changed($core, TRUE);

		$this->assertNotNull($reason);
		foreach ($words as $word) {
			$this->assertStringContainsString($word, $reason);
		}
		$this->assertSame($reason, file_get_contents("{$this->dir}/core_settings_failed"));
		$this->assertSame(1, $this->logged($reason), 'one log line per outage');
	}

	public function testAFailedNoticeIsRetriedByTheNextTickWithNoConfigChange(): void
	{
		// Given a forced notice that failed while Core still holds an older revision
		$core = $this->core(['SettingsChanged' => self::down('the Core API did not answer: x')]);
		$this->assertNotNull(pfb_core_settings_changed($core, TRUE));
		$this->assertFileExists("{$this->dir}/core_settings_failed");

		// When the next tick finds Core at another revision than config.xml's
		$core = $this->core(['GetSettings' => self::held(self::projected() + 1), 'SettingsChanged' => self::held(self::projected())]);
		$retried = pfb_core_settings_changed($core);

		// Then it tells Core again, and the failure is cleared
		$this->assertNull($retried);
		$this->assertSame(['GetSettings', 'SettingsChanged'], $this->methods());
		$this->assertFileDoesNotExist("{$this->dir}/core_settings_failed");
	}

	public function testASuccessfulForcedNoticeClearsAPendingFailure(): void
	{
		file_put_contents("{$this->dir}/core_settings_failed", 'earlier');
		$core = $this->core(['SettingsChanged' => self::held(3)]);

		$this->assertNull(pfb_core_settings_changed($core, TRUE));

		$this->assertFileDoesNotExist("{$this->dir}/core_settings_failed");
	}

	public function testATickWhoseCoreAgreesClearsAPendingFailure(): void
	{
		file_put_contents("{$this->dir}/core_settings_failed", 'earlier');
		$core = $this->core(['GetSettings' => self::held(self::projected())]);

		$this->assertNull(pfb_core_settings_changed($core));

		$this->assertFileDoesNotExist("{$this->dir}/core_settings_failed", 'Core holds what config.xml says: nothing is pending');
	}
}
