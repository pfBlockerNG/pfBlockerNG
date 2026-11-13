<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3913 / #3924: the Outpost's side of Core's `settings/dns`. Pinned here:
 *   - pfb_core_dns_settings(): config.xml's values as Core's 17 native `settings/dns` fields, equal to the parity fixture's
 *     `native` for every valid case (CoreSettingsDnsParityTest freezes the same cases against pfb_unbound.ini); the settings
 *     adapter (CoreSettingsBackendTest) answers exactly this projection;
 *   - pfb_core_settings_validate(): the dry run through Core before a save; only a Core `invalid_argument` refuses, anything
 *     else (Core down, no such method, an error) leaves the page's own checks to decide;
 *   - pfblockerng_tick() tells Core about config.xml changes once per tick (pfb_core_settings_changed()), a running update pass or not.
 */
#[CoversFunction('pfb_core_dns_settings')]
#[CoversFunction('pfb_core_settings_validate')]
#[CoversFunction('pfblockerng_tick')]
final class CoreSettingsDnsSettingsTest extends TestCase
{
	private const FIXTURE = __DIR__ . '/../core/fixtures/settings_dns_parity.json';
	private const DNSBL = 'installedpackages/pfblockerngdnsblsettings/config/0';

	private array $priorConfig;
	private array $priorG;
	private array $priorPfb;
	private string $dir;
	/** @var list<array{0: string, 1: array}> every call the fake Core got: method, params */
	private array $calls = [];

	protected function setUp(): void
	{
		$this->priorConfig = $GLOBALS['config'] ?? [];
		$this->priorG = $GLOBALS['g'] ?? [];
		$this->priorPfb = $GLOBALS['pfb'];
		$this->dir = sys_get_temp_dir() . '/pfb_core_dns_' . bin2hex(random_bytes(8));
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
		$GLOBALS['g'] = $this->priorG;
		$GLOBALS['pfb'] = $this->priorPfb;
		unset($GLOBALS['pfb_test_process_running']);
		rmdir_recursive($this->dir);
	}

	/** @return array<string, mixed> the fixture's `defaults` native values: all 17 fields, in the protocol note's order */
	private static function defaults(): array
	{
		$doc = json_decode((string) file_get_contents(self::FIXTURE), TRUE, 512, JSON_THROW_ON_ERROR);
		foreach ($doc['cases'] as $case) {
			if ($case['id'] === 'defaults') {
				return $case['native'];
			}
		}
		throw new RuntimeException('the fixture has no defaults case');
	}

	/**
	 * @param array<string, bool|int|string> $changes
	 * @return array<string, bool|int|string> the defaults with $changes, the fields still in the protocol note's order
	 */
	private static function defaultsWith(array $changes): array
	{
		return array_merge(self::defaults(), $changes);
	}

	/** @return array<string, array{0: array<string, mixed>}> every fixture case PHP accepts, stored or posted */
	public static function validCases(): array
	{
		$doc = json_decode((string) file_get_contents(self::FIXTURE), TRUE, 512, JSON_THROW_ON_ERROR);
		$cases = [];
		foreach ($doc['cases'] as $case) {
			if ($case['valid']) {
				$cases[$case['id']] = [$case];
			}
		}
		return $cases;
	}

	/** @param array<string, ?string> $values registry key => stored value, as the parity test puts it into config.xml */
	private function store(array $values): void
	{
		foreach ($values as $key => $value) {
			[$alias, $leaf] = explode('/', $key, 2);
			if ($value !== NULL) {
				config_set_path(PFB_SECTIONS[$alias] . '/' . $leaf, $value);
			}
		}
	}

	/** @return array{status: int, body: array, error: null} */
	private static function ok(array $body): array
	{
		return ['status' => 200, 'body' => $body, 'error' => NULL];
	}

	/** @return array{status: int, body: array, error: null} */
	private static function refused(int $status, string $code, string $message, array $fieldErrors = []): array
	{
		$error = ['code' => $code, 'message' => $message];
		if ($fieldErrors !== []) {
			$error['fieldErrors'] = $fieldErrors;
		}
		return ['status' => $status, 'body' => ['error' => $error], 'error' => NULL];
	}

	/** @return array{status: int, body: null, error: string} */
	private static function down(string $why): array
	{
		return ['status' => 0, 'body' => NULL, 'error' => $why];
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

	// ----- T1: the translation -----

	/** @param array<string, mixed> $case */
	#[DataProvider('validCases')]
	public function testTheTranslationGivesTheFixturesNativeValues(array $case): void
	{
		$this->store($case['values']);

		$native = pfb_core_dns_settings();

		$this->assertSame(array_keys(self::defaults()), array_keys($native), "{$case['id']}: all 17 fields, in the protocol note's order");
		foreach ($case['native'] as $field => $expected) {
			$this->assertSame($expected, $native[$field], "{$case['id']}: {$field}");
		}
	}

	public function testNothingStoredGivesTheDefaultsCaseExactly(): void
	{
		$this->assertSame(self::defaults(), pfb_core_dns_settings());
	}

	/** @return array<string, array{0: string, 1: int}> */
	public static function cacheCaps(): array
	{
		return ['above the cap is clamped' => ['9999999', 5000000], 'empty is the default' => ['', 10000], 'junk is the default' => ['abc', 10000],
			'negative is the default' => ['-1', 10000], 'zero is unlimited' => ['0', 0], 'a number is itself' => ['42', 42]];
	}

	#[DataProvider('cacheCaps')]
	public function testTheDecisionCacheCapIsClampedAsTheIniClampsIt(string $stored, int $expected): void
	{
		$this->store(['dnsbl/pfb_py_cache_max' => $stored]);

		$this->assertSame($expected, pfb_core_dns_settings()['decisionCacheMax']);
	}

	// ----- the validation -----

	public function testRefusedSettingsGiveOneMessagePerFieldError(): void
	{
		$this->store(['dnsbl/pfb_hsts' => '']);
		$core = $this->core(['ValidateSettings' => self::refused(400, 'invalid_argument', 'invalid settings', [
			['field' => 'changes.dns.decisionCacheMax', 'message' => 'must be at most 5000000'],
			['field' => 'changes.dns.idnMode', 'message' => 'not one of off, confusable, on'],
		])]);

		$messages = pfb_core_settings_validate($core);

		$this->assertSame([
			'pfBlockerNG Core refused the DNS settings: dns.decisionCacheMax: must be at most 5000000',
			'pfBlockerNG Core refused the DNS settings: dns.idnMode: not one of off, confusable, on',
		], $messages);
		$this->assertSame('ValidateSettings', $this->calls[0][0]);
		$this->assertSame(['changes'], array_keys($this->calls[0][1]), 'a dry run has no requestId');
		$this->assertSame(['dns' => self::defaultsWith(['hstsNullBlocking' => FALSE])], $this->calls[0][1]['changes'], 'the in-memory config is what is validated');
	}

	public function testRefusedSettingsWithoutFieldErrorsGiveTheErrorsMessage(): void
	{
		$core = $this->core(['ValidateSettings' => self::refused(400, 'invalid_argument', 'the settings are not valid')]);

		$this->assertSame(['pfBlockerNG Core refused the DNS settings: the settings are not valid'], pfb_core_settings_validate($core));
	}

	public function testAcceptedSettingsGiveNoMessage(): void
	{
		$core = $this->core(['ValidateSettings' => self::ok([])]);

		$this->assertSame([], pfb_core_settings_validate($core));
	}

	/** @return array<string, array{0: array}> */
	public static function unusableCores(): array
	{
		return [
			'Core down' => [self::down('the Core API did not answer: connection refused')],
			'a Core without the method' => [self::refused(404, 'not_found', 'no such method')],
			'a Core error' => [self::refused(500, 'internal', 'boom')],
		];
	}

	/** @param array $reply */
	#[DataProvider('unusableCores')]
	public function testACoreThatCannotJudgeLeavesTheDecisionToThePage(array $reply): void
	{
		$core = $this->core(['ValidateSettings' => $reply]);

		$this->assertSame([], pfb_core_settings_validate($core));
	}

	// ----- the tick -----

	/** @return array<string, array{0: list<string>}> */
	public static function passStates(): array
	{
		return ['no update pass' => [[]], 'an update pass running' => [['root 4242 0.0 0.1 /usr/local/bin/php -f /usr/local/www/pfblockerng.php cron']]];
	}

	/** @param list<string> $psLines */
	#[DataProvider('passStates')]
	public function testTheTickTellsCoreOncePerTick(array $psLines): void
	{
		// Given a tick sandbox in which no scheduled job is due (as TickApplyReconciliationTest has it)
		$GLOBALS['pfb_test_process_running'] = ['unbound' => TRUE];
		foreach (['dbdir', 'schedule_state_dir', 'aliasdir', 'dnsbldir'] as $key) {
			$GLOBALS['pfb'][$key] = $this->dir;
		}
		$GLOBALS['pfb']['pending_marker'] = "{$this->dir}/pfb_pending_changes";
		$GLOBALS['pfb']['extraslog'] = "{$this->dir}/extras.log";
		$GLOBALS['pfb']['dnsbl_file'] = "{$this->dir}/dnsbl_file";
		$php = "{$this->dir}/php_recorder";
		file_put_contents($php, "#!/bin/sh\nexit 0\n");
		chmod($php, 0755);
		$GLOBALS['pfb']['php'] = $php;
		$gen = 'installedpackages/pfblockerng/config/0';
		$ip = 'installedpackages/pfblockerngipsettings/config/0';
		foreach (['pfb_min' => '0', 'pfb_hour' => '0', 'pfb_dailystart' => '0', 'skipfeed' => '0', 'pfb_interval' => 'Disabled', 'pfb_quiet_hours' => ''] as $leaf => $value) {
			config_set_path("{$gen}/{$leaf}", $value);
		}
		foreach (['suppression' => '', 'database_cc' => '', 'maxmind_locale' => 'en', 'asn_reporting' => 'disabled', 'asn_token' => '', 'maxmind_account' => '', 'maxmind_key' => ''] as $leaf => $value) {
			config_set_path("{$ip}/{$leaf}", $value);
		}
		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '8.8.8.8');
		foreach (['pfb_dnsvip4' => '', 'pfb_dnsvip6' => '', 'pfb_dnsport' => '8081', 'pfb_dnsport_ssl' => '8443', 'top1m_enable' => '', 'pfb_py_reply' => '', 'pfb_regex' => '',
			'pfb_regex_list' => '', 'pfb_cname' => '', 'tld_allow' => '', 'pfb_py_nolog' => '', 'pfb_noaaaa' => '', 'pfb_noaaaa_list' => '', 'pfb_gp' => '', 'pfb_gp_bypass_list' => ''] as $leaf => $value) {
			config_set_path(self::DNSBL . "/{$leaf}", $value);
		}
		$GLOBALS['g']['unbound_chroot_path'] ??= '/var/unbound';
		foreach (['cron', 'dcc', 'bl', 'extra:dcc'] as $jobKey) {
			pfb_due_ledger_write_entry($jobKey, ['last_run' => time() - 3600, 'next_due' => time() + 3600, 'jitter' => 0], $this->dir);
		}
		$notices = 0;

		// When the tick runs
		pfb_global();
		pfblockerng_tick(ps_lines: $psLines, core_settings: function () use (&$notices): ?string {
			$notices++;
			return NULL;
		});

		// Then Core was told exactly once
		$this->assertSame(1, $notices);
	}
}
