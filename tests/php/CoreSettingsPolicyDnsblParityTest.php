<?php

declare(strict_types=1);

require_once __DIR__ . '/ConfigXmlDiskTrait.php';
require_once __DIR__ . '/PageStatementLoader.php';
require_once __DIR__ . '/PfbNoPhpWarningTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4031: freezes today's PHP behaviour for Core's `policy/dnsbl` projection (the DNSBL build policy: the DNSBL switch, the
 * whitelist, TOP1M, TLD wildcard lists, TLD Allow, the Regex list, SafeSearch, the DNSBL-IP action, and the logging policy
 * derived from the settings and the groups) as the parity fixture tests/core/fixtures/settings_policy_dnsbl_parity.json;
 * go/pfb_core/settings passes the same file.
 *   - A case is a config.xml: the fixture's `base` (a section the DNSBL page saved: Default mode, Null Blocking) under the case's
 *     `config` (key => stored value), `text` (key => text stored base64 as the pages store it), `groups` (the stored DNSBL
 *     groups), `blacklist` (the Blacklist page's keys); `bare` drops the base. `php` is what today's readers make of it
 *     (the shipped statements of pfb_global() and the apply pass, run as shipped; pfb_dnsbl_whitelist_lines(); the decoders the
 *     manifest builder calls), `policyDnsbl` (over the fixture's defaults) what the settings adapter's read answers. Where Core
 *     and today's PHP differ (a value no page offers, or one Core cannot hold) the case says why.
 *   - The Regex list is read by pfB-DNS (go/pfb_dns_gateway/decider loadUserRegexEntries), not by PHP: its cases freeze what
 *     PHP hands the ini, and `policyDnsbl.regexList` is that reader's entries.
 *   - A refused row is a value Core refuses to read; the adapter's write refuses it too, naming the field.
 */
#[CoversFunction('pfb_core_settings')]
#[CoversFunction('pfb_core_settings_backend')]
#[CoversFunction('pfb_core_settings_request_refusal')]
final class CoreSettingsPolicyDnsblParityTest extends TestCase
{
	use ConfigXmlDiskTrait;
	use PfbNoPhpWarningTrait;

	private const FIXTURE = __DIR__ . '/../core/fixtures/settings_policy_dnsbl_parity.json';
	private const PFB = 'src/usr/local/pkg/pfblockerng/pfblockerng.inc';
	private const APPLY = 'src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';

	/** @var array<string, string>|null the shipped statements the observations run, extracted once */
	private static ?array $code = NULL;

	private array $priorConfig;
	private array $priorG;
	private array $priorPfb;
	private string $dir;

	protected function setUp(): void
	{
		$this->priorConfig = $GLOBALS['config'] ?? [];
		$this->priorG = $GLOBALS['g'] ?? [];
		$this->priorPfb = $GLOBALS['pfb'];
		$this->dir = sys_get_temp_dir() . '/pfb_core_policy_dnsbl_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->dir, 0700));
		$GLOBALS['config'] = [];
		$GLOBALS['pfb']['pending_marker'] = "{$this->dir}/pending";
		$GLOBALS['pfb']['metrics_lock'] = "{$this->dir}/metrics.lock";
		$GLOBALS['pfb']['log'] = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$this->dir}/error.log";
		$GLOBALS['pfb']['runlog'] = '';
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_lock_events'] = [];
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = $this->priorConfig;
		$GLOBALS['g'] = $this->priorG;
		$GLOBALS['pfb'] = $this->priorPfb;
		foreach (['write_config_calls', 'write_config_args', 'write_config_result', 'write_config_hook', 'config_read_hook', 'config_read_calls',
			'config_read_lock_held', 'lock_events', 'lock_held', 'try_lock_fail'] as $global) {
			unset($GLOBALS["pfb_test_{$global}"]);
		}
		rmdir_recursive($this->dir);
	}

	/** @return array<string, mixed> */
	private static function fixture(): array
	{
		return json_decode((string) file_get_contents(self::FIXTURE), TRUE, 512, JSON_THROW_ON_ERROR);
	}

	/** @return array<string, array{0: array<string, mixed>}> */
	public static function cases(): array
	{
		$cases = [];
		foreach (self::fixture()['cases'] as $case) {
			$cases[$case['id']] = [$case];
		}
		return $cases;
	}

	/** @return array<string, array{0: array<string, mixed>}> */
	public static function refused(): array
	{
		$rows = [];
		foreach (self::fixture()['refused'] as $row) {
			$rows[$row['id']] = [$row];
		}
		return $rows;
	}

	/** config.xml as the case holds it. @param array<string, mixed> $case */
	private function arrange(array $case): void
	{
		$stored = array_replace_recursive(($case['bare'] ?? FALSE) ? [] : self::fixture()['base'], $case['config'] ?? []);
		foreach ($stored as $alias => $keys) {
			foreach ($keys as $key => $value) {
				config_set_path(PFB_SECTIONS[$alias] . "/{$key}", $value);
			}
		}
		foreach ($case['text'] ?? [] as $key => $text) {
			[$alias, $leaf] = explode('/', $key, 2);
			config_set_path(PFB_SECTIONS[$alias] . "/{$leaf}", base64_encode($text));
		}
		if (isset($case['groups'])) {
			config_set_path('installedpackages/pfblockerngdnsbl/config', $case['groups']);
		}
		foreach ($case['blacklist'] ?? [] as $key => $value) {
			config_set_path("installedpackages/pfblockerngblacklist/{$key}", $value);
		}
	}

	/** @return array<string, mixed> the adapter's read */
	private function read(): array
	{
		$reply = $this->backend(['version' => 1, 'op' => 'read']);
		$this->assertArrayHasKey('settings', $reply, 'the read answered ' . json_encode($reply));
		$this->assertArrayHasKey('policy/dnsbl', $reply['settings'], 'the read answers the policy/dnsbl projection: ' . json_encode(array_keys($reply['settings'])));
		return $reply;
	}

	private function backend(array $request): array
	{
		return pfb_core_settings_backend($request, "{$this->dir}/node_exporter", static fn(): array => []);
	}

	/** @return array<string, mixed> Core's write of the read with $change applied to its `policy/dnsbl` */
	private function writePolicy(callable $change, ?int $revision = NULL): array
	{
		$read = $this->read();
		$settings = $read['settings'];
		$settings['policy/dnsbl'] = $change($settings['policy/dnsbl']);
		return $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $revision ?? $read['revision'], 'settings' => $settings]);
	}

	/** @return array<string, string> the shipped code the observations run, by name */
	private static function code(): array
	{
		return self::$code ??= [
			'globals' => implode('', array_map(static fn(string $pattern): string => pfb_test_page_statement(self::PFB, $pattern), [
				'/\$pfb\[\'dnsblconfig\'\]\s*=\s*PfbConfig::readSection/',
				'/\$pfb\[\'blconfig\'\]\s*=\s*config_get_path/',
				'/\$pfb\[\'dnsbl\'\]\s*=\s*PfbConfig::read\(\'dnsbl\/pfb_dnsbl\'\)/',
				'/\$pfb\[\'dnsbl_top1m\'\]\s*=\s*PfbConfig::read/',
				'/\$pfb\[\'dnsbl_regex\'\]\s*=\s*PfbConfig::read/',
				'/\$pfb\[\'dnsbl_tld_allow\'\]\s*=\s*PfbConfig::read/',
			])),
			'policy' => pfb_test_page_region(self::PFB, "\t\$pfb_dnsbl_groups = config_get_path(", "\t// issue #3539: TRUE while any effective DNSBL block"),
			'safesearch' => pfb_test_page_region(self::PFB, "\t// SafeSearch — read via gateway (ADR-29).", "\t// External DNS Server for TLD drill"),
			'top1m' => implode('', array_map(static fn(string $pattern): string => pfb_test_page_statement(self::APPLY, $pattern), [
				'/\$pfb\[\'dnsbl_ip\'\]\s*=\s*pfb_dnsblip_action_value/',
				'/\$pfb\[\'dnsbl_top1m_cnt\'\]\s*=/',
				'/\$pfb\[\'dnsbl_top1m_inc\'\]\s*=\s*\$pfb\[\'dnsblconfig\'\]/',
				'/\$pfb\[\'dnsbl_top1m_inc\'\]\s*=\s*pfb_filter/',
			])),
			'tldAllow' => pfb_test_page_region(self::PFB, "\t\$tld_allow = 'off';", "\n\t\$python_nolog"),
		];
	}

	/**
	 * What today's readers make of the case's config.xml: the shipped statements of pfb_global() and of the apply pass, run as shipped
	 * (a value they read without a guard warns, and what they then compute is what the fixture freezes).
	 *
	 * @param list<string> $keys the observations to make
	 * @return array<string, mixed>
	 */
	private function observe(array $keys): array
	{
		$code = self::code();
		$pfb = &$GLOBALS['pfb'];
		set_error_handler(static fn(): bool => TRUE);
		try {
			eval($code['globals'] . $code['safesearch'] . $code['policy'] . $code['top1m']);
			$groups = static function () use (&$pfb): array {
				$out = [];
				foreach (config_get_path('installedpackages/pfblockerngdnsbl/config', []) as $list) {
					$filter_top1m = $list['filter_top1m'] ?? NULL;
					$out[] = [
						'name'        => $list['aliasname'] ?? NULL,
						'logging'     => pfb_dnsbl_effective_logging($list['logging'] ?? NULL, $pfb['dnsbl_global_log'], $pfb['dnsbl_global_mode'], $pfb['dnsbl_policy_legacy']),
						'primary'     => $list['order'] == 'primary',
						'top1mFilter' => pfb_cfg_toggle_read($filter_top1m) === PfbToggle::On,
					];
				}
				return $out;
			};
			$seen = [
				'enabled'           => static fn(): bool => $pfb['dnsbl'] === PfbToggle::On,
				'top1m'             => static fn(): bool => $pfb['dnsbl_top1m'] === PfbToggle::On,
				'tldAllow'          => static fn(): bool => $pfb['dnsbl_tld_allow'] === PfbToggle::On,
				'regex'             => static fn(): bool => $pfb['dnsbl_regex'] === PfbToggle::On,
				'whitelist'         => static fn(): array => pfb_dnsbl_whitelist_lines(),
				'top1mCount'        => static fn(): mixed => $pfb['dnsbl_top1m_cnt'],
				'top1mInclusions'   => static fn(): mixed => $pfb['dnsbl_top1m_inc'],
				'tldBlacklist'      => static fn(): array => pfb_text_area_decode($pfb['dnsblconfig']['tld_wildcard_blacklist'] ?? NULL, TRUE, FALSE, TRUE) ?: [],
				'tldExclusions'     => static fn(): array => pfb_text_area_decode($pfb['dnsblconfig']['tld_wildcard_exclusion'] ?? NULL, TRUE, FALSE, TRUE) ?: [],
				'tldAllowList'      => static fn(): string => pfb_test_page_eval($code['tldAllow'], ['pfb' => $pfb])['tld_allow_list'],
				'regexIni'          => static fn(): mixed => PfbConfig::read('dnsbl/pfb_regex_list'),
				'safeSearch'        => static fn(): bool => $pfb['safesearch_enable'] == 'Enable',
				'safeSearchYoutube' => static fn(): string => $pfb['safesearch_youtube'] == 'Strict' ? 'Strict' : ($pfb['safesearch_youtube'] == 'Moderate' ? 'Moderate' : 'Disable'),
				'safeSearchDoh'     => static fn(): bool => $pfb['safesearch_doh'] == 'Enable',
				'safeSearchDohList' => static fn(): array => $pfb['safesearch_doh_list'],
				'safeSearchAny'     => static fn(): bool => $pfb['dnsbl_safe_search'],
				'dnsblIpAction'     => static fn(): string => $pfb['dnsbl_ip'],
				'logging'           => static fn(): string => $pfb['dnsbl_global_log'],
				'blacklistLogging'  => static fn(): string => pfb_dnsbl_effective_logging(pfb_dnsbl_blacklist_logging($pfb['blconfig']), $pfb['dnsbl_global_log'],
					$pfb['dnsbl_global_mode'], $pfb['dnsbl_policy_legacy']),
				'groups'            => $groups,
			];
			return array_combine($keys, array_map(static fn(string $key): mixed => $seen[$key](), $keys));
		} finally {
			restore_error_handler();
		}
	}

	public function testTheFixtureHoldsTheCoverageMatrixAndHostileRows(): void
	{
		$doc = self::fixture();
		$this->assertSame(1, $doc['schema']);
		$this->assertSame('policy/dnsbl', $doc['projection']);
		$ids = array_column($doc['cases'], 'id');
		$this->assertSame(array_values(array_unique($ids)), $ids, 'a case id appears once');
		$expected = ['defaults'];
		foreach (['enabled', 'top1m', 'tldAllow', 'regex'] as $toggle) {
			array_push($expected, ...array_map(static fn(string $v): string => "{$toggle}-{$v}", ['on', 'empty', 'upper', 'off', 'array']));
		}
		foreach (['safeSearch', 'safeSearchDoh'] as $toggle) {
			array_push($expected, ...array_map(static fn(string $v): string => "{$toggle}-{$v}", ['enable', 'disable', 'lower-case', 'array']));
		}
		array_push($expected, 'safeSearchYoutube-disable', 'safeSearchYoutube-moderate', 'safeSearchYoutube-strict', 'safeSearchYoutube-lower-case', 'safeSearchYoutube-array',
			'top1mCount-empty', 'top1mCount-zero', 'top1mCount-lowest-option', 'top1mCount-default', 'top1mCount-highest-option', 'top1mCount-non-option',
			'top1mCount-negative', 'top1mCount-text', 'top1mCount-exponent', 'top1mCount-huge-exponent', 'top1mCount-trailing-text', 'top1mCount-over-range', 'top1mCount-array',
			'top1mInclusions-one', 'top1mInclusions-several', 'top1mInclusions-page-default', 'top1mInclusions-empty-token', 'top1mInclusions-unsafe-csv',
			'top1mInclusions-dotted', 'top1mInclusions-array',
			'safeSearchDohList-one', 'safeSearchDohList-several', 'safeSearchDohList-spaces-around', 'safeSearchDohList-empty-tokens', 'safeSearchDohList-array',
			'dnsblIpAction-Disabled', 'dnsblIpAction-Deny_Inbound', 'dnsblIpAction-Deny_Outbound', 'dnsblIpAction-Deny_Both', 'dnsblIpAction-Alias_Deny',
			'dnsblIpAction-Alias_Native', 'dnsblIpAction-Permit_Both', 'dnsblIpAction-invalid', 'dnsblIpAction-array');
		foreach (['whitelist', 'tldBlacklist', 'tldExclusions', 'regexList'] as $list) {
			array_push($expected, ...array_map(static fn(string $v): string => "{$list}-{$v}", ['one', 'several', 'comments-blank-crlf', 'repeated', 'array']));
		}
		array_push($expected, 'whitelist-leading-dot-wildcard', 'whitelist-idn', 'whitelist-upper-case', 'whitelist-invalid-domain-dropped', 'whitelist-nul-inside',
			'whitelist-bare-cr', 'whitelist-invalid-utf8', 'whitelist-base64-garbage',
			'regexList-hash-prefix', 'regexList-inline-hash', 'regexList-upper-case-kept', 'regexList-nul-inside', 'regexList-bare-cr', 'regexList-invalid-utf8',
			'regexList-base64-garbage', 'regexList-unpadded-base64');
		foreach (['Gtld', 'Cctld', 'Itld', 'Bgtld'] as $bucket) {
			array_push($expected, "tldAllow{$bucket}-one", "tldAllow{$bucket}-several", "tldAllow{$bucket}-array");
		}
		array_push($expected, 'tldAllowGtld-page-form', 'tldAllowGtld-empty-local-tld', 'tldAllowCctld-empty-token', 'tldAllowCctld-leading-space', 'tldAllowCctld-line-break-in-token');
		foreach (['default', 'override'] as $mode) {
			foreach (PFB_DNSBL_CONCRETE_MECHANISMS as $mechanism) {
				$expected[] = "logging-{$mode}-mode-{$mechanism}";
			}
		}
		array_push($expected, 'logging-legacy-no-override', 'logging-legacy-global-log-empty', 'logging-legacy-global-log-set', 'logging-legacy-junk-mechanism',
			'logging-default-mode-junk-mechanism', 'logging-trailing-space-mechanism', 'logging-null-mechanism', 'logging-array-mechanism',
			'groups-none', 'groups-default-mode', 'groups-override-mode', 'groups-legacy-mode', 'groups-primary-order', 'groups-top1m-filter', 'groups-not-projected',
			'blacklistLogging-absent', 'blacklistLogging-empty', 'blacklistLogging-default', 'blacklistLogging-mechanism', 'blacklistLogging-junk',
			'blacklistLogging-override-mode', 'blacklistLogging-array');
		foreach ($expected as $id) {
			$this->assertContains($id, $ids, "the coverage matrix row {$id}");
		}
		$refused = array_column($doc['refused'], 'id');
		$this->assertSame(array_values(array_unique($refused)), $refused, 'a refused row id appears once');
		foreach (['whitelist-newline', 'whitelist-nul', 'whitelist-empty-entry', 'whitelist-repeated-entry', 'regex-list-newline', 'top1m-count-zero', 'top1m-count-negative',
			'top1m-count-over-range', 'top1m-count-string', 'tld-allow-comma', 'tld-allow-space', 'dnsbl-ip-action-unknown', 'logging-unknown', 'safe-search-youtube-unknown',
			'groups-repeated-name'] as $id) {
			$this->assertContains($id, $refused, "the hostile row {$id}");
		}
		$this->assertSame(['enabled', 'whitelist', 'top1m', 'top1mCount', 'top1mInclusions', 'tldBlacklist', 'tldExclusions', 'tldAllow', 'tldAllowGtld', 'tldAllowCctld',
			'tldAllowItld', 'tldAllowBgtld', 'regex', 'regexList', 'safeSearch', 'safeSearchYoutube', 'safeSearchDoh', 'safeSearchDohList', 'dnsblIpAction', 'logging',
			'blacklistLogging', 'groups'], array_keys($doc['defaults']), 'the defaults name every field in the protocol order');
	}

	public function testTheShippedReadersStillTakeTheInputsTheFixtureObserves(): void
	{
		$pfb = pfb_test_page_source(self::PFB);
		$apply = pfb_test_page_source(self::APPLY);

		$this->assertStringContainsString("pfb_text_area_decode(\$pfb['dnsblconfig']['tld_wildcard_blacklist'], TRUE, FALSE, TRUE)", $pfb, 'the manifest reads the TLD blacklist so');
		$this->assertStringContainsString("pfb_text_area_decode(\$pfb['dnsblconfig']['tld_wildcard_exclusion'], TRUE, FALSE, TRUE)", $pfb, 'the manifest reads the TLD exclusions so');
		$this->assertStringContainsString("'user_whitelist'=> pfb_dnsbl_whitelist_lines()", $pfb, 'the manifest takes the whitelist from pfb_dnsbl_whitelist_lines()');
		$this->assertStringContainsString("regex_list = {\$pfb['dnsbl_regex_list']}", $pfb, 'the ini hands the stored Regex list to pfB-DNS verbatim');
		$this->assertStringContainsString("\$tld_allow_list .= ',' . \$pfb['dnsblconfig'][\$field];", $pfb, 'the ini joins the TLD Allow buckets as stored');
		$this->assertStringContainsString("if (\$list['order'] == 'primary')", $apply, 'a group is primary when its stored order is primary');
		$this->assertStringContainsString("\$filter_top1m = \$list['filter_top1m'] ?? NULL;", $apply, 'a group filters TOP1M by its stored filter_top1m');
		$this->assertStringContainsString("\$list['logging'] ?? NULL,", $apply, 'a group logs as its stored logging says');
		$this->assertStringContainsString('pfb_cfg_toggle_read($filter_top1m) === PfbToggle::On', $pfb, 'the manifest reads the group filter as a toggle');
	}

	/** @param array<string, mixed> $case */
	#[DataProvider('cases')]
	public function testTodaysPhpGivesTheFixturesObservations(array $case): void
	{
		$this->arrange($case);
		$this->assertNotSame([], $case['php'], "{$case['id']}: the case observes today's PHP");

		$seen = $this->observe(array_keys($case['php']));

		$this->assertSame($case['php'], $seen, "{$case['id']}: today's PHP readings");
	}

	/** @param array<string, mixed> $case */
	#[DataProvider('cases')]
	public function testTheAdapterProjectsTheFixturesPolicyDnsbl(array $case): void
	{
		$this->arrange($case);

		$reply = $this->assertNoPhpWarning(fn(): array => $this->read());

		$this->assertSame(array_replace(self::fixture()['defaults'], $case['policyDnsbl']), $reply['settings']['policy/dnsbl'], "{$case['id']}: the policy/dnsbl projection");
		$this->assertSame([], $GLOBALS['pfb_test_lock_events'], 'a read takes no lock');
		$this->assertNull(pfb_core_settings_request_refusal(['version' => 1, 'op' => 'write', 'expectedRevision' => $reply['revision'], 'settings' => $reply['settings']],
			static fn(): array => []), "{$case['id']}: the adapter's write validation accepts what its read answered");
	}

	/** @param array<string, mixed> $row */
	#[DataProvider('refused')]
	public function testTheAdaptersWriteRefusesTheFixturesHostileValueNamingTheFieldAndWritesNothing(array $row): void
	{
		$this->configXmlOnDisk();
		$before = $GLOBALS['config'];

		$reply = $this->assertNoPhpWarning(fn(): array => $this->writePolicy(static fn(array $policy): array => array_replace($policy, $row['policyDnsbl'])));

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, "{$row['id']}: " . json_encode($reply));
		$this->assertContains("policy/dnsbl.{$row['field']}", array_column($reply['error']['fieldErrors'] ?? [], 'field'), "{$row['id']}: {$row['description']} " . json_encode($reply));
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], "{$row['id']}: write_config() was called");
		$this->assertSame($before, $GLOBALS['config'], "{$row['id']}: config.xml changed");
		$this->assertFileDoesNotExist("{$this->dir}/pending", "{$row['id']}: pending changes were marked");
		$this->assertEmpty($GLOBALS['pfb_test_lock_held'] ?? FALSE, "{$row['id']}: the config lock is still held");
	}
}
