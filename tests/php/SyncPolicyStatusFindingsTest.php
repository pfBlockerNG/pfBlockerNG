<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3453 -- effective-policy findings (docs/specs/xmlrpc-per-field-sync.md, "Reporting" item 4
 * and acceptance 12): once an apply completes, received policy that cannot take effect on this node
 * (a credential the local node never receives, a force-disabled DNSBL VIP, a skipped reserved header)
 * is listed in {dbdir}/pfb_sync_findings.json and raised as ONE notice, never again for an unchanged
 * list. Findings are fixed value-free strings: no credential, VIP address or interface ever reaches
 * the file, the notice or the log.
 */
#[CoversFunction('pfb_sync_effective_findings')]
#[CoversFunction('pfb_sync_effective_facts')]
#[CoversFunction('pfb_sync_findings_record')]
#[CoversFunction('pfb_sync_findings_read')]
#[CoversFunction('pfb_blacklist_reg_providers')]
#[CoversFunction('pfb_global')]
final class SyncPolicyStatusFindingsTest extends TestCase
{
	private const NOTICE_PREFIX = 'Policy that cannot take effect on this node: ';
	private const VIP_FINDING   = 'DNSBL disabled: the DNSBL VIP failed validation';

	private string $dir = '';
	private mixed $originalPfb = NULL;
	private mixed $originalConfig = NULL;
	private mixed $originalG = NULL;

	protected function setUp(): void
	{
		$this->originalPfb    = $GLOBALS['pfb'];
		$this->originalConfig = $GLOBALS['config'] ?? NULL;
		$this->originalG      = $GLOBALS['g'] ?? NULL;

		$this->dir = sys_get_temp_dir() . '/pfb_findings_' . getmypid() . '_' . bin2hex(random_bytes(4));
		mkdir($this->dir, 0755, TRUE);
		file_put_contents($this->dir . '/regprov_global_usage', "# fixture\nTITLE: Reg Provider\nXML: RegProv\nREG: yes\nNAME:\tads\n");
		file_put_contents($this->dir . '/regprov2_global_usage', "XML: RegProv2\nREG:\n");
		file_put_contents($this->dir . '/plainprov_global_usage', "# fixture\nTITLE: Plain Provider\nXML: plainprov\nNAME:\tads\n");

		$GLOBALS['config']                = [];
		$GLOBALS['pfb_test_file_notices'] = [];
		$GLOBALS['pfb_test_logger_calls'] = [];
		$GLOBALS['pfb']['enable']         = PfbToggle::On;
		$GLOBALS['pfb']['dnsbl_top1m']    = PfbToggle::Off;
		$GLOBALS['pfb']['dnsbl_top1m_type'] = PfbTop1mSource::Tranco;
		$GLOBALS['pfb']['maxmind_key']    = '';
		$GLOBALS['pfb']['maxmind_account'] = '';
		$GLOBALS['pfb']['asn_token']      = '';
		unset($GLOBALS['pfb']['dnsbl_vip_disabled'], $GLOBALS['pfb']['reserved_header_skips']);
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb']    = $this->originalPfb;
		$GLOBALS['config'] = $this->originalConfig;
		if ($this->originalG === NULL) {
			unset($GLOBALS['g']);
		} else {
			$GLOBALS['g'] = $this->originalG;
		}
		unset($GLOBALS['pfb_test_file_notices'], $GLOBALS['pfb_test_logger_calls'], $GLOBALS['pfb_test_vip_list']);
		foreach (glob($this->dir . '/{,.}*', GLOB_BRACE) ?: [] as $entry) {
			if (is_file($entry)) {
				@unlink($entry);
			}
		}
		@rmdir($this->dir);
	}

	// ---- helpers -----------------------------------------------------------------------

	private function usageGlob(): string
	{
		return $this->dir . '/*_global_usage';
	}

	/** @return array<string,mixed> */
	private function gather(): array
	{
		return pfb_sync_effective_facts($this->usageGlob());
	}

	private function stateBytes(): string
	{
		return (string) @file_get_contents($this->dir . '/pfb_sync_findings.json');
	}

	/** @return list<string> */
	private function noticeTexts(): array
	{
		return array_column($GLOBALS['pfb_test_file_notices'], 'notice');
	}

	/** @param array<string,mixed> $row */
	private function enableListRow(string $format, array $row = []): void
	{
		config_set_path('installedpackages/pfblockernglistsv4/config', [[
			'action' => 'Deny_Inbound',
			'row'    => [$row + ['format' => $format, 'state' => 'Enabled', 'url' => 'https://example.com/list.txt']],
		]]);
	}

	/** @param list<array<string,string>> $items */
	private function seedBlacklist(string $enable, string $selected, array $items): void
	{
		config_set_path('installedpackages/pfblockerngblacklist/blacklist_enable', $enable);
		config_set_path('installedpackages/pfblockerngblacklist/blacklist_selected', $selected);
		config_set_path('installedpackages/pfblockerngblacklist/item', $items);
	}

	// ---- 1. the pure mapping -----------------------------------------------------------

	/** @return array<string,array{0:array<string,mixed>,1:list<string>}> */
	public static function singleFindingProvider(): array
	{
		return [
			'vip'            => [['vip_disabled' => TRUE], [self::VIP_FINDING]],
			'maxmind key'    => [['maxmind_missing' => ['license key']], ['MaxMind: license key missing']],
			'maxmind acct'   => [['maxmind_missing' => ['account ID']], ['MaxMind: account ID missing']],
			'asn'            => [['asn_token_missing' => TRUE], ['ASN: IPinfo token missing']],
			'top1m'          => [['top1m_token_missing' => TRUE], ['TOP1M: provider token missing']],
			'reserved'       => [['reserved_headers' => ['pfB_Top (pfblockernglistsv4)']], ['Header skipped as reserved: pfB_Top (pfblockernglistsv4)']],
			'blacklist'      => [['blacklist_missing' => ['regprov']], ['Blacklist regprov: username or password missing']],
			'nothing'        => [[], []],
			'all falsy'      => [['vip_disabled' => FALSE, 'maxmind_missing' => [], 'asn_token_missing' => FALSE, 'top1m_token_missing' => FALSE, 'reserved_headers' => [], 'blacklist_missing' => []], []],
		];
	}

	/** @param array<string,mixed> $facts @param list<string> $expected */
	#[DataProvider('singleFindingProvider')]
	public function testEachFindingTypeAloneYieldsExactlyItsString(array $facts, array $expected): void
	{
		$this->assertSame($expected, pfb_sync_effective_findings($facts));
	}

	public function testAllFindingsTogetherAreSortedAndUnique(): void
	{
		$findings = pfb_sync_effective_findings([
			'vip_disabled'        => TRUE,
			'maxmind_missing'     => ['license key', 'account ID'],
			'asn_token_missing'   => TRUE,
			'top1m_token_missing' => TRUE,
			'reserved_headers'    => ['Zed (v4)', 'Zed (v4)'],
			'blacklist_missing'   => ['regprov'],
		]);

		$this->assertSame([
			'ASN: IPinfo token missing',
			'Blacklist regprov: username or password missing',
			self::VIP_FINDING,
			'Header skipped as reserved: Zed (v4)',
			'MaxMind: account ID missing',
			'MaxMind: license key missing',
			'TOP1M: provider token missing',
		], $findings);
	}

	// ---- 2. no value ever leaks --------------------------------------------------------

	public function testNoSecretVipOrInterfaceReachesFindingsStateNoticeOrLog(): void
	{
		$sentinels = [
			'maxmind_key' => 'LEAK_SENTINEL_MAXMIND_KEY', 'maxmind_account' => 'LEAK_SENTINEL_MAXMIND_ACCT',
			'asn_token'   => 'LEAK_SENTINEL_ASN_TOKEN',   'top1m_token'     => 'LEAK_SENTINEL_TOP1M_TOKEN',
			'bl_user'     => 'LEAK_SENTINEL_BL_USER',     'bl_pass'         => 'LEAK_SENTINEL_BL_PASS',
			'vip'         => 'LEAK_SENTINEL_VIP_ADDR',    'iface'           => 'LEAK_SENTINEL_IFACE',
		];
		config_set_path('installedpackages/pfblockerngipsettings/config/0/maxmind_key', $sentinels['maxmind_key']);
		config_set_path('installedpackages/pfblockerngipsettings/config/0/maxmind_account', $sentinels['maxmind_account']);
		config_set_path('installedpackages/pfblockerngipsettings/config/0/asn_token', $sentinels['asn_token']);
		config_set_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsvip4', $sentinels['vip']);
		PfbConfig::write('dnsbl/top1m_token', $sentinels['top1m_token']);
		PfbConfig::write('dnsbl/dnsbl_interface', $sentinels['iface']);
		// Each sentinel credential sits next to a finding that is raised for a DIFFERENT field of the same row.
		$this->seedBlacklist('Enable', 'regprov,regprov2', [
			['xml' => 'regprov', 'selected' => 'ads', 'username' => $sentinels['bl_user'], 'password' => ''],
			['xml' => 'regprov2', 'selected' => 'ads', 'username' => '', 'password' => $sentinels['bl_pass']],
		]);
		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'], [
			'maxmind_key'        => $sentinels['maxmind_key'],
			'maxmind_account'    => '',
			'asn_token'          => $sentinels['asn_token'],
			'dnsbl_vip_disabled' => TRUE,
			'dnsbl_iface'        => $sentinels['iface'],
			'dnsbl_vip4'         => $sentinels['vip'],
		]);
		$this->enableListRow('geoip');

		$configBytes = json_encode($GLOBALS['config']) . json_encode($GLOBALS['pfb']);
		foreach ($sentinels as $name => $sentinel) {
			$this->assertStringContainsString($sentinel, $configBytes, "fixture really holds the {$name} sentinel");
		}

		$findings = pfb_sync_effective_findings($this->gather());
		$this->assertContains(self::VIP_FINDING, $findings);
		$this->assertContains('MaxMind: account ID missing', $findings, 'a finding really fires next to the sentinels');
		$this->assertContains('Blacklist regprov: username or password missing', $findings);
		$this->assertContains('Blacklist regprov2: username or password missing', $findings);
		$this->assertTrue(pfb_sync_findings_record($findings, $this->dir));

		$surface = json_encode($findings) . $this->stateBytes() . implode("\n", $this->noticeTexts()) . json_encode($GLOBALS['pfb_test_logger_calls']);
		$this->assertNotSame('', $this->stateBytes());
		foreach ($sentinels as $name => $sentinel) {
			$this->assertStringNotContainsString($sentinel, $surface, "{$name} must never reach findings, state, notice or log");
		}
	}

	// ---- 3. Blacklist username/password -------------------------------------------------

	public function testBlacklistRegProviderWithEmptyUsernameRaisesFinding(): void
	{
		$this->seedBlacklist('Enable', 'regprov', [['xml' => 'regprov', 'selected' => 'ads', 'username' => '', 'password' => 'p']]);
		$this->assertSame(['regprov'], $this->gather()['blacklist_missing']);
	}

	public function testBlacklistRegProviderWithEmptyPasswordRaisesFinding(): void
	{
		$this->seedBlacklist('Enable', 'regprov', [['xml' => 'regprov', 'selected' => 'ads', 'username' => 'u', 'password' => '']]);
		$this->assertSame(['regprov'], $this->gather()['blacklist_missing']);
	}

	public function testBlacklistRegProviderWithBothSetRaisesNothing(): void
	{
		$this->seedBlacklist('Enable', 'regprov', [['xml' => 'regprov', 'selected' => 'ads', 'username' => 'u', 'password' => 'p']]);
		$this->assertSame([], $this->gather()['blacklist_missing']);
	}

	public function testBlacklistProviderWithoutRegAndEmptyCredentialsRaisesNothing(): void
	{
		$this->seedBlacklist('Enable', 'plainprov', [['xml' => 'plainprov', 'selected' => 'ads', 'username' => '', 'password' => '']]);
		$this->assertSame([], $this->gather()['blacklist_missing']);
	}

	public function testDisabledBlacklistItemRaisesNothing(): void
	{
		$item = ['xml' => 'regprov', 'selected' => 'ads', 'username' => '', 'password' => ''];
		$this->seedBlacklist('Disable', 'regprov', [$item]);
		$this->assertSame([], $this->gather()['blacklist_missing'], 'Blacklist disabled');

		$this->seedBlacklist('Enable', 'plainprov', [$item]);
		$this->assertSame([], $this->gather()['blacklist_missing'], 'provider not in blacklist_selected');

		$this->seedBlacklist('Enable', 'regprov', [['selected' => ''] + $item]);
		$this->assertSame([], $this->gather()['blacklist_missing'], 'no category selected');
	}

	public function testRegProvidersComeFromTheUsageFilesNotTheShippedOnes(): void
	{
		$this->assertEqualsCanonicalizing(['regprov', 'regprov2'], array_keys(pfb_blacklist_reg_providers($this->usageGlob())));
	}

	// ---- 4. MaxMind / ASN / TOP1M ------------------------------------------------------

	public function testMaxmindAndAsnOnlyWhenARowIsEnabled(): void
	{
		$this->assertSame([], $this->gather()['maxmind_missing'], 'no rows at all');
		$this->assertFalse($this->gather()['asn_token_missing']);

		$this->enableListRow('geoip');
		$this->assertSame(['license key', 'account ID'], $this->gather()['maxmind_missing']);
		$this->assertFalse($this->gather()['asn_token_missing'], 'a geoip row does not need the ASN token');

		$GLOBALS['pfb']['maxmind_key'] = 'k';
		$this->assertSame(['account ID'], $this->gather()['maxmind_missing']);

		$this->enableListRow('asn');
		$this->assertSame([], $this->gather()['maxmind_missing'], 'an asn row does not need MaxMind');
		$this->assertTrue($this->gather()['asn_token_missing']);

		$GLOBALS['pfb']['asn_token'] = 't';
		$this->assertFalse($this->gather()['asn_token_missing']);
	}

	public function testDisabledGeoipRowsAndDisabledPfblockerRaiseNothing(): void
	{
		$this->enableListRow('geoip', ['state' => 'Disabled']);
		$this->assertSame([], $this->gather()['maxmind_missing'], 'disabled row');

		config_set_path('installedpackages/pfblockernglistsv4/config', [['action' => 'Disabled', 'row' => [['format' => 'geoip', 'state' => 'Enabled', 'url' => 'https://example.com/l.txt']]]]);
		$this->assertSame([], $this->gather()['maxmind_missing'], 'disabled alias');

		$this->enableListRow('geoip');
		$GLOBALS['pfb']['enable'] = PfbToggle::Off;
		$this->assertSame([], $this->gather()['maxmind_missing'], 'pfBlockerNG disabled');
	}

	public function testEnabledContinentCountsAsAGeoipRow(): void
	{
		config_set_path('installedpackages/pfblockerngeurope/config/0/action', 'Deny_Inbound');
		$this->assertSame(['license key', 'account ID'], $this->gather()['maxmind_missing']);
	}

	public function testContinentWithAnActionTheRuntimeRejectsIsNotAGeoipRow(): void
	{
		config_set_path('installedpackages/pfblockerngeurope/config/0/action', 'bogus');
		$this->assertSame([], $this->gather()['maxmind_missing']);
	}

	public function testTop1mTokenFindingNeedsAnAuthProviderAndAnEmptyToken(): void
	{
		$GLOBALS['pfb']['dnsbl_top1m']      = PfbToggle::On;
		$GLOBALS['pfb']['dnsbl_top1m_type'] = PfbTop1mSource::Tranco;
		$this->assertFalse($this->gather()['top1m_token_missing'], 'keyless provider, empty token');

		$GLOBALS['pfb']['dnsbl_top1m_type'] = PfbTop1mSource::Cloudflare;
		$this->assertTrue($this->gather()['top1m_token_missing'], 'auth provider, empty token');

		PfbConfig::write('dnsbl/top1m_token', 'tok');
		$this->assertFalse($this->gather()['top1m_token_missing'], 'auth provider, token set');

		PfbConfig::write('dnsbl/top1m_token', '');
		$GLOBALS['pfb']['dnsbl_top1m'] = PfbToggle::Off;
		$this->assertFalse($this->gather()['top1m_token_missing'], 'TOP1M disabled');
	}

	public function testReservedHeaderSkipsAreCarriedAsFacts(): void
	{
		$this->assertSame([], $this->gather()['reserved_headers']);
		$GLOBALS['pfb']['reserved_header_skips'] = ['pfB_Top (pfblockernglistsv4)'];
		$this->assertSame(['pfB_Top (pfblockernglistsv4)'], $this->gather()['reserved_headers']);
	}

	// ---- 5. de-duplicated notice -------------------------------------------------------

	public function testNoticeFiresOncePerChangedFindingList(): void
	{
		$a = ['ASN: IPinfo token missing'];
		$b = ['ASN: IPinfo token missing', self::VIP_FINDING];

		$this->assertTrue(pfb_sync_findings_record($a, $this->dir));
		$this->assertSame([self::NOTICE_PREFIX . 'ASN: IPinfo token missing'], $this->noticeTexts(), 'change: one notice');
		$notice = $GLOBALS['pfb_test_file_notices'][0];
		$this->assertSame('pfBlockerNG Sync', $notice['id']);
		$this->assertSame('pfBlockerNG', $notice['category']);
		$this->assertSame('/pfblockerng/pfblockerng_sync.php', $notice['url']);
		$this->assertSame(2, $notice['priority']);
		$this->assertCount(1, $GLOBALS['pfb_test_logger_calls'], 'one log line beside the notice');
		$this->assertSame(LOG_WARNING, $GLOBALS['pfb_test_logger_calls'][0]['priority']);
		$this->assertSame(self::NOTICE_PREFIX . 'ASN: IPinfo token missing', $GLOBALS['pfb_test_logger_calls'][0]['message']);
		$this->assertSame($a, pfb_sync_findings_read($this->dir)['findings']);
		$this->assertSame(0600, fileperms($this->dir . '/pfb_sync_findings.json') & 0777, 'root-only state file');

		$bytes = $this->stateBytes();
		$inode = fileinode($this->dir . '/pfb_sync_findings.json');
		$mtime = filemtime($this->dir . '/pfb_sync_findings.json');
		clearstatcache();
		$this->assertTrue(pfb_sync_findings_record($a, $this->dir));
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices'], 'repeat: no second notice');
		$this->assertCount(1, $GLOBALS['pfb_test_logger_calls'], 'repeat: no second log line');
		$this->assertSame($bytes, $this->stateBytes(), 'repeat: file untouched');
		$this->assertSame($inode, fileinode($this->dir . '/pfb_sync_findings.json'), 'repeat: file not rewritten');
		$this->assertSame($mtime, filemtime($this->dir . '/pfb_sync_findings.json'));

		$this->assertTrue(pfb_sync_findings_record($b, $this->dir));
		$this->assertCount(2, $GLOBALS['pfb_test_file_notices'], 'different list: one more notice');
		$this->assertSame(self::NOTICE_PREFIX . implode('; ', $b), $this->noticeTexts()[1]);

		$this->assertTrue(pfb_sync_findings_record([], $this->dir));
		$this->assertCount(2, $GLOBALS['pfb_test_file_notices'], 'cleared: no notice');
		$this->assertSame([], pfb_sync_findings_read($this->dir)['findings']);
		$this->assertSame([], json_decode($this->stateBytes(), TRUE)['findings'], 'cleared: stored as []');

		$this->assertTrue(pfb_sync_findings_record($a, $this->dir));
		$this->assertCount(3, $GLOBALS['pfb_test_file_notices'], 're-appear: notice again');
	}

	public function testPublishFailureLogsOneValueFreeLineAndReturnsFalseWithoutNotice(): void
	{
		$this->assertFalse(pfb_sync_findings_record(['ASN: IPinfo token missing'], $this->dir, ['fail_write' => TRUE]));

		$this->assertSame([], $this->noticeTexts());
		$this->assertCount(1, $GLOBALS['pfb_test_logger_calls']);
		$this->assertStringNotContainsString('ASN', $GLOBALS['pfb_test_logger_calls'][0]['message']);
		$this->assertSame([], pfb_sync_findings_read($this->dir)['findings']);
	}

	// ---- 6. missing / corrupt state ----------------------------------------------------

	public function testMissingFindingsFileReadsEmptyAndFirstRecordNoticesOnce(): void
	{
		$this->assertSame(['time' => NULL, 'findings' => []], pfb_sync_findings_read($this->dir));

		$this->assertTrue(pfb_sync_findings_record([self::VIP_FINDING], $this->dir));
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices']);
		$this->assertTrue(pfb_sync_findings_record([self::VIP_FINDING], $this->dir));
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices']);
		$read = pfb_sync_findings_read($this->dir);
		$this->assertIsInt($read['time']);
		$this->assertSame([self::VIP_FINDING], $read['findings']);
	}

	public function testCorruptFindingsFileReadsEmptyAndIsRewrittenOnTheNextFinding(): void
	{
		file_put_contents($this->dir . '/pfb_sync_findings.json', '{not json');
		$this->assertSame(['time' => NULL, 'findings' => []], pfb_sync_findings_read($this->dir));

		$this->assertTrue(pfb_sync_findings_record([self::VIP_FINDING], $this->dir));
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices']);
		$this->assertSame([self::VIP_FINDING], pfb_sync_findings_read($this->dir)['findings']);
	}

	public function testMalformedFindingEntriesAreDropped(): void
	{
		file_put_contents($this->dir . '/pfb_sync_findings.json', json_encode(['time' => 5, 'findings' => ['ok', 7, NULL, ['x'], 'also ok']]));
		$this->assertSame(['time' => 5, 'findings' => ['ok', 'also ok']], pfb_sync_findings_read($this->dir));

		file_put_contents($this->dir . '/pfb_sync_findings.json', json_encode(['time' => 'soon', 'findings' => 'not a list']));
		$this->assertSame(['time' => NULL, 'findings' => []], pfb_sync_findings_read($this->dir));
	}

	// ---- 7. the VIP force-disable flag -------------------------------------------------

	private function seedGlobalPrereqs(): void
	{
		$gen   = 'installedpackages/pfblockerng/config/0';
		$ip    = 'installedpackages/pfblockerngipsettings/config/0';
		$dnsbl = 'installedpackages/pfblockerngdnsblsettings/config/0';
		foreach (['pfb_min' => '0', 'pfb_hour' => '0', 'pfb_dailystart' => '0', 'skipfeed' => '0'] as $key => $value) {
			config_set_path("{$gen}/{$key}", $value);
		}
		foreach (['suppression' => '', 'database_cc' => '', 'maxmind_locale' => 'en', 'asn_reporting' => 'disabled', 'asn_token' => '', 'maxmind_account' => '', 'maxmind_key' => ''] as $key => $value) {
			config_set_path("{$ip}/{$key}", $value);
		}
		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '8.8.8.8');
		foreach (['pfb_dnsvip6' => '', 'pfb_dnsport' => '8081', 'pfb_dnsport_ssl' => '8443', 'top1m_enable' => '', 'pfb_cache' => '', 'pfb_py_reply' => '', 'pfb_regex' => '',
			'pfb_regex_list' => '', 'pfb_cname' => '', 'tld_allow' => '', 'pfb_py_nolog' => '', 'pfb_noaaaa' => '', 'pfb_noaaaa_list' => '', 'pfb_gp' => '', 'pfb_gp_bypass_list' => ''] as $key => $value) {
			config_set_path("{$dnsbl}/{$key}", $value);
		}
		$GLOBALS['g']['unbound_chroot_path'] ??= '/var/unbound';
		$GLOBALS['pfb_test_vip_list'] = [];
		PfbConfig::write('dnsbl/pfb_dnsbl', 'on');
		PfbConfig::write('dnsbl/pfb_dnsvip_auto', '');
		PfbConfig::write('dnsbl/dnsbl_interface', 'opt-double');
		config_set_path('installedpackages/pfblockerngdnsblsettings/config/0/tld_allow', 'on');	// issue #3539: a built-in answers with the VIP, so it is validated
		config_set_path('installedpackages/pfblockerngdnsblsettings/config/0/tld_allow_gtld', 'com');	// TLD Allow is on only with a selection
	}

	public function testVipDisabledFlagIsSetOnlyByManualModeForceDisable(): void
	{
		$this->seedGlobalPrereqs();
		config_set_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsvip4', '_vip_test_missing');

		pfb_global();
		$this->assertSame(PfbToggle::Off, $GLOBALS['pfb']['dnsbl']);
		$this->assertTrue($GLOBALS['pfb']['dnsbl_vip_disabled'], 'manual mode, invalid VIP: flag set');
		$this->assertContains(self::VIP_FINDING, pfb_sync_effective_findings($this->gather()));

		PfbConfig::write('dnsbl/pfb_dnsvip_auto', 'on');
		pfb_global();
		$this->assertSame(PfbToggle::On, $GLOBALS['pfb']['dnsbl']);
		$this->assertFalse($GLOBALS['pfb']['dnsbl_vip_disabled'], 'auto mode defers: flag reset, not leaked from the previous pass');

		PfbConfig::write('dnsbl/pfb_dnsvip_auto', '');
		$GLOBALS['pfb_test_vip_list'] = ['_vip_test_valid' => '203.0.113.10'];
		config_set_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsvip4', '_vip_test_valid');
		pfb_global();
		$this->assertSame(PfbToggle::On, $GLOBALS['pfb']['dnsbl']);
		$this->assertFalse($GLOBALS['pfb']['dnsbl_vip_disabled'], 'valid VIP: flag unset');
		$this->assertNotContains(self::VIP_FINDING, pfb_sync_effective_findings($this->gather()));
	}

	// ---- 8. receiver drift --------------------------------------------------------------

	private const DRIFT_FINDING = 'Policy changed locally since the last accepted receive';

	/** @return array<string,array{0:array<string,mixed>,1:list<string>}> */
	public static function driftProvider(): array
	{
		return [
			'drift'   => [['drift' => TRUE], [self::DRIFT_FINDING]],
			'no drift' => [['drift' => FALSE], []],
			'absent'  => [[], []],
		];
	}

	/** @param array<string,mixed> $facts @param list<string> $expected */
	#[DataProvider('driftProvider')]
	public function testDriftFactMapsToItsFinding(array $facts, array $expected): void
	{
		$this->assertSame($expected, pfb_sync_effective_findings($facts));
	}

	private function acceptDigest(?string $digest): void
	{
		$GLOBALS['pfb']['dbdir'] = $this->dir;
		if ($digest !== NULL) {
			file_put_contents($this->dir . '/pfb_sync_receive.json', json_encode(['accepted_digest' => $digest]));
		}
	}

	public function testFactsReportDriftWhenAcceptedDigestDiffersFromCurrent(): void
	{
		$this->acceptDigest(str_repeat('0', 64));
		$this->assertTrue($this->gather()['drift']);
	}

	public function testFactsReportNoDriftWhenAcceptedDigestIsCurrent(): void
	{
		$this->acceptDigest(pfb_sync_policy_current_digest());
		$this->assertFalse($this->gather()['drift']);
	}

	public function testFactsReportNoDriftWithoutStateFile(): void
	{
		$this->acceptDigest(NULL);
		$this->assertFalse($this->gather()['drift']);
	}

	public function testDriftNoticeFiresOnceAndNotAgainWhenCleared(): void
	{
		$drift = [self::DRIFT_FINDING];
		$this->assertTrue(pfb_sync_findings_record($drift, $this->dir));
		$this->assertSame([self::NOTICE_PREFIX . self::DRIFT_FINDING], $this->noticeTexts());
		$this->assertTrue(pfb_sync_findings_record($drift, $this->dir));
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices'], 'repeat: no second notice');
		$this->assertTrue(pfb_sync_findings_record([], $this->dir));
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices'], 'cleared: no notice');
	}
}
