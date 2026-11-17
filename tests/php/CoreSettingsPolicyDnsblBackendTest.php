<?php

declare(strict_types=1);

require_once __DIR__ . '/ConfigXmlDiskTrait.php';
require_once __DIR__ . '/PfbNoPhpWarningTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4031: the settings adapter writes Core's `policy/dnsbl` projection into config.xml by merging, never by rewriting:
 *   - only the key of a field whose native value differs from what the read gives is written, in the one write_config() under the
 *     DNS config lock; an unchanged write is a no-op, and a value the read normalizes (a count of abc reads 1000) stays until Core changes it;
 *   - the three Enable/Disable switches store those tokens, a CSV is stored in the given order, the count as plain digits;
 *   - a text area that changes its entries keeps the lines it does not own (comments, blank lines, lines holding no valid entry) and the
 *     comments of the entries that stay, drops the lines of the entries that went, and appends each new entry; a reorder alone writes nothing;
 *     each text area is read as its consumer reads it (the whitelist's IDN lines, the Regex list's raw lines);
 *   - the derived fields (logging, blacklistLogging, groups) are accepted and never stored, and the revision follows them;
 *   - a malformed projection is invalid_argument naming policy/dnsbl.<field>, changing nothing.
 */
#[CoversFunction('pfb_core_settings_backend')]
#[CoversFunction('pfb_core_table_faults')]
#[CoversFunction('pfb_core_table_merge')]
#[CoversFunction('pfb_core_table_text_rewrite')]
#[CoversFunction('pfb_core_table_read')]
final class CoreSettingsPolicyDnsblBackendTest extends TestCase
{
	use ConfigXmlDiskTrait;
	use PfbNoPhpWarningTrait;

	private const DNSBL = 'installedpackages/pfblockerngdnsblsettings/config/0';
	private const SS = 'installedpackages/pfblockerngsafesearch';
	private const GROUPS = 'installedpackages/pfblockerngdnsbl/config';
	private const MESSAGE = '[pfBlockerNG] pfBlockerNG Core saved the settings';
	private const WHITELIST = "example.com # mine\n# keep me\nbogus line!\nexample.org\n\nOld.example # x\n";
	private const TLDS = "xyz # bad\nzip\n";
	private const REGEX = "# header\r\n^ads\\. # trailing\r\n^TRACK\r\nbogus\ttab\r\n";

	private array $priorConfig;
	private array $priorPfb;
	private string $dir;

	protected function setUp(): void
	{
		$this->priorConfig = $GLOBALS['config'] ?? [];
		$this->priorPfb = $GLOBALS['pfb'];
		$this->dir = sys_get_temp_dir() . '/pfb_core_policy_dnsbl_backend_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->dir, 0700));
		$GLOBALS['config'] = [];
		$GLOBALS['pfb']['pending_marker'] = "{$this->dir}/pending";
		$GLOBALS['pfb']['metrics_lock'] = "{$this->dir}/metrics.lock";
		$GLOBALS['pfb']['log'] = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$this->dir}/error.log";
		$GLOBALS['pfb']['runlog'] = '';
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_lock_events'] = [];
		$this->arrange();
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = $this->priorConfig;
		$GLOBALS['pfb'] = $this->priorPfb;
		foreach (['write_config_calls', 'write_config_args', 'write_config_result', 'write_config_hook', 'config_read_hook', 'config_read_calls',
			'config_read_lock_held', 'lock_events', 'lock_held', 'try_lock_fail'] as $global) {
			unset($GLOBALS["pfb_test_{$global}"]);
		}
		rmdir_recursive($this->dir);
	}

	/** config.xml: every policy/dnsbl key set to a value a field can change from, beside a key no field maps to and a stored group. */
	private function arrange(array $over = []): void
	{
		$sections = $over + [
			self::DNSBL => ['pfb_dnsbl' => 'on', 'whitelist' => base64_encode(self::WHITELIST), 'top1m_enable' => '', 'top1m_count' => '500', 'top1m_inclusion' => 'com,net',
				'tld_wildcard_blacklist' => base64_encode(self::TLDS), 'tld_wildcard_exclusion' => base64_encode("example.com\n"), 'tld_allow' => '',
				'tld_allow_gtld' => 'arpa,,com', 'tld_allow_cctld' => 'de', 'tld_allow_itld' => '', 'tld_allow_bgtld' => '', 'pfb_regex' => '',
				'pfb_regex_list' => base64_encode(self::REGEX), 'action' => 'Deny_Both', 'global_log_mode' => 'default', 'global_log' => 'disabled_log', 'pfb_dnsport' => '8081'],
			self::SS => ['safesearch_enable' => 'Disable', 'safesearch_youtube' => 'Strict', 'safesearch_doh' => 'Disable', 'safesearch_doh_list' => 'dns.google'],
			self::GROUPS => [['aliasname' => 'g1', 'action' => 'unbound', 'logging' => 'nodata', 'order' => 'primary', 'filter_top1m' => 'on']],
		];
		foreach ($sections as $path => $value) {
			config_set_path($path, $value);
		}
		$this->configXmlOnDisk();
	}

	private function backend(array $request): array
	{
		return pfb_core_settings_backend($request, "{$this->dir}/node_exporter", static fn(): array => []);
	}

	/** @return array<string, mixed> */
	private function read(): array
	{
		$reply = $this->assertNoPhpWarning(fn(): array => $this->backend(['version' => 1, 'op' => 'read']));
		$this->assertArrayHasKey('policy/dnsbl', $reply['settings'] ?? [], 'the read answers the policy/dnsbl projection: ' . json_encode($reply));
		return $reply;
	}

	/** @return array<string, mixed> Core's write of the read with $change applied to its `policy/dnsbl` */
	private function writePolicy(callable $change): array
	{
		$read = $this->read();
		$settings = $read['settings'];
		$settings['policy/dnsbl'] = $change($settings['policy/dnsbl']);
		return $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings]);
	}

	/** @return array<string, scalar> every leaf of config.xml by its path */
	private static function leaves(array $config, string $prefix = ''): array
	{
		$out = [];
		foreach ($config as $key => $value) {
			is_array($value) ? $out += self::leaves($value, "{$prefix}{$key}/") : $out["{$prefix}{$key}"] = $value;
		}
		return $out;
	}

	/** @return array<string, array{0: mixed, 1: mixed}> path => [before, after] for the leaves that differ, added or removed ones included (NULL) */
	private static function changes(array $before, array $after): array
	{
		$a = self::leaves($before);
		$b = self::leaves($after);
		$out = [];
		foreach (array_unique(array_merge(array_keys($a), array_keys($b))) as $path) {
			if (($a[$path] ?? NULL) !== ($b[$path] ?? NULL)) {
				$out[$path] = [$a[$path] ?? NULL, $b[$path] ?? NULL];
			}
		}
		ksort($out);
		return $out;
	}

	/** @param array<string, array{0: mixed, 1: mixed}> $expected */
	private function assertWrittenOnly(array $expected, array $before, array $reply, int $revisionBefore): void
	{
		$this->assertSame(['version' => 1, 'revision' => $this->read()['revision']], $reply, 'the reply is the revision config.xml projects now');
		$this->assertNotSame($revisionBefore, $reply['revision'], 'the revision moves with the change');
		$this->assertSame([self::MESSAGE], $GLOBALS['pfb_test_write_config_calls'], 'one write_config(), with the Core message');
		$this->assertSame('try_lock', $GLOBALS['pfb_test_lock_events'][0][0], 'the write holds the config lock');
		$this->assertSame(PFB_DNS_CONFIG_LOCK, $GLOBALS['pfb_test_lock_events'][0][1], 'the DNS config lock');
		$this->assertFileExists("{$this->dir}/pending", 'the change applies on the next Update');
		$this->assertEmpty($GLOBALS['pfb_test_lock_held'], 'the lock is released');
		$this->assertSame($this->disk, $GLOBALS['config'], 'what was written is what config.xml holds');
		ksort($expected);
		$this->assertSame($expected, self::changes($before, $GLOBALS['config']), 'exactly these keys of config.xml changed');
	}

	private function assertNothingWritten(array $before, string $why): void
	{
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], "{$why}: write_config() was called");
		$this->assertSame([], self::changes($before, $GLOBALS['config']), "{$why}: config.xml changed");
		$this->assertFileDoesNotExist("{$this->dir}/pending", "{$why}: pending changes were marked");
		$this->assertEmpty($GLOBALS['pfb_test_lock_held'] ?? FALSE, "{$why}: the config lock is still held");
	}

	/** @return array<string, array{0: string, 1: mixed, 2: array<string, array{0: mixed, 1: mixed}>}> field, native value, the keys of config.xml that change */
	public static function fields(): array
	{
		$d = self::DNSBL . '/';
		$s = self::SS . '/';
		return [
			'enabled off'                      => ['enabled', FALSE, [$d . 'pfb_dnsbl' => ['on', '']]],
			'top1m on'                         => ['top1m', TRUE, [$d . 'top1m_enable' => ['', 'on']]],
			'top1m count'                      => ['top1mCount', 1000, [$d . 'top1m_count' => ['500', '1000']]],
			'top1m count highest'              => ['top1mCount', 1000000, [$d . 'top1m_count' => ['500', '1000000']]],
			'top1m inclusion added'            => ['top1mInclusions', [['tld' => 'com'], ['tld' => 'net'], ['tld' => 'org']], [$d . 'top1m_inclusion' => ['com,net', 'com,net,org']]],
			'top1m inclusions emptied'         => ['top1mInclusions', [], [$d . 'top1m_inclusion' => ['com,net', '']]],
			'tld allow on'                     => ['tldAllow', TRUE, [$d . 'tld_allow' => ['', 'on']]],
			'tld allow gtld over an empty token' => ['tldAllowGtld', [['tld' => 'arpa'], ['tld' => 'com'], ['tld' => 'net']], [$d . 'tld_allow_gtld' => ['arpa,,com', 'arpa,com,net']]],
			'tld allow cctld emptied'          => ['tldAllowCctld', [], [$d . 'tld_allow_cctld' => ['de', '']]],
			'tld allow itld from empty'        => ['tldAllowItld', [['tld' => 'arpa']], [$d . 'tld_allow_itld' => ['', 'arpa']]],
			'tld allow bgtld from empty'       => ['tldAllowBgtld', [['tld' => 'app'], ['tld' => 'dev']], [$d . 'tld_allow_bgtld' => ['', 'app,dev']]],
			'regex on'                         => ['regex', TRUE, [$d . 'pfb_regex' => ['', 'on']]],
			'safe search on'                   => ['safeSearch', TRUE, [$s . 'safesearch_enable' => ['Disable', 'Enable']]],
			'youtube moderate'                 => ['safeSearchYoutube', 'Moderate', [$s . 'safesearch_youtube' => ['Strict', 'Moderate']]],
			'youtube disable'                  => ['safeSearchYoutube', 'Disable', [$s . 'safesearch_youtube' => ['Strict', 'Disable']]],
			'doh on'                           => ['safeSearchDoh', TRUE, [$s . 'safesearch_doh' => ['Disable', 'Enable']]],
			'doh list'                         => ['safeSearchDohList', [['host' => 'dns.google'], ['host' => 'x.example']], [$s . 'safesearch_doh_list' => ['dns.google', 'dns.google,x.example']]],
			'dnsbl ip action'                  => ['dnsblIpAction', 'Alias_Deny', [$d . 'action' => ['Deny_Both', 'Alias_Deny']]],
			'dnsbl ip action disabled'         => ['dnsblIpAction', 'Disabled', [$d . 'action' => ['Deny_Both', 'Disabled']]],
		];
	}

	/** @param array<string, array{0: mixed, 1: mixed}> $expected */
	#[DataProvider('fields')]
	public function testAChangedFieldReachesItsKeyAndOnlyIt(string $field, mixed $value, array $expected): void
	{
		$before = $GLOBALS['config'];
		$revision = $this->read()['revision'];

		$reply = $this->writePolicy(static function (array $policy) use ($field, $value): array {
			$policy[$field] = $value;
			return $policy;
		});

		$this->assertWrittenOnly($expected, $before, $reply, $revision);
		$this->assertSame($value, $this->read()['settings']['policy/dnsbl'][$field], 'the read gives back what Core asked');
	}

	public function testAnUnchangedWriteIsANoOp(): void
	{
		$read = $this->read();
		$before = $GLOBALS['config'];

		$reply = $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $read['settings']]);

		$this->assertSame(['version' => 1, 'revision' => $read['revision']], $reply);
		$this->assertNothingWritten($before, 'an unchanged write');
	}

	public function testAStoredValueTheReadNormalizesStaysUntilCoreChangesIt(): void
	{
		$this->arrange([self::DNSBL => ['top1m_count' => '1e1', 'top1m_inclusion' => 'com;net', 'action' => 'Deny', 'tld_allow_cctld' => ' de,fr', 'global_log' => 'bogus', 'global_log_mode' => 'default'],
			self::SS => ['safesearch_enable' => 'enable', 'safesearch_youtube' => 'strict', 'safesearch_doh_list' => ' a.example ,,b.example']]);
		$before = $GLOBALS['config'];
		$this->assertSame(1000, $this->read()['settings']['policy/dnsbl']['top1mCount'], 'before-state: the count reads as the default');

		$reply = $this->writePolicy(static fn(array $policy): array => $policy);

		$this->assertSame(['version' => 1, 'revision' => $this->read()['revision']], $reply);
		$this->assertNothingWritten($before, 'values read as their defaults and written back as they were read');
	}

	public function testTheDerivedFieldsAreAcceptedAndNeverStored(): void
	{
		$before = $GLOBALS['config'];
		$read = $this->read();
		$this->assertSame([['name' => 'g1', 'logging' => 'nodata', 'primary' => TRUE, 'top1mFilter' => TRUE]], $read['settings']['policy/dnsbl']['groups'], 'before-state');

		$reply = $this->writePolicy(static function (array $policy): array {
			$policy['logging'] = 'nxdomain';
			$policy['blacklistLogging'] = 'enabled';
			$policy['groups'] = [['name' => 'other', 'logging' => 'disabled', 'primary' => FALSE, 'top1mFilter' => FALSE]];
			return $policy;
		});

		$this->assertSame(['version' => 1, 'revision' => $read['revision']], $reply, 'a write that changes only derived values is a no-op');
		$this->assertNothingWritten($before, 'derived fields');
		$this->assertSame($read['settings']['policy/dnsbl'], $this->read()['settings']['policy/dnsbl'], 'the read still answers what the Outpost derives');
	}

	public function testADerivedFieldNextToARealChangeStoresOnlyTheRealChange(): void
	{
		$before = $GLOBALS['config'];
		$revision = $this->read()['revision'];

		$reply = $this->writePolicy(static function (array $policy): array {
			$policy['regex'] = TRUE;
			$policy['logging'] = 'nxdomain';
			$policy['groups'] = [];
			return $policy;
		});

		$this->assertWrittenOnly([self::DNSBL . '/pfb_regex' => ['', 'on']], $before, $reply, $revision);
		$this->assertSame('disabled_log', $this->read()['settings']['policy/dnsbl']['logging'], 'what the client sent for a derived field never sticks');
	}

	public function testTheRevisionMovesWhenAGroupsStoredLoggingChangesTheDerivedValue(): void
	{
		$first = $this->read();
		$this->assertSame('nodata', $first['settings']['policy/dnsbl']['groups'][0]['logging'], 'before-state');

		config_set_path(self::GROUPS . '/0/logging', 'nxdomain');
		$this->configXmlOnDisk();
		$second = $this->read();

		$this->assertSame('nxdomain', $second['settings']['policy/dnsbl']['groups'][0]['logging']);
		$this->assertNotSame($first['revision'], $second['revision'], 'a derived value that changed moves the revision');
		$this->assertSame('conflict', $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $first['revision'], 'settings' => $first['settings']])['error']['code'] ?? NULL,
			'a Core that read the old derived value is stale');
	}

	public function testAWhitelistKeepsItsCommentsAndInvalidLinesDropsTheEntriesThatWentAndAppendsTheNewOnes(): void
	{
		$before = $GLOBALS['config'];
		$revision = $this->read()['revision'];
		$this->assertSame([['domain' => 'example.com'], ['domain' => 'example.org'], ['domain' => 'old.example']], $this->read()['settings']['policy/dnsbl']['whitelist'], 'before-state');

		$reply = $this->writePolicy(static function (array $policy): array {
			$policy['whitelist'] = [['domain' => 'example.org'], ['domain' => 'example.com'], ['domain' => '.new.example.net']];
			return $policy;
		});

		$text = "example.com # mine\n# keep me\nbogus line!\nexample.org\n\n.new.example.net";
		$this->assertWrittenOnly([self::DNSBL . '/whitelist' => [base64_encode(self::WHITELIST), base64_encode($text)]], $before, $reply, $revision);
		$this->assertSame($text, base64_decode(config_get_path(self::DNSBL . '/whitelist')), 'the stored text');
	}

	public function testAnIdnWhitelistLineStaysWhenItsPunycodeEntryStays(): void
	{
		$this->arrange([self::DNSBL => ['whitelist' => base64_encode("bücher.de # shop\n")]]);
		$this->assertSame([['domain' => 'xn--bcher-kva.de']], $this->read()['settings']['policy/dnsbl']['whitelist'], 'before-state');
		$before = $GLOBALS['config'];

		$this->writePolicy(static function (array $policy): array {
			$policy['whitelist'][] = ['domain' => 'example.com'];
			return $policy;
		});

		$this->assertSame("bücher.de # shop\nexample.com", base64_decode(config_get_path(self::DNSBL . '/whitelist')), 'the Unicode line is kept as the user typed it');
		$this->assertNotSame([], self::changes($before, $GLOBALS['config']));
	}

	public function testATldListAndAnExclusionListAreRewrittenLikeTheWhitelist(): void
	{
		$reply = $this->writePolicy(static function (array $policy): array {
			$policy['tldBlacklist'] = [['tld' => 'zip'], ['tld' => 'mov']];
			$policy['tldExclusions'] = [];
			return $policy;
		});

		$this->assertArrayHasKey('revision', $reply, json_encode($reply));
		$this->assertSame("zip\nmov", base64_decode(config_get_path(self::DNSBL . '/tld_wildcard_blacklist')), 'xyz went with its comment, zip stays, mov is new');
		$this->assertSame('', base64_decode(config_get_path(self::DNSBL . '/tld_wildcard_exclusion')), 'the only entry went');
	}

	public function testTheRegexListKeepsItsRawLinesAndTheInlineHashOfAnEntryThatStays(): void
	{
		$before = $GLOBALS['config'];
		$revision = $this->read()['revision'];
		$this->assertSame([['pattern' => '^ads\\. # trailing'], ['pattern' => '^TRACK']], $this->read()['settings']['policy/dnsbl']['regexList'], 'before-state');

		$reply = $this->writePolicy(static function (array $policy): array {
			$policy['regexList'] = [['pattern' => '^TRACK'], ['pattern' => '^New\\.']];
			return $policy;
		});

		$text = "# header\n^TRACK\nbogus\ttab\n^New\\.";
		$this->assertWrittenOnly([self::DNSBL . '/pfb_regex_list' => [base64_encode(self::REGEX), base64_encode($text)]], $before, $reply, $revision);
		$this->assertSame($text, base64_decode(config_get_path(self::DNSBL . '/pfb_regex_list')), 'upper case is kept, the line with a tab (no entry Core holds) is left alone');
	}

	public function testARegexListThatPfbDnsCannotLoadIsRewrittenFromNothing(): void
	{
		$this->arrange([self::DNSBL => ['pfb_regex_list' => '!!!not base64']]);
		$this->assertSame([], $this->read()['settings']['policy/dnsbl']['regexList'], 'before-state');

		$this->writePolicy(static function (array $policy): array {
			$policy['regexList'] = [['pattern' => '^a$']];
			return $policy;
		});

		$this->assertSame('^a$', base64_decode(config_get_path(self::DNSBL . '/pfb_regex_list')), 'what pfB-DNS ignored is replaced');
		$this->assertSame([['pattern' => '^a$']], $this->read()['settings']['policy/dnsbl']['regexList']);
	}

	public function testAReorderedTextAreaWritesNothing(): void
	{
		$before = $GLOBALS['config'];

		$reply = $this->writePolicy(static function (array $policy): array {
			$policy['whitelist'] = array_reverse($policy['whitelist']);
			$policy['regexList'] = array_reverse($policy['regexList']);
			return $policy;
		});

		$this->assertSame(['version' => 1, 'revision' => $this->read()['revision']], $reply);
		$this->assertNothingWritten($before, 'a reorder of text area lists');
	}

	public function testAMegabyteLineReadsWithoutAWarningAndIsHeldAsTheListsRulesSay(): void
	{
		$line = str_repeat('a', 1000000);
		$this->arrange([self::DNSBL => ['whitelist' => base64_encode("{$line}.example.com\nexample.com\n"), 'pfb_regex_list' => base64_encode("{$line}\n^x$\n"),
			'tld_wildcard_blacklist' => base64_encode("{$line}\nxyz\n")]]);

		$policy = $this->read()['settings']['policy/dnsbl'];

		$this->assertSame([['domain' => 'example.com']], $policy['whitelist'], 'the domain filter drops a line longer than a domain');
		$this->assertSame([['pattern' => $line], ['pattern' => '^x$']], $policy['regexList'], 'a long pattern is an entry, as pfB-DNS loads it');
		$this->assertSame([['tld' => $line], ['tld' => 'xyz']], $policy['tldBlacklist']);
	}

	public function testAWriteBeneathAStaleRevisionIsAConflictAndWritesNothing(): void
	{
		$read = $this->read();
		$settings = $read['settings'];
		$settings['policy/dnsbl']['enabled'] = FALSE;
		config_set_path(self::DNSBL . '/top1m_count', '2000');
		$this->configXmlOnDisk();
		$before = $GLOBALS['config'];

		$reply = $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings]);

		$this->assertSame('conflict', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertNothingWritten($before, 'a stale revision');
	}

	public function testOneWriteCarriesAPolicyIpChangeAndAPolicyDnsblChange(): void
	{
		$read = $this->read();
		$settings = $read['settings'];
		$settings['policy/ip']['dedup'] = TRUE;
		$settings['policy/dnsbl']['top1mCount'] = 750;

		$reply = $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings]);

		$this->assertSame(['version' => 1, 'revision' => $this->read()['revision']], $reply);
		$this->assertSame([self::MESSAGE], $GLOBALS['pfb_test_write_config_calls'], 'one write_config() for both projections');
		$this->assertSame('750', config_get_path(self::DNSBL . '/top1m_count'));
		$this->assertSame('on', config_get_path('installedpackages/pfblockerngipsettings/config/0/enable_dup'));
	}

	/** @return array<string, array{0: array<string, mixed>, 1: bool}> a change of the projection, and whether the DNSBL page's save would flag TOP1M for it */
	public static function top1mInputs(): array
	{
		return [
			'the count'         => [['top1mCount' => 5000], TRUE],
			'the switch'        => [['top1m' => TRUE], TRUE],
			'the inclusions'    => [['top1mInclusions' => [['tld' => 'com'], ['tld' => 'net']]], TRUE],
			'the regex switch'  => [['regex' => TRUE], FALSE],
			'the SafeSearch'    => [['safeSearch' => TRUE], FALSE],
		];
	}

	/** @param array<string, mixed> $change */
	#[DataProvider('top1mInputs')]
	public function testAWriteThatChangesATop1mInputFlagsTheWhitelistForTheNextUpdateAsTheDnsblPageDoes(array $change, bool $flagged): void
	{
		$GLOBALS['pfb']['dbdir'] = $this->dir;
		$marker = "{$this->dir}/top-1m.update";
		$this->assertFileDoesNotExist($marker, 'before-state: no marker');

		$reply = $this->writePolicy(static fn(array $policy): array => $change + $policy);

		$this->assertArrayNotHasKey('error', $reply, json_encode($reply));
		$this->assertSame($flagged, file_exists($marker), $flagged ? 'the next Update rebuilds the TOP1M whitelist' : 'TOP1M is not flagged for a setting it does not read');
	}

	public function testARefusedWriteOfATop1mInputFlagsNothing(): void
	{
		$GLOBALS['pfb']['dbdir'] = $this->dir;
		$this->configXmlOnDisk(FALSE);

		$reply = $this->writePolicy(static fn(array $policy): array => ['top1mCount' => 5000] + $policy);

		$this->assertSame('unavailable', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertFileDoesNotExist("{$this->dir}/top-1m.update", 'config.xml did not change: nothing to rebuild');
	}

	public function testTheAdapterTakesTheDnsblProjectionAfterGeoipInTheProtocolsOrder(): void
	{
		$this->assertSame(['dns', 'feeds/ipv4', 'feeds/ipv6', 'feeds/dnsbl', 'schedule', 'ingest', 'policy/ip', 'feeds/geoip', 'policy/dnsbl', 'extras', 'hooks', 'maintenance'], array_keys($this->read()['settings']));
	}

	/** @return array<string, array{0: callable, 1: string, 2: string}> a change of the written projection, the field it is named by, its message */
	public static function malformed(): array
	{
		return [
			'a field left out'       => [static function (array $p): array { unset($p['groups']); return $p; }, 'policy/dnsbl.groups', 'required'],
			'an unknown field'       => [static fn(array $p): array => $p + ['bogus' => TRUE], 'policy/dnsbl.bogus', 'no such field'],
			'a bool as a string'     => [static fn(array $p): array => ['enabled' => 'on'] + $p, 'policy/dnsbl.enabled', 'not a bool'],
			'a switch as a string'   => [static fn(array $p): array => ['safeSearch' => 'Enable'] + $p, 'policy/dnsbl.safeSearch', 'not a bool'],
			'a count as a string'    => [static fn(array $p): array => ['top1mCount' => '1000'] + $p, 'policy/dnsbl.top1mCount', 'not an integer from 1 to 1000000'],
			'a count of 0'           => [static fn(array $p): array => ['top1mCount' => 0] + $p, 'policy/dnsbl.top1mCount', 'not an integer from 1 to 1000000'],
			'a count over the range' => [static fn(array $p): array => ['top1mCount' => 1000001] + $p, 'policy/dnsbl.top1mCount', 'not an integer from 1 to 1000000'],
			'an enum off its tokens' => [static fn(array $p): array => ['safeSearchYoutube' => 'strict'] + $p, 'policy/dnsbl.safeSearchYoutube', 'not a valid value'],
			'an action off its tokens' => [static fn(array $p): array => ['dnsblIpAction' => 'Deny'] + $p, 'policy/dnsbl.dnsblIpAction', 'not a valid value'],
			'a list that is a string' => [static fn(array $p): array => ['whitelist' => 'example.com'] + $p, 'policy/dnsbl.whitelist', 'not a list'],
			'an item that is a string' => [static fn(array $p): array => ['tldAllowGtld' => ['com']] + $p, 'policy/dnsbl.tldAllowGtld[0]', 'not an object'],
			'an upper-case domain'   => [static fn(array $p): array => ['whitelist' => [['domain' => 'Example.com']]] + $p, 'policy/dnsbl.whitelist[0].domain', 'not a valid value'],
			'a domain with no dot'   => [static fn(array $p): array => ['whitelist' => [['domain' => 'nodots']]] + $p, 'policy/dnsbl.whitelist[0].domain', 'not a valid value'],
			'a regex with a line break' => [static fn(array $p): array => ['regexList' => [['pattern' => "a\nb"]]] + $p, 'policy/dnsbl.regexList[0].pattern', 'not a valid value'],
			'a regex that is a comment' => [static fn(array $p): array => ['regexList' => [['pattern' => '#a']]] + $p, 'policy/dnsbl.regexList[0].pattern', 'not a valid value'],
			'a TLD with a comma'     => [static fn(array $p): array => ['tldAllowCctld' => [['tld' => 'a,b']]] + $p, 'policy/dnsbl.tldAllowCctld[0].tld', 'not a valid value'],
			'a repeated item'        => [static fn(array $p): array => ['tldAllowBgtld' => [['tld' => 'app'], ['tld' => 'app']]] + $p, 'policy/dnsbl.tldAllowBgtld[1].tld', "repeats an earlier item's"],
			'an item with a field the list lacks' => [static fn(array $p): array => ['safeSearchDohList' => [['host' => 'a.example', 'x' => 1]]] + $p, 'policy/dnsbl.safeSearchDohList[0].x', 'no such field'],
			'a mechanism off its tokens' => [static fn(array $p): array => ['logging' => 'default'] + $p, 'policy/dnsbl.logging', 'not a valid value'],
			'a derived list that is a string' => [static fn(array $p): array => ['groups' => 'g1'] + $p, 'policy/dnsbl.groups', 'not a list'],
			'a group field left out' => [static fn(array $p): array => ['groups' => [['name' => 'g', 'logging' => 'enabled', 'primary' => FALSE]]] + $p, 'policy/dnsbl.groups[0].top1mFilter', 'required'],
			'a group name off its pattern' => [static fn(array $p): array => ['groups' => [['name' => 'a b', 'logging' => 'enabled', 'primary' => FALSE, 'top1mFilter' => FALSE]]] + $p, 'policy/dnsbl.groups[0].name', 'not a valid value'],
			'a repeated group'       => [static fn(array $p): array => ['groups' => array_fill(0, 2, ['name' => 'g', 'logging' => 'enabled', 'primary' => FALSE, 'top1mFilter' => FALSE])] + $p, 'policy/dnsbl.groups[1].name', "repeats an earlier item's"],
			'a projection that is no object' => [static fn(array $p): array => ['x'], 'policy/dnsbl', 'not an object'],
		];
	}

	#[DataProvider('malformed')]
	public function testAMalformedPolicyIsInvalidArgumentNamingTheFieldAndChangesNothing(callable $change, string $field, string $message): void
	{
		$before = $GLOBALS['config'];

		$reply = $this->writePolicy($change);

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertContains(['field' => $field, 'message' => $message], $reply['error']['fieldErrors'] ?? [], json_encode($reply));
		$this->assertNothingWritten($before, 'a malformed policy/dnsbl');
	}

	public function testAWriteWithoutPolicyDnsblIsMalformedNamingTheProjections(): void
	{
		$read = $this->read();
		$settings = $read['settings'];
		unset($settings['policy/dnsbl']);
		$before = $GLOBALS['config'];

		$reply = $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings]);

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertStringContainsString('policy/dnsbl', $reply['error']['message'] ?? '', 'the refusal names the projections a write holds');
		$this->assertNothingWritten($before, 'a write without policy/dnsbl');
	}
}
