<?php

declare(strict_types=1);

require_once __DIR__ . '/ConfigXmlDiskTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3937: the settings adapter writes Core's feed projections (`feeds/ipv4`, `feeds/ipv6`, `feeds/dnsbl`) into config.xml by
 * merging, never by rewriting:
 *   - groups are matched by name and feeds by header; only the config.xml keys whose native value differs from what the read gives
 *     are written, so a stored token the read normalizes stays as it is until Core changes that field;
 *   - a new group or feed is appended with its projected keys only; a projected one missing from Core's list is deleted;
 *   - what does not project (a group or feed the read leaves out, a key no native field maps to) is never touched;
 *   - credentials go back into the URL's userinfo, a file:// URL back to its local path, an ASN source is stored HTML-escaped;
 *   - bindAddress is an interface's IPv4 address, mapped to and from `srcint` through the adapter's interface seam; an address no
 *     interface holds, like any value outside a field's rule, is invalid_argument naming the field, and changes nothing.
 *   - the adapter leaves out and never touches what it cannot project faithfully (issue #3946): a group whose Source Interface does not
 *     resolve to an IPv4 address, whose name or whose rows' headers Core can then not repeat; a custom list is read as valid UTF-8, a script
 *     name is a plain file name, and a changed custom list is flagged for a rebuild, as the Groups editor flags it, once the write is stored.
 */
#[CoversFunction('pfb_core_settings_backend')]
#[CoversFunction('pfb_core_settings_request_refusal')]
#[CoversFunction('pfb_core_settings_serve')]
final class CoreSettingsFeedsBackendTest extends TestCase
{
	use ConfigXmlDiskTrait;

	private const V4 = 'installedpackages/pfblockernglistsv4/config';
	private const V6 = 'installedpackages/pfblockernglistsv6/config';
	private const DNSBL = 'installedpackages/pfblockerngdnsbl/config';
	private const MESSAGE = '[pfBlockerNG] pfBlockerNG Core saved the settings';

	/** The interfaces the seam reports: realif => its IPv4 address ('' when it has none). */
	private const INTERFACES = ['em0' => '192.0.2.1', 'em1' => '10.0.0.1', 'em2' => ''];

	/** The list folders a rebuild marker lands in, each as the sandbox folder name => the $pfb key that holds its path. */
	private const LIST_FOLDERS = ['deny' => 'denydir', 'permit' => 'permitdir', 'match' => 'matchdir', 'native' => 'nativedir', 'dnsbl' => 'dnsdir'];

	private array $priorConfig;
	private array $priorPfb;
	private string $dir;

	/** @var list<string> every PHP warning, notice or deprecation the adapter raised in this test */
	private array $warnings = [];

	protected function setUp(): void
	{
		$this->priorConfig = $GLOBALS['config'] ?? [];
		$this->priorPfb = $GLOBALS['pfb'];
		$this->dir = sys_get_temp_dir() . '/pfb_core_feeds_backend_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->dir, 0700));
		$GLOBALS['config'] = [];
		$GLOBALS['pfb']['pending_marker'] = "{$this->dir}/pending";
		$GLOBALS['pfb']['metrics_lock'] = "{$this->dir}/metrics.lock";
		$GLOBALS['pfb']['log'] = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$this->dir}/error.log";
		$GLOBALS['pfb']['runlog'] = '';
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_lock_events'] = [];
		foreach (self::LIST_FOLDERS as $folder => $key) {
			$this->assertTrue(mkdir("{$this->dir}/{$folder}", 0700));
			$GLOBALS['pfb'][$key] = "{$this->dir}/{$folder}";
		}
		// The adapter process never sets these (only the update pass does)
		unset($GLOBALS['pfb']['reuse'], $GLOBALS['pfb']['reuse_dnsbl']);
		$this->warnings = [];
		set_error_handler(function (int $level, string $message): bool {
			$this->warnings[] = $message;
			return TRUE;
		});
	}

	protected function tearDown(): void
	{
		restore_error_handler();
		$GLOBALS['config'] = $this->priorConfig;
		$GLOBALS['pfb'] = $this->priorPfb;
		foreach (['write_config_calls', 'write_config_args', 'write_config_result', 'write_config_hook', 'config_read_hook', 'config_read_calls',
			'config_read_lock_held', 'lock_events', 'lock_held', 'try_lock_fail'] as $global) {
			unset($GLOBALS["pfb_test_{$global}"]);
		}
		rmdir_recursive($this->dir);
	}

	/** An IPv4 group as the Groups editor stores it: keys no native field maps to, legacy tokens, and a row that does not project. */
	private static function v4Group(): array
	{
		return [
			'aliasname' => 'Spam', 'description' => 'kept', 'action' => 'Deny_Inbound', 'cron' => 'EveryDay', 'sort' => 'sort', 'aliaslog' => 'enabled',
			'srcint' => '', 'script_pre' => '', 'script_post' => '', 'custom' => '', 'suppression_cidr' => 'Disabled', 'whois_convert' => '',
			'schedule_override' => '', 'autoproto_in' => 'any',
			'row' => [
				['format' => 'Auto', 'state' => 'Whatever', 'url' => 'https://example.org/a.txt', 'header' => 'A'],
				['format' => 'auto', 'state' => 'Enabled', 'url' => '', 'header' => 'Inert'],
				['format' => 'auto', 'state' => 'Enabled', 'url' => 'https://example.org/b.txt', 'header' => 'B'],
			],
		];
	}

	private static function v6Group(): array
	{
		return ['aliasname' => 'Six', 'action' => 'Match_Both', 'cron' => 'Never', 'aliaslog' => 'enabled',
			'row' => [['format' => 'rsync', 'state' => 'Enabled', 'url' => 'rsync://example.org/six.txt', 'header' => 'S']]];
	}

	private static function dnsblGroup(): array
	{
		return ['aliasname' => 'Ads', 'action' => 'unbound', 'cron' => 'Never', 'logging' => 'enabled', 'order' => 'default', 'filter_top1m' => '',
			'row' => [['format' => 'auto', 'state' => 'Enabled', 'url' => 'https://example.com/hosts', 'header' => 'H', 'action' => 'Permit']]];
	}

	/** @param array<string, list<mixed>> $sections config path => its groups; becomes config.xml and the file on disk */
	private function arrange(array $sections): void
	{
		foreach ($sections as $path => $groups) {
			config_set_path($path, $groups);
		}
		$this->configXmlOnDisk();
	}

	private function backend(array $request): array
	{
		return pfb_core_settings_backend($request, "{$this->dir}/node_exporter", static fn(): array => self::INTERFACES);
	}

	/** @return array<string, mixed> the adapter's read, which must answer every projection */
	private function read(): array
	{
		$reply = $this->backend(['version' => 1, 'op' => 'read']);
		$this->assertSame(['dns', 'feeds/ipv4', 'feeds/ipv6', 'feeds/dnsbl', 'schedule'], array_keys($reply['settings'] ?? []), 'the read answers: ' . json_encode($reply));
		return $reply;
	}

	/** @return array<string, mixed> Core's write of $settings at $revision */
	private function write(array $settings, int $revision): array
	{
		return $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $revision, 'settings' => $settings]);
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

	/** @return list<string> the leaves of config.xml that differ between two copies, added or removed ones included */
	private static function changedLeaves(array $before, array $after): array
	{
		$a = self::leaves($before);
		$b = self::leaves($after);
		return array_values(array_unique(array_merge(array_keys(array_diff_assoc($a, $b)), array_keys(array_diff_assoc($b, $a)))));
	}

	/** $value with every map's keys sorted: a stored group compared key by key, whatever order the writer set them in */
	private static function sorted(mixed $value): mixed
	{
		if (!is_array($value)) {
			return $value;
		}
		if (!array_is_list($value)) {
			ksort($value);
		}
		return array_map(self::sorted(...), $value);
	}

	private function assertWritten(array $reply): void
	{
		$this->assertSame(['version' => 1, 'revision' => $this->read()['revision']], $reply, 'the reply is the revision config.xml projects now');
		$this->assertSame([self::MESSAGE], $GLOBALS['pfb_test_write_config_calls'], 'one write_config(), with the Core message');
		$this->assertFileExists("{$this->dir}/pending", 'the change applies on the next Update');
		$this->assertEmpty($GLOBALS['pfb_test_lock_held'], 'the lock is released');
		$this->assertSame($this->disk, $GLOBALS['config'], 'what was written is what config.xml holds');
	}

	private function assertNothingWritten(array $before, string $why): void
	{
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], "{$why}: write_config() was called");
		$this->assertSame([], self::changedLeaves($before, $GLOBALS['config']), "{$why}: config.xml changed");
		$this->assertFileDoesNotExist("{$this->dir}/pending", "{$why}: pending changes were marked");
		$this->assertEmpty($GLOBALS['pfb_test_lock_held'] ?? FALSE, "{$why}: the config lock is still held");
	}

	// ----- the read -----

	public function testTheReadAnswersEachGroupTypeFromItsOwnSectionAndTheRevisionCoversThem(): void
	{
		$this->arrange([self::V4 => [self::v4Group()], self::V6 => [self::v6Group()], self::DNSBL => [self::dnsblGroup()]]);

		$read = $this->read();

		$this->assertSame(['Spam'], array_column($read['settings']['feeds/ipv4']['groups'], 'name'));
		$this->assertSame(['A', 'B'], array_column($read['settings']['feeds/ipv4']['groups'][0]['feeds'], 'header'), 'the enabled row with no source does not project');
		$this->assertSame(['Six'], array_column($read['settings']['feeds/ipv6']['groups'], 'name'));
		$this->assertSame(['Ads'], array_column($read['settings']['feeds/dnsbl']['groups'], 'name'));
		$this->assertSame('permit', $read['settings']['feeds/dnsbl']['groups'][0]['feeds'][0]['action']);
		$this->assertSame(pfb_core_settings_revision($read['settings']), $read['revision'], 'the revision is the one of all four projections');
		foreach (['feeds/ipv4', 'feeds/ipv6', 'feeds/dnsbl'] as $projection) {
			$moved = $read['settings'];
			$moved[$projection]['groups'][0]['feeds'][0]['url'] .= '?moved';
			$this->assertNotSame($read['revision'], pfb_core_settings_revision($moved), "{$projection} moves the revision");
		}
		$this->assertSame([], $GLOBALS['pfb_test_lock_events'], 'a read takes no lock');
	}

	public function testBindAddressIsTheIpv4AddressOfTheSourceInterface(): void
	{
		$groups = [];
		foreach (['Plain' => '', 'Local' => 'lo0', 'Bound' => 'em1'] as $name => $srcint) {
			$groups[] = ['aliasname' => $name, 'action' => 'Disabled', 'cron' => 'Never', 'srcint' => $srcint];
		}
		$this->arrange([self::V4 => $groups]);

		$read = $this->read();

		$this->assertSame(['Plain' => '', 'Local' => '127.0.0.1', 'Bound' => '10.0.0.1'],
			array_column($read['settings']['feeds/ipv4']['groups'], 'bindAddress', 'name'));
	}

	// ----- a changed field -----

	/**
	 * @return array<string, array{0: array<string, mixed>, 1: string, 2: mixed, 3: string, 4: string}> what is stored over v4Group(),
	 *   the native field of group 0 (`feeds.0.<field>` for feed A), its new value, the config.xml key under group 0 and its stored value
	 */
	public static function fieldWrites(): array
	{
		$feedA = static fn(array $row): array => ['row' => [0 => $row]];
		return [
			'action'                             => [[], 'action', 'Permit_Outbound', 'action', 'Permit_Outbound'],
			'updateFrequency'                    => [[], 'updateFrequency', 'Weekly', 'cron', 'Weekly'],
			'preScript'                          => [[], 'preScript', 'pfb_pre.sh', 'script_pre', 'pfb_pre.sh'],
			'postScript'                         => [[], 'postScript', 'pfb_post.sh', 'script_post', 'pfb_post.sh'],
			'customList'                         => [[], 'customList', "192.0.2.0/24\nAS13335", 'custom', base64_encode("192.0.2.0/24\nAS13335")],
			'suppressionCidr: Disabled to 24'    => [[], 'suppressionCidr', 24, 'suppression_cidr', '24'],
			'suppressionCidr: 16 to Disabled'    => [['suppression_cidr' => '16'], 'suppressionCidr', 0, 'suppression_cidr', 'Disabled'],
			'whoisConvert: off to on'            => [[], 'whoisConvert', TRUE, 'whois_convert', 'on'],
			'whoisConvert: on to off'            => [['whois_convert' => 'on'], 'whoisConvert', FALSE, 'whois_convert', ''],
			'bindAddress: an interface address'  => [[], 'bindAddress', '10.0.0.1', 'srcint', 'em1'],
			'bindAddress: loopback'              => [[], 'bindAddress', '127.0.0.1', 'srcint', 'lo0'],
			'bindAddress: back to the default'   => [['srcint' => 'em1'], 'bindAddress', '', 'srcint', ''],
			'feed state: disabled'               => [[], 'feeds.0.state', 'disabled', 'row/0/state', 'Disabled'],
			'feed state: hold'                   => [[], 'feeds.0.state', 'hold', 'row/0/state', 'Hold'],
			'feed state: flex'                   => [[], 'feeds.0.state', 'flex', 'row/0/state', 'Flex'],
			'feed state: disabled to enabled'    => [$feedA(['state' => 'Disabled']), 'feeds.0.state', 'enabled', 'row/0/state', 'Enabled'],
			'feed format'                        => [[], 'feeds.0.format', 'regex', 'row/0/format', 'regex'],
			'feed url'                           => [[], 'feeds.0.url', 'https://example.org/c.txt', 'row/0/url', 'https://example.org/c.txt'],
			'feed url: a local path'             => [[], 'feeds.0.url', 'file:///var/db/pfblockerng/own.txt', 'row/0/url', '/var/db/pfblockerng/own.txt'],
			'feed credentials: into the url'     => [[], 'feeds.0.credentials', 'user:s3cret', 'row/0/url', 'https://user:s3cret@example.org/a.txt'],
			'feed credentials: out of the url'   => [$feedA(['url' => 'https://user:s3cret@example.org/a.txt']), 'feeds.0.credentials', '', 'row/0/url', 'https://example.org/a.txt'],
		];
	}

	#[DataProvider('fieldWrites')]
	public function testAChangedFieldWritesOnlyItsKeyAndTheReadGivesBackWhatCoreAsked(array $preset, string $field, mixed $value, string $key, string $stored): void
	{
		$this->arrange([self::V4 => [array_replace_recursive(self::v4Group(), $preset)]]);
		$read = $this->read();
		$settings = $read['settings'];
		$node = &$settings['feeds/ipv4']['groups'][0];
		foreach (explode('.', $field) as $step) {
			$node = &$node[$step];
		}
		$this->assertNotSame($value, $node, 'before-state: the field holds another value');
		$node = $value;
		unset($node);
		$before = $GLOBALS['config'];

		$reply = $this->write($settings, $read['revision']);

		$this->assertWritten($reply);
		$this->assertSame($settings, $this->read()['settings'], 'the read gives back what Core asked for');
		$this->assertSame($stored, config_get_path(self::V4 . "/0/{$key}"), "{$key} as stored");
		$this->assertSame([self::V4 . "/0/{$key}"], self::changedLeaves($before, $GLOBALS['config']), 'no other config.xml key is touched');
	}

	public function testAnAsnSourceIsStoredHtmlEscapedAsTheGroupsEditorStoresIt(): void
	{
		$this->arrange([self::V4 => [self::v4Group()]]);
		$read = $this->read();
		$settings = $read['settings'];
		$settings['feeds/ipv4']['groups'][0]['feeds'][0]['format'] = 'asn';
		$settings['feeds/ipv4']['groups'][0]['feeds'][0]['url'] = 'AS13335 & Cloudflare';

		$reply = $this->write($settings, $read['revision']);

		$this->assertWritten($reply);
		$this->assertSame(['format' => 'asn', 'state' => 'Whatever', 'url' => 'AS13335 &amp; Cloudflare', 'header' => 'A'], config_get_path(self::V4 . '/0/row/0'),
			'the unchanged state keeps its stored token');
		$this->assertSame($settings, $this->read()['settings']);
	}

	public function testAWriteOfWhatTheReadGaveChangesNothingAndKeepsTheStoredTokens(): void
	{
		// Given a group whose stored tokens the read normalizes (state Whatever reads enabled, format Auto reads auto)
		$this->arrange([self::V4 => [self::v4Group()], self::V6 => [self::v6Group()], self::DNSBL => [self::dnsblGroup()]]);
		$read = $this->read();
		$this->assertSame(['enabled', 'auto'], [$read['settings']['feeds/ipv4']['groups'][0]['feeds'][0]['state'], $read['settings']['feeds/ipv4']['groups'][0]['feeds'][0]['format']]);
		$before = $GLOBALS['config'];

		// When Core writes back what it read
		$reply = $this->write($read['settings'], $read['revision']);

		// Then nothing is written and the tokens stay
		$this->assertSame(['version' => 1, 'revision' => $read['revision']], $reply);
		$this->assertNothingWritten($before, 'an unchanged write');
		$this->assertSame('Whatever', config_get_path(self::V4 . '/0/row/0/state'));
	}

	public function testOneWriteCarriesADnsChangeAndAFeedChange(): void
	{
		$this->arrange([self::DNSBL => [self::dnsblGroup()]]);
		$read = $this->read();
		$settings = $read['settings'];
		$settings['dns']['hstsNullBlocking'] = !$settings['dns']['hstsNullBlocking'];
		$settings['feeds/dnsbl']['groups'][0]['feeds'][0]['action'] = 'deny';

		$reply = $this->write($settings, $read['revision']);

		$this->assertWritten($reply);
		$this->assertSame($settings, $this->read()['settings']);
		$this->assertSame('Deny', config_get_path(self::DNSBL . '/0/row/0/action'));
	}

	// ----- feeds added and deleted -----

	public function testANewFeedIsAppendedAfterTheRowsThatDoNotProjectWithItsProjectedKeysOnly(): void
	{
		$this->arrange([self::V4 => [self::v4Group()]]);
		$read = $this->read();
		$settings = $read['settings'];
		$settings['feeds/ipv4']['groups'][0]['feeds'][] = ['header' => 'C', 'state' => 'hold', 'format' => 'regex', 'url' => 'https://example.org/c.html', 'credentials' => 'u:p'];
		$before = $GLOBALS['config'];

		$reply = $this->write($settings, $read['revision']);

		$this->assertWritten($reply);
		$rows = config_get_path(self::V4 . '/0/row');
		$this->assertSame(array_slice($before['installedpackages']['pfblockernglistsv4']['config'][0]['row'], 0, 3), array_slice($rows, 0, 3), 'the rows before it are untouched');
		$this->assertSame(self::sorted(['format' => 'regex', 'state' => 'Hold', 'url' => 'https://u:p@example.org/c.html', 'header' => 'C']), self::sorted($rows[3]));
		$this->assertCount(4, $rows);
		$this->assertSame($settings, $this->read()['settings']);
	}

	public function testANewDnsblFeedCarriesItsAction(): void
	{
		$this->arrange([self::DNSBL => [self::dnsblGroup()]]);
		$read = $this->read();
		$settings = $read['settings'];
		$settings['feeds/dnsbl']['groups'][0]['feeds'][] = ['header' => 'More', 'state' => 'enabled', 'format' => 'auto', 'url' => 'https://example.com/more', 'credentials' => '', 'action' => 'deny'];

		$reply = $this->write($settings, $read['revision']);

		$this->assertWritten($reply);
		$this->assertSame(self::sorted(['format' => 'auto', 'state' => 'Enabled', 'url' => 'https://example.com/more', 'header' => 'More', 'action' => 'Deny']),
			self::sorted(config_get_path(self::DNSBL . '/0/row/1')));
	}

	public function testAFeedMissingFromCoresListIsDeletedAndTheRowThatDoesNotProjectStays(): void
	{
		$this->arrange([self::V4 => [self::v4Group()]]);
		$read = $this->read();
		$settings = $read['settings'];
		$settings['feeds/ipv4']['groups'][0]['feeds'] = [$settings['feeds/ipv4']['groups'][0]['feeds'][1]];
		$this->assertSame('B', $settings['feeds/ipv4']['groups'][0]['feeds'][0]['header']);

		$reply = $this->write($settings, $read['revision']);

		$this->assertWritten($reply);
		$this->assertSame(array_slice(self::v4Group()['row'], 1), config_get_path(self::V4 . '/0/row'), 'A is gone; the inert row and B stay as stored');
		$this->assertSame('kept', config_get_path(self::V4 . '/0/description'));
	}

	// ----- groups added and deleted -----

	/** @return array<string, array{0: string, 1: string, 2: array<string, mixed>, 3: array<string, mixed>}> */
	public static function newGroups(): array
	{
		$feed = ['header' => 'F', 'state' => 'enabled', 'format' => 'auto', 'url' => 'https://example.org/f.txt', 'credentials' => ''];
		$row = ['format' => 'auto', 'state' => 'Enabled', 'url' => 'https://example.org/f.txt', 'header' => 'F'];
		$group = ['name' => 'New', 'action' => 'Deny_Both', 'updateFrequency' => '01hour', 'bindAddress' => '10.0.0.1', 'preScript' => '',
			'postScript' => 'pfb_post.sh', 'customList' => 'x'];
		$stored = ['aliasname' => 'New', 'action' => 'Deny_Both', 'cron' => '01hour', 'srcint' => 'em1', 'script_pre' => '', 'script_post' => 'pfb_post.sh',
			'custom' => base64_encode('x')];
		return [
			'IPv4'  => ['feeds/ipv4', self::V4, $group + ['suppressionCidr' => 0, 'whoisConvert' => TRUE, 'feeds' => [$feed]],
				$stored + ['suppression_cidr' => 'Disabled', 'whois_convert' => 'on', 'row' => [$row]]],
			'IPv6'  => ['feeds/ipv6', self::V6, $group + ['whoisConvert' => FALSE, 'feeds' => [$feed]],
				$stored + ['whois_convert' => '', 'row' => [$row]]],
			'DNSBL' => ['feeds/dnsbl', self::DNSBL, array_merge($group, ['action' => 'unbound', 'feeds' => [$feed + ['action' => 'permit']]]),
				array_merge($stored, ['action' => 'unbound', 'row' => [$row + ['action' => 'Permit']]])],
		];
	}

	/**
	 * @param array<string, mixed> $group
	 * @param array<string, mixed> $stored
	 */
	#[DataProvider('newGroups')]
	public function testANewGroupIsAppendedWithItsProjectedKeysOnly(string $projection, string $path, array $group, array $stored): void
	{
		$this->arrange([self::V4 => [self::v4Group()], self::V6 => [self::v6Group()], self::DNSBL => [self::dnsblGroup()]]);
		$read = $this->read();
		$settings = $read['settings'];
		$settings[$projection]['groups'][] = $group;
		$first = config_get_path("{$path}/0");

		$reply = $this->write($settings, $read['revision']);

		$this->assertWritten($reply);
		$this->assertSame($first, config_get_path("{$path}/0"), 'the group before it is untouched');
		$this->assertSame(self::sorted($stored), self::sorted(config_get_path("{$path}/1")));
		$settings['schedule']['groups'][] = ['id' => substr($projection, 6) . '/' . $group['name'], 'override' => FALSE, 'weekday' => 7, 'hour' => 0, 'minute' => 0];
		usort($settings['schedule']['groups'], static fn(array $a, array $b): int => array_search(explode('/', $a['id'])[0], ['ipv4', 'ipv6', 'dnsbl'], TRUE)
			<=> array_search(explode('/', $b['id'])[0], ['ipv4', 'ipv6', 'dnsbl'], TRUE));
		$this->assertSame($settings, $this->read()['settings']);
	}

	public function testAGroupMissingFromCoresListIsDeletedAndAGroupThatDoesNotProjectStays(): void
	{
		$bad = ['aliasname' => 'bad name', 'action' => 'Deny_Inbound', 'cron' => 'Never'];
		$other = ['aliasname' => 'Other', 'action' => 'Disabled', 'cron' => 'Never', 'description' => 'mine'];
		$this->arrange([self::V4 => [self::v4Group(), $bad, $other]]);
		$read = $this->read();
		$settings = $read['settings'];
		$this->assertSame(['Spam', 'Other'], array_column($settings['feeds/ipv4']['groups'], 'name'), 'before-state');
		$settings['feeds/ipv4']['groups'] = [$settings['feeds/ipv4']['groups'][1]];

		$reply = $this->write($settings, $read['revision']);

		$this->assertWritten($reply);
		$this->assertSame([$bad, $other], config_get_path(self::V4));
	}

	public function testAnEmptyJsonListOfGroupsDeletesEveryProjectedGroup(): void
	{
		// Given an IPv6 group, and a request as Core sends it: JSON text, `groups` a JSON array
		$this->arrange([self::V6 => [self::v6Group()]]);
		$read = $this->read();
		$settings = $read['settings'];
		$settings['feeds/ipv6']['groups'] = [];
		$json = (string) json_encode(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings]);
		$this->assertStringContainsString('"feeds\/ipv6":{"groups":[]}', $json);

		// When the adapter serves it
		$reply = json_decode(pfb_core_settings_serve($json), TRUE);

		// Then the group is deleted
		$this->assertArrayNotHasKey('error', $reply, json_encode($reply));
		$this->assertSame([], config_get_path(self::V6));
		$this->assertSame(['version' => 1, 'revision' => $this->read()['revision']], $reply);
	}

	// ----- refusals -----

	public function testAnAddressNoInterfaceHoldsIsRefusedBeforeAnyLockAndChangesNothing(): void
	{
		$this->arrange([self::V4 => [self::v4Group()]]);
		$read = $this->read();
		$settings = $read['settings'];
		$settings['feeds/ipv4']['groups'][0]['bindAddress'] = '198.51.100.9';
		$before = $GLOBALS['config'];
		$GLOBALS['pfb_test_lock_events'] = [];

		$reply = $this->write($settings, $read['revision']);

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertContains('feeds/ipv4.groups[0].bindAddress', array_column($reply['error']['fieldErrors'] ?? [], 'field'));
		$this->assertNothingWritten($before, 'an unknown address');
		$this->assertSame([], $GLOBALS['pfb_test_lock_events'], 'no lock was asked for');
	}

	public function testAWriteAgainstAFeedChangeCoreHasNotReadIsAConflict(): void
	{
		// Given Core read the settings, and another writer then changed a feed's source in config.xml
		$this->arrange([self::V4 => [self::v4Group()]]);
		$read = $this->read();
		$this->disk['installedpackages']['pfblockernglistsv4']['config'][0]['row'][2]['url'] = 'https://example.org/moved.txt';
		$GLOBALS['config'] = $this->disk;
		$this->assertNotSame($read['revision'], $this->read()['revision'], 'before-state: the feed change moved the revision');
		$settings = $read['settings'];
		$settings['feeds/ipv4']['groups'][0]['action'] = 'Permit_Both';
		$before = $GLOBALS['config'];

		// When Core writes at the revision it read
		$reply = $this->write($settings, $read['revision']);

		// Then the write is a conflict and nothing changes
		$this->assertSame('conflict', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertNothingWritten($before, 'a stale revision');
	}

	/** @return array<string, array{0: callable(array): array, 1: string}> a change to a valid write, and the field its refusal names */
	public static function malformedWrites(): array
	{
		$v4 = static fn(callable $edit): callable => static function (array $s) use ($edit): array {
			$edit($s['feeds/ipv4']['groups'][0]);
			return $s;
		};
		$feed = static fn(callable $edit): callable => $v4(static function (array &$g) use ($edit): void {
			$edit($g['feeds'][0]);
		});
		$set = static fn(string $field, mixed $value): callable => $v4(static function (array &$g) use ($field, $value): void {
			$g[$field] = $value;
		});
		$feedSet = static fn(string $field, mixed $value): callable => $feed(static function (array &$f) use ($field, $value): void {
			$f[$field] = $value;
		});
		$whole = static fn(callable $edit): callable => static function (array $s) use ($edit): array {
			$edit($s);
			return $s;
		};
		$prefix = 'feeds/ipv4.groups[0]';
		return [
			'a projection not an object'        => [$whole(static function (array &$s): void { $s['feeds/ipv6'] = 'x'; }), 'feeds/ipv6'],
			'a projection without groups'       => [$whole(static function (array &$s): void { $s['feeds/ipv6'] = []; }), 'feeds/ipv6.groups'],
			'a projection with another field'   => [$whole(static function (array &$s): void { $s['feeds/ipv6']['extra'] = 1; }), 'feeds/ipv6.extra'],
			'groups not a list'                 => [$whole(static function (array &$s): void { $s['feeds/ipv4']['groups'] = ['a' => $s['feeds/ipv4']['groups'][0]]; }), 'feeds/ipv4.groups'],
			'a group not an object'             => [$whole(static function (array &$s): void { $s['feeds/ipv4']['groups'][] = 'x'; }), 'feeds/ipv4.groups[1]'],
			'a duplicate name'                  => [$whole(static function (array &$s): void { $s['feeds/ipv4']['groups'][] = $s['feeds/ipv4']['groups'][0]; }), 'feeds/ipv4.groups[1].name'],
			'a name not a word'                 => [$set('name', 'a-b'), "{$prefix}.name"],
			'an empty name'                     => [$set('name', ''), "{$prefix}.name"],
			'an IP name over 24 characters'     => [$set('name', str_repeat('A', 25)), "{$prefix}.name"],
			'a missing field'                   => [$v4(static function (array &$g): void { unset($g['updateFrequency']); }), "{$prefix}.updateFrequency"],
			'an unknown field'                  => [$set('bogus', 1), "{$prefix}.bogus"],
			'a DNSBL action on an IP group'     => [$set('action', 'unbound'), "{$prefix}.action"],
			'an update frequency not a token'   => [$set('updateFrequency', 'Daily'), "{$prefix}.updateFrequency"],
			'a bindAddress not a string'        => [$set('bindAddress', 5), "{$prefix}.bindAddress"],
			'a script with a slash'             => [$set('preScript', 'a/b.sh'), "{$prefix}.preScript"],
			'a script with a control character' => [$set('postScript', "b\x01.sh"), "{$prefix}.postScript"],
			'a customList not a string'         => [$set('customList', ['x']), "{$prefix}.customList"],
			'a suppressionCidr over 32'         => [$set('suppressionCidr', 33), "{$prefix}.suppressionCidr"],
			'a suppressionCidr as a string'     => [$set('suppressionCidr', '8'), "{$prefix}.suppressionCidr"],
			'a whoisConvert not a bool'         => [$set('whoisConvert', 'on'), "{$prefix}.whoisConvert"],
			'feeds not a list'                  => [$set('feeds', 'x'), "{$prefix}.feeds"],
			'a feed not an object'              => [$feed(static function (mixed &$f): void { $f = 'x'; }), "{$prefix}.feeds[0]"],
			'a feed with an unknown field'      => [$feedSet('bogus', 1), "{$prefix}.feeds[0].bogus"],
			'a feed missing a field'            => [$feed(static function (array &$f): void { unset($f['credentials']); }), "{$prefix}.feeds[0].credentials"],
			'a header not a word'               => [$feedSet('header', 'a-b'), "{$prefix}.feeds[0].header"],
			'a reserved header'                 => [$feedSet('header', 'pfB_Europe'), "{$prefix}.feeds[0].header"],
			'a duplicate header'                => [$v4(static function (array &$g): void { $g['feeds'][1]['header'] = 'A'; }), "{$prefix}.feeds[1].header"],
			'a state not a token'               => [$feedSet('state', 'Enabled'), "{$prefix}.feeds[0].state"],
			'a format not a token'              => [$feedSet('format', 'Auto'), "{$prefix}.feeds[0].format"],
			'a url with <'                      => [$feedSet('url', 'https://example.org/<x>'), "{$prefix}.feeds[0].url"],
			'an enabled feed without a url'     => [$feedSet('url', ''), "{$prefix}.feeds[0].url"],
			'a url with the API key placeholder' => [$feedSet('url', 'https://example.org/_API_KEY_/a.txt'), "{$prefix}.feeds[0].url"],
			'a url holding credentials'         => [$feedSet('url', 'https://u:p@example.org/a.txt'), "{$prefix}.feeds[0].url"],
			'credentials with a quote'          => [$feedSet('credentials', 'u:"p'), "{$prefix}.feeds[0].credentials"],
			'credentials on a source with no scheme' => [$feed(static function (array &$f): void { $f['format'] = 'geoip'; $f['url'] = 'US United States'; $f['credentials'] = 'u:p'; }), "{$prefix}.feeds[0].url"],
			'a suppressionCidr on an IPv6 group' => [$whole(static function (array &$s): void { $s['feeds/ipv6']['groups'][0]['suppressionCidr'] = 0; }), 'feeds/ipv6.groups[0].suppressionCidr'],
			'a whoisConvert on a DNSBL group'   => [$whole(static function (array &$s): void { $s['feeds/dnsbl']['groups'][0]['whoisConvert'] = FALSE; }), 'feeds/dnsbl.groups[0].whoisConvert'],
			'an IP action on a DNSBL group'     => [$whole(static function (array &$s): void { $s['feeds/dnsbl']['groups'][0]['action'] = 'Deny_Inbound'; }), 'feeds/dnsbl.groups[0].action'],
			'a GeoIP format on a DNSBL feed'    => [$whole(static function (array &$s): void { $s['feeds/dnsbl']['groups'][0]['feeds'][0]['format'] = 'geoip'; }), 'feeds/dnsbl.groups[0].feeds[0].format'],
			'a DNSBL feed action not a token'   => [$whole(static function (array &$s): void { $s['feeds/dnsbl']['groups'][0]['feeds'][0]['action'] = 'Permit'; }), 'feeds/dnsbl.groups[0].feeds[0].action'],
		];
	}

	#[DataProvider('malformedWrites')]
	public function testAWriteOutsideAFieldsRuleIsInvalidArgumentNamingItBeforeAnyLockOrWrite(callable $edit, string $field): void
	{
		$this->arrange([self::V4 => [self::v4Group()], self::V6 => [self::v6Group()], self::DNSBL => [self::dnsblGroup()]]);
		$read = $this->read();
		$this->assertNull(pfb_core_settings_request_refusal(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $read['settings']], static fn(): array => self::INTERFACES),
			'positive control: the unchanged write is valid');
		$before = $GLOBALS['config'];
		$GLOBALS['pfb_test_lock_events'] = [];

		$reply = $this->write($edit($read['settings']), $read['revision']);

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertContains($field, array_column($reply['error']['fieldErrors'] ?? [], 'field'), 'the faulty field is named: ' . json_encode($reply));
		$this->assertNothingWritten($before, 'a malformed write');
		$this->assertSame([], $GLOBALS['pfb_test_lock_events'], 'no lock was asked for');
	}

	// ----- edges of the adapter (issue #3946) -----

	/** @return list<string> every rebuild marker in the sandbox's list folders, as `<folder>/<file>` */
	private function markers(): array
	{
		$found = [];
		foreach (array_keys(self::LIST_FOLDERS) as $folder) {
			foreach (glob("{$this->dir}/{$folder}/*.update") ?: [] as $path) {
				$found[] = "{$folder}/" . basename($path);
			}
		}
		sort($found);
		return $found;
	}

	/** @return array<string, array{0: string}> a custom list as stored, in raw bytes */
	public static function customListBytes(): array
	{
		return [
			'a bad byte in the middle' => ["a\xff\nb"],
			'a bad byte at the end'    => ["ab\xff"],
			'an overlong encoding'     => ["x\xC0\x80y"],
			'a truncated sequence'     => ["x\xE2\x82"],
			'an empty list'            => [''],
			'valid UTF-8'              => ["h\u{e9}llo\n"],
		];
	}

	#[DataProvider('customListBytes')]
	public function testACustomListThatIsNotUtf8ReadsAsUtf8AndAnUnrelatedWriteLeavesItsStoredBytes(string $raw): void
	{
		// Given a group with a stored custom list, and another group
		$spam = array_replace(self::v4Group(), ['custom' => base64_encode($raw)]);
		$other = ['aliasname' => 'Other', 'action' => 'Disabled', 'cron' => 'Never'];
		$this->arrange([self::V4 => [$spam, $other]]);
		$list = $this->read()['settings']['feeds/ipv4']['groups'][0]['customList'];
		$this->assertTrue(mb_check_encoding($list, 'UTF-8'), 'the read holds valid UTF-8');
		$this->assertSame(mb_scrub($raw, 'UTF-8'), $list, 'a valid list reads as it is stored');

		// When Core writes back what it read through JSON, with one unrelated change
		$read = json_decode(pfb_core_settings_serve('{"version":1,"op":"read"}'), TRUE);
		$settings = $read['settings'];
		$settings['feeds/ipv4']['groups'][1]['updateFrequency'] = 'Weekly';
		$before = $GLOBALS['config'];
		$reply = json_decode(pfb_core_settings_serve((string) json_encode(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings])), TRUE);

		// Then the stored list is byte-identical and the one change is the only one
		$this->assertArrayNotHasKey('error', $reply, (string) json_encode($reply));
		$this->assertSame(base64_encode($raw), config_get_path(self::V4 . '/0/custom'));
		$this->assertSame([self::V4 . '/1/cron'], self::changedLeaves($before, $GLOBALS['config']));
	}

	/** @return array<string, array{0: string, 1: string}> a feed projection and the config.xml section of its groups */
	public static function feedSections(): array
	{
		return ['IPv4' => ['feeds/ipv4', self::V4], 'IPv6' => ['feeds/ipv6', self::V6], 'DNSBL' => ['feeds/dnsbl', self::DNSBL]];
	}

	#[DataProvider('feedSections')]
	public function testAGroupWhoseSourceInterfaceDoesNotResolveIsLeftOutOfTheRead(string $projection, string $path): void
	{
		$groups = [];
		foreach (['Plain' => '', 'Local' => 'lo0', 'Bound' => 'em1', 'Missing' => 'em9', 'NoAddress' => 'em2', 'Second' => 'em0'] as $name => $srcint) {
			$groups[] = ['aliasname' => $name, 'action' => 'Disabled', 'cron' => 'Never', 'srcint' => $srcint];
		}
		$this->arrange([$path => $groups]);

		$read = $this->read();

		$this->assertSame(['Plain' => '', 'Local' => '127.0.0.1', 'Bound' => '10.0.0.1', 'Second' => '192.0.2.1'],
			array_column($read['settings'][$projection]['groups'], 'bindAddress', 'name'), 'neither a missing interface nor one with no IPv4 reads as the default route');
	}

	/** @return list<array<string, mixed>> a group that projects, and one whose Source Interface does not resolve, with a row of its own */
	private static function unresolvedGroups(): array
	{
		return [self::v4Group(), ['aliasname' => 'Unbound', 'description' => 'mine', 'action' => 'Deny_Inbound', 'cron' => 'Weekly', 'srcint' => 'em9', 'custom' => 'eA==',
			'row' => [['format' => 'auto', 'state' => 'Enabled', 'url' => 'https://example.org/u.txt', 'header' => 'HiddenFeed']]]];
	}

	public function testAWriteLeavesAGroupWhoseSourceInterfaceDoesNotResolveWhereItIs(): void
	{
		$groups = self::unresolvedGroups();
		$this->arrange([self::V4 => $groups]);
		$read = $this->read();
		$this->assertSame(['Spam'], array_column($read['settings']['feeds/ipv4']['groups'], 'name'), 'before-state: the group is not in the read');
		$settings = $read['settings'];
		$settings['feeds/ipv4']['groups'][0]['updateFrequency'] = 'Weekly';
		$before = $GLOBALS['config'];

		$reply = $this->write($settings, $read['revision']);

		$this->assertWritten($reply);
		$this->assertSame($groups[1], config_get_path(self::V4 . '/1'));
		$this->assertSame([self::V4 . '/0/cron'], self::changedLeaves($before, $GLOBALS['config']));
	}

	public function testANewGroupCannotTakeTheNameOfAGroupThatDoesNotProject(): void
	{
		$this->arrange([self::V4 => self::unresolvedGroups()]);
		$read = $this->read();
		$settings = $read['settings'];
		$new = ['name' => 'Unbound', 'action' => 'Deny_Both', 'updateFrequency' => 'Never', 'bindAddress' => '', 'preScript' => '', 'postScript' => '',
			'customList' => '', 'suppressionCidr' => 0, 'whoisConvert' => FALSE, 'feeds' => []];
		$at = count($settings['feeds/ipv4']['groups']);
		$settings['feeds/ipv4']['groups'][] = $new;
		$before = $GLOBALS['config'];

		$reply = $this->write($settings, $read['revision']);

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, json_encode($reply));
		$message = array_column($reply['error']['fieldErrors'] ?? [], 'message', 'field')["feeds/ipv4.groups[{$at}].name"] ?? '';
		$this->assertStringContainsString('does not project', $message, 'the name is refused because a stored group holds it');
		$this->assertNothingWritten($before, 'a name a stored group holds');
		$settings['feeds/ipv4']['groups'][$at]['name'] = 'Fresh';
		$this->assertNull(pfb_core_settings_request_refusal(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings], static fn(): array => self::INTERFACES),
			'positive control: the same group under a name no stored group holds is valid');
	}

	/** @return list<array<string, mixed>> Spam (rows A, Inert that does not project, B), Other (row O) and Hidden: a group that does not project, with a row */
	private static function headerGroups(): array
	{
		$row = static fn(string $header): array => ['format' => 'auto', 'state' => 'Enabled', 'url' => "https://example.org/{$header}.txt", 'header' => $header];
		return [self::v4Group(), ['aliasname' => 'Other', 'action' => 'Deny_Both', 'cron' => 'Never', 'row' => [$row('O')]],
			['aliasname' => 'Hidden', 'action' => 'Deny_Both', 'cron' => 'Never', 'srcint' => 'em9', 'row' => [$row('HiddenFeed')]]];
	}

	/** @return array<string, array{0: int, 1: string, 2: bool}> the group a new feed goes to, its header, and whether the write is refused */
	public static function newFeedHeaders(): array
	{
		return [
			'the header of a row that does not project, in its group'     => [0, 'Inert', TRUE],
			'the header of a row that does not project, in another group' => [1, 'Inert', TRUE],
			'the header of a row of a group that does not project'        => [0, 'HiddenFeed', TRUE],
			'a header no stored row holds'                                => [1, 'Fresh', FALSE],
		];
	}

	#[DataProvider('newFeedHeaders')]
	public function testANewFeedCannotRepeatTheHeaderOfAStoredRowThatDoesNotProject(int $group, string $header, bool $refused): void
	{
		$this->arrange([self::V4 => self::headerGroups()]);
		$read = $this->read();
		$settings = $read['settings'];
		$at = count($settings['feeds/ipv4']['groups'][$group]['feeds']);
		$settings['feeds/ipv4']['groups'][$group]['feeds'][] = ['header' => $header, 'state' => 'enabled', 'format' => 'auto', 'url' => 'https://example.org/new.txt', 'credentials' => ''];
		$before = $GLOBALS['config'];

		$reply = $this->write($settings, $read['revision']);

		if (!$refused) {
			$this->assertWritten($reply);
			$this->assertSame($settings, $this->read()['settings']);
			return;
		}
		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, json_encode($reply));
		$message = array_column($reply['error']['fieldErrors'] ?? [], 'message', 'field')["feeds/ipv4.groups[{$group}].feeds[{$at}].header"] ?? '';
		$this->assertStringContainsString('does not project', $message, 'the header is refused because a stored row holds it');
		$this->assertNothingWritten($before, 'a header a stored row holds');
	}

	/** @return array<string, array{0: string, 1: string}> a script name as stored, and what the read gives (a path reads as its file name) */
	public static function storedScriptNames(): array
	{
		return [
			'a dot'                      => ['.', ''],
			'two dots'                   => ['..', ''],
			'a path ending in two dots'  => ['/tmp/..', ''],
			'a leading dash'             => ['-x', ''],
			'two dashes'                 => ['--', ''],
			'a control character'        => ["x\x01", ''],
			'none'                       => ['', ''],
			'a path reads as its name'   => ['dir/b.sh', 'b.sh'],
			'a plain name'               => ['ok.sh', 'ok.sh'],
			'a dash inside'              => ['a-b', 'a-b'],
			'a leading space'            => [' leading space', ' leading space'],
			'a hidden file name'         => ['.hook', '.hook'],
		];
	}

	#[DataProvider('storedScriptNames')]
	public function testAScriptNameThatIsNotAPlainFileNameReadsAsNone(string $stored, string $read): void
	{
		$this->arrange([self::V4 => [array_replace(self::v4Group(), ['script_pre' => $stored, 'script_post' => $stored])]]);

		$group = $this->read()['settings']['feeds/ipv4']['groups'][0];

		$this->assertSame([$read, $read], [$group['preScript'], $group['postScript']]);
	}

	/** @return array<string, array{0: string, 1: bool}> a script name Core writes, and whether the adapter accepts it */
	public static function writtenScriptNames(): array
	{
		return [
			'a dot'               => ['.', FALSE],
			'two dots'            => ['..', FALSE],
			'a leading dash'      => ['-x', FALSE],
			'two dashes'          => ['--', FALSE],
			'a slash'             => ['a/b', FALSE],
			'a control character' => ["x\x01", FALSE],
			'none'                => ['', TRUE],
			'a plain name'        => ['ok.sh', TRUE],
			'a dash inside'       => ['a-b', TRUE],
			'a leading space'     => [' leading space', TRUE],
			'a hidden file name'  => ['.hook', TRUE],
		];
	}

	#[DataProvider('writtenScriptNames')]
	public function testAScriptNameThatIsNotAPlainFileNameIsRefusedOnAWrite(string $name, bool $accepted): void
	{
		$this->arrange([self::V4 => [self::v4Group()]]);
		$read = $this->read();
		foreach (['preScript', 'postScript'] as $field) {
			$settings = $read['settings'];
			$settings['feeds/ipv4']['groups'][0][$field] = $name;

			$refusal = pfb_core_settings_request_refusal(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings], static fn(): array => self::INTERFACES);

			if ($accepted) {
				$this->assertNull($refusal, "{$field} " . json_encode($name) . ' is accepted');
			} else {
				$this->assertSame('invalid_argument', $refusal['error']['code'] ?? NULL, "{$field} " . json_encode($name));
				$this->assertContains("feeds/ipv4.groups[0].{$field}", array_column($refusal['error']['fieldErrors'] ?? [], 'field'));
			}
		}
	}

	/** @return array<string, array{0: string, 1: string, 2: array<string, mixed>, 3: string}> a projection, its section, a stored group and the marker a changed list flags */
	public static function customListFlags(): array
	{
		return [
			'an IPv4 Deny group'                         => ['feeds/ipv4', self::V4, self::v4Group(), 'deny/Spam_custom_v4.update'],
			'an IPv4 Permit group'                       => ['feeds/ipv4', self::V4, array_replace(self::v4Group(), ['action' => 'Permit_Outbound']), 'permit/Spam_custom_v4.update'],
			'an IPv4 group that inverts its destination' => ['feeds/ipv4', self::V4, array_replace(self::v4Group(), ['autoaddrnot_out' => 'on']), 'native/Spam_custom_v4.update'],
			'an IPv6 Deny group'                         => ['feeds/ipv6', self::V6, array_replace(self::v6Group(), ['action' => 'Deny_Both']), 'deny/Six_custom_v6.update'],
			'a DNSBL group'                              => ['feeds/dnsbl', self::DNSBL, self::dnsblGroup(), 'dnsbl/Ads_custom.update'],
		];
	}

	/** @param array<string, mixed> $group */
	#[DataProvider('customListFlags')]
	public function testAChangedCustomListIsFlaggedForARebuildLikeTheGroupsEditorFlagsIt(string $projection, string $path, array $group, string $marker): void
	{
		$this->arrange([$path => [$group]]);
		$read = $this->read();
		$settings = $read['settings'];
		$settings[$projection]['groups'][0]['customList'] = "192.0.2.0/24\n";
		$this->assertSame([], $this->markers(), 'before-state: nothing is flagged');

		$reply = $this->write($settings, $read['revision']);

		$this->assertWritten($reply);
		$this->assertSame([$marker], $this->markers());
		$this->assertSame([], $this->warnings, 'flagging the list raised no PHP warning');
	}

	public function testAWriteThatLeavesEveryCustomListAloneFlagsNothing(): void
	{
		$spam = array_replace(self::v4Group(), ['custom' => base64_encode("a\n")]);
		$this->arrange([self::V4 => [$spam]]);
		$read = $this->read();
		$settings = $read['settings'];
		$settings['feeds/ipv4']['groups'][0]['updateFrequency'] = 'Weekly';

		$reply = $this->write($settings, $read['revision']);

		$this->assertWritten($reply);
		$this->assertSame([], $this->markers());
		$this->assertSame([], $this->warnings);
	}

	public function testOnlyAGroupWhoseCustomListChangedIsFlagged(): void
	{
		$spam = array_replace(self::v4Group(), ['custom' => base64_encode("a\n")]);
		$other = ['aliasname' => 'Other', 'action' => 'Deny_Both', 'cron' => 'Never', 'custom' => base64_encode("b\n")];
		$this->arrange([self::V4 => [$spam, $other]]);
		$read = $this->read();
		$settings = $read['settings'];
		$settings['feeds/ipv4']['groups'][0]['updateFrequency'] = 'Weekly';
		$settings['feeds/ipv4']['groups'][1]['customList'] = "c\n";

		$reply = $this->write($settings, $read['revision']);

		$this->assertWritten($reply);
		$this->assertSame(['deny/Other_custom_v4.update'], $this->markers());
		$this->assertSame([], $this->warnings);
	}

	public function testANewGroupWithACustomListIsFlaggedAndOneWithoutIsNot(): void
	{
		$this->arrange([self::V4 => [self::v4Group()]]);
		$read = $this->read();
		$settings = $read['settings'];
		$new = ['action' => 'Deny_Both', 'updateFrequency' => 'Never', 'bindAddress' => '', 'preScript' => '', 'postScript' => '', 'suppressionCidr' => 0,
			'whoisConvert' => FALSE, 'feeds' => []];
		$settings['feeds/ipv4']['groups'][] = ['name' => 'Listed', 'customList' => "x\n"] + $new;
		$settings['feeds/ipv4']['groups'][] = ['name' => 'Empty', 'customList' => ''] + $new;

		$reply = $this->write($settings, $read['revision']);

		$this->assertWritten($reply);
		$this->assertSame(['deny/Listed_custom_v4.update'], $this->markers());
		$this->assertSame([], $this->warnings, 'a group Core created lacks the keys the editor stores, and flagging it raised no PHP warning');
	}

	/** @return array<string, array{0: string, 1: string, 2: list<string>}> the stored action, the action Core writes with a changed list, and the markers */
	public static function actionsWithAChangedList(): array
	{
		return [
			'a group that stays Disabled'                => ['Disabled', 'Disabled', []],
			'a Disabled group that becomes a Deny group' => ['Disabled', 'Deny_Both', ['deny/Spam_custom_v4.update']],
			'a Deny group that becomes Disabled'         => ['Deny_Inbound', 'Disabled', []],
		];
	}

	/** @param list<string> $markers */
	#[DataProvider('actionsWithAChangedList')]
	public function testTheFlagFollowsTheActionTheGroupIsStoredWithAfterTheWriteAndAGroupWithNoListFolderIsNotFlagged(string $was, string $now, array $markers): void
	{
		$this->arrange([self::V4 => [array_replace(self::v4Group(), ['action' => $was])]]);
		$read = $this->read();
		$settings = $read['settings'];
		$settings['feeds/ipv4']['groups'][0]['action'] = $now;
		$settings['feeds/ipv4']['groups'][0]['customList'] = "x\n";
		$this->assertFileDoesNotExist('/Spam_custom_v4.update', 'before-state: nothing at the root of the filesystem');

		try {
			$reply = $this->write($settings, $read['revision']);

			$this->assertWritten($reply);
			$this->assertSame($markers, $this->markers());
			$this->assertSame([], $this->warnings, 'a group with no list folder raised no touch() warning (an unprivileged user cannot create a file at the root)');
			$this->assertFileDoesNotExist('/Spam_custom_v4.update', 'a group with no list folder is not flagged at the root of the filesystem');
		} finally {
			@unlink('/Spam_custom_v4.update');
		}
	}

	public function testAConflictFlagsNothing(): void
	{
		$this->arrange([self::V4 => [self::v4Group()]]);
		$read = $this->read();
		$this->disk['installedpackages']['pfblockernglistsv4']['config'][0]['row'][2]['url'] = 'https://example.org/moved.txt';
		$GLOBALS['config'] = $this->disk;
		$settings = $read['settings'];
		$settings['feeds/ipv4']['groups'][0]['customList'] = "x\n";

		$reply = $this->write($settings, $read['revision']);

		$this->assertSame('conflict', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertSame([], $this->markers());
	}

	#[DataProvider('refusedWrites')]
	public function testAWriteThatPfSenseRefusesFlagsNothing(mixed $answer): void
	{
		$this->arrange([self::V4 => [self::v4Group()]]);
		$this->configXmlOnDisk($answer);
		$read = $this->read();
		$settings = $read['settings'];
		$settings['feeds/ipv4']['groups'][0]['customList'] = "x\n";

		$reply = $this->write($settings, $read['revision']);

		$this->assertSame('unavailable', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertSame([], $this->markers());
	}

	/** @return callable(): array<string, string> a lookup that counts its calls in $calls and answers $maps in turn (the last one thereafter) */
	private static function lookup(int &$calls, array ...$maps): callable
	{
		return static function () use (&$calls, $maps): array {
			return $maps[min($calls++, count($maps) - 1)];
		};
	}

	public function testTheInterfaceLookupRunsOnceForARead(): void
	{
		$bound = static fn(string $name, string $srcint): array => ['aliasname' => $name, 'action' => 'Disabled', 'cron' => 'Never', 'srcint' => $srcint];
		$this->arrange([self::V4 => [$bound('A', 'em0'), $bound('B', 'em1')], self::V6 => [$bound('C', 'em1')], self::DNSBL => [$bound('D', 'em0')]]);
		$calls = 0;

		$reply = pfb_core_settings_backend(['version' => 1, 'op' => 'read'], "{$this->dir}/node_exporter", self::lookup($calls, self::INTERFACES));

		$this->assertSame(['192.0.2.1', '10.0.0.1'], array_column($reply['settings']['feeds/ipv4']['groups'] ?? [], 'bindAddress'), 'the read answers');
		$this->assertSame(1, $calls, 'the interface lookup runs once per request');
	}

	public function testTheInterfaceLookupRunsOnceForAWrite(): void
	{
		$bound = static fn(string $name, string $srcint): array => ['aliasname' => $name, 'action' => 'Disabled', 'cron' => 'Never', 'srcint' => $srcint];
		$this->arrange([self::V4 => [$bound('A', 'em0'), $bound('B', 'em1')], self::DNSBL => [$bound('D', 'em0')]]);
		$read = $this->read();
		$settings = $read['settings'];
		$settings['feeds/ipv4']['groups'][1]['bindAddress'] = '192.0.2.1';
		$calls = 0;

		$reply = pfb_core_settings_backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings], "{$this->dir}/node_exporter",
			self::lookup($calls, self::INTERFACES));

		$this->assertArrayNotHasKey('error', $reply, json_encode($reply));
		$this->assertSame('em0', config_get_path(self::V4 . '/1/srcint'), 'the write is stored');
		$this->assertSame(1, $calls, 'the interface lookup runs once per request');
	}

	public function testAnAddressThatPassedValidationIsStoredAsItsInterfaceEvenIfTheLookupAnswersDifferentlyLater(): void
	{
		// Given a group on the default route, and a lookup under which em1 holds its address once and no address afterwards
		$this->arrange([self::V4 => [self::v4Group()]]);
		$read = $this->read();
		$settings = $read['settings'];
		$settings['feeds/ipv4']['groups'][0]['bindAddress'] = '10.0.0.1';
		$calls = 0;
		$this->assertSame('', config_get_path(self::V4 . '/0/srcint'), 'before-state: the default route');

		// When Core writes that address
		$reply = pfb_core_settings_backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings], "{$this->dir}/node_exporter",
			self::lookup($calls, self::INTERFACES, ['em0' => '192.0.2.1', 'em1' => '']));

		// Then the address the request was validated against is the one stored, as its interface
		$this->assertArrayNotHasKey('error', $reply, json_encode($reply));
		$this->assertSame('em1', config_get_path(self::V4 . '/0/srcint'));
		$this->assertSame('10.0.0.1', $this->read()['settings']['feeds/ipv4']['groups'][0]['bindAddress']);
	}

	/** @return array<string, mixed> a stored row that projects: auto format, enabled, a source of its own */
	private static function sourceRow(string $header): array
	{
		return ['format' => 'auto', 'state' => 'Enabled', 'url' => "https://example.org/{$header}.txt", 'header' => $header];
	}

	/** @return list<array<string, mixed>> the name Dup twice, the first on an interface that is gone (it does not project), and another group */
	private static function duplicateNameGroups(): array
	{
		$first = ['aliasname' => 'Dup', 'description' => 'first', 'action' => 'Deny_Inbound', 'cron' => 'Never', 'srcint' => 'em9', 'row' => [self::sourceRow('One')]];
		$second = ['aliasname' => 'Dup', 'description' => 'second', 'action' => 'Deny_Both', 'cron' => 'Weekly', 'srcint' => '', 'row' => [self::sourceRow('Two')]];
		return [$first, $second, ['aliasname' => 'Other', 'action' => 'Deny_Both', 'cron' => 'Never']];
	}

	public function testAGroupNameAHiddenGroupHoldsStaysHiddenInEveryLaterGroupOfThatName(): void
	{
		// Given the name Dup twice, the first copy hidden
		$groups = self::duplicateNameGroups();
		$this->arrange([self::V4 => $groups]);

		// Then the read has neither copy, in the feeds and in the schedule alike
		$read = $this->read();
		$this->assertSame(['Other'], array_column($read['settings']['feeds/ipv4']['groups'], 'name'), 'the later Dup does not take the place of the hidden one');
		$this->assertSame(['ipv4/Other'], array_column($read['settings']['schedule']['groups'], 'id'));

		// When Core writes an unrelated change, then neither copy is touched
		$settings = $read['settings'];
		$settings['feeds/ipv4']['groups'][0]['updateFrequency'] = 'Weekly';
		$before = $GLOBALS['config'];
		$this->assertWritten($this->write($settings, $read['revision']));
		$this->assertSame([self::V4 . '/2/cron'], self::changedLeaves($before, $GLOBALS['config']));
		$this->assertSame([$groups[0], $groups[1]], array_slice(config_get_path(self::V4), 0, 2));
	}

	public function testCoreCannotWriteTheScheduleOfANameAHiddenGroupHolds(): void
	{
		// Given the name Dup twice, the first copy hidden, and a schedule write that overrides the slot of ipv4/Dup
		$groups = self::duplicateNameGroups();
		$this->arrange([self::V4 => $groups]);
		$read = $this->read();
		$other = array_values(array_filter($read['settings']['schedule']['groups'], static fn(array $g): bool => $g['id'] === 'ipv4/Other'));
		$this->assertCount(1, $other, 'before-state: the group that projects has its slot');
		$settings = $read['settings'];
		$settings['schedule']['groups'] = [['id' => 'ipv4/Dup', 'override' => TRUE, 'weekday' => 7, 'hour' => 5, 'minute' => 0], $other[0]];
		$before = $GLOBALS['config'];

		// When Core writes it
		$reply = $this->write($settings, $read['revision']);

		// Then it is refused: no group of that name projects, and neither copy takes the override
		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertContains('schedule.groups[0].id', array_column($reply['error']['fieldErrors'] ?? [], 'field'), json_encode($reply));
		$this->assertNothingWritten($before, 'a schedule slot of a group that does not project');
		$this->assertSame([$groups[0], $groups[1]], array_slice(config_get_path(self::V4), 0, 2));
	}

	public function testAHeaderAHiddenGroupHoldsStaysHiddenInEveryLaterGroup(): void
	{
		// Given a group on an interface that is gone with the rows F and E, and a later group with the rows F and K
		$hidden = ['aliasname' => 'Hidden', 'action' => 'Deny_Both', 'cron' => 'Never', 'srcint' => 'em9', 'row' => [self::sourceRow('F'), self::sourceRow('E')]];
		$shown = ['aliasname' => 'Shown', 'action' => 'Deny_Both', 'cron' => 'Never', 'row' => [self::sourceRow('F'), self::sourceRow('K')]];
		$this->arrange([self::V4 => [$hidden, $shown]]);

		// Then the read gives the later group the one feed whose header no earlier group's row holds
		$read = $this->read();
		$this->assertSame([['K']], array_map(static fn(array $g): array => array_column($g['feeds'], 'header'), $read['settings']['feeds/ipv4']['groups']),
			'a header an earlier group holds is that group\'s, hidden or not');

		// When Core writes back what it read, nothing is written
		$before = $GLOBALS['config'];
		$reply = $this->write($read['settings'], $read['revision']);
		$this->assertSame(['version' => 1, 'revision' => $read['revision']], $reply);
		$this->assertNothingWritten($before, 'an unchanged write');

		// When Core drops K, no row of F or E goes with it
		$settings = $read['settings'];
		$settings['feeds/ipv4']['groups'][0]['feeds'] = [];
		$this->assertWritten($this->write($settings, $read['revision']));
		$this->assertSame(['F', 'E'], array_column(config_get_path(self::V4 . '/0/row'), 'header'));
		$this->assertSame(['F'], array_column(config_get_path(self::V4 . '/1/row'), 'header'), 'only K was dropped');
	}

	public function testAGroupThatProjectedAtCoresReadButLostItsInterfaceSinceIsRefusedAndNothingChanges(): void
	{
		// Given Core read a group bound to em0
		$bound = ['aliasname' => 'Bound', 'action' => 'Deny_Both', 'cron' => 'Never', 'srcint' => 'em0', 'custom' => '', 'row' => [self::sourceRow('F')]];
		$this->arrange([self::V4 => [$bound]]);
		$read = $this->read();
		$this->assertSame('192.0.2.1', $read['settings']['feeds/ipv4']['groups'][0]['bindAddress'], 'before-state: the group projected');
		$settings = $read['settings'];
		$settings['feeds/ipv4']['groups'][0]['updateFrequency'] = 'Weekly';
		$settings['feeds/ipv4']['groups'][0]['customList'] = "x\n";
		$before = $GLOBALS['config'];

		// When em0 is gone by the time Core writes
		$reply = pfb_core_settings_backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings],
			"{$this->dir}/node_exporter", static fn(): array => ['em1' => '10.0.0.1']);

		// Then the write is refused for the group's name and its address, and nothing is written or flagged
		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, json_encode($reply));
		$fields = array_column($reply['error']['fieldErrors'] ?? [], 'field');
		$this->assertContains('feeds/ipv4.groups[0].name', $fields, json_encode($reply));
		$this->assertContains('feeds/ipv4.groups[0].bindAddress', $fields, json_encode($reply));
		$this->assertNothingWritten($before, 'a group whose interface is gone');
		$this->assertSame([], $this->markers());
	}

	public function testAHiddenGroupThatClaimsTheHeaderAfterCoreValidatedItIsRefusedUnderTheLock(): void
	{
		// Given Core read, then another writer stored a group on a gone interface whose row holds H (no projection changes)
		$this->arrange([self::V4 => [array_replace(self::v4Group(), ['row' => [self::sourceRow('A')]])]]);
		$read = $this->read();
		$settings = $read['settings'];
		$settings['feeds/ipv4']['groups'][0]['feeds'][] = ['header' => 'H', 'state' => 'enabled', 'format' => 'auto', 'url' => 'https://example.org/h.txt', 'credentials' => ''];
		$this->assertNull(pfb_core_settings_request_refusal(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings], static fn(): array => self::INTERFACES),
			'before-state: the request is valid against the config Core read');
		$this->disk['installedpackages']['pfblockernglistsv4']['config'][] = ['aliasname' => 'Late', 'action' => 'Deny_Both', 'cron' => 'Never', 'srcint' => 'em9', 'row' => [self::sourceRow('H')]];
		$before = $this->disk;

		// When Core writes
		$reply = $this->write($settings, $read['revision']);

		// Then the fresh config is checked too: refused, nothing written
		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertContains('feeds/ipv4.groups[0].feeds[1].header', array_column($reply['error']['fieldErrors'] ?? [], 'field'), json_encode($reply));
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
		$this->assertSame($before, $this->disk, 'config.xml is as the other writer left it');
		$this->assertEmpty($GLOBALS['pfb_test_lock_held'] ?? FALSE, 'the lock is released');
	}

	/** @return list<array<string, mixed>> A with the projected row H, B with a row H that does not project (it repeats A's header) */
	private static function movedHeaderGroups(): array
	{
		return [['aliasname' => 'A', 'action' => 'Deny_Both', 'cron' => 'Never', 'row' => [self::sourceRow('H')]],
			['aliasname' => 'B', 'action' => 'Deny_Both', 'cron' => 'Never', 'row' => [self::sourceRow('X'), self::sourceRow('H')]]];
	}

	public function testAHeaderCannotMoveIntoAGroupThatStoresAnUnprojectedRowOfIt(): void
	{
		$this->arrange([self::V4 => self::movedHeaderGroups()]);
		$read = $this->read();
		$settings = $read['settings'];
		$row = $settings['feeds/ipv4']['groups'][0]['feeds'][0];
		$settings['feeds/ipv4']['groups'][0]['feeds'] = [];
		$settings['feeds/ipv4']['groups'][1]['feeds'][] = $row;
		$before = $GLOBALS['config'];

		$reply = $this->write($settings, $read['revision']);

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertContains('feeds/ipv4.groups[1].feeds[1].header', array_column($reply['error']['fieldErrors'] ?? [], 'field'), json_encode($reply));
		$this->assertNothingWritten($before, 'a header moved next to an unprojected row of it');
	}

	public function testAHeaderTheGroupAlreadyProjectsMayBeEditedEvenIfItRepeatsAnUnprojectedRow(): void
	{
		$groups = self::movedHeaderGroups();
		$groups[0]['row'] = [self::sourceRow('Y')];
		$groups[1]['row'] = [self::sourceRow('H'), self::sourceRow('H')];
		$this->arrange([self::V4 => $groups]);
		$read = $this->read();
		$settings = $read['settings'];
		$this->assertSame(['H'], array_column($settings['feeds/ipv4']['groups'][1]['feeds'], 'header'), 'before-state: B projects H');
		$settings['feeds/ipv4']['groups'][1]['feeds'][0]['url'] = 'https://example.org/moved.txt';

		$reply = $this->write($settings, $read['revision']);

		$this->assertWritten($reply);
		$this->assertSame('https://example.org/moved.txt', config_get_path(self::V4 . '/1/row/0/url'));
	}
}
