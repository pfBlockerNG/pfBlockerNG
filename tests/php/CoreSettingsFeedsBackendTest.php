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

	private array $priorConfig;
	private array $priorPfb;
	private string $dir;

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
		$this->assertSame(['dns', 'feeds/ipv4', 'feeds/ipv6', 'feeds/dnsbl'], array_keys($reply['settings'] ?? []), 'the read answers: ' . json_encode($reply));
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
		foreach (['Plain' => '', 'Local' => 'lo0', 'Bound' => 'em1', 'NoAddress' => 'em2'] as $name => $srcint) {
			$groups[] = ['aliasname' => $name, 'action' => 'Disabled', 'cron' => 'Never', 'srcint' => $srcint];
		}
		$this->arrange([self::V4 => $groups]);

		$read = $this->read();

		$this->assertSame(['Plain' => '', 'Local' => '127.0.0.1', 'Bound' => '10.0.0.1', 'NoAddress' => ''],
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
}
