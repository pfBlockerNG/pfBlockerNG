<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/SyncPolicyFixtureTrait.php';

/**
 * Issue #3451 — pfb_sync_policy_merge(): the pure receive-side merge of an incoming policy
 * snapshot into the receiver's current sections (docs/specs/xmlrpc-per-field-sync.md,
 * "Receive merge"). Policy content follows the sender; local content never changes.
 *
 * Every expectation is written out as a literal tree (assertSame is key-order and type
 * sensitive). Receiver locals carry the visible sentinel LOCAL-SENTINEL-*, sender-injected
 * locals carry EVIL*, so a leak in either direction shows in the failure diff.
 *
 * Hostile-input refusals live in SyncPolicyMergeRefusalTest.
 */
#[CoversFunction('pfb_sync_policy_merge')]
final class SyncPolicyMergeTest extends TestCase
{
	use SyncPolicyFixtureTrait;

	private const NEW1 = ' lead/trail space ';
	private const NEW2 = '007';
	private const NEW3 = 'MiXeD';

	/** @return array<string,mixed> */
	private function merge(array $incoming, array $current): array
	{
		return $this->assertNoDiagnostics(static fn (): array => pfb_sync_policy_merge($incoming, $current));
	}

	// ---- section catalogue -------------------------------------------------------------

	/** @return 'S'|'G'|'M'|'F'|'B' */
	private static function kind(string $section): string
	{
		return match (TRUE) {
			in_array($section, ['pfblockerng', 'pfblockerngipsettings', 'pfblockerngdnsblsettings'], TRUE) => 'S',
			in_array($section, ['pfblockernglistsv4', 'pfblockernglistsv6', 'pfblockerngdnsbl'], TRUE) => 'G',
			$section === 'pfblockerngblacklist' => 'B',
			in_array($section, ['pfblockerngglobal', 'pfblockerngsafesearch'], TRUE) => 'F',
			default => 'M',
		};
	}

	/**
	 * keys: 7 policy keys (1-3 replaced, 4 absent from incoming, 5 sent as [], 6 sent as '',
	 * 7 new on the receiver). head/tail: receiver-local keys before/after the policy keys.
	 * fixed: policy keys identical on both sides (the G identity key).
	 *
	 * @return array{keys: list<string>, head: list<string>, tail: list<string>, fixed: array<string,string>}
	 */
	private static function spec(string $section): array
	{
		$generic = ['action', 'cron', 'logging', 'dow', 'description', 'format', 'detail'];
		$none    = ['head' => [], 'tail' => [], 'fixed' => []];

		return match ($section) {
			'pfblockerng' => [
				'keys' => ['pfb_keep', 'pfb_scheduled_feed_updates', 'pfb_schedule_weekday', 'pfb_schedule_hour',
					'pfb_schedule_minute', 'skipfeed', 'pfb_agg_types'],
				'head' => ['log_syslog'], 'tail' => ['zz_unknown'], 'fixed' => [],
			],
			'pfblockerngipsettings' => [
				'keys' => ['v4suppression', 'v6suppression', 'suppression', 'enable_dup', 'enable_agg', 'enable_log',
					'database_cc'],
				'head' => ['maxmind_key'], 'tail' => ['zz_unknown'], 'fixed' => [],
			],
			'pfblockerngdnsblsettings' => [
				'keys' => ['pfb_dnsbl', 'pfb_dnsbl_nonat', 'top1m_enable', 'top1m_source', 'top1m_count', 'global_log',
					'pfb_hsts'],
				'head' => ['top1m_token'], 'tail' => ['zz_unknown', 'dnsbl_webpage'], 'fixed' => [],
			],
			'pfblockernglistsv4', 'pfblockernglistsv6', 'pfblockerngdnsbl' => [
				'keys' => $generic,
				'head' => ['srcint'], 'tail' => ['script_pre', 'script_post', 'agateway_in', 'agateway_out'],
				'fixed' => ['aliasname' => 'GRP'],
			],
			'pfblockerngglobal' => [
				'keys' => ['feed_Foo', 'feed_alt_Foo', 'feed_Bar', 'feed_alt_Bar', 'feed_Baz', 'feed_alt_Baz', 'feed_Qux'],
				'head' => ['alertrefresh'], 'tail' => ['widget-pfblockerng'], 'fixed' => [],
			],
			'pfblockerngsafesearch' => [
				'keys' => ['safesearch_enable', 'safesearch_youtube', 'safesearch_doh', 'safesearch_doh_list',
					'safesearch_bing', 'safesearch_google', 'safesearch_yandex'],
			] + $none,
			'pfblockerngblacklist' => [
				'keys' => ['blacklist_enable', 'blacklist_freq', 'blacklist_lang', 'blacklist_logging',
					'blacklist_selected', 'blacklist_tld', 'blacklist_misc'],
			] + $none,
			default => ['keys' => $generic, 'head' => ['agateway_in'], 'tail' => ['agateway_out'], 'fixed' => []],
		};
	}

	/** @param list<string> $keys @return array<string,string> */
	private static function locals(string $section, array $keys): array
	{
		$out = [];
		foreach ($keys as $key) {
			$out[$key] = "LOCAL-SENTINEL-{$section}-{$key}";
		}
		return $out;
	}

	/** @param list<string> $keys @return array<string,string> */
	private static function hostile(array $keys): array
	{
		$out = [];
		foreach ($keys as $key) {
			$out[$key] = match ($key) {
				'srcint'      => 'wan; rm -rf /',
				'agateway_in' => 'EVIL_GW',
				default       => "EVIL-{$key}",
			};
		}
		return $out;
	}

	/** @return array<string,mixed> incoming map of one section's policy keys */
	private static function incMap(string $section): array
	{
		$sp = self::spec($section);
		[$k1, $k2, $k3, , $k5, $k6, $k7] = $sp['keys'];
		return $sp['fixed'] + [
			$k6 => '', $k1 => self::NEW1, $k2 => self::NEW2, $k3 => self::NEW3, $k5 => [], $k7 => "NEW-{$k7}",
		];
	}

	/** @return array<string,mixed> */
	private static function curMap(string $section): array
	{
		$sp  = self::spec($section);
		$map = self::locals($section, $sp['head']) + $sp['fixed'];
		foreach (array_slice($sp['keys'], 0, 6) as $key) {
			$map[$key] = "OLD-{$key}";
		}
		return $map + self::locals($section, $sp['tail']);
	}

	/** @return array<string,mixed> */
	private static function expMap(string $section): array
	{
		$sp = self::spec($section);
		[$k1, $k2, $k3, , $k5, $k6, $k7] = $sp['keys'];
		return self::locals($section, $sp['head']) + $sp['fixed']
			+ [$k1 => self::NEW1, $k2 => self::NEW2, $k3 => self::NEW3, $k5 => '', $k6 => '']
			+ self::locals($section, $sp['tail'])
			+ [$k7 => "NEW-{$k7}"];
	}

	/** @return array<string,mixed> */
	private static function place(string $section, array $map, bool $hooks = FALSE): array
	{
		$tree = in_array(self::kind($section), ['S', 'G', 'M'], TRUE) ? ['config' => [0 => $map]] : $map;
		if ($hooks && $section === 'pfblockerng') {
			$tree['hooks'] = ['row' => [0 => ['script' => 'HOOK-SENTINEL']]];
		}
		return $tree;
	}

	/** @return array<string,mixed> the policy map inside a merged section */
	private static function mapOf(string $section, array $out): array
	{
		return in_array(self::kind($section), ['S', 'G', 'M'], TRUE) ? $out[$section]['config'][0] : $out[$section];
	}

	/** Receiver content left after the sender sent nothing for $section. */
	private static function localsOnly(string $section): array
	{
		if (self::kind($section) === 'G') {
			return [];
		}
		$sp = self::spec($section);
		return self::place($section, self::locals($section, array_merge($sp['head'], $sp['tail'])), TRUE);
	}

	// ---- providers ---------------------------------------------------------------------

	/** @return array<string,array{string}> */
	public static function allSections(): array
	{
		$out = [];
		foreach (pfblockerng_sync_sections(TRUE) as $section) {
			$out[$section] = [$section];
		}
		return $out;
	}

	/** @return array<string,array{string}> */
	public static function sectionsWithLocals(): array
	{
		return array_filter(self::allSections(), static fn (array $row): bool => self::spec($row[0])['head'] !== []);
	}

	/** @return array<string,array{string}> */
	public static function groupSections(): array
	{
		return array_filter(self::allSections(), static fn (array $row): bool => self::kind($row[0]) === 'G');
	}

	/** @return array<string,array{string}> */
	public static function mapSections(): array
	{
		return array_filter(self::allSections(), static fn (array $row): bool => self::kind($row[0]) === 'M');
	}

	// ---- guards --------------------------------------------------------------------------

	public function testCatalogueMatchesTheRegistryAndTheNineteenSections(): void
	{
		$this->assertCount(19, pfblockerng_sync_sections(TRUE));
		$registry = pfb_cfg_registry();
		$alias    = ['pfblockerng' => 'gen', 'pfblockerngipsettings' => 'ip', 'pfblockerngdnsblsettings' => 'dnsbl'];
		foreach ($alias as $section => $prefix) {
			$sp = self::spec($section);
			foreach ($sp['keys'] as $key) {
				$this->assertSame('policy', $registry["{$prefix}/{$key}"]['sync'] ?? NULL, "{$prefix}/{$key} must be registry policy");
			}
		}
		foreach (['gen/log_syslog', 'ip/maxmind_key', 'dnsbl/top1m_token'] as $key) {
			$this->assertSame('local', $registry[$key]['sync'] ?? NULL, "{$key} must be registry local");
		}
	}

	// ---- row 1: per section ---------------------------------------------------------------

	#[DataProvider('allSections')]
	public function testPolicyFollowsSenderAndLocalsStayInPlace(string $section): void
	{
		$out = $this->merge(
			[$section => self::place($section, self::incMap($section))],
			[$section => self::place($section, self::curMap($section), TRUE)]
		);
		$this->assertSame([$section => self::place($section, self::expMap($section), TRUE)], $out);
	}

	#[DataProvider('allSections')]
	public function testChangedValuesAreByteExactAbsentKeyDeletedEmptyFormsNormalised(string $section): void
	{
		$out = self::mapOf($section, $this->merge(
			[$section => self::place($section, self::incMap($section))],
			[$section => self::place($section, self::curMap($section), TRUE)]
		));
		[$k1, $k2, $k3, $k4, $k5, $k6, $k7] = self::spec($section)['keys'];
		$this->assertSame(' lead/trail space ', $out[$k1]);
		$this->assertSame('007', $out[$k2]);
		$this->assertSame('MiXeD', $out[$k3]);
		$this->assertArrayNotHasKey($k4, $out, 'a policy key absent from incoming is deleted');
		$this->assertArrayHasKey($k5, $out, '[] is present, not deleted');
		$this->assertSame('', $out[$k5], 'the [] wire sentinel becomes an empty string');
		$this->assertSame('', $out[$k6], 'an explicit empty string is kept');
		$this->assertSame("NEW-{$k7}", $out[$k7]);
	}

	#[DataProvider('allSections')]
	public function testMissingIncomingSectionDropsPolicyKeepsLocals(string $section): void
	{
		$out = $this->merge([], [$section => self::place($section, self::curMap($section), TRUE)]);
		$this->assertSame([$section => self::localsOnly($section)], $out);
	}

	#[DataProvider('allSections')]
	public function testEmptyIncomingSectionDropsPolicyKeepsLocals(string $section): void
	{
		$out = $this->merge([$section => []], [$section => self::place($section, self::curMap($section), TRUE)]);
		$this->assertSame([$section => self::localsOnly($section)], $out);
	}

	public function testSettingsSectionsKeepUnknownHookAndForeignKeysExactly(): void
	{
		$cur = [
			'pfblockerng' => ['config' => [0 => ['pfb_keep' => 'old', 'zz_unknown' => 'U1', 'log_syslog' => 'L1']],
				'hooks' => ['row' => [0 => ['script' => 'HOOK-SENTINEL']]]],
			'pfblockerngdnsblsettings' => ['config' => [0 => ['pfb_dnsbl' => 'old', 'dnsbl_webpage' => 'dnsbl_custom.php',
				'top1m_token' => 'SECRET-top1m']]],
		];
		$out = $this->merge([], $cur);
		$this->assertSame([
			'pfblockerng' => ['config' => [0 => ['zz_unknown' => 'U1', 'log_syslog' => 'L1']],
				'hooks' => ['row' => [0 => ['script' => 'HOOK-SENTINEL']]]],
			'pfblockerngdnsblsettings' => ['config' => [0 => ['dnsbl_webpage' => 'dnsbl_custom.php',
				'top1m_token' => 'SECRET-top1m']]],
		], $out);
	}

	// ---- row 2: injected locals ignored -----------------------------------------------------

	#[DataProvider('sectionsWithLocals')]
	public function testInjectedLocalsAreIgnoredAndNeverCreated(string $section): void
	{
		$sp   = self::spec($section);
		[$k1, $k2] = $sp['keys'];
		$cur  = self::place($section, self::locals($section, $sp['head']) + $sp['fixed'] + [$k1 => 'OLD1', $k2 => 'OLD2'], TRUE);
		$inc  = self::place($section, $sp['fixed'] + self::hostile($sp['head']) + [$k1 => self::NEW1]
			+ self::hostile($sp['tail']) + [$k2 => self::NEW2]);
		if ($section === 'pfblockerng') {
			$inc['hooks'] = ['row' => [0 => ['script' => 'EVIL-HOOK']]];
		}
		$exp = self::place($section, self::locals($section, $sp['head']) + $sp['fixed'] + [$k1 => self::NEW1, $k2 => self::NEW2], TRUE);

		$out = $this->merge([$section => $inc], [$section => $cur]);
		$this->assertSame([$section => $exp], $out);
		$this->assertStringNotContainsString('EVIL', serialize($out));
		$this->assertStringNotContainsString('rm -rf', serialize($out));
	}

	// ---- row 3: G sections ------------------------------------------------------------------

	/** @return array<string,mixed> */
	private static function feed(string $alias, int $n, string $v = ''): array
	{
		return ['format' => 'auto', 'state' => 'Enabled', 'url' => "https://feeds.example/{$alias}/{$n}{$v}", 'header' => "Hdr{$alias}{$n}"];
	}

	/** @return array<string,mixed> */
	private static function grow(string $alias, string $v = '', array $locals = [], ?array $rows = NULL): array
	{
		return [
			'aliasname' => $alias,
			'action'    => "Deny_Inbound{$v}",
			'cron'      => "EveryDay{$v}",
			'row'       => $rows ?? [0 => self::feed($alias, 0, $v), 1 => self::feed($alias, 1, $v)],
		] + $locals;
	}

	/** @return array<string,string> */
	private static function glocals(string $alias): array
	{
		return self::locals($alias, ['srcint', 'script_pre', 'script_post', 'agateway_in', 'agateway_out']);
	}

	/** @return array<string,string> the editor's defaults for a row created by sync */
	private static function gdefaults(string $section): array
	{
		return ['srcint' => '', 'script_pre' => '', 'script_post' => '']
			+ ($section === 'pfblockerngdnsbl' ? [] : ['agateway_in' => 'default', 'agateway_out' => 'default']);
	}

	/** @param array<int|string,mixed> $rows @return array<string,mixed> */
	private static function gsec(array $rows): array
	{
		return ['config' => $rows];
	}

	#[DataProvider('groupSections')]
	public function testAddedRowGetsEditorLocalDefaultsNotSenderValues(string $section): void
	{
		$cur = [$section => self::gsec([0 => self::grow('Alpha', '', self::glocals('Alpha'))])];
		$inc = [$section => self::gsec([
			0 => self::grow('Alpha'),
			1 => self::grow('Beta', '', ['srcint' => 'SENDER-srcint-Beta', 'agateway_in' => 'SENDER-gw-Beta']),
		])];

		$out = $this->merge($inc, $cur);
		$this->assertSame([$section => self::gsec([
			0 => self::grow('Alpha', '', self::glocals('Alpha')),
			1 => self::grow('Beta', '', self::gdefaults($section)),
		])], $out);
		$this->assertStringNotContainsString('SENDER-', serialize($out));
	}

	#[DataProvider('groupSections')]
	public function testReorderFollowsIncomingOrderAndKeysEachRowKeepsItsOwnLocals(string $section): void
	{
		$cur = [$section => self::gsec([
			0 => self::grow('Alpha', '', self::glocals('Alpha')),
			1 => self::grow('Beta', '', self::glocals('Beta')),
		])];
		$inc = [$section => self::gsec([7 => self::grow('Beta'), 3 => self::grow('Alpha')])];

		$this->assertSame([$section => self::gsec([
			7 => self::grow('Beta', '', self::glocals('Beta')),
			3 => self::grow('Alpha', '', self::glocals('Alpha')),
		])], $this->merge($inc, $cur));
	}

	#[DataProvider('groupSections')]
	public function testMatchedRowPolicyUpdatedLocalsKept(string $section): void
	{
		$cur = [$section => self::gsec([
			0 => self::grow('Alpha', '', self::glocals('Alpha')),
			1 => self::grow('Beta', '', self::glocals('Beta')),
		])];
		$inc = [$section => self::gsec([0 => self::grow('Alpha', '-v2'), 1 => self::grow('Beta')])];

		$this->assertSame([$section => self::gsec([
			0 => self::grow('Alpha', '-v2', self::glocals('Alpha')),
			1 => self::grow('Beta', '', self::glocals('Beta')),
		])], $this->merge($inc, $cur));
	}

	#[DataProvider('groupSections')]
	public function testRenamedRowIsDeletePlusAddAndDoesNotInheritOldLocals(string $section): void
	{
		$cur = [$section => self::gsec([0 => self::grow('OldName', '', self::glocals('OldName'))])];
		$inc = [$section => self::gsec([0 => self::grow('NewName')])];

		$out = $this->merge($inc, $cur);
		$this->assertSame([$section => self::gsec([0 => self::grow('NewName', '', self::gdefaults($section))])], $out);
		$this->assertStringNotContainsString('LOCAL-SENTINEL-OldName', serialize($out));
	}

	#[DataProvider('groupSections')]
	public function testDeletedRowIsDroppedWithItsLocals(string $section): void
	{
		$cur = [$section => self::gsec([
			0 => self::grow('Alpha', '', self::glocals('Alpha')),
			1 => self::grow('Beta', '', self::glocals('Beta')),
			2 => self::grow('Gamma', '', self::glocals('Gamma')),
		])];
		$inc = [$section => self::gsec([0 => self::grow('Alpha'), 2 => self::grow('Gamma')])];

		$out = $this->merge($inc, $cur);
		$this->assertSame([$section => self::gsec([
			0 => self::grow('Alpha', '', self::glocals('Alpha')),
			2 => self::grow('Gamma', '', self::glocals('Gamma')),
		])], $out);
		$this->assertStringNotContainsString('LOCAL-SENTINEL-Beta', serialize($out));
	}

	#[DataProvider('groupSections')]
	public function testDeleteAllRowsViaMissingEmptySectionAndEmptyConfig(string $section): void
	{
		$cur = [$section => self::gsec([
			0 => self::grow('Alpha', '', self::glocals('Alpha')),
			1 => self::grow('Beta', '', self::glocals('Beta')),
		])];

		$this->assertSame([$section => []], $this->merge([], $cur), 'missing incoming section');
		$this->assertSame([$section => []], $this->merge([$section => []], $cur), 'empty incoming section');
		$this->assertSame([$section => ['config' => []]], $this->merge([$section => ['config' => []]], $cur), 'empty incoming config');
	}

	#[DataProvider('groupSections')]
	public function testEmptyIncomingGroupRowsAreIgnoredAndEmptyReceiverRowsTolerated(string $section): void
	{
		$cur = [$section => self::gsec([0 => self::grow('Alpha', '', self::glocals('Alpha'))])];
		$inc = [$section => self::gsec([0 => '', 1 => [], 2 => self::grow('Alpha')])];
		$exp = [$section => self::gsec([2 => self::grow('Alpha', '', self::glocals('Alpha'))])];

		$this->assertSame($exp, $this->merge($inc, $cur));

		$curWithEmpty = [$section => self::gsec([0 => '', 1 => [], 2 => self::grow('Alpha', '', self::glocals('Alpha'))])];
		$this->assertSame($exp, $this->merge($inc, $curWithEmpty));
	}

	#[DataProvider('groupSections')]
	public function testFeedRowListIsReplacedByTheIncomingList(string $section): void
	{
		$f   = static fn (int $n, string $v = ''): array => self::feed('Alpha', $n, $v);
		$cur = static fn (array $rows): array => [$section => self::gsec([0 => self::grow('Alpha', '', self::glocals('Alpha'), $rows)])];

		// feed removed (the middle one) and updated
		$this->assertSame(
			$cur([0 => $f(0), 2 => $f(2, '-v2')]),
			$this->merge($cur([0 => $f(0), 2 => $f(2, '-v2')]), $cur([0 => $f(0), 1 => $f(1), 2 => $f(2)]))
		);
		// feed added
		$this->assertSame(
			$cur([0 => $f(0), 1 => $f(1), 2 => $f(2), 3 => $f(3)]),
			$this->merge($cur([0 => $f(0), 1 => $f(1), 2 => $f(2), 3 => $f(3)]), $cur([0 => $f(0)]))
		);
		// all feeds removed: the incoming empty list stays an empty list
		$this->assertSame($cur([]), $this->merge($cur([]), $cur([0 => $f(0), 1 => $f(1)])));
	}

	#[DataProvider('groupSections')]
	public function testEmptyFeedHeaderPassesAndEmptyFeedRowsAreCopiedAsEmptyString(string $section): void
	{
		$feed0 = ['format' => 'auto', 'state' => 'Enabled', 'url' => 'https://feeds.example/Beta/0', 'header' => ''];
		$feed1 = ['format' => 'auto', 'state' => 'Enabled', 'url' => 'https://feeds.example/Beta/1', 'header' => []];
		$inc   = [$section => self::gsec([0 => self::grow('Beta', '', [], [0 => $feed0, 1 => $feed1, 2 => '', 3 => []])])];

		$this->assertSame([$section => self::gsec([0 => self::grow('Beta', '', self::gdefaults($section), [
			0 => $feed0,
			1 => ['format' => 'auto', 'state' => 'Enabled', 'url' => 'https://feeds.example/Beta/1', 'header' => ''],
			2 => '',
			3 => '',
		])])], $this->merge($inc, []));
	}

	// ---- row 4: M config/0 maps -------------------------------------------------------------

	#[DataProvider('mapSections')]
	public function testMapLocalGatewaysKeptWhenIncomingConfigLacksThemOrIsMissing(string $section): void
	{
		$cur = [$section => ['config' => [0 => [
			'agateway_in' => 'LOCAL-GW-IN', 'aliasname' => 'Region', 'action' => 'old', 'agateway_out' => 'LOCAL-GW-OUT',
		]]]];
		$gwOnly = [$section => ['config' => [0 => ['agateway_in' => 'LOCAL-GW-IN', 'agateway_out' => 'LOCAL-GW-OUT']]]];

		$this->assertSame(
			[$section => ['config' => [0 => [
				'agateway_in' => 'LOCAL-GW-IN', 'aliasname' => 'Region', 'action' => 'new', 'agateway_out' => 'LOCAL-GW-OUT',
			]]]],
			$this->merge([$section => ['config' => [0 => ['aliasname' => 'Region', 'action' => 'new']]]], $cur),
			'incoming config/0 without gateways'
		);
		$this->assertSame($gwOnly, $this->merge([$section => ['config' => []]], $cur), 'incoming empty config');
		$this->assertSame($gwOnly, $this->merge([$section => []], $cur), 'incoming empty section');
		$this->assertSame($gwOnly, $this->merge([], $cur), 'incoming section missing');
	}

	#[DataProvider('mapSections')]
	public function testMapFeedRowListReplacedAndInjectedGatewaysIgnored(string $section): void
	{
		$f   = static fn (int $n, string $v = ''): array => self::feed('Region', $n, $v);
		$cur = [$section => ['config' => [0 => [
			'agateway_in' => 'LOCAL-GW-IN', 'aliasname' => 'Region', 'row' => [0 => $f(0), 1 => $f(1)],
		]]]];
		$inc = [$section => ['config' => [0 => [
			'aliasname' => 'Region', 'agateway_in' => 'EVIL_GW', 'agateway_out' => 'EVIL_GW_OUT', 'row' => [0 => $f(0, '-v2')],
		]]]];

		$out = $this->merge($inc, $cur);
		$this->assertSame([$section => ['config' => [0 => [
			'agateway_in' => 'LOCAL-GW-IN', 'aliasname' => 'Region', 'row' => [0 => $f(0, '-v2')],
		]]]], $out);
		$this->assertStringNotContainsString('EVIL', serialize($out));
	}

	// ---- row 5: F global --------------------------------------------------------------------

	public function testGlobalFeedKeysArePolicyEverythingElseIsLocalAndNeverCreated(): void
	{
		$cur = ['pfblockerngglobal' => [
			'alertrefresh' => 'LOCAL-SENTINEL-alert', 'feed_Foo' => 'old', 'widget-pfblockerng' => 'LOCAL-SENTINEL-widget',
			'feed_alt_Foo' => 'old-alt', 'pfbextdns' => 'LOCAL-SENTINEL-ext', 'feed_Gone' => 'old-gone',
		]];
		$inc = ['pfblockerngglobal' => [
			'feed_Foo' => 'NEW-Foo', 'alertrefresh' => 'EVIL-alert', 'feed_alt_Foo' => 'NEW-alt-Foo',
			'feed_Add' => 'NEW-Add', 'feed_alt_Add' => 'NEW-alt-Add', 'widget-x' => 'EVIL-widget-x',
			'zz_new' => 'EVIL-new', 'pfbextdns' => 'EVIL-ext',
		]];

		$out = $this->merge($inc, $cur);
		$this->assertSame(['pfblockerngglobal' => [
			'alertrefresh' => 'LOCAL-SENTINEL-alert', 'feed_Foo' => 'NEW-Foo', 'widget-pfblockerng' => 'LOCAL-SENTINEL-widget',
			'feed_alt_Foo' => 'NEW-alt-Foo', 'pfbextdns' => 'LOCAL-SENTINEL-ext',
			'feed_Add' => 'NEW-Add', 'feed_alt_Add' => 'NEW-alt-Add',
		]], $out);
		$this->assertStringNotContainsString('EVIL', serialize($out));
	}

	// ---- row 6: B blacklist -----------------------------------------------------------------

	/** @return array<string,string> */
	private static function bitem(string $xml, string $v = '', array $creds = []): array
	{
		return ['title' => "Title {$xml}{$v}", 'xml' => $xml, 'feed' => "Feed{$v}", 'size' => '1', 'selected' => 'on'] + $creds;
	}

	/** @return array<string,string> */
	private static function secrets(string $tag): array
	{
		return ['username' => "SECRET-user-{$tag}", 'password' => "SECRET-pass-{$tag}"];
	}

	/** @return array<string,mixed> receiver blacklist: two providers holding credentials */
	private static function blCurrent(): array
	{
		return ['pfblockerngblacklist' => [
			'blacklist_enable' => 'on',
			'item' => [
				0 => self::bitem('shallalist.xml', '', self::secrets('shalla')),
				1 => self::bitem('ut1-capitole.xml', '', self::secrets('ut1')),
			],
		]];
	}

	public function testBlacklistFlatKeysAreDenyListPolicy(): void
	{
		$cur = ['pfblockerngblacklist' => ['blacklist_enable' => 'old', 'blacklist_freq' => 'old', 'item' => [0 => self::bitem('shallalist.xml', '', self::secrets('shalla'))]]];
		$inc = ['pfblockerngblacklist' => ['blacklist_freq' => self::NEW1, 'blacklist_lang' => self::NEW2, 'item' => [0 => self::bitem('shallalist.xml')]]];

		$this->assertSame(['pfblockerngblacklist' => [
			'blacklist_freq' => ' lead/trail space ', 'item' => [0 => self::bitem('shallalist.xml', '', self::secrets('shalla'))],
			'blacklist_lang' => '007',
		]], $this->merge($inc, $cur));
	}

	public function testBlacklistReorderKeepsEachProvidersCredentials(): void
	{
		$inc = ['pfblockerngblacklist' => ['blacklist_enable' => 'on', 'item' => [
			5 => self::bitem('ut1-capitole.xml'), 2 => self::bitem('shallalist.xml'),
		]]];

		$this->assertSame(['pfblockerngblacklist' => ['blacklist_enable' => 'on', 'item' => [
			5 => self::bitem('ut1-capitole.xml', '', self::secrets('ut1')),
			2 => self::bitem('shallalist.xml', '', self::secrets('shalla')),
		]]], $this->merge($inc, self::blCurrent()));
	}

	public function testBlacklistUpdateKeepsCredentialsAndIgnoresInjectedOnes(): void
	{
		$inc = ['pfblockerngblacklist' => ['blacklist_enable' => 'on', 'item' => [
			0 => self::bitem('shallalist.xml', '-v2', ['username' => 'EVIL-user', 'password' => 'EVIL-pass']),
			1 => self::bitem('ut1-capitole.xml'),
		]]];

		$out = $this->merge($inc, self::blCurrent());
		$this->assertSame(['pfblockerngblacklist' => ['blacklist_enable' => 'on', 'item' => [
			0 => self::bitem('shallalist.xml', '-v2', self::secrets('shalla')),
			1 => self::bitem('ut1-capitole.xml', '', self::secrets('ut1')),
		]]], $out);
		$this->assertStringNotContainsString('EVIL', serialize($out));
	}

	public function testBlacklistNewProviderGetsEmptyCredentialsNotTheSenders(): void
	{
		$inc = ['pfblockerngblacklist' => ['blacklist_enable' => 'on', 'item' => [
			0 => self::bitem('shallalist.xml'),
			1 => self::bitem('ut1-capitole.xml'),
			2 => self::bitem('a.b-c.xml', '', ['username' => 'SENDER-user', 'password' => 'SENDER-pass']),
		]]];

		$out = $this->merge($inc, self::blCurrent());
		$this->assertSame(['pfblockerngblacklist' => ['blacklist_enable' => 'on', 'item' => [
			0 => self::bitem('shallalist.xml', '', self::secrets('shalla')),
			1 => self::bitem('ut1-capitole.xml', '', self::secrets('ut1')),
			2 => self::bitem('a.b-c.xml', '', ['username' => '', 'password' => '']),
		]]], $out);
		$this->assertStringNotContainsString('SENDER-', serialize($out));
	}

	public function testBlacklistRemovedProviderCredentialsAreGone(): void
	{
		$inc = ['pfblockerngblacklist' => ['blacklist_enable' => 'on', 'item' => [0 => self::bitem('ut1-capitole.xml')]]];

		$out = $this->merge($inc, self::blCurrent());
		$this->assertSame(['pfblockerngblacklist' => ['blacklist_enable' => 'on', 'item' => [
			0 => self::bitem('ut1-capitole.xml', '', self::secrets('ut1')),
		]]], $out);
		$this->assertStringNotContainsString('SECRET-user-shalla', serialize($out));
		$this->assertStringNotContainsString('SECRET-pass-shalla', serialize($out));

		foreach ([[], ['pfblockerngblacklist' => []], ['pfblockerngblacklist' => ['item' => []]]] as $emptyInc) {
			$serialized = serialize($this->merge($emptyInc, self::blCurrent()));
			$this->assertStringNotContainsString('SECRET-', $serialized, 'no provider left on the sender');
		}
	}

	// ---- rows 7-9: whole-input behaviour ----------------------------------------------------

	/** @return array<string,mixed> */
	private static function fullSnapshot(bool $incoming): array
	{
		$out = [];
		foreach (pfblockerng_sync_sections(TRUE) as $section) {
			$out[$section] = self::place(
				$section,
				$incoming ? self::incMap($section) : self::curMap($section),
				!$incoming
			);
			if (self::kind($section) === 'G') {
				$out[$section]['config'][1] = $incoming
					? self::grow('Delta')
					: self::grow('Echo', '', self::glocals('Echo'));
			}
			if ($section === 'pfblockerngblacklist') {
				$out[$section]['item'] = $incoming
					? [0 => self::bitem('shallalist.xml'), 1 => self::bitem('new-list.xml')]
					: [0 => self::bitem('ut1-capitole.xml', '', self::secrets('ut1')), 1 => self::bitem('shallalist.xml', '-old', self::secrets('shalla'))];
			}
		}
		return $out;
	}

	public function testMergeIsIdempotent(): void
	{
		$inc = self::fullSnapshot(TRUE);
		$cur = self::fullSnapshot(FALSE);

		$once  = $this->merge($inc, $cur);
		$twice = $this->merge($inc, $once);
		$this->assertNotSame($cur, $once, 'vacuity guard: the merge changes the receiver');
		$this->assertSame($once, $twice);
		$this->assertSame(pfblockerng_sync_sections(TRUE), array_keys($once));
	}

	#[DataProvider('allSections')]
	public function testReceiverAlreadyEqualToIncomingIsReturnedUnchangedWithoutReordering(string $section): void
	{
		$once = $this->merge(
			[$section => self::place($section, self::incMap($section))],
			[$section => self::place($section, self::curMap($section), TRUE)]
		);
		$reversedInc = [$section => self::place($section, array_reverse(self::incMap($section), TRUE))];

		$this->assertSame($once, $this->merge($reversedInc, $once));
	}

	public function testOutputHoldsOnlyTheNineteenSectionsInSyncOrder(): void
	{
		$inc = [
			'status'                   => 'ok',
			'pfblockerngsafesearch'    => ['safesearch_enable' => 'on'],
			'pfblockerngsync'          => ['config' => [0 => ['syncscope' => 'EVIL-scope']]],
			'pfblockerngbogus'         => ['config' => [0 => ['x' => 'EVIL-bogus']]],
			'removed_aliases'          => ['Alpha'],
		];
		$cur = [
			'pfblockerngglobal' => ['alertrefresh' => 'LOCAL-SENTINEL-alert'],
			'pfblockerngsync'   => ['config' => [0 => ['syncscope' => 'LOCAL-SENTINEL-scope']]],
			'pfblockerngbogus'  => ['config' => [0 => ['x' => 'LOCAL-SENTINEL-bogus']]],
		];

		$this->assertSame([
			'pfblockerngglobal'     => ['alertrefresh' => 'LOCAL-SENTINEL-alert'],
			'pfblockerngsafesearch' => ['safesearch_enable' => 'on'],
		], $this->merge($inc, $cur));
	}

	public function testSectionOnNeitherSideIsAbsentAndEmptyReceiverSectionCountsAsPresent(): void
	{
		$this->assertSame([], $this->merge([], []));

		$out = $this->merge([], ['pfblockerngglobal' => [], 'pfblockerngsafesearch' => '']);
		$this->assertSame(['pfblockerngglobal', 'pfblockerngsafesearch'], array_keys($out));

		$this->assertSame(
			['pfblockerngglobal' => ['feed_Foo' => 'on']],
			$this->merge(['pfblockerngglobal' => ['feed_Foo' => 'on']], ['pfblockerngglobal' => ''])
		);
	}

	public function testInputsAreNotModified(): void
	{
		$inc  = self::fullSnapshot(TRUE);
		$cur  = self::fullSnapshot(FALSE);
		$inc0 = unserialize(serialize($inc));
		$cur0 = unserialize(serialize($cur));

		$this->merge($inc, $cur);
		$this->assertSame($inc0, $inc);
		$this->assertSame($cur0, $cur);
	}
}
