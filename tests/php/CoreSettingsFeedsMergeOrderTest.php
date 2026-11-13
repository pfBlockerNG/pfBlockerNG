<?php

declare(strict_types=1);

require_once __DIR__ . '/ConfigXmlDiskTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3937 (CodeRabbit on PR #3942): what a feed-projection write from Core leaves in config.xml beyond the changed keys.
 *   - Order matters (IP de-duplication priority): the groups and feeds Core lists take the projected slots in Core's order, and
 *     a group or row that does not project keeps its own slot.
 *   - Deleting a name or header deletes every stored occurrence of it, so a duplicate the read left out never takes its place.
 *   - Headers are unique across the groups of a type: each names one file in the type's directory.
 *   - A feed Core adds to a group whose first row has no source is refused: the apply path ignores every row of such a group, so
 *     it would never be downloaded; the rows already there are left as they are.
 */
#[CoversFunction('pfb_core_settings_backend')]
final class CoreSettingsFeedsMergeOrderTest extends TestCase
{
	use ConfigXmlDiskTrait;

	private const V4 = 'installedpackages/pfblockernglistsv4/config';

	private array $priorConfig;
	private array $priorPfb;
	private string $dir;

	protected function setUp(): void
	{
		$this->priorConfig = $GLOBALS['config'] ?? [];
		$this->priorPfb = $GLOBALS['pfb'];
		$this->dir = sys_get_temp_dir() . '/pfb_core_feeds_merge_' . bin2hex(random_bytes(8));
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

	private static function row(string $header, string $url = ''): array
	{
		return ['format' => 'auto', 'state' => 'Enabled', 'url' => $url ?: "https://example.org/{$header}.txt", 'header' => $header];
	}

	private static function group(string $name, array $rows = []): array
	{
		return ['aliasname' => $name, 'action' => 'Deny_Inbound', 'cron' => 'Never', 'description' => "kept {$name}", 'row' => $rows];
	}

	private function backend(array $request): array
	{
		return pfb_core_settings_backend($request, "{$this->dir}/node_exporter", static fn(): array => []);
	}

	/** Core's write of the read's settings with the IPv4 groups replaced by what $change makes of them. */
	private function writeV4(array $groups, callable $change): array
	{
		config_set_path(self::V4, $groups);
		$this->configXmlOnDisk();
		$read = $this->backend(['version' => 1, 'op' => 'read']);
		$settings = $read['settings'];
		$settings['feeds/ipv4']['groups'] = $change($settings['feeds/ipv4']['groups']);
		$reply = $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings]);
		$this->assertArrayNotHasKey('error', $reply, json_encode($reply));
		return config_get_path(self::V4, []);
	}

	public function testGroupsTakeCoresOrderAndAGroupThatDoesNotProjectKeepsItsSlot(): void
	{
		$stored = $this->writeV4([self::group('A'), self::group('bad name'), self::group('B')], static fn(array $g): array => [$g[1], $g[0]]);

		$this->assertSame(['B', 'bad name', 'A'], array_column($stored, 'aliasname'));
		$this->assertSame('kept A', $stored[2]['description'], 'a moved group keeps what Core does not see');
	}

	public function testFeedsTakeCoresOrderAndARowThatDoesNotProjectKeepsItsSlot(): void
	{
		$rows = [self::row('X'), self::row('DNSBLIP'), self::row('Y')];
		$stored = $this->writeV4([self::group('A', $rows)], static function (array $g): array {
			$g[0]['feeds'] = array_reverse($g[0]['feeds']);
			return $g;
		});

		$this->assertSame(['Y', 'DNSBLIP', 'X'], array_column($stored[0]['row'], 'header'));
	}

	public function testDeletingAGroupDeletesTheDuplicateTheReadLeftOut(): void
	{
		$stored = $this->writeV4([self::group('A'), self::group('Keep'), self::group('A')], static fn(array $g): array => [$g[1]]);

		$this->assertSame(['Keep'], array_column($stored, 'aliasname'), 'no group A is left to become the projected A');
	}

	public function testDeletingAFeedDeletesTheDuplicateTheReadLeftOut(): void
	{
		$rows = [self::row('F', 'https://example.org/one.txt'), self::row('G'), self::row('F', 'https://example.org/two.txt')];
		$stored = $this->writeV4([self::group('A', $rows)], static function (array $g): array {
			$g[0]['feeds'] = [$g[0]['feeds'][1]];
			return $g;
		});

		$this->assertSame(['G'], array_column($stored[0]['row'], 'header'), 'no feed F is left to become the projected F');
	}

	public function testAFeedCoreAddsToAGroupWhoseFirstRowHasNoSourceIsRefusedAndNothingIsWritten(): void
	{
		$placeholder = ['format' => 'Auto', 'state' => 'Disabled', 'url' => '', 'header' => ''];
		config_set_path(self::V4, [self::group('A', [$placeholder, self::row('Old')])]);
		$this->configXmlOnDisk();
		$before = $GLOBALS['config'];
		$read = $this->backend(['version' => 1, 'op' => 'read']);
		$settings = $read['settings'];
		$settings['feeds/ipv4']['groups'][0]['feeds'][] = ['header' => 'New', 'state' => 'enabled', 'format' => 'auto', 'url' => 'https://example.org/new.txt', 'credentials' => ''];

		$reply = $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings]);

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, json_encode($reply));
		$this->assertSame('feeds/ipv4.groups[0].feeds', $reply['error']['fieldErrors'][0]['field'] ?? NULL, json_encode($reply));
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls'], 'nothing is written');
		$this->assertSame($before, $GLOBALS['config']);
	}

	public function testAHeaderRepeatedInAnotherGroupOfTheTypeIsRefused(): void
	{
		config_set_path(self::V4, []);
		$this->configXmlOnDisk();
		$read = $this->backend(['version' => 1, 'op' => 'read']);
		$settings = $read['settings'];
		$feed = ['header' => 'F', 'state' => 'enabled', 'format' => 'auto', 'url' => 'https://example.org/f.txt', 'credentials' => ''];
		$group = ['name' => 'A', 'action' => 'Deny_Inbound', 'updateFrequency' => 'Never', 'bindAddress' => '', 'preScript' => '', 'postScript' => '',
			'customList' => '', 'suppressionCidr' => 0, 'whoisConvert' => FALSE, 'feeds' => [$feed]];
		$settings['feeds/ipv4']['groups'] = [$group, ['name' => 'B'] + $group];

		$reply = $this->backend(['version' => 1, 'op' => 'write', 'expectedRevision' => $read['revision'], 'settings' => $settings]);

		$this->assertSame('invalid_argument', $reply['error']['code'] ?? NULL, 'one file per header in the type\'s directory: ' . json_encode($reply));
		$this->assertSame('feeds/ipv4.groups[1].feeds[0].header', $reply['error']['fieldErrors'][0]['field'] ?? NULL, json_encode($reply));
	}

	public function testTheReadLeavesOutAHeaderAnEarlierGroupOfTheTypeHas(): void
	{
		config_set_path(self::V4, [self::group('A', [self::row('F')]), self::group('B', [self::row('F'), self::row('G')])]);
		$this->configXmlOnDisk();

		$groups = $this->backend(['version' => 1, 'op' => 'read'])['settings']['feeds/ipv4']['groups'];

		$this->assertSame([['F'], ['G']], [array_column($groups[0]['feeds'], 'header'), array_column($groups[1]['feeds'], 'header')]);
	}

	public function testDeletingAHeaderDeletesItsDuplicateInAnotherGroup(): void
	{
		$stored = $this->writeV4([self::group('A', [self::row('F')]), self::group('B', [self::row('F'), self::row('G')])], static function (array $g): array {
			$g[0]['feeds'] = [];
			return $g;
		});

		$this->assertSame([[], ['G']], [array_column($stored[0]['row'] ?? [], 'header'), array_column($stored[1]['row'], 'header')],
			'no feed F is left to become the projected F');
	}

	public function testDeletingAHeaderAlsoDeletesItsDuplicateInAGroupWhoseInterfaceDoesNotResolve(): void
	{
		$hidden = self::group('Hidden', [self::row('F'), self::row('G')]) + ['srcint' => 'missing'];
		$stored = $this->writeV4([self::group('A', [self::row('F')]), $hidden], static function (array $g): array {
			$thisNames = array_column($g, 'name');
			self::assertSame(['A'], $thisNames, 'the unresolved group does not project');
			$g[0]['feeds'] = [];
			return $g;
		});

		$hidden['row'] = [$hidden['row'][1]];
		$this->assertSame($hidden, $stored[1], 'only the type-wide dropped header goes; its other rows and fields stay');
	}
}
