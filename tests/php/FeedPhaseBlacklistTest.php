<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

#[CoversNothing]
final class FeedPhaseBlacklistTest extends TestCase
{

	private string $dir = '';

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_feed_phase_blacklist_' . getmypid() . '_' . bin2hex(random_bytes(4));
		mkdir($this->dir, 0700, TRUE);
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->dir);
	}
	public function testScheduleProviderProjectsItsReadOnlyTitle(): void
	{
		$providers = pfb_core_schedule_providers([
			'blacklist_selected' => 'work',
			'item' => [[
				'xml' => 'work', 'title' => 'Work', 'feed' => 'https://example.test/work', 'selected' => 'adult,phishing',
			]],
		]);

		$this->assertSame([[
			'id' => 'work', 'title' => 'Work', 'selected' => TRUE, 'categories' => 'adult,phishing',
		]], array_values($providers));
	}

	public function testFeedPhaseRequestAcceptsTheBlacklistCategoryId(): void
	{
		$savedPfb = $GLOBALS['pfb'];
		$GLOBALS['pfb']['reuse'] = '';
		$GLOBALS['pfb']['reuse_dnsbl'] = '';
		$id = 'blacklist:work-provider:adult-category';
		$params = [];
		$calledMethod = '';
		try {
			$result = pfb_core_feed_phase(str_repeat('f', 64), 'dnsbl', [$id], 'none',
				static function (string $method, array $request, ?string $socket, int $timeout) use (&$params, &$calledMethod, $id): array {
					$calledMethod = $method;
					$params = $request;
					return ['status' => 200, 'body' => ['results' => [self::feedPhaseResult($id)]], 'error' => NULL];
				});
		} finally {
			$GLOBALS['pfb'] = $savedPfb;
		}

		$this->assertSame('FeedPhase', $calledMethod);
		$this->assertSame('dnsbl', $params['phase'] ?? NULL);
		$this->assertSame([$id], $params['feeds'] ?? NULL);
		$this->assertSame($id, $result[0]['id'] ?? NULL);
	}

	public function testUpdateRequestAcceptsBlacklistCategoryIds(): void
	{
		$id = 'blacklist:work-provider:adult-category';
		$request = pfb_core_update_request(json_encode([
			'version' => 1, 'trigger' => 'scheduled', 'scope' => 'dnsbl', 'force' => 'none',
			'feeds' => [$id], 'extras' => [], 'token' => str_repeat('a', 64),
		], JSON_THROW_ON_ERROR));

		$this->assertSame([$id], $request['feeds']);
	}

	public function testDnsblPhaseKeepsBlacklistIdsInMixedListOrder(): void
	{
		$lists = [
			[
				'aliasname' => 'Work',
				'row' => [[
					'feed_phase_id' => 'blacklist:work-provider:adult-category',
					'url' => 'file:///feed', 'state' => 'Enabled', 'header' => 'Work_adult_category',
				]],
			],
			[
				'aliasname' => 'Regular',
				'row' => [
					['url' => 'https://example.test/feed', 'state' => 'Enabled', 'header' => 'regular_feed'],
					['url' => 'https://example.test/disabled', 'state' => 'Disabled', 'header' => 'disabled_feed'],
				],
			],
			[
				'aliasname' => 'custom_group',
				'row' => [[
					'url' => 'custom', 'state' => 'Enabled', 'header' => 'custom_group_custom', 'custom' => TRUE,
				]],
			],
		];

		$this->assertSame([
			'blacklist:work-provider:adult-category',
			'dnsbl:regular_feed',
			'custom:dnsbl:custom_group',
		], pfb_dnsbl_feed_phase_ids($lists, static fn (array $list, array $row, string $header, string $id): bool => TRUE));
	}

	public function testIpReusePredicateSplitsFeedPhaseRequestsInLoopOrder(): void
	{
		$feeds = [
			[
				'list' => ['aliasname' => 'reuse', 'vtype' => '_v4'],
				'row' => ['header' => 'reuse', 'url' => 'file:///reuse', 'state' => 'Enabled'],
				'header' => 'reuse_v4', 'reuse' => TRUE, 'orig' => TRUE,
			],
			[
				'list' => ['aliasname' => 'fresh', 'vtype' => '_v4'],
				'row' => ['header' => 'fresh', 'url' => 'https://example.test/fresh', 'state' => 'Enabled'],
				'header' => 'fresh_v4', 'reuse' => FALSE, 'orig' => FALSE,
			],
			[
				'list' => ['aliasname' => 'DNSBLIP', 'vtype' => '_v4', 'dnsblip' => ''],
				'row' => ['header' => 'DNSBLIP', 'url' => 'file:///DNSBLIP_v4.txt', 'state' => 'Enabled'],
				'header' => 'DNSBLIP_v4', 'reuse' => TRUE, 'orig' => TRUE,
			],
		];
		$ids = $parseIds = [];
		foreach ($feeds as $feed) {
			$id = pfb_ip_feed_phase_id($feed['list'], $feed['row'], $feed['header']);
			$this->assertIsString($id);
			$ids[] = $id;
			if (pfb_ip_reuse_skip_active($feed['reuse'], $feed['orig'], isset($feed['list']['dnsblip']))) {
				$parseIds[] = $id;
			}
		}
		$groups = pfb_core_feed_phase_request_groups($ids, $parseIds, 'none');
		$originalPfb = $GLOBALS['pfb'];
		$GLOBALS['pfb']['reuse'] = '';
		$calls = [];
		try {
			$results = pfb_core_feed_phase_groups('ip', str_repeat('e', 64), $groups,
				static function (string $method, array $params, ?string $socket, int $timeout) use (&$calls): array {
					$calls[] = [
						'method' => $method, 'phase' => $params['phase'],
						'feeds' => $params['feeds'], 'force' => $params['force'],
					];
					return [
						'status' => 200,
						'body' => ['results' => array_map(
							static fn (string $id): array => self::feedPhaseResult($id),
							$params['feeds']
						)],
						'error' => NULL,
					];
				});
		} finally {
			$GLOBALS['pfb'] = $originalPfb;
		}

		$this->assertSame([
			['method' => 'FeedPhase', 'phase' => 'ip', 'feeds' => ['ipv4:reuse_v4'], 'force' => 'parse'],
			[
				'method' => 'FeedPhase', 'phase' => 'ip',
				'feeds' => ['ipv4:fresh_v4', 'synthetic:ipv4:DNSBLIP_v4'], 'force' => 'none',
			],
		], $calls);
		$this->assertSame($ids, array_keys($results));
	}


	public function testBlacklistCategoryResultCopiesDnsblArtifactsAndRemovesEmptyFamily(): void
	{
		$orig = $this->dir . '/original';
		$folder = $this->dir . '/dnsbl';
		mkdir($orig, 0700, TRUE);
		mkdir($folder, 0700, TRUE);
		$header = 'Work_adult_category';
		file_put_contents("{$orig}/{$header}.parsed.ndjson", "ads.example.com\n");
		file_put_contents("{$orig}/{$header}.parsed.v4.ip", "198.51.100.1\n");
		file_put_contents("{$orig}/{$header}.parsed.v6.ip", '');
		file_put_contents("{$folder}/{$header}_v6.ip", "2001:db8::1\n");
		$result = self::feedPhaseResult('blacklist:work-provider:adult-category');
		$result['disposition'] = 'changed';

		$this->assertTrue(pfb_dnsbl_feed_phase_copy_artifacts($result, $orig, $folder, $header));
		$this->assertSame("ads.example.com\n", file_get_contents("{$folder}/{$header}.bk"));
		$this->assertSame("198.51.100.1\n", file_get_contents("{$folder}/{$header}_v4.ip"));
		$this->assertFileDoesNotExist("{$folder}/{$header}_v6.ip");
	}


	public function testUnchangedFeedCanRebuildMissingDnsblOutputFromCoreArtifacts(): void
	{
		$orig = $this->dir . '/rebuild-original';
		$folder = $this->dir . '/rebuild-dnsbl';
		mkdir($orig, 0700, TRUE);
		mkdir($folder, 0700, TRUE);
		$header = 'missing_dnsbl';
		file_put_contents("{$orig}/{$header}.parsed.ndjson", "ads.example.com\n");
		file_put_contents("{$orig}/{$header}.parsed.v4.ip", '');
		file_put_contents("{$orig}/{$header}.parsed.v6.ip", '');

		$this->assertTrue(pfb_dnsbl_feed_phase_copy_artifacts(
			self::feedPhaseResult("dnsbl:{$header}"), $orig, $folder, $header
		));
		$this->assertSame("ads.example.com\n", file_get_contents("{$folder}/{$header}.bk"));
	}

	public function testCoreServicePassesTheBlacklistDirectoryFlag(): void
	{
		$source = file_get_contents('src/usr/local/pkg/pfblockerng/pfblockerng.inc');
		$this->assertIsString($source);
		$this->assertTrue(str_contains($source, '--feed-blacklist-dir'));
	}
	public function testCoreUpdateRequestRejectsMalformedBlacklistCategoryIds(): void
	{
		$this->expectException(InvalidArgumentException::class);
		pfb_core_update_request(json_encode([
			'version' => 1, 'trigger' => 'scheduled', 'scope' => 'dnsbl', 'force' => 'none',
			'feeds' => ['blacklist:work,provider:adult'], 'extras' => [], 'token' => str_repeat('a', 64),
		], JSON_THROW_ON_ERROR));
	}

	public function testCategoryDotsDoNotWidenRegularOrCustomIds(): void
	{
		foreach (['blacklist:ut2:.', 'blacklist:ut2:..', 'blacklist:ut2:a/b', 'blacklist:ut2:a\\b', 'dnsbl:a.b', 'custom:dnsbl:a.b'] as $id) {
			try {
				pfb_core_update_request(json_encode([
					'version' => 1, 'trigger' => 'scheduled', 'token' => str_repeat('a', 64), 'feeds' => [$id],
				], JSON_THROW_ON_ERROR));
				$this->fail("accepted unsafe ID {$id}");
			} catch (InvalidArgumentException) {
				$this->assertTrue(TRUE);
			}
		}
		$this->assertFalse(pfb_sanitise_feed_header('regular.dot'));
	}

	private static function feedPhaseResult(string $id): array
	{
		return [
			'id' => $id, 'disposition' => 'unchanged', 'stage' => 'normalize', 'reason' => 'normalized_unchanged',
			'entries' => 0, 'parseFailures' => 0, 'suppressed' => FALSE, 'mappedDrops' => 0, 'dnsblRows' => 0,
			'ipv4Count' => 0, 'ipv6Count' => 0, 'updateIP' => FALSE, 'schemeSkipped' => 0, 'hpHostsStop' => FALSE,

			'placeholder' => '', 'preScriptFailed' => FALSE, 'sourceChanged' => FALSE, 'normalizedChanged' => FALSE,
		];
	}
}
