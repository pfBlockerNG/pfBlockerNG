<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_core_feed_phase')]
final class FeedPhaseClientTest extends TestCase
{
	private const RESULT_KEYS = [
		'id', 'disposition', 'stage', 'reason', 'entries', 'parseFailures', 'suppressed', 'mappedDrops', 'dnsblRows',
		'ipv4Count', 'ipv6Count', 'updateIP', 'schemeSkipped', 'hpHostsStop', 'placeholder', 'preScriptFailed',
		'sourceChanged', 'normalizedChanged',
	];

	public function testPostsOrderedFeedPhaseRequestAndReturnsValidatedCoreResults(): void
	{
		$ids = ['dnsbl:zeta', 'dnsbl:alpha'];
		$rows = [self::feedPhaseResult($ids[0], ['disposition' => 'changed']), self::feedPhaseResult($ids[1], ['disposition' => 'unchanged'])];
		$calls = [];
		$result = pfb_core_feed_phase(str_repeat('a', 64), 'dnsbl', $ids, 'none',
			static function (string $method, array $params, ?string $socket, int $timeout) use (&$calls, $rows): array {
				$calls[] = [$method, $params, $socket, $timeout];
				return ['status' => 200, 'body' => ['results' => $rows], 'error' => NULL];
			});

		$this->assertCount(1, $calls);
		[$method, $params, $socket, $timeout] = $calls[0];
		$this->assertSame('FeedPhase', $method);
		$this->assertSame(str_repeat('a', 64), $params['token']);
		$this->assertSame('dnsbl', $params['phase']);
		$this->assertSame($ids, $params['feeds']);
		$this->assertSame('none', $params['force']);
		$this->assertMatchesRegularExpression('/\A[a-f0-9]{32}\z/', $params['requestId']);
		$this->assertNull($socket);
		$this->assertGreaterThan(0, $timeout);
		$this->assertSame($rows, $result);
	}

	#[DataProvider('phaseForceCases')]
	public function testPhaseForceUsesReuseForOnlyItsFeedFamily(
		string $phase,
		string $force,
		string $reuse,
		string $reuseDnsbl,
		string $expected
	): void {
		$savedPfb = $GLOBALS['pfb'];
		$GLOBALS['pfb']['reuse'] = $reuse;
		$GLOBALS['pfb']['reuse_dnsbl'] = $reuseDnsbl;
		$id = $phase === 'dnsbl' ? 'dnsbl:feed' : 'ipv4:feed_v4';
		$params = [];
		try {
			pfb_core_feed_phase(str_repeat('d', 64), $phase, [$id], $force,
				static function (string $method, array $request, ?string $socket, int $timeout) use (&$params, $id): array {
					$params = $request;
					return ['status' => 200, 'body' => ['results' => [self::feedPhaseResult($id)]], 'error' => NULL];
				});
		} finally {
			$GLOBALS['pfb'] = $savedPfb;
		}

		$this->assertSame($expected, $params['force']);
	}

	public static function phaseForceCases(): array
	{
		return [
			'DNSBL reuse forces parse' => ['dnsbl', 'download', '', 'on', 'parse'],
			'IP reuse forces parse' => ['ip', 'both', 'on', '', 'parse'],
			'IP reuse does not force DNSBL parse' => ['dnsbl', 'none', 'on', '', 'none'],
			'DNSBL reuse does not force IP parse' => ['ip', 'download', '', 'on', 'download'],
			'ordinary IP keeps update force' => ['ip', 'both', '', '', 'both'],
			'ordinary DNSBL keeps update force' => ['dnsbl', 'none', '', '', 'none'],
		];
	}

	public function testTransportFailureFailsEveryFeedAtCoreStage(): void
	{
		$result = pfb_core_feed_phase(str_repeat('b', 64), 'ip', ['ipv4:first_v4', 'ipv6:second_v6'], 'download',
			static fn (string $method, array $params, ?string $socket, int $timeout): array => [
				'status' => 0, 'body' => NULL, 'error' => 'socket unavailable',
			]);

		$this->assertEveryResultFailedAtCore($result, ['ipv4:first_v4', 'ipv6:second_v6'], 'core_transport_failed');
	}

	#[DataProvider('invalidReplies')]
	public function testMalformedReplyFailsEveryRequestedFeed(string $case, array $body): void
	{
		$ids = ['dnsbl:first', 'dnsbl:second'];
		$result = pfb_core_feed_phase(str_repeat('c', 64), 'dnsbl', $ids, 'parse',
			static fn (string $method, array $params, ?string $socket, int $timeout): array => [
				'status' => 200, 'body' => $body, 'error' => NULL,
			]);

		$this->assertEveryResultFailedAtCore($result, $ids, 'core_response_invalid', $case);
	}

	public static function invalidReplies(): array
	{
		$first = self::feedPhaseResult('dnsbl:first');
		$second = self::feedPhaseResult('dnsbl:second');
		return [
			'missing results' => ['missing results', []],
			'unknown top-level field' => ['unknown top-level field', ['results' => [$first, $second], 'extra' => TRUE]],
			'non-list results' => ['non-list results', ['results' => ['first' => $first, 'second' => $second]]],
			'missing feed result' => ['missing feed result', ['results' => [$first]]],
			'wrong result order' => ['wrong result order', ['results' => [$second, $first]]],
			'unknown result field' => ['unknown result field', ['results' => [$first + ['unexpected' => TRUE], $second]]],
			'missing result field' => ['missing result field', ['results' => [array_diff_key($first, ['reason' => TRUE]), $second]]],
			'unknown disposition' => ['unknown disposition', ['results' => [self::feedPhaseResult('dnsbl:first', ['disposition' => 'reuse']), $second]]],
			'unknown stage' => ['unknown stage', ['results' => [self::feedPhaseResult('dnsbl:first', ['stage' => 'download']), $second]]],
			'unsafe reason' => ['unsafe reason', ['results' => [self::feedPhaseResult('dnsbl:first', ['reason' => "bad\nreason"]), $second]]],
			'negative count' => ['negative count', ['results' => [self::feedPhaseResult('dnsbl:first', ['entries' => -1]), $second]]],
			'non-integer count' => ['non-integer count', ['results' => [self::feedPhaseResult('dnsbl:first', ['entries' => '1']), $second]]],
			'integer boolean' => ['integer boolean', ['results' => [self::feedPhaseResult('dnsbl:first', ['suppressed' => 1]), $second]]],
			'unknown placeholder' => ['unknown placeholder', ['results' => [self::feedPhaseResult('dnsbl:first', ['placeholder' => 'other']), $second]]],
		];
	}

	private function assertEveryResultFailedAtCore(array $results, array $ids, string $reason, string $message = ''): void
	{
		$this->assertCount(count($ids), $results, $message);
		$this->assertSame($ids, array_column($results, 'id'), $message);
		foreach ($results as $result) {
			$this->assertSame('failed', $result['disposition'], $message);
			$this->assertSame('core', $result['stage'], $message);
			$this->assertSame($reason, $result['reason'], $message);
		}
	}

	public static function orderedBatchSizes(): array
	{
		return ['empty' => [0], 'one' => [1], 'limit' => [1024], 'over limit' => [1025], 'three batches' => [2049]];
	}

	#[DataProvider('orderedBatchSizes')]
	public function testGroupedPhaseKeepsEveryFeedInOrderWithinTheStrictLimit(int $count): void
	{
		$ids = $count === 0 ? [] : array_map(static fn (int $n): string => "dnsbl:feed_{$n}", range(1, $count));
		$groups = pfb_core_feed_phase_request_groups($ids, [], 'none');
		$calls = [];
		$results = pfb_core_feed_phase_groups('dnsbl', str_repeat('a', 64), $groups,
			static function (string $method, array $params) use (&$calls): array {
				$calls[] = $params;
				return ['status' => 200, 'body' => ['results' => array_map(self::feedPhaseResult(...), $params['feeds'])], 'error' => NULL];
			});
		$this->assertSame($ids, array_merge([], ...array_column($calls, 'feeds')), 'transport visits every feed exactly once in configured order');
		$this->assertSame($ids, array_keys($results));
		$this->assertCount((int) ceil($count / 1024), $calls);
		foreach ($calls as $call) {
			$this->assertLessThanOrEqual(1024, count($call['feeds']));
			$this->assertSame('none', $call['force']);
		}
	}

	public function testParseForceInterleavingStaysContiguousInsteadOfRegroupingFeeds(): void
	{
		$ids = ['dnsbl:one', 'dnsbl:two', 'dnsbl:three', 'dnsbl:four', 'dnsbl:five'];
		$this->assertSame([
			['feeds' => ['dnsbl:one'], 'force' => 'none'],
			['feeds' => ['dnsbl:two', 'dnsbl:three'], 'force' => 'parse'],
			['feeds' => ['dnsbl:four'], 'force' => 'none'],
			['feeds' => ['dnsbl:five'], 'force' => 'parse'],
		], pfb_core_feed_phase_request_groups($ids, ['dnsbl:two', 'dnsbl:three', 'dnsbl:five'], 'none'));
	}

	public static function invalidCompleteSets(): array
	{
		$valid = array_map(static fn (int $n): string => "dnsbl:feed_{$n}", range(1, 1024));
		return [
			'duplicate across chunk boundary' => [[...$valid, $valid[0]]],
			'malformed after first complete chunk' => [[...$valid, 'dnsbl:bad/path']],
			'ordinary dotted ID remains forbidden' => [[...$valid, 'dnsbl:bad.dot']],
		];
	}

	#[DataProvider('invalidCompleteSets')]
	public function testCompleteSetValidationRejectsBeforeAnyTransport(array $ids): void
	{
		$calls = [];
		$groups = pfb_core_feed_phase_request_groups($ids, [], 'none');
		$results = pfb_core_feed_phase_groups('dnsbl', str_repeat('a', 64), $groups,
			static function (string $method, array $params) use (&$calls): array {
				$calls[] = $params;
				return ['status' => 200, 'body' => ['results' => array_map(self::feedPhaseResult(...), $params['feeds'])], 'error' => NULL];
			});
		$this->assertSame([], $calls, 'known invalid complete selection must not partially execute the first chunk');
		$this->assertNotEmpty($results);
		foreach ($results as $result) {
			$this->assertSame('failed', $result['disposition']);
			$this->assertSame('core_request_invalid', $result['reason']);
		}
	}

	public function testDuplicateAcrossForceGroupsIsRejectedBeforeTransport(): void
	{
		$calls = 0;
		$results = pfb_core_feed_phase_groups('dnsbl', str_repeat('a', 64), [
			['feeds' => ['dnsbl:one'], 'force' => 'none'],
			['feeds' => ['dnsbl:one'], 'force' => 'parse'],
		], static function (string $method, array $params) use (&$calls): array {
			$calls++;
			return ['status' => 200, 'body' => ['results' => [self::feedPhaseResult('dnsbl:one')]], 'error' => NULL];
		});
		$this->assertSame(0, $calls);
		$this->assertSame('core_request_invalid', $results['dnsbl:one']['reason']);
	}

	public function testInvalidLaterForceGroupDoesNotExecuteAnEarlierValidGroup(): void
	{
		$calls = 0;
		$results = pfb_core_feed_phase_groups('dnsbl', str_repeat('a', 64), [
			['feeds' => ['dnsbl:one'], 'force' => 'none'],
			['feeds' => ['dnsbl:two'], 'force' => 'invalid'],
		], static function (string $method, array $params) use (&$calls): array {
			$calls++;
			return ['status' => 200, 'body' => ['results' => array_map(self::feedPhaseResult(...), $params['feeds'])], 'error' => NULL];
		});
		$this->assertSame(0, $calls, 'validate the whole phase before any transport, not only the next request');
		$this->assertEveryResultFailedAtCore(array_values($results), ['dnsbl:one', 'dnsbl:two'], 'core_request_invalid');
	}

	public function testStrictSingleRequestClientStillRejects1025Feeds(): void
	{
		$ids = array_map(static fn (int $n): string => "dnsbl:feed_{$n}", range(1, 1025));
		$calls = 0;
		$results = pfb_core_feed_phase(str_repeat('a', 64), 'dnsbl', $ids, 'none',
			static function () use (&$calls): array {
				$calls++;
				return ['status' => 0, 'body' => NULL, 'error' => 'must not execute'];
			});
		$this->assertSame(0, $calls, 'batch outside the strict client instead of widening its protocol limit');
		$this->assertEveryResultFailedAtCore($results, $ids, 'core_request_invalid');
	}

	private static function feedPhaseResult(string $id, array $overrides = []): array
	{
		return array_replace(array_fill_keys(self::RESULT_KEYS, 0), [
			'id' => $id,
			'disposition' => 'unchanged',
			'stage' => '',
			'reason' => '',
			'suppressed' => FALSE,
			'updateIP' => FALSE,
			'hpHostsStop' => FALSE,
			'placeholder' => '',
			'preScriptFailed' => FALSE,
			'sourceChanged' => FALSE,
			'normalizedChanged' => FALSE,
		], $overrides);
	}
}
