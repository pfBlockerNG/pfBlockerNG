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
