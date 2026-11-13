<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3941 (C3): the Update page starts and views the one Update through Core. Three pure helpers carry the page's
 * calls to Core and are pinned here with a stand-in for pfb_core_call():
 *   - pfb_update_view_response(): the page's `?ajax=update` poll, one GetUpdate relayed as the poller's JSON;
 *   - pfb_update_start(): Run Now / Force / the Wizard reload, one StartUpdate of trigger `manual`;
 *   - pfb_update_schedule_view(): the Schedule section, GetSchedule in the shape the section's formatters take.
 */
#[CoversFunction('pfb_update_view_response')]
#[CoversFunction('pfb_update_start')]
#[CoversFunction('pfb_update_schedule_view')]
final class UpdateViewResponseTest extends TestCase
{
	/** @var list<array{0: string, 1: array}> every call the fake Core got: method, params */
	private array $calls = [];

	/** @return array{status: int, body: array, error: null} */
	private static function ok(array $body): array
	{
		return ['status' => 200, 'body' => $body, 'error' => NULL];
	}

	/** @return array{status: int, body: array, error: null} */
	private static function refused(int $status, string $code, string $message): array
	{
		return ['status' => $status, 'body' => ['error' => ['code' => $code, 'message' => $message]], 'error' => NULL];
	}

	/** @return array{status: int, body: null, error: string} */
	private static function down(string $why): array
	{
		return ['status' => 0, 'body' => NULL, 'error' => $why];
	}

	/** A Core that answers every method with $reply and records each call in $this->calls. */
	private function core(array $reply): callable
	{
		return function (string $method, array $params = []) use ($reply): array {
			$this->calls[] = [$method, $params];
			return $reply;
		};
	}

	/** @return array<string, mixed> */
	private function decoded(array $response): array
	{
		$this->assertSame(
			['Content-Type: application/json', 'Cache-Control: no-cache, no-store, must-revalidate'],
			$response['headers'],
			'the poll answer is JSON and never cached'
		);
		$body = json_decode($response['body'], TRUE);
		$this->assertIsArray($body, 'the body must be valid JSON');
		return $body;
	}

	private static function update(int $startedAt = 1700000000): array
	{
		return ['trigger' => 'manual', 'scope' => 'dnsbl', 'force' => 'none', 'startedAt' => $startedAt];
	}

	// ---- pfb_update_view_response ----

	public function testARunningUpdateIsRelayedWithTheLogTheNextCursorAndTheUpdate(): void
	{
		$update = self::update();
		$body = $this->decoded(pfb_update_view_response(
			['ajax' => 'update'],
			$this->core(self::ok(['running' => TRUE, 'update' => $update, 'log' => "line one\n", 'next' => '1099511627800']))
		));

		$this->assertSame(
			['running' => TRUE, 'done' => FALSE, 'log' => "line one\n", 'next' => '1099511627800', 'update' => $update],
			$body
		);
		$this->assertSame([['GetUpdate', []]], $this->calls, 'a first poll carries no cursor');
	}

	public function testAFinishedUpdateIsDone(): void
	{
		$update = self::update() + ['finishedAt' => 1700000042, 'result' => 'success'];
		$body = $this->decoded(pfb_update_view_response(
			['ajax' => 'update', 'after' => '1099511627800'],
			$this->core(self::ok(['running' => FALSE, 'update' => $update, 'log' => '', 'next' => '1099511627800']))
		));

		$this->assertFalse($body['running']);
		$this->assertTrue($body['done'], 'done is the negation of running');
		$this->assertSame($update, $body['update']);
		$this->assertSame([['GetUpdate', ['after' => '1099511627800']]], $this->calls);
	}

	public function testBeforeTheFirstUpdateThereIsNothingToViewAndNothingRunning(): void
	{
		$body = $this->decoded(pfb_update_view_response(
			[],
			$this->core(self::ok(['running' => FALSE, 'update' => NULL, 'log' => '', 'next' => '0']))
		));

		$this->assertSame(['running' => FALSE, 'done' => TRUE, 'log' => '', 'next' => '0', 'update' => NULL], $body);
	}

	/** @return array<string, array{mixed}> */
	public static function hostileCursors(): array
	{
		return [
			'negative'                  => ['-1'],
			'letters'                   => ['abc'],
			'exponent'                  => ['1e9'],
			'fraction'                  => ['1.5'],
			'empty'                     => [''],
			'padded'                    => [' 5'],
			'hex'                       => ['0x10'],
			'past 63 bits'              => ['9223372036854775808'],
			'twenty digits'             => ['10000000000000000000'],
			'an array'                  => [['1']],
			'an integer is not a string' => [5],
		];
	}

	#[DataProvider('hostileCursors')]
	public function testAHostileCursorIsDroppedBeforeTheCallSoTheViewReadsFromTheStart(mixed $after): void
	{
		$body = $this->decoded(pfb_update_view_response(
			['ajax' => 'update', 'after' => $after],
			$this->core(self::ok(['running' => TRUE, 'update' => self::update(), 'log' => "a\n", 'next' => '7']))
		));

		$this->assertSame([['GetUpdate', []]], $this->calls, 'only a string of decimal digits reaches Core');
		$this->assertSame("a\n", $body['log']);
	}

	/** @return array<string, array{string}> */
	public static function validCursors(): array
	{
		return ['zero' => ['0'], 'beyond 2^53' => ['1099511627800'], 'the largest 63-bit value' => ['9223372036854775807']];
	}

	#[DataProvider('validCursors')]
	public function testACursorIsSentBackToCoreExactlyAsTheStringItIs(string $after): void
	{
		pfb_update_view_response(['ajax' => 'update', 'after' => $after], $this->core(self::ok(['running' => FALSE, 'log' => '', 'next' => $after])));

		$this->assertSame([['GetUpdate', ['after' => $after]]], $this->calls, 'a JSON number would be refused by Core');
	}

	public function testAnUnreachableCoreIsAnErrorThatEndsThePoll(): void
	{
		$body = $this->decoded(pfb_update_view_response(
			['ajax' => 'update'],
			$this->core(self::down('the Core API did not answer: Failed to connect'))
		));

		$this->assertSame('the Core API did not answer: Failed to connect', $body['error']);
		$this->assertFalse($body['running']);
		$this->assertTrue($body['done'], 'the poller stops on an error');
		$this->assertSame('', $body['log']);
	}

	public function testAnErrorFromCoreNamesItsCodeAndMessage(): void
	{
		$body = $this->decoded(pfb_update_view_response(
			['ajax' => 'update'],
			$this->core(self::refused(503, 'unavailable', 'Core runs no scheduler: start it with --update-cmd'))
		));

		$this->assertStringContainsString('unavailable', $body['error']);
		$this->assertStringContainsString('Core runs no scheduler', $body['error']);
		$this->assertTrue($body['done']);
		$this->assertFalse($body['running']);
	}

	public function testAnInvalidUtf8ByteInTheLogIsSubstitutedInsteadOfBreakingTheJson(): void
	{
		$response = pfb_update_view_response(
			['ajax' => 'update'],
			$this->core(self::ok(['running' => TRUE, 'update' => self::update(), 'log' => "bad \xFF\n", 'next' => '9']))
		);

		$body = $this->decoded($response);
		$this->assertStringContainsString("\u{FFFD}", $body['log']);
	}

	public function testOnlyAnExplicitTrueMeansRunning(): void
	{
		$body = $this->decoded(pfb_update_view_response(
			[],
			$this->core(self::ok(['running' => 'yes', 'log' => '', 'next' => '0']))
		));

		$this->assertFalse($body['running']);
		$this->assertTrue($body['done']);
	}

	// ---- pfb_update_start ----

	public function testARunNowAsksCoreForAManualUpdateOfTheScopeAndForce(): void
	{
		$message = pfb_update_start('dnsbl', 'none', $this->core(self::ok([])));

		$this->assertSame('Running: scope=dnsbl force=none', $message);
		$this->assertCount(1, $this->calls);
		[$method, $params] = $this->calls[0];
		$this->assertSame('StartUpdate', $method);
		$this->assertSame(['manual', 'dnsbl', 'none'], [$params['trigger'], $params['scope'], $params['force']]);
		$this->assertSame(['requestId', 'trigger', 'scope', 'force'], array_keys($params));
		$this->assertMatchesRegularExpression('/^[!-~]{1,128}$/D', $params['requestId'], 'a requestId is printable ASCII without spaces');
	}

	public function testEachRunNowIsItsOwnRequest(): void
	{
		$core = $this->core(self::ok([]));
		pfb_update_start('both', 'parse', $core);
		pfb_update_start('both', 'parse', $core);

		$this->assertNotSame($this->calls[0][1]['requestId'], $this->calls[1][1]['requestId'], 'a reused requestId would replay the first answer');
	}

	public function testAnUpdateThatIsRunningIsReportedAsSuch(): void
	{
		$message = pfb_update_start('both', 'none', $this->core(self::refused(409, 'conflict', 'an Update is running')));

		$this->assertSame('An Update is running.', $message);
	}

	public function testAnUnreachableCoreIsReportedWithItsMessage(): void
	{
		$message = pfb_update_start('both', 'none', $this->core(self::down('the Core API did not answer: Failed to connect')));

		$this->assertStringContainsString('the Core API did not answer: Failed to connect', $message);
		$this->assertStringNotContainsString('Running:', $message);
		$this->assertStringNotContainsString('An Update is running.', $message);
	}

	public function testACoreThatRunsNoSchedulerIsReportedWithItsMessage(): void
	{
		$message = pfb_update_start('both', 'none', $this->core(self::refused(503, 'unavailable', 'Core runs no scheduler: start it with --update-cmd')));

		$this->assertStringContainsString('Core runs no scheduler', $message);
		$this->assertStringNotContainsString('An Update is running.', $message);
	}

	/** @return array<string, array{string, string, string, string}> */
	public static function hostileRequests(): array
	{
		return [
			'path in the scope'     => ['../x', 'none', 'both', 'none'],
			'shell in the scope'    => ['ip; rm -rf /', 'parse', 'both', 'parse'],
			'unknown force'         => ['ip', 'everything', 'ip', 'none'],
			'path in the force'     => ['dnsbl', '../../etc/passwd', 'dnsbl', 'none'],
			'both empty'            => ['', '', 'both', 'none'],
			'case matters'          => ['IP', 'NONE', 'both', 'none'],
		];
	}

	#[DataProvider('hostileRequests')]
	public function testScopeAndForceAreAllowListedBeforeTheCall(string $scope, string $force, string $sentScope, string $sentForce): void
	{
		$message = pfb_update_start($scope, $force, $this->core(self::ok([])));

		$params = $this->calls[0][1];
		$this->assertSame([$sentScope, $sentForce], [$params['scope'], $params['force']], 'the unknown value falls back to its default');
		$this->assertSame("Running: scope={$sentScope} force={$sentForce}", $message, 'the message never repeats what was refused');
	}

	// ---- pfb_update_schedule_view ----

	public function testTheSectionTakesTheFeedsAndBothExtrasFromTheSchedule(): void
	{
		$view = pfb_update_schedule_view($this->core(self::ok([
			'scheduled' => TRUE,
			'feeds'     => ['lastRun' => 1700000000, 'nextDue' => 1700000900],
			'extras'    => [
				'extra:dcc' => ['lastRun' => 1699990000, 'nextDue' => 1700086400],
				'extra:bl'  => ['lastRun' => 0, 'nextDue' => 1700003600],
			],
		])));

		$this->assertSame([['GetSchedule', []]], $this->calls);
		$this->assertNull($view['error']);
		$this->assertSame(['last_run' => 1700000000, 'next_due' => 1700000900], $view['feeds']);
		$this->assertSame(['last_run' => 1699990000, 'next_due' => 1700086400], $view['dcc']);
		$this->assertSame(['next_due' => 1700003600], $view['bl'], 'a job that never ran has no last run to show');
	}

	public function testWhatCoreDoesNotScheduleHasNoEntry(): void
	{
		$view = pfb_update_schedule_view($this->core(self::ok(['scheduled' => FALSE, 'feeds' => NULL, 'extras' => []])));

		$this->assertNull($view['error']);
		$this->assertSame([NULL, NULL, NULL], [$view['feeds'], $view['dcc'], $view['bl']]);
	}

	public function testAnUnreachableCoreIsAnErrorForTheWholeSection(): void
	{
		$view = pfb_update_schedule_view($this->core(self::down('the Core API did not answer: Failed to connect')));

		$this->assertSame('the Core API did not answer: Failed to connect', $view['error']);
		$this->assertSame([NULL, NULL, NULL], [$view['feeds'], $view['dcc'], $view['bl']]);
	}

	public function testAScheduleCoreCannotComputeIsAnErrorWithItsReason(): void
	{
		$view = pfb_update_schedule_view($this->core(self::refused(503, 'unavailable', 'the settings are not initialized')));

		$this->assertStringContainsString('the settings are not initialized', (string) $view['error']);
		$this->assertNull($view['feeds']);
	}
}
