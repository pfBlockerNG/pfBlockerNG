<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3941 (cutover review): every call the Update page makes to Core is bounded, and the page tells a Core that is down from
 * a Core that answered with an error.
 *   - A page request holds a php-fpm worker while it waits for Core, and the poll comes once a second: a wedged Core must not hold
 *     a worker for pfb_core_call()'s default 30 s. Each helper therefore calls with the method, the parameters, NULL (the default
 *     socket) and a 5 s timeout, and the page reaches Core only through them.
 *   - The Schedule view reports `unreachable` only when no HTTP reply came (status 0): a Core that answered 503 is up and its
 *     message is what the row shows.
 */
#[CoversFunction('pfb_update_view_response')]
#[CoversFunction('pfb_update_start')]
#[CoversFunction('pfb_update_schedule_view')]
#[CoversFunction('pfb_update_running')]
final class UpdateCoreCallBoundsTest extends TestCase
{
	/** @var list<array<int, mixed>> every call the fake Core got, as it was made: method, params, socket, timeout */
	private array $calls = [];

	/** A Core that answers every method with $reply and records each call exactly as made. */
	private function core(array $reply): callable
	{
		return function (...$args) use ($reply): array {
			$this->calls[] = $args;
			return $reply;
		};
	}

	/** @return array{status: int, body: array, error: null} */
	private static function ok(array $body): array
	{
		return ['status' => 200, 'body' => $body, 'error' => NULL];
	}

	// ---- S4: the bound ----

	public function testThePollRelayCallsCoreWithAFiveSecondTimeout(): void
	{
		pfb_update_view_response([], $this->core(self::ok(['running' => FALSE, 'log' => '', 'next' => '0'])));
		pfb_update_view_response(['after' => '7'], $this->core(self::ok(['running' => FALSE, 'log' => '', 'next' => '7'])));

		$this->assertSame([['GetUpdate', [], NULL, 5], ['GetUpdate', ['after' => '7'], NULL, 5]], $this->calls);
	}

	public function testRunNowCallsCoreWithAFiveSecondTimeout(): void
	{
		pfb_update_start('dnsbl', 'none', $this->core(self::ok([])));

		$this->assertCount(1, $this->calls);
		[$method, $params, $socket, $timeout] = $this->calls[0];
		$this->assertSame(['StartUpdate', 'manual', NULL, 5], [$method, $params['trigger'], $socket, $timeout]);
	}

	public function testTheScheduleSectionCallsCoreWithAFiveSecondTimeout(): void
	{
		pfb_update_schedule_view($this->core(self::ok(['scheduled' => TRUE, 'feeds' => NULL, 'extras' => []])));

		$this->assertSame([['GetSchedule', [], NULL, 5]], $this->calls);
	}

	public function testTheStatusLineCallsCoreWithAFiveSecondTimeoutAndReadsRunning(): void
	{
		$this->assertTrue(pfb_update_running($this->core(self::ok(['running' => TRUE, 'log' => '', 'next' => '0']))));
		$this->assertFalse(pfb_update_running($this->core(self::ok(['running' => FALSE, 'log' => '', 'next' => '0']))));
		$this->assertFalse(pfb_update_running($this->core(self::ok(['running' => 'yes']))), 'only an explicit true is running');
		$this->assertFalse(pfb_update_running($this->core(['status' => 0, 'body' => NULL, 'error' => 'down'])), 'a Core that does not answer is not running one');
		$this->assertFalse(pfb_update_running($this->core(['status' => 503, 'body' => ['error' => ['code' => 'unavailable', 'message' => 'x']], 'error' => NULL])));

		$this->assertSame([['GetUpdate', [], NULL, 5]], array_values(array_unique($this->calls, SORT_REGULAR)));
	}

	public function testThePageReachesCoreOnlyThroughTheBoundedHelpers(): void
	{
		$page = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_update.php');

		$this->assertDoesNotMatchRegularExpression('/\bpfb_core_call\s*\(/', $page, 'a direct call would use the default 30 s timeout');
		$this->assertStringContainsString('pfb_update_running(', $page);
		$this->assertStringContainsString('pfb_update_schedule_view(', $page);
		$this->assertStringContainsString('pfb_update_start(', $page);
		$this->assertStringContainsString('pfb_update_view_response(', $page);
	}

	// ---- S2: down is not the same as an error ----

	public function testAScheduleCoreDidNotAnswerIsUnreachable(): void
	{
		$view = pfb_update_schedule_view($this->core(['status' => 0, 'body' => NULL, 'error' => 'the Core API did not answer: Failed to connect']));

		$this->assertTrue($view['unreachable']);
		$this->assertSame('the Core API did not answer: Failed to connect', $view['error']);
	}

	public function testAScheduleCoreRefusedIsAnErrorWithItsMessageAndNotUnreachable(): void
	{
		$view = pfb_update_schedule_view($this->core([
			'status' => 503, 'body' => ['error' => ['code' => 'unavailable', 'message' => 'the settings are not initialized']], 'error' => NULL,
		]));

		$this->assertFalse($view['unreachable'], 'Core answered, so it is up');
		$this->assertSame('unavailable: the settings are not initialized', $view['error']);
	}

	public function testAReplyThatIsNoJsonObjectIsAnErrorOfACoreThatAnswered(): void
	{
		$view = pfb_update_schedule_view($this->core(['status' => 200, 'body' => NULL, 'error' => 'the Core API reply is not a JSON object']));

		$this->assertFalse($view['unreachable'], 'an HTTP reply came');
		$this->assertSame('the Core API reply is not a JSON object', $view['error']);
	}

	public function testAGoodScheduleIsNeitherAnErrorNorUnreachable(): void
	{
		$view = pfb_update_schedule_view($this->core(self::ok(['scheduled' => TRUE, 'feeds' => NULL, 'extras' => []])));

		$this->assertNull($view['error']);
		$this->assertFalse($view['unreachable']);
	}
}
