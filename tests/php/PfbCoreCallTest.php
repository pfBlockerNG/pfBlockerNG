<?php

declare(strict_types=1);

require_once __DIR__ . '/support/ProcessRunner.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #3841 -- pfb_core_call(), the PHP side of the Core API (docs/misc/core-api-protocol.md): POST /v1/<Method> over the
 * Core's Unix socket with the parameters as one JSON object, and the reply's HTTP status and decoded JSON object handed back
 * as they are, the error envelope included. A call that gets no HTTP reply is status 0 with the reason.
 *
 * The socket is served by a stand-in (support/CoreApiStandIn.php) that records the raw request and answers what the test says.
 */
#[CoversFunction('pfb_core_call')]
final class PfbCoreCallTest extends TestCase
{
	private string $dir = '';

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfbcall' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir($this->dir, 0700));
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->dir);
	}

	/**
	 * Serve one reply on a fresh socket while $call runs against it.
	 *
	 * @return array{0: array{status: int, body: ?array, error: ?string}, 1: string} what $call returned, then the raw request
	 */
	private function exchange(int $status, string $body, callable $call): array
	{
		$socket = "{$this->dir}/api.sock";
		$started = pfb_test_start_process([PHP_BINARY, __DIR__ . '/support/CoreApiStandIn.php', $socket, "{$this->dir}/request", (string) $status, $body]);
		// Readiness: the stand-in prints "ready" once it listens; the deadline only salvages a stuck run
		$deadline = hrtime(TRUE) + 10_000_000_000;
		while (!file_exists($socket)) {
			if (hrtime(TRUE) > $deadline) {
				pfb_test_finish_process($started, 1.0);
				throw new RuntimeException('STUCK/ENVIRONMENT: the stand-in never listened');
			}
			usleep(1000);
		}
		$result = $call($socket);
		$run = pfb_test_finish_process($started, 10.0);
		$this->assertSame(0, $run['exit'], "stand-in failed: {$run['stderr']}");
		return [$result, (string) file_get_contents("{$this->dir}/request")];
	}

	public function testTheVersionCallPostsAnEmptyObjectToTheVersionedPathAndReturnsTheDecodedReply(): void
	{
		$reply = '{"service":"pfblockerng-core","apiVersion":"v1","status":"serving"}';
		[$result, $request] = $this->exchange(200, $reply, static fn (string $s): array => pfb_core_call('GetVersion', [], $s));

		$this->assertSame(['status' => 200, 'body' => ['service' => 'pfblockerng-core', 'apiVersion' => 'v1', 'status' => 'serving'], 'error' => NULL], $result);
		$this->assertStringStartsWith("POST /v1/GetVersion HTTP/1.1\r\n", $request);
		$this->assertMatchesRegularExpression('~^Content-Type: application/json\r$~mi', $request);
		$this->assertStringEndsWith("\r\n\r\n{}", $request, 'the empty parameters were not sent as the empty JSON object');
	}

	public function testParametersAreSentAsOneJsonObject(): void
	{
		[$result, $request] = $this->exchange(200, '{"count":1}',
			static fn (string $s): array => pfb_core_call('TestIncrement', ['requestId' => 'r-1', 'add' => 2], $s));

		$this->assertSame(200, $result['status']);
		$this->assertStringStartsWith("POST /v1/TestIncrement HTTP/1.1\r\n", $request);
		$this->assertStringEndsWith("\r\n\r\n{\"requestId\":\"r-1\",\"add\":2}", $request);
	}

	public function testAnErrorEnvelopeComesBackWithItsStatus(): void
	{
		$envelope = '{"error":{"code":"unauthenticated","message":"no"}}';
		[$result] = $this->exchange(401, $envelope, static fn (string $s): array => pfb_core_call('GetVersion', [], $s));

		$this->assertSame(['status' => 401, 'body' => ['error' => ['code' => 'unauthenticated', 'message' => 'no']], 'error' => NULL], $result);
	}

	public function testAReplyThatIsNotAJsonObjectIsAnError(): void
	{
		[$result] = $this->exchange(200, 'oops', static fn (string $s): array => pfb_core_call('GetVersion', [], $s));

		$this->assertSame(200, $result['status']);
		$this->assertNull($result['body']);
		$this->assertIsString($result['error']);
		$this->assertStringContainsString('JSON', (string) $result['error']);
	}

	public function testNoServerIsStatusZeroWithTheReason(): void
	{
		$result = pfb_core_call('GetVersion', [], "{$this->dir}/absent.sock");

		$this->assertSame(0, $result['status']);
		$this->assertNull($result['body']);
		$this->assertNotSame('', (string) $result['error'], 'no reason was given');
	}
}
