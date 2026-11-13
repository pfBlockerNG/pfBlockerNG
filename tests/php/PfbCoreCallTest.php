<?php

declare(strict_types=1);

require_once __DIR__ . '/support/ProcessRunner.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
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

	/** @var array<string, string|false> the proxy variables a test changed, as they were */
	private array $savedEnvironment = [];

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfbcall' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir($this->dir, 0700));
	}

	protected function tearDown(): void
	{
		foreach ($this->savedEnvironment as $name => $value) {
			putenv($value === FALSE ? $name : "{$name}={$value}");
		}
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
		$this->awaitListening($started);
		$result = $call($socket);
		$run = pfb_test_finish_process($started, 10.0);
		$this->assertSame(0, $run['exit'], "stand-in failed: {$run['stderr']}");
		return [$result, (string) file_get_contents("{$this->dir}/request")];
	}

	/**
	 * Block until the stand-in prints "ready" (its socket FILE exists from bind(), before listen()). A stand-in that exits first fails
	 * at once with what it said; the deadline only salvages a stuck run.
	 *
	 * @param array{0: resource, 1: array<int, resource>, 2: string} $started
	 */
	private function awaitListening(array $started): void
	{
		$stdout = $started[1][1];
		$said = '';
		$deadline = hrtime(TRUE) + 10_000_000_000;
		while (!str_contains($said, "ready\n")) {
			if (feof($stdout)) {
				$run = pfb_test_finish_process($started, 5.0);
				$this->fail("the stand-in exited ({$run['exit']}) before it listened: {$run['stderr']}");
			}
			if (hrtime(TRUE) > $deadline) {
				pfb_test_finish_process($started, 1.0);
				throw new RuntimeException('STUCK/ENVIRONMENT: the stand-in never listened');
			}
			$read = [$stdout];
			$write = $except = NULL;
			stream_select($read, $write, $except, 0, 100_000);
			$said .= (string) fread($stdout, 64);
		}
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

	public function testAReplyThatIsAJsonListIsAnErrorWithItsStatus(): void
	{
		[$result] = $this->exchange(200, '[1,2]', static fn (string $s): array => pfb_core_call('GetVersion', [], $s));

		$this->assertSame(200, $result['status']);
		$this->assertNull($result['body'], 'a JSON list was handed back as the reply object');
		$this->assertIsString($result['error']);
		$this->assertStringContainsString('not a JSON object', (string) $result['error']);
	}

	/** @return array<string, array{string}> */
	public static function emptyReplies(): array
	{
		return ['an empty object' => ['{}'], 'an empty list' => ['[]']];
	}

	#[DataProvider('emptyReplies')]
	public function testAnEmptyReplyIsAnEmptyBodyNotAnError(string $reply): void
	{
		[$result] = $this->exchange(200, $reply, static fn (string $s): array => pfb_core_call('GetVersion', [], $s));

		$this->assertSame(['status' => 200, 'body' => [], 'error' => NULL], $result);
	}

	public function testACallAboveCurlsExpectThresholdIsSentWithoutAnExpectHeaderAndArrivesWhole(): void
	{
		// libcurl adds "Expect: 100-continue" to a POST body above 1 MiB; pfb_core_call opts out of it
		$params = ['blob' => str_repeat('a', 1024 * 1024)];
		$sent = (string) json_encode((object) $params);
		[$result, $request] = $this->exchange(200, '{"ok":true}', static fn (string $s): array => pfb_core_call('TestIncrement', $params, $s));
		[$head, $body] = explode("\r\n\r\n", $request, 2);

		$this->assertSame(200, $result['status']);
		$this->assertDoesNotMatchRegularExpression('~^Expect:~mi', $head, 'the call carried an Expect header');
		$this->assertSame([strlen($sent), sha1($sent)], [strlen($body), sha1($body)], 'the body did not arrive whole (length, sha1)');
	}

	public function testAProxyInTheEnvironmentNeverDivertsTheCall(): void
	{
		foreach (['http_proxy', 'HTTP_PROXY', 'ALL_PROXY', 'all_proxy'] as $name) {
			$this->savedEnvironment[$name] = getenv($name);
			putenv("{$name}=http://127.0.0.1:9");
		}
		// Before: the same environment does divert a TCP call that has no opt-out, so the 200 below is the call's own
		$control = curl_init('http://pfb-core-control.invalid/');
		curl_setopt_array($control, [CURLOPT_RETURNTRANSFER => TRUE, CURLOPT_CONNECTTIMEOUT => 5]);
		curl_exec($control);
		$this->assertStringContainsString('127.0.0.1 port 9', curl_error($control), 'the environment proxy is not in effect for this process');

		[$result] = $this->exchange(200, '{"ok":true}', static fn (string $s): array => pfb_core_call('GetVersion', [], $s));

		$this->assertSame(['status' => 200, 'body' => ['ok' => TRUE], 'error' => NULL], $result);
	}

	public function testNoServerIsStatusZeroWithTheReason(): void
	{
		$result = pfb_core_call('GetVersion', [], "{$this->dir}/absent.sock");

		$this->assertSame(0, $result['status']);
		$this->assertNull($result['body']);
		$this->assertNotSame('', (string) $result['error'], 'no reason was given');
	}
}
