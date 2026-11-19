<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/support/HttpFixtureReadiness.php';

/**
 * Issue #4073 -- the Status subtab's lookup request (docs/specs/crowdsec-integration.md D7), driven over real HTTP against a local
 * `php -S` stand-in for the LAPI:
 *   - the key travels only in the X-Api-Key header, never in the URL;
 *   - a redirect is not followed (it would carry the key to another place);
 *   - an answer larger than PFB_CROWDSEC_LOOKUP_MAX fails the request;
 *   - a server that does not answer is cut off by the time limit, and the request reports it;
 *   - the whole lookup, request and parse, shows the stand-in's decisions.
 */
#[CoversFunction('pfb_crowdsec_lapi_get')]
#[CoversFunction('pfb_crowdsec_lookup')]
final class CrowdsecLapiRequestTest extends TestCase
{
	private const KEY = 'Zk9-request_KEY.0123456789';

	private string $workdir;
	/** @var resource|null */
	private $server = NULL;
	private int $port = 0;

	protected function setUp(): void
	{
		$this->workdir = sys_get_temp_dir() . '/pfb_crowdsec_lapi_' . bin2hex(random_bytes(8));
		mkdir($this->workdir);
		$this->startServer();
	}

	protected function tearDown(): void
	{
		if (is_resource($this->server)) {
			proc_terminate($this->server);
			proc_close($this->server);
		}
		rmdir_recursive($this->workdir);
	}

	/**
	 * Routes: /v1/decisions answers one decision for ?ip=; /redirect 302s to /v1/decisions; /big answers one byte over the cap;
	 * /silent answers nothing for 8 s. Every request is logged as "<uri> <X-Api-Key>". One process, no workers: proc_terminate() reaches
	 * it, where forked workers would outlive the test.
	 */
	private function startServer(): void
	{
		$router = "{$this->workdir}/router.php";
		file_put_contents($router, <<<'PHP'
<?php
$uri = $_SERVER['REQUEST_URI'] ?? '';
if ($uri === '/__pfb_ready') {
	echo getenv('READY_TOKEN');
	return;
}
file_put_contents(getenv('REQ_LOG'), $uri . ' ' . ($_SERVER['HTTP_X_API_KEY'] ?? '-') . PHP_EOL, FILE_APPEND);
header('Content-Type: application/json');
switch (parse_url($uri, PHP_URL_PATH)) {
case '/v1/decisions':
	parse_str((string) parse_url($uri, PHP_URL_QUERY), $q);
	echo json_encode([['value' => $q['ip'] ?? '', 'scope' => 'Ip', 'origin' => 'crowdsec', 'scenario' => 'crowdsecurity/ssh-bf', 'type' => 'ban', 'duration' => '1h']]);
	return;
case '/redirect':
	http_response_code(302);
	header('Location: /v1/decisions?ip=192.0.2.1');
	return;
case '/big':
	echo str_repeat(' ', (int) getenv('BIG'));
	return;
case '/silent':
	sleep(8);
	echo 'null';
	return;
}
http_response_code(404);
PHP);
		for ($try = 0; $try < 10; $try++) {
			$nonce = bin2hex(random_bytes(16));
			$stderr = "{$this->workdir}/server-{$try}.stderr";
			$proc = proc_open(['php', '-S', '127.0.0.1:0', $router], [1 => ['file', '/dev/null', 'w'], 2 => ['file', $stderr, 'w']], $pipes,
			    $this->workdir, ['REQ_LOG' => "{$this->workdir}/requests.log", 'READY_TOKEN' => $nonce, 'BIG' => (string) (PFB_CROWDSEC_LOOKUP_MAX + 1),
			    'PATH' => (string) getenv('PATH')]);
			if (!is_resource($proc)) {
				continue;
			}
			$port = pfb_test_http_fixture_port($stderr);
			for ($i = 0; $port !== 0 && $i < 40; $i++) {
				if (pfb_test_http_fixture_event_received($port, $nonce)) {
					$this->server = $proc;
					$this->port = $port;
					return;
				}
				usleep(50000);
			}
			proc_terminate($proc);
			proc_close($proc);
		}
		$this->fail('could not start the php -S stand-in for the LAPI');
	}

	private function url(string $path): string
	{
		return "http://127.0.0.1:{$this->port}{$path}";
	}

	/** @return list<string> */
	private function requests(): array
	{
		return (array) @file("{$this->workdir}/requests.log", FILE_IGNORE_NEW_LINES);
	}

	public function testTheKeyTravelsOnlyInItsHeader(): void
	{
		$answer = pfb_crowdsec_lapi_get($this->url('/v1/decisions?ip=192.0.2.1'), self::KEY);

		$this->assertSame('', $answer['error']);
		$this->assertSame(200, $answer['status']);
		$this->assertSame(['/v1/decisions?ip=192.0.2.1 ' . self::KEY], $this->requests(), 'one request, the key in X-Api-Key and not in the URL');
	}

	public function testARedirectIsNotFollowed(): void
	{
		$answer = pfb_crowdsec_lapi_get($this->url('/redirect'), self::KEY);

		$this->assertSame(302, $answer['status']);
		$this->assertSame(['/redirect ' . self::KEY], $this->requests(), 'the redirect target is never asked');
	}

	public function testAnAnswerOverTheCapFailsTheRequest(): void
	{
		$answer = pfb_crowdsec_lapi_get($this->url('/big'), self::KEY);

		$this->assertNotSame('', $answer['error'], 'an answer one byte over the cap is a failed request');
		$this->assertLessThanOrEqual(PFB_CROWDSEC_LOOKUP_MAX, strlen($answer['body']), 'nothing past the cap is kept');
	}

	public function testAServerThatDoesNotAnswerIsCutOffByTheTimeLimit(): void
	{
		$answer = pfb_crowdsec_lapi_get($this->url('/silent'), self::KEY);

		$this->assertStringContainsString('timed out', $answer['error'], 'the request gives up on its own, before the server answers');
		$this->assertSame('', $answer['body']);
	}

	public function testTheLookupShowsTheDecisionsTheLapiAnswers(): void
	{
		$result = pfb_crowdsec_lookup('2001:db8::7', $this->url(''), self::KEY);

		$this->assertSame(['/v1/decisions?ip=2001%3Adb8%3A%3A7 ' . self::KEY], $this->requests());
		$this->assertSame(['error' => NULL, 'decisions' => [
			['value' => '2001:db8::7', 'scope' => 'Ip', 'origin' => 'crowdsec', 'scenario' => 'crowdsecurity/ssh-bf', 'type' => 'ban', 'duration' => '1h'],
		]], $result);
	}
}
