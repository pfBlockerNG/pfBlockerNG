<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4073 -- what the CrowdSec tab's Status subtab reads (docs/specs/crowdsec-integration.md, D7).
 *
 * Pinned here:
 *   - why the bouncer does not run, one reason each, and none while it should;
 *   - the lookup (pfb_crowdsec_lookup()): an address that is not an IP sends nothing; the request is GET /v1/decisions?ip=<addr>
 *     with the key in X-Api-Key, 5 s for the whole request and no redirect; the LAPI's answers (decisions, null, a refusal, a
 *     transport error, garbage) each read as specified, and no result ever carries the key;
 *   - the status file as the page reads it, including an origin JSON decodes to an integer key;
 *   - the last 50 system log lines tagged pfb_crowdsec, in both pfSense log formats, and nothing from other programs;
 *   - a table's contents from pfctl, and NULL when pfctl fails.
 */
#[CoversFunction('pfb_crowdsec_off_reason')]
#[CoversFunction('pfb_crowdsec_lookup')]
#[CoversFunction('pfb_crowdsec_lapi_curl_options')]
#[CoversFunction('pfb_crowdsec_status_read')]
#[CoversFunction('pfb_crowdsec_log_tail')]
#[CoversFunction('pfb_crowdsec_table_entries')]
#[CoversFunction('pfb_crowdsec_subtabs')]
final class CrowdsecStatusTest extends TestCase
{
	private const SECTION = 'installedpackages/pfblockerngcrowdsec/config/0';
	private const KEY = 'Zk9-lookup_KEY.0123456789';
	private const URL = 'http://192.0.2.10:8080/';

	private string $root;
	private mixed $savedConfig;
	private mixed $savedPfb;
	/** @var list<array{string, string}> the requests the lookup's seam received */
	private array $requests = [];

	protected function setUp(): void
	{
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$this->savedPfb = $GLOBALS['pfb'] ?? NULL;
		$GLOBALS['config'] = [];
		$GLOBALS['pfb']['enable'] = PfbToggle::On;
		$this->root = sys_get_temp_dir() . '/pfb_crowdsec_status_' . bin2hex(random_bytes(8));
		mkdir($this->root);
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = $this->savedConfig;
		$GLOBALS['pfb'] = $this->savedPfb;
		rmdir_recursive($this->root);
	}

	// ---- why it does not run ----------------------------------------------------------------

	public function testEachReasonTheBouncerDoesNotRunIsNamedAndNoneWhileItShould(): void
	{
		config_set_path(self::SECTION . '/enable', 'on');
		config_set_path(self::SECTION . '/api_key', self::KEY);
		$this->assertNull(pfb_crowdsec_off_reason(), 'all three hold: it should run');
		$this->assertTrue(pfb_crowdsec_should_run());

		config_set_path(self::SECTION . '/api_key', '');
		$this->assertSame('no bouncer API key is stored on this node', pfb_crowdsec_off_reason());
		config_set_path(self::SECTION . '/enable', '');
		$this->assertSame('CrowdSec is disabled', pfb_crowdsec_off_reason(), 'CrowdSec off is named before the key');
		$GLOBALS['pfb']['enable'] = PfbToggle::Off;
		$this->assertSame('pfBlockerNG is disabled', pfb_crowdsec_off_reason(), 'pfBlockerNG off is named first');
		$this->assertFalse(pfb_crowdsec_should_run());
	}

	public function testTheSecondRowSelectsTheGivenSubtab(): void
	{
		$this->assertSame([['Settings', FALSE, PFB_CROWDSEC_PAGE], ['Status', TRUE, PFB_CROWDSEC_STATUS_PAGE]],
		    pfb_crowdsec_subtabs(PFB_CROWDSEC_STATUS_PAGE));
		$this->assertSame([['Settings', TRUE, PFB_CROWDSEC_PAGE], ['Status', FALSE, PFB_CROWDSEC_STATUS_PAGE]],
		    pfb_crowdsec_subtabs(PFB_CROWDSEC_PAGE));
	}

	// ---- the lookup ---------------------------------------------------------------------------

	/** A seam that records each request and answers $answer. */
	private function lapi(int $status, string $body, string $error = ''): callable
	{
		return function (string $url, string $key) use ($status, $body, $error): array {
			$this->requests[] = [$url, $key];
			return ['status' => $status, 'body' => $body, 'error' => $error];
		};
	}

	/** @return iterable<string, array{string}> */
	public static function notAnIp(): iterable
	{
		yield 'empty' => [''];
		yield 'out of range' => ['192.0.2.300'];
		yield 'a prefix' => ['192.0.2.0/24'];
		yield 'a name' => ['lapi.example'];
		yield 'a second parameter' => ['192.0.2.1&scope=range'];
		yield 'a header' => ["192.0.2.1\r\nX-Api-Key: other"];
		yield 'surrounding space' => [' 192.0.2.1'];
		yield 'an IPv6 zone' => ['fe80::1%em0'];
		yield 'a bracketed IPv6' => ['[2001:db8::1]'];
	}

	#[DataProvider('notAnIp')]
	public function testAnAddressThatIsNotAnIpSendsNothing(string $ip): void
	{
		$result = pfb_crowdsec_lookup($ip, self::URL, self::KEY, $this->lapi(200, 'null'));

		$this->assertSame([], $this->requests, 'no request');
		$this->assertSame('The lookup address is not an IP address.', $result['error']);
		$this->assertSame([], $result['decisions']);
	}

	/** @return iterable<string, array{string, string}> address => the request URL */
	public static function addresses(): iterable
	{
		yield 'IPv4' => ['192.0.2.77', 'http://192.0.2.10:8080/v1/decisions?ip=192.0.2.77'];
		yield 'IPv6' => ['2001:db8::77', 'http://192.0.2.10:8080/v1/decisions?ip=2001%3Adb8%3A%3A77'];
	}

	#[DataProvider('addresses')]
	public function testTheLookupAsksTheLapiForThatAddressWithTheKey(string $ip, string $url): void
	{
		$body = json_encode([
			['id' => 1, 'origin' => 'crowdsec', 'type' => 'ban', 'scope' => 'Ip', 'value' => $ip, 'duration' => '3h59m', 'scenario' => 'crowdsecurity/ssh-bf'],
			['id' => 2, 'origin' => 'cscli', 'type' => 'ban', 'scope' => 'Ip', 'value' => $ip, 'duration' => '1h', 'scenario' => "manual 'ban'", 'until' => 'x'],
		]);

		$result = pfb_crowdsec_lookup($ip, self::URL, self::KEY, $this->lapi(200, $body));

		$this->assertSame([[$url, self::KEY]], $this->requests);
		$this->assertNull($result['error']);
		$this->assertSame([
			['value' => $ip, 'scope' => 'Ip', 'origin' => 'crowdsec', 'scenario' => 'crowdsecurity/ssh-bf', 'type' => 'ban', 'duration' => '3h59m'],
			['value' => $ip, 'scope' => 'Ip', 'origin' => 'cscli', 'scenario' => "manual 'ban'", 'type' => 'ban', 'duration' => '1h'],
		], $result['decisions']);
	}

	public function testNoMatchingDecisionIsAnEmptyListNotAnError(): void
	{
		$result = pfb_crowdsec_lookup('192.0.2.1', self::URL, self::KEY, $this->lapi(200, "null\n"));

		$this->assertSame(['error' => NULL, 'decisions' => []], $result);
	}

	/** @return iterable<string, array{int, string, string, string}> status, body, transport error => the error shown */
	public static function failures(): iterable
	{
		yield 'refused key' => [403, '{"message":"access forbidden"}', '', 'The LAPI answered HTTP 403.'];
		yield 'server error' => [500, '', '', 'The LAPI answered HTTP 500.'];
		yield 'timeout' => [0, '', 'Operation timed out after 5000 milliseconds with 0 bytes received',
		    'The LAPI request failed: Operation timed out after 5000 milliseconds with 0 bytes received'];
		yield 'not JSON' => [200, '<html>', '', 'The LAPI answer is not a list of decisions.'];
		yield 'an object' => [200, '{"value":"192.0.2.1"}', '', 'The LAPI answer is not a list of decisions.'];
		yield 'a list of scalars' => [200, '[1,2]', '', 'The LAPI answer is not a list of decisions.'];
		yield 'a string' => [200, '"null"', '', 'The LAPI answer is not a list of decisions.'];
	}

	#[DataProvider('failures')]
	public function testEachFailedLookupIsReportedWithoutTheKey(int $status, string $body, string $error, string $shown): void
	{
		$result = pfb_crowdsec_lookup('192.0.2.1', self::URL, self::KEY, $this->lapi($status, $body, $error));

		$this->assertCount(1, $this->requests);
		$this->assertSame(['error' => $shown, 'decisions' => []], $result);
		$this->assertStringNotContainsString(self::KEY, (string) $result['error']);
	}

	public function testANonStringFieldReadsAsTextAndAMissingOneAsEmpty(): void
	{
		$body = json_encode([['value' => '192.0.2.1', 'scope' => ['x'], 'origin' => 7, 'type' => 'ban']]);

		$result = pfb_crowdsec_lookup('192.0.2.1', self::URL, self::KEY, $this->lapi(200, $body));

		$this->assertSame([['value' => '192.0.2.1', 'scope' => '', 'origin' => '7', 'scenario' => '', 'type' => 'ban', 'duration' => '']],
		    $result['decisions']);
	}

	/** @return iterable<string, array{string, string}> */
	public static function unusableSettings(): iterable
	{
		yield 'no URL' => ['', self::KEY];
		yield 'a file URL' => ['file:///etc', self::KEY];
		yield 'a URL with a query' => ['http://192.0.2.10:8080/?x=1', self::KEY];
		yield 'no key' => [self::URL, ''];
		yield 'a key with a line break' => [self::URL, "abc\r\nX-Other: 1"];
		yield 'a key with a space' => [self::URL, 'abc def'];
	}

	#[DataProvider('unusableSettings')]
	public function testWithoutAUsableUrlAndKeyNothingIsSent(string $url, string $key): void
	{
		$result = pfb_crowdsec_lookup('192.0.2.1', $url, $key, $this->lapi(200, 'null'));

		$this->assertSame([], $this->requests);
		$this->assertSame('Store the Remote LAPI URL and the Bouncer API key on the Settings subtab first.', $result['error']);
	}

	public function testTheRequestCarriesTheKeyHasFiveSecondsAndFollowsNoRedirect(): void
	{
		$options = pfb_crowdsec_lapi_curl_options(self::KEY);

		$this->assertContains('X-Api-Key: ' . self::KEY, $options[CURLOPT_HTTPHEADER]);
		$this->assertSame(5, $options[CURLOPT_TIMEOUT], 'D7: a 5 s timeout');
		$this->assertSame(5, $options[CURLOPT_CONNECTTIMEOUT]);
		$this->assertFalse($options[CURLOPT_FOLLOWLOCATION], 'a redirect would carry the key elsewhere');
		$this->assertTrue($options[CURLOPT_HTTPGET]);
	}

	// ---- the status file, as the page reads it ------------------------------------------------

	public function testTheStatusFileReadsBackAsTheDaemonWroteIt(): void
	{
		$path = "{$this->root}/status.json";
		file_put_contents($path, '{"version":"0.1.0","start_time":1,"update_frequency_seconds":10,"updated_at":5,"last_pull":4,'
		    . '"last_error_time":3,"last_error":"boom <b>","lapi_requests":9,"lapi_errors":2,'
		    . '"banned":{"ipv4":{"total":3,"origins":{"crowdsec":2,"123":1}},"ipv6":{"total":0,"origins":{}}},'
		    . '"dropped":{"ipv4":{"packets":7,"bytes":420},"ipv6":{"packets":0,"bytes":0}}}');

		$status = pfb_crowdsec_status_read($path);

		$this->assertSame([
			'version' => '0.1.0', 'last_error' => 'boom <b>', 'start_time' => 1, 'update_frequency_seconds' => 10, 'updated_at' => 5,
			'last_pull' => 4, 'last_error_time' => 3, 'lapi_requests' => 9, 'lapi_errors' => 2,
			'banned' => ['ipv4' => ['total' => 3, 'origins' => ['crowdsec' => 2, 123 => 1]], 'ipv6' => ['total' => 0, 'origins' => []]],
			'dropped' => ['ipv4' => ['packets' => 7, 'bytes' => 420], 'ipv6' => ['packets' => 0, 'bytes' => 0]],
		], $status);
		$this->assertTrue(pfb_crowdsec_status_fresh($status, 35), '30 s after its write: fresh');
		$this->assertFalse(pfb_crowdsec_status_fresh($status, 36), '31 s after: stale');
		$this->assertNull(pfb_crowdsec_status_read("{$this->root}/absent.json"));
	}

	/** A healthy status document with $changes merged over it. */
	private static function statusJson(array $changes = []): string
	{
		return json_encode(array_replace([
			'version' => '0.1.0', 'start_time' => 1, 'update_frequency_seconds' => 10, 'updated_at' => 1000, 'last_pull' => 4,
			'last_error_time' => 0, 'last_error' => '', 'lapi_requests' => 9, 'lapi_errors' => 0,
			'banned' => ['ipv4' => ['total' => 0, 'origins' => new stdClass()], 'ipv6' => ['total' => 0, 'origins' => new stdClass()]],
			'dropped' => ['ipv4' => ['packets' => 0, 'bytes' => 0], 'ipv6' => ['packets' => 0, 'bytes' => 0]],
		], $changes));
	}

	public function testAZeroUpdateFrequencyIsNotTheDaemonsFile(): void
	{
		$path = "{$this->root}/status.json";
		file_put_contents($path, self::statusJson(['update_frequency_seconds' => 1]));
		$this->assertIsArray(pfb_crowdsec_status_read($path), 'before-state: a positive frequency reads');

		file_put_contents($path, self::statusJson(['update_frequency_seconds' => 0]));
		$this->assertNull(pfb_crowdsec_status_read($path));
	}

	public function testAValidDocumentOverOneMebibyteIsRefused(): void
	{
		$path = "{$this->root}/status.json";
		$json = self::statusJson();
		file_put_contents($path, $json . str_repeat(' ', PFB_CROWDSEC_STATUS_MAX - strlen($json)));
		$this->assertIsArray(pfb_crowdsec_status_read($path), 'before-state: exactly the limit, trailing spaces and all, reads');

		file_put_contents($path, $json . str_repeat(' ', PFB_CROWDSEC_STATUS_MAX - strlen($json) + 1));
		$this->assertNull(pfb_crowdsec_status_read($path), 'one byte over the limit');
	}

	public function testAFileFromTheFutureIsStaleBeyondOneInterval(): void
	{
		$status = ['updated_at' => 1000, 'update_frequency_seconds' => 10];

		$this->assertTrue(pfb_crowdsec_status_fresh($status, 990), 'one interval ahead: a clock a little behind the writer');
		$this->assertFalse(pfb_crowdsec_status_fresh($status, 989), 'more than one interval ahead');
		$this->assertFalse(pfb_crowdsec_status_fresh(['updated_at' => PHP_INT_MAX, 'update_frequency_seconds' => 10], 1000));
	}

	// ---- the log ----------------------------------------------------------------------------

	public function testOnlyTheLogsLastMebibyteIsReadAndNotTheLineItStartsIn(): void
	{
		$log = "{$this->root}/system.log";
		$old = "Nov 19 09:00:00 pfSense pfb_crowdsec[1]: level=info msg=too old\n";
		$filler = str_repeat("Nov 19 09:30:00 pfSense php-fpm[7]: filler\n", 30000);
		// The forged text sits inside another program's line, starting exactly where the read may start: at the window or a byte before it
		$forged = "Nov 19 10:00:00 pfSense pfb_crowdsec[1]: level=error msg=FORGED\n";
		$real = "Nov 19 10:00:01 pfSense pfb_crowdsec[2]: level=info msg=REAL\n";
		foreach ([PFB_CROWDSEC_LOG_WINDOW, PFB_CROWDSEC_LOG_WINDOW + 1] as $from) {
			$tail = $forged . str_repeat("Nov 19 10:00:00 pfSense php-fpm[7]: filler\n", 20000);
			$tail .= str_repeat('x', $from - strlen($tail) - strlen($real) - 1) . "\n" . $real;
			$this->assertSame($from, strlen($tail), 'fixture: the forged text starts that many bytes before the end');
			file_put_contents($log, $old . $filler . 'Nov 19 10:00:00 pfSense php-fpm[7]: /index.php: user input ' . $tail);

			$this->assertSame(['Nov 19 10:00:01 pfSense pfb_crowdsec[2]: level=info msg=REAL'], pfb_crowdsec_log_tail($log), "forged at -{$from}");
		}

		file_put_contents($log, $old . $real);
		$this->assertSame([rtrim($old), rtrim($real)], pfb_crowdsec_log_tail($log), 'a log inside the window is read from its first line');
	}


	public function testTheLogShowsTheLastFiftyLinesTaggedPfbCrowdsecInEitherFormat(): void
	{
		$log = "{$this->root}/system.log";
		$lines = ['Nov 19 09:59:59 pfSense pfb_crowdsec_other[1]: level=info msg=not ours'];
		for ($i = 1; $i <= 60; $i++) {
			$lines[] = sprintf('Nov %2d 10:00:%02d pfSense pfb_crowdsec[42]: level=info msg=pull %d', 9, $i % 60, $i);
			$lines[] = "Nov 19 10:00:00 pfSense php-fpm[7]: /index.php: pfb_crowdsec[42]: msg=quoted {$i}";
		}
		$lines[] = '<30>1 2026-11-19T10:01:00.123+00:00 pfSense.home.arpa pfb_crowdsec 42 - - level=error msg=rfc5424';
		$lines[] = '<30>1 2026-11-19T10:01:01+00:00 pfSense.home.arpa pfb_crowdsecd 43 - - level=error msg=not ours';
		file_put_contents($log, implode("\n", $lines) . "\n");

		$tail = pfb_crowdsec_log_tail($log);

		$this->assertCount(50, $tail);
		$this->assertStringEndsWith('msg=pull 12', $tail[0], 'the oldest of the last 50');
		$this->assertStringEndsWith('msg=pull 60', $tail[48]);
		$this->assertStringEndsWith('msg=rfc5424', $tail[49]);
		$this->assertSame([], array_filter($tail, static fn (string $l): bool => str_contains($l, 'not ours') || str_contains($l, 'quoted')));
		$this->assertSame([], pfb_crowdsec_log_tail("{$this->root}/absent.log"));
	}

	// ---- a table's contents -----------------------------------------------------------------

	public function testATableIsListedFromPfctlAndAFailureIsNull(): void
	{
		$GLOBALS['pfb']['pfctl'] = "{$this->root}/pfctl";
		file_put_contents($GLOBALS['pfb']['pfctl'], "#!/bin/sh\n[ \"\$2\" = crowdsec_v4 ] || { echo 'pfctl: Table does not exist.' >&2; exit 1; }\n"
		    . "printf '   192.0.2.1\\n   198.51.100.0/24\\n\\n'\n");
		chmod($GLOBALS['pfb']['pfctl'], 0755);

		$this->assertSame(['192.0.2.1', '198.51.100.0/24'], pfb_crowdsec_table_entries('crowdsec_v4'));
		$this->assertNull(pfb_crowdsec_table_entries('crowdsec_v6'));
	}
}
