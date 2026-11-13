<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

// The data providers run before setUpBeforeClass().
require_once __DIR__ . '/FeedParseCorpusFile.php';

/**
 * The per-feed parity corpus (issue #3976, go/pfb_core/feedparse/testdata/feed.json, schema in that directory's
 * README.md): whole feed files through the production loops, pfb_ip_parse_feed() and pfb_dnsbl_parse_feed(), and the
 * apply script's own empty-feed and de-duplication blocks, cut out of it and evaluated (they are inline code there). The
 * Go runner (feedparse/feed_corpus_test.go) replays the same file against Core's ParseIPFeed and ParseDNSBLFeed.
 *
 * The parse-error records and the parser's notices are read back from the log files the production code wrote, as an
 * operator reads them.
 */
#[CoversFunction('pfb_ip_parse_feed')]
#[CoversFunction('pfb_dnsbl_parse_feed')]
final class FeedParseFeedCorpusTest extends TestCase
{
	private const CORPUS = __DIR__ . '/../../go/pfb_core/feedparse/testdata/feed.json';
	private const APPLY = 'src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';
	private const HEADER = 'hdr';
	private const STAMP = '\d{4}-\d\d-\d\d \d\d:\d\d:\d\d';
	/** The smallest well-formed case of each list: the loader tests start from these and break one thing at a time. */
	private const WELL_IP = '{"id": "a", "description": "d", "config": {"vtype": "_v4", "pftype": "auto", "custom": false, "cidr_floor_v4": "Disabled", "cidr_floor_v6": "Disabled", "suppression": false, "placeholder": "127.1.7.7"}, "input": "1.2.3.4\n", "expect": {"out": "1.2.3.4\n", "parse_fail": 0, "suppressed": false, "details": [], "messages": [], "placeholder": ""}}';
	private const WELL_DNSBL = '{"id": "b", "description": "d", "config": {"dnsbl_ip": true, "lenient": true, "custom": false, "suppression": false}, "input": "a.example\n", "expect": {"out": "[\"d\",\"a.example\"]\n", "ip4": [], "ip6": [], "updateip": false, "scheme_skipped": 0, "stop": false, "details": []}}';

	private string $dir;
	private mixed $savedPfb = NULL;
	private string|false $savedLocale = FALSE;
	private string|false $savedLcAll = FALSE;

	public static function setUpBeforeClass(): void
	{
		require_once __DIR__ . '/PageStatementLoader.php';
		require_once dirname(__DIR__, 2) . '/' . self::APPLY;
	}

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_fpfeed_' . getmypid() . '_' . bin2hex(random_bytes(4));
		mkdir($this->dir, 0700, TRUE);
		$this->savedPfb = $GLOBALS['pfb'] ?? NULL;
		// ctype_print() and ctype_alnum() read LC_CTYPE; the appliance runs PHP under the C locale, and grep's character
		// classes (the empty-feed probe) follow the environment.
		$this->savedLocale = setlocale(LC_CTYPE, '0');
		setlocale(LC_CTYPE, 'C');
		$this->savedLcAll = getenv('LC_ALL');
		putenv('LC_ALL=C');
	}

	protected function tearDown(): void
	{
		foreach (glob("{$this->dir}/*") ?: [] as $f) {
			@unlink($f);
		}
		@rmdir($this->dir);
		$GLOBALS['pfb'] = $this->savedPfb;
		if ($this->savedLocale !== FALSE) {
			setlocale(LC_CTYPE, $this->savedLocale);
		}
		putenv($this->savedLcAll === FALSE ? 'LC_ALL' : "LC_ALL={$this->savedLcAll}");
	}

	/** @return array<string, mixed> */
	private static function corpus(): array
	{
		static $doc = NULL;
		if ($doc === NULL) {
			$doc = FeedParseCorpusFile::load(self::CORPUS, ['ip', 'dnsbl']);
			foreach ($doc['ip'] as $case) {
				self::checkIpCase($case);
			}
			foreach ($doc['dnsbl'] as $case) {
				self::checkDnsblCase($case);
			}
		}
		return $doc;
	}

	/** @param array<string, mixed> $case */
	private static function checkIpCase(array $case): void
	{
		$w = "case {$case['id']}";
		FeedParseCorpusFile::keys($case, array_merge(['id', 'description', 'config', 'expect'], self::inputKeys($case)), $w);
		FeedParseCorpusFile::keys($case['config'], ['vtype', 'pftype', 'custom', 'cidr_floor_v4', 'cidr_floor_v6', 'suppression', 'placeholder'], "{$w} config");
		$c = $case['config'];
		if (!in_array($c['vtype'], ['_v4', '_v6'], TRUE) || !in_array($c['pftype'], ['auto', 'regex'], TRUE) || !is_bool($c['custom'])
		    || !is_bool($c['suppression']) || !is_string($c['placeholder']) || $c['placeholder'] === '') {
			throw new RuntimeException("{$w} config: vtype, pftype, custom, suppression or placeholder is malformed");
		}
		foreach (['cidr_floor_v4', 'cidr_floor_v6'] as $k) {
			if (!is_string($c[$k]) || ($c[$k] !== 'Disabled' && preg_match('/^[0-9]+$/', $c[$k]) !== 1)) {
				throw new RuntimeException("{$w} config.{$k}: 'Disabled' or a decimal string");
			}
		}
		FeedParseCorpusFile::input($case, $w);
		$e = $case['expect'];
		FeedParseCorpusFile::keys($e, array_merge(['parse_fail', 'suppressed', 'details', 'messages', 'placeholder'], self::outKeys($e)), "{$w} expect");
		FeedParseCorpusFile::bytes($e, 'out', "{$w} expect");
		if (!is_int($e['parse_fail']) || !is_bool($e['suppressed']) || !in_array($e['placeholder'], ['', 'empty', 'suppressed'], TRUE)) {
			throw new RuntimeException("{$w} expect: parse_fail, suppressed or placeholder is malformed");
		}
		self::details($e['details'], "{$w} expect.details");
		if (!is_array($e['messages']) || !array_is_list($e['messages'])) {
			throw new RuntimeException("{$w} expect.messages: list expected");
		}
		foreach ($e['messages'] as $i => $m) {
			FeedParseCorpusFile::item($m, "{$w} expect.messages #{$i}");
		}
	}

	/** @param array<string, mixed> $case */
	private static function checkDnsblCase(array $case): void
	{
		$w = "case {$case['id']}";
		FeedParseCorpusFile::keys($case, array_merge(['id', 'description', 'config', 'expect'], self::inputKeys($case)), $w);
		FeedParseCorpusFile::flags($case['config'], ['dnsbl_ip', 'lenient', 'custom', 'suppression'], "{$w} config");
		FeedParseCorpusFile::input($case, $w);
		$e = $case['expect'];
		FeedParseCorpusFile::keys($e, array_merge(['ip4', 'ip6', 'updateip', 'scheme_skipped', 'stop', 'details'], self::outKeys($e)), "{$w} expect");
		FeedParseCorpusFile::bytes($e, 'out', "{$w} expect");
		foreach (['ip4', 'ip6'] as $k) {
			if (!is_array($e[$k]) || !array_is_list($e[$k]) || array_filter($e[$k], static fn($v): bool => !is_string($v) || $v === '') !== []) {
				throw new RuntimeException("{$w} expect.{$k}: list of non-empty strings expected");
			}
			if (count(array_unique($e[$k])) !== count($e[$k])) {
				throw new RuntimeException("{$w} expect.{$k}: the lists are de-duplicated");
			}
		}
		if (!is_bool($e['updateip']) || !is_bool($e['stop']) || !is_int($e['scheme_skipped'])) {
			throw new RuntimeException("{$w} expect: updateip, stop or scheme_skipped is malformed");
		}
		self::details($e['details'], "{$w} expect.details");
	}

	/** @param array<string, mixed> $case @return list<string> */
	private static function inputKeys(array $case): array
	{
		foreach (['input_parts', 'input_hex'] as $k) {
			if (array_key_exists($k, $case)) {
				return [$k];
			}
		}
		return ['input'];
	}

	/** @param array<string, mixed> $e @return list<string> */
	private static function outKeys(array $e): array
	{
		return [array_key_exists('out_hex', $e) ? 'out_hex' : 'out'];
	}

	private static function details(mixed $details, string $where): void
	{
		if (!is_array($details) || !array_is_list($details)) {
			throw new RuntimeException("{$where}: list expected");
		}
		$last = 0;
		foreach ($details as $i => $d) {
			FeedParseCorpusFile::keys($d, ['line_no', 'line', 'raw'], "{$where} #{$i}");
			if (!is_int($d['line_no']) || $d['line_no'] < $last || $d['line_no'] < 1) {
				throw new RuntimeException("{$where} #{$i}: line_no is a positive int, never smaller than the one before");
			}
			$last = $d['line_no'];
			FeedParseCorpusFile::item($d['line'], "{$where} #{$i} line");
			FeedParseCorpusFile::item($d['raw'], "{$where} #{$i} raw");
		}
	}

	/** @return array<string, array{array<string, mixed>}> */
	public static function ipCases(): array
	{
		$out = [];
		foreach (self::corpus()['ip'] as $case) {
			$out[$case['id']] = [$case];
		}
		return $out;
	}

	/** @return array<string, array{array<string, mixed>}> */
	public static function dnsblCases(): array
	{
		$out = [];
		foreach (self::corpus()['dnsbl'] as $case) {
			$out[$case['id']] = [$case];
		}
		return $out;
	}

	/** @param array<string, mixed> $case */
	#[DataProvider('ipCases')]
	public function testIpFeedMatchesTheProductionLoop(array $case): void
	{
		$e = $case['expect'];
		$want = [
			'out'         => FeedParseCorpusFile::bytes($e, 'out', ''),
			'parse_fail'  => $e['parse_fail'],
			'suppressed'  => $e['suppressed'],
			'details'     => self::wantDetails($e['details']),
			'messages'    => array_map(static fn($m): string => FeedParseCorpusFile::item($m, ''), $e['messages']),
			'placeholder' => $e['placeholder'],
		];
		$this->assertSame($want, $this->replayIp($case), "{$case['id']}: {$case['description']}");
	}

	/** @param array<string, mixed> $case */
	#[DataProvider('dnsblCases')]
	public function testDnsblFeedMatchesTheProductionLoop(array $case): void
	{
		$e = $case['expect'];
		$want = [
			'out'            => FeedParseCorpusFile::bytes($e, 'out', ''),
			'ip4'            => $e['ip4'],
			'ip6'            => $e['ip6'],
			'updateip'       => $e['updateip'],
			'scheme_skipped' => $e['scheme_skipped'],
			'stop'           => $e['stop'],
			'details'        => self::wantDetails($e['details']),
		];
		$this->assertSame($want, $this->replayDnsbl($case), "{$case['id']}: {$case['description']}");
	}

	/**
	 * A corpus the runner would read as a different corpus is a test error: the loader rejects every malformed shape.
	 *
	 * @return array<string, array{string}>
	 */
	public static function malformedProvider(): array
	{
		$ip = self::WELL_IP;
		$dn = self::WELL_DNSBL;
		$doc = static fn(string $ip, string $dn): string => '{"schema": 1, "ip": [' . $ip . '], "dnsbl": [' . $dn . ']}';
		return [
			'unknown top key'       => [str_replace('"schema": 1', '"schema": 1, "x": 1', $doc($ip, $dn))],
			'schema 2'              => [str_replace('"schema": 1', '"schema": 2', $doc($ip, $dn))],
			'empty dnsbl list'      => [$doc($ip, '')],
			'duplicate id'          => [$doc($ip, str_replace('"id": "b"', '"id": "a"', $dn))],
			'empty description'     => [$doc(str_replace('"description": "d"', '"description": ""', $ip), $dn)],
			'unknown case key'      => [$doc(str_replace('"input": "1.2.3.4\n",', '"input": "1.2.3.4\n", "x": 1,', $ip), $dn)],
			'input and input_hex'   => [$doc(str_replace('"input": "1.2.3.4\n",', '"input": "1.2.3.4\n", "input_hex": "ff",', $ip), $dn)],
			'input_hex is UTF-8'    => [$doc(str_replace('"input": "1.2.3.4\n",', '"input_hex": "61",', $ip), $dn)],
			'upper-case hex'        => [$doc(str_replace('"input": "1.2.3.4\n",', '"input_hex": "FF",', $ip), $dn)],
			'unknown config key'    => [$doc(str_replace('"custom": false,', '"custom": false, "x": 1,', $ip), $dn)],
			'bad vtype'             => [$doc(str_replace('"_v4"', '"_v5"', $ip), $dn)],
			'bad floor'             => [$doc(str_replace('"cidr_floor_v4": "Disabled"', '"cidr_floor_v4": "x"', $ip), $dn)],
			'empty placeholder'     => [$doc(str_replace('"127.1.7.7"', '""', $ip), $dn)],
			'unknown expect key'    => [$doc(str_replace('"parse_fail": 0,', '"parse_fail": 0, "x": 1,', $ip), $dn)],
			'missing expect key'    => [$doc(str_replace('"suppressed": false, ', '', $ip), $dn)],
			'bad placeholder name'  => [$doc(str_replace('"placeholder": ""}', '"placeholder": "x"}', $ip), $dn)],
			'out and out_hex'       => [$doc(str_replace('"out": "1.2.3.4\n",', '"out": "1.2.3.4\n", "out_hex": "ff",', $ip), $dn)],
			'detail unknown key'    => [$doc(str_replace('"details": []', '"details": [{"line_no": 1, "line": "a", "raw": "a", "x": 1}]', $ip), $dn)],
			'detail line_no 0'      => [$doc(str_replace('"details": []', '"details": [{"line_no": 0, "line": "a", "raw": "a"}]', $ip), $dn)],
			'detail order'          => [$doc(str_replace('"details": []', '"details": [{"line_no": 2, "line": "a", "raw": "a"}, {"line_no": 1, "line": "a", "raw": "a"}]', $ip), $dn)],
			'unknown dnsbl config'  => [$doc($ip, str_replace('"custom": false,', '"custom": false, "x": true,', $dn))],
			'dnsbl flag not a bool' => [$doc($ip, str_replace('"lenient": true', '"lenient": 1', $dn))],
			'dnsbl ip not unique'   => [$doc($ip, str_replace('"ip4": []', '"ip4": ["1.2.3.4", "1.2.3.4"]', $dn))],
			'dnsbl missing stop'    => [$doc($ip, str_replace('"stop": false, ', '', $dn))],
			'repeat count 0'        => [$doc(str_replace('"input": "1.2.3.4\n",', '"input_parts": [{"repeat": "a", "count": 0}],', $ip), $dn)],
			'parts with input'      => [$doc(str_replace('"input": "1.2.3.4\n",', '"input": "a", "input_parts": ["a"],', $ip), $dn)],
		];
	}

	public function testLoaderAcceptsAWellFormedDocument(): void
	{
		$doc = FeedParseCorpusFile::load(self::tempCorpus('{"schema": 1, "ip": [' . self::WELL_IP . '], "dnsbl": [' . self::WELL_DNSBL . ']}'), ['ip', 'dnsbl']);
		self::checkIpCase($doc['ip'][0]);
		self::checkDnsblCase($doc['dnsbl'][0]);
		$this->addToAssertionCount(1);
	}

	#[DataProvider('malformedProvider')]
	public function testLoaderIsStrict(string $json): void
	{
		$this->expectException(RuntimeException::class);
		$doc = FeedParseCorpusFile::load(self::tempCorpus($json), ['ip', 'dnsbl']);
		foreach ($doc['ip'] as $case) {
			self::checkIpCase($case);
		}
		foreach ($doc['dnsbl'] as $case) {
			self::checkDnsblCase($case);
		}
	}

	private static function tempCorpus(string $json): string
	{
		$path = tempnam(sys_get_temp_dir(), 'pfb_fpfeed_doc_');
		if ($path === FALSE || file_put_contents($path, $json) === FALSE) {
			throw new RuntimeException('cannot write the scratch corpus');
		}
		register_shutdown_function(static fn() => @unlink($path));
		return $path;
	}

	/**
	 * @param list<array{line_no: int, line: mixed, raw: mixed}> $details
	 * @return list<array{line_no: int, line: string, raw: string}>
	 */
	private static function wantDetails(array $details): array
	{
		return array_map(static fn(array $d): array => [
			'line_no' => $d['line_no'],
			'line'    => FeedParseCorpusFile::item($d['line'], ''),
			'raw'     => FeedParseCorpusFile::item($d['raw'], ''),
		], $details);
	}

	/** One whole IP feed through the production loop and the apply script's empty-feed block. @return array<string, mixed> */
	private function replayIp(array $case): array
	{
		$c = $case['config'];
		$input = FeedParseCorpusFile::input($case, '');
		$path = "{$this->dir}/feed.in";
		file_put_contents($path, $input);
		$fail = "{$this->dir}/parse_err.log";
		$main = "{$this->dir}/main.log";
		file_put_contents($fail, '');
		file_put_contents($main, '');
		$grep = trim((string) shell_exec('command -v grep'));
		if ($grep === '') {
			$this->markTestSkipped('grep not found on PATH: the empty-feed probe needs it');
		}
		$pfb = [
			'log' => $main, 'errlog' => "{$this->dir}/err.log", 'supp' => $c['suppression'] ? PfbToggle::On : PfbToggle::Off,
			'ip_parse_err' => $fail, 'ip_ph' => $c['placeholder'], 'grep' => $grep,
		] + pfb_ip_regex_config();
		$GLOBALS['pfb'] = $pfb;

		return $this->withDiagnosticsAsErrors(function () use ($c, $input, $path, $fail, $main, $pfb): array {
			$fh = fopen($path, 'r');
			$r = pfb_ip_parse_feed($fh, self::HEADER, ['vtype' => $c['vtype']], $c['pftype'], $c['custom'], $c['cidr_floor_v4'], $c['cidr_floor_v6'], $pfb);
			fclose($fh);
			$messages = $this->loggedMessages($main);
			$details = $this->failRecords((string) file_get_contents($fail), $input);
			file_put_contents($main, '');

			// The apply script's own block: the emptiness probe of the parsed file, then both placeholders.
			$scope = pfb_test_page_eval(
				pfb_test_page_region(self::APPLY, '$file_chk = pfb_ip_script_probe_staged(', 'if (!empty($ip_data)) {'),
				[
					'custom' => $c['custom'], 'pfb_parse_path' => $path, 'pfb_staged_path' => NULL, 'pfb_norm' => ['path' => "{$this->dir}/none.norm"],
					'file_dwn' => "{$this->dir}/feed", 'pfb' => $pfb, 'ip_data' => $r['ip_data'], 'ip_suppressed' => $r['ip_suppressed'],
					'list' => ['vtype' => $c['vtype']],
				]
			);
			$log = (string) file_get_contents($main);
			$placeholder = str_contains($log, 'Empty file, Adding') ? 'empty' : (str_contains($log, 'All IPv6 entries suppressed') ? 'suppressed' : '');
			return [
				'out'         => $scope['ip_data'],
				'parse_fail'  => $r['parse_fail'],
				'suppressed'  => $r['ip_suppressed'],
				'details'     => $details,
				'messages'    => $messages,
				'placeholder' => $placeholder,
			];
		});
	}

	/** One whole DNSBL feed through the production loop and the apply script's IP de-duplication block. @return array<string, mixed> */
	private function replayDnsbl(array $case): array
	{
		$c = $case['config'];
		$input = FeedParseCorpusFile::input($case, '');
		$path = "{$this->dir}/feed.in";
		$bk = "{$this->dir}/" . self::HEADER . '.bk';
		$fail = "{$this->dir}/parse_err.log";
		file_put_contents($path, $input);
		file_put_contents($fail, '');
		$GLOBALS['pfb'] = ['log' => "{$this->dir}/main.log", 'errlog' => "{$this->dir}/err.log", 'supp' => $c['suppression'] ? PfbToggle::On : PfbToggle::Off];

		return $this->withDiagnosticsAsErrors(function () use ($c, $input, $path, $bk, $fail): array {
			$state = pfb_dnsbl_parse_state();
			$ctx = ['header' => self::HEADER, 'custom' => $c['custom'], 'dnsbl_ip' => $c['dnsbl_ip'], 'lenient' => $c['lenient'], 'parse_err' => $fail];
			$fh = fopen($path, 'r');
			$out = fopen($bk, 'w');
			$r = pfb_dnsbl_parse_feed($fh, $out, $state, $ctx);
			fclose($fh);
			fclose($out);

			pfb_test_page_eval(
				pfb_test_page_region(self::APPLY, '// Remove duplicates and save any IPs found in domain feed', '// Validate feed with Unbound-checkconf'),
				['pfbfolder' => $this->dir, 'header' => self::HEADER, 'domain_data_ip' => $state['ip4'], 'domain_data_ip6' => $state['ip6']]
			);
			return [
				'out'            => (string) file_get_contents($bk),
				'ip4'            => $this->ipFile("{$this->dir}/" . self::HEADER . '_v4.ip'),
				'ip6'            => $this->ipFile("{$this->dir}/" . self::HEADER . '_v6.ip'),
				'updateip'       => $state['updateip'],
				'scheme_skipped' => $state['scheme_skipped'],
				'stop'           => $r['stop'],
				'details'        => $this->failRecords((string) file_get_contents($fail), $input),
			];
		});
	}

	/** @return list<string> */
	private function ipFile(string $path): array
	{
		return is_file($path) ? explode("\n", substr((string) file_get_contents($path), 0, -1)) : [];
	}

	/** Run $body with every PHP diagnostic the code did not silence raised as an exception: a warning is a defect in the old path, not a result. */
	private function withDiagnosticsAsErrors(callable $body): mixed
	{
		set_error_handler(static function (int $no, string $str): bool {
			// A deprecation and a diagnostic the code itself silenced with @ are not results.
			if (($no & (E_DEPRECATED | E_USER_DEPRECATED)) !== 0 || (error_reporting() & $no) === 0) {
				return TRUE;
			}
			throw new RuntimeException("PHP diagnostic while replaying: {$str}");
		});
		try {
			return $body();
		} finally {
			restore_error_handler();
		}
	}

	/**
	 * The notices pfb_logger() wrote to the main log, unstamped: each one opens with "\n", and the stamp follows it.
	 *
	 * @return list<string>
	 */
	private function loggedMessages(string $log): array
	{
		$chunks = preg_split('/\n' . self::STAMP . ' /', (string) file_get_contents($log));
		if ($chunks === FALSE || array_shift($chunks) !== '') {
			throw new RuntimeException('unexpected main log: ' . json_encode((string) file_get_contents($log), JSON_INVALID_UTF8_SUBSTITUTE));
		}
		return array_map(static fn(string $c): string => "\n{$c}", $chunks);
	}

	/**
	 * The parse-error records: "{stamp},{header},{line},{oline},{lineno}\n", where oline is the input line without its
	 * trailing CR and LF and lineno names it, so each record splits at the one tail that names a line of the input.
	 *
	 * @return list<array{line_no: int, line: string, raw: string}>
	 */
	private function failRecords(string $log, string $input): array
	{
		$lines = preg_split('/(?<=\n)/', $input, -1, PREG_SPLIT_NO_EMPTY);
		$head = '/^' . self::STAMP . ',' . preg_quote(self::HEADER, '/') . ',/';
		$records = [];
		$from = 1;
		while ($log !== '') {
			if (preg_match($head, $log, $m) !== 1) {
				throw new RuntimeException('unexpected parse-error record: ' . json_encode($log, JSON_INVALID_UTF8_SUBSTITUTE));
			}
			$rest = substr($log, strlen($m[0]));
			$best = NULL;
			for ($n = $from; $n <= count($lines); $n++) {
				$raw = rtrim($lines[$n - 1], "\r\n");
				$tail = ",{$raw},{$n}\n";
				$p = strpos($rest, $tail);
				if ($p !== FALSE && ($best === NULL || $p < $best[0])) {
					$best = [$p, $n, $raw, strlen($tail)];
				}
			}
			if ($best === NULL) {
				throw new RuntimeException('parse-error record names no line of the input: ' . json_encode($log, JSON_INVALID_UTF8_SUBSTITUTE));
			}
			[$p, $n, $raw, $tailLen] = $best;
			$records[] = ['line_no' => $n, 'line' => substr($rest, 0, $p), 'raw' => $raw];
			$log = substr($rest, $p + $tailLen);
			$from = $n;
		}
		return $records;
	}
}
