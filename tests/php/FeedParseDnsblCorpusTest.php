<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Replays go/pfb_core/feedparse/testdata/dnsbl.json (issue #3906) through the production per-line DNSBL parser,
 * pfb_dnsbl_parse_line(). The Go runner replays the same file against Core's port; the two must agree line for line.
 * The file's schema is documented in testdata/README.md; every unknown or missing key and every duplicate id is an error.
 */
final class FeedParseDnsblCorpusTest extends TestCase
{
	private const CORPUS = __DIR__ . '/../../go/pfb_core/feedparse/testdata/dnsbl.json';
	private const HEADER = 'hdr';

	private string $failLog = '';
	private string $mainLog = '';
	private mixed $savedPfb = NULL;
	private string|false $savedLocale = FALSE;

	protected function setUp(): void
	{
		$this->failLog = (string) tempnam(sys_get_temp_dir(), 'pfb_corpus_fail_');
		$this->mainLog = (string) tempnam(sys_get_temp_dir(), 'pfb_corpus_log_');
		$this->savedPfb = $GLOBALS['pfb'] ?? NULL;
		// ctype_print() and ctype_alnum() read LC_CTYPE; the appliance runs PHP under the C locale.
		$this->savedLocale = setlocale(LC_CTYPE, '0');
		setlocale(LC_CTYPE, 'C');
	}

	protected function tearDown(): void
	{
		@unlink($this->failLog);
		@unlink($this->mainLog);
		$GLOBALS['pfb'] = $this->savedPfb;
		if ($this->savedLocale !== FALSE) {
			setlocale(LC_CTYPE, $this->savedLocale);
		}
	}

	/** @return array<string, array{array<string, mixed>}> */
	public static function caseProvider(): array
	{
		$json = file_get_contents(self::CORPUS);
		if ($json === FALSE) {
			throw new RuntimeException('corpus unreadable: ' . self::CORPUS);
		}
		$doc = json_decode($json, TRUE, 512, JSON_THROW_ON_ERROR);
		self::keys($doc, ['schema', 'cases'], 'file');
		if ($doc['schema'] !== 1 || !is_array($doc['cases']) || $doc['cases'] === []) {
			throw new RuntimeException('corpus: schema must be 1 with a non-empty cases list');
		}
		$out = [];
		foreach ($doc['cases'] as $i => $case) {
			$where = "case #{$i}";
			self::keys($case, ['id', 'description', 'config', 'lines'], $where);
			if (!is_string($case['id']) || $case['id'] === '' || !is_string($case['description']) || $case['description'] === '') {
				throw new RuntimeException("{$where}: id and description must be non-empty strings");
			}
			$where = "case {$case['id']}";
			if (isset($out[$case['id']])) {
				throw new RuntimeException("{$where}: duplicate id");
			}
			self::keys($case['config'], ['dnsbl_ip', 'lenient', 'custom', 'suppression'], "{$where} config");
			foreach ($case['config'] as $k => $v) {
				if (!is_bool($v)) {
					throw new RuntimeException("{$where} config.{$k}: must be a bool");
				}
			}
			if (!is_array($case['lines']) || $case['lines'] === []) {
				throw new RuntimeException("{$where}: lines must be a non-empty list");
			}
			$last = count($case['lines']) - 1;
			foreach ($case['lines'] as $n => $line) {
				$lw = "{$where} line {$n}";
				self::keys($line, array_key_exists('line_hex', $line) ? ['line_hex', 'expect'] : ['line', 'expect'], $lw);
				self::feedBytes($line, $lw);
				self::keys($line['expect'], ['rows', 'ip4', 'ip6', 'fail', 'scheme_skipped', 'stop'], "{$lw} expect");
				$e = $line['expect'];
				if (!is_bool($e['stop']) || !is_int($e['scheme_skipped']) || !is_array($e['rows']) || !is_array($e['ip4'])
				    || !is_array($e['ip6']) || !is_array($e['fail'])) {
					throw new RuntimeException("{$lw}: expect has a field of the wrong type");
				}
				if ($e['stop'] && $n !== $last) {
					throw new RuntimeException("{$lw}: nothing is read after a stop");
				}
			}
			$out[$case['id']] = [$case];
		}
		return $out;
	}

	/** @param array<string, mixed> $case */
	#[DataProvider('caseProvider')]
	public function testCaseMatchesTheProductionParser(array $case): void
	{
		$cfg = $case['config'];
		$GLOBALS['pfb']['supp'] = $cfg['suppression'] ? PfbToggle::On : PfbToggle::Off;
		$GLOBALS['pfb']['log'] = $this->mainLog;
		$ctx = [
			'header'    => self::HEADER,
			'custom'    => $cfg['custom'],
			'dnsbl_ip'  => $cfg['dnsbl_ip'],
			'lenient'   => $cfg['lenient'],
			'parse_err' => $this->failLog,
		];
		$state = pfb_dnsbl_parse_state();
		$problems = [];
		foreach ($case['lines'] as $n => $line) {
			$raw = self::feedBytes($line, '');
			file_put_contents($this->failLog, '');
			$ip4 = count($state['ip4']);
			$ip6 = count($state['ip6']);
			$skipped = $state['scheme_skipped'];
			$res = pfb_dnsbl_parse_line($raw, $n + 1, $state, $ctx);
			$actual = [
				'rows'           => $res['row'] === NULL ? [] : [json_decode(rtrim($res['row'], "\n"), TRUE, 512, JSON_THROW_ON_ERROR)],
				'ip4'            => array_slice($state['ip4'], $ip4),
				'ip6'            => array_slice($state['ip6'], $ip6),
				'fail'           => $this->failFields($raw, $n + 1),
				'scheme_skipped' => $state['scheme_skipped'] - $skipped,
				'stop'           => $res['stop'],
			];
			$expect = $line['expect'];
			$expect['fail'] = array_map(static fn($f) => is_array($f) ? hex2bin($f['hex']) : $f, $expect['fail']);
			foreach ($expect as $field => $want) {
				if ($want !== $actual[$field]) {
					$problems[] = sprintf("line %d %s\n    expected %s\n    actual   %s", $n, self::show($raw), "{$field} = " . self::show($want), self::show($actual[$field]));
				}
			}
		}
		$this->assertSame([], $problems, "case {$case['id']}:\n  " . implode("\n  ", array_slice($problems, 0, 12)));
	}

	/**
	 * The `line` field of every pfb_parse_fail_log() record written for one input line: the record is
	 * "{timestamp},{header},{line},{oline},{lineno}\n" and oline and lineno are known.
	 *
	 * @return list<string>
	 */
	private function failFields(string $raw, int $lineno): array
	{
		$log = (string) file_get_contents($this->failLog);
		$tail = ',' . rtrim($raw, "\r\n") . ',' . $lineno . "\n";
		$head = '/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,' . preg_quote(self::HEADER, '/') . ',/';
		$fields = [];
		while ($log !== '') {
			if (preg_match($head, $log, $m) !== 1) {
				throw new RuntimeException('unexpected parse-failure record: ' . json_encode($log, JSON_INVALID_UTF8_SUBSTITUTE));
			}
			$rest = substr($log, strlen($m[0]));
			$p = strpos($rest, $tail);
			if ($p === FALSE) {
				throw new RuntimeException('parse-failure record does not end with the input line: ' . json_encode($log, JSON_INVALID_UTF8_SUBSTITUTE));
			}
			$fields[] = substr($rest, 0, $p);
			$log = substr($rest, $p + strlen($tail));
		}
		return $fields;
	}

	/** @param array<mixed> $arr @param list<string> $keys */
	private static function keys(mixed $arr, array $keys, string $where): void
	{
		if (!is_array($arr)) {
			throw new RuntimeException("{$where}: object expected");
		}
		$have = array_keys($arr);
		sort($have);
		sort($keys);
		if ($have !== $keys) {
			throw new RuntimeException("{$where}: keys [" . implode(',', $have) . '] must be exactly [' . implode(',', $keys) . ']');
		}
	}

	/** The feed bytes of a line object: a text key, or the hex key when (and only when) the bytes are not UTF-8. */
	private static function feedBytes(array $line, string $where): string
	{
		if (array_key_exists('line_hex', $line)) {
			$raw = is_string($line['line_hex']) && preg_match('/^(?:[0-9a-f]{2})+$/', $line['line_hex']) === 1 ? hex2bin($line['line_hex']) : FALSE;
			if ($raw === FALSE || mb_check_encoding($raw, 'UTF-8')) {
				throw new RuntimeException("{$where}: line_hex must be lower-case hex of bytes that are not UTF-8");
			}
			return $raw;
		}
		if (!is_string($line['line'])) {
			throw new RuntimeException("{$where}: line must be a string");
		}
		return $line['line'];
	}

	private static function show(mixed $v): string
	{
		return json_encode($v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR);
	}
}
