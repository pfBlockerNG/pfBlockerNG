<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The feed parse parity corpus for IP feed lines (issue #3906, schema in
 * go/pfb_core/feedparse/testdata/README.md): the old path replayed line for line.
 * The Go runner (feedparse/ip_corpus_test.go) replays the same file against Core.
 *
 * Each row runs through the production pfb_ip_parse_line_replay(); the parser type of a
 * feed URL runs through the production dispatch block itself, cut out of the apply
 * script, because it is inline code there and not a function.
 */
#[CoversFunction('pfb_ip_parse_line')]
#[CoversFunction('pfb_ip_parse_line_replay')]
final class FeedParseIpCorpusTest extends TestCase
{
	private const CORPUS = __DIR__ . '/../../go/pfb_core/feedparse/testdata/ip.json';
	private const APPLY = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';

	/** @return array<string, mixed> */
	private static function corpus(): array
	{
		static $corpus = NULL;
		if ($corpus === NULL) {
			$corpus = json_decode((string) file_get_contents(self::CORPUS), TRUE, 512, JSON_THROW_ON_ERROR);
			self::validate($corpus);
		}
		return $corpus;
	}

	/** The loader is strict: an unknown or missing key and a duplicate id are errors, never skips. */
	private static function validate(mixed $corpus): void
	{
		self::exactKeys($corpus, ['schema', 'cases', 'types'], 'corpus');
		self::check($corpus['schema'] === 1, 'schema must be 1');
		self::check(is_array($corpus['cases']) && $corpus['cases'] !== [] && array_is_list($corpus['cases']), 'cases must be a non-empty list');
		self::check(is_array($corpus['types']) && $corpus['types'] !== [] && array_is_list($corpus['types']), 'types must be a non-empty list');
		$seen = [];
		foreach ($corpus['cases'] as $case) {
			self::checkCase($case, $seen);
		}
		$seen = [];
		foreach ($corpus['types'] as $type) {
			self::exactKeys($type, ['id', 'description', 'format', 'url', 'expect'], 'type');
			self::checkId($type, $seen);
			self::check(is_string($type['format']) && is_string($type['url']), "type {$type['id']}: format and url are strings");
			self::check(in_array($type['expect'], ['auto', 'regex'], TRUE), "type {$type['id']}: expect is auto or regex");
		}
	}

	private static function check(bool $ok, string $what): void
	{
		if (!$ok) {
			throw new RuntimeException("ip.json: {$what}");
		}
	}

	/** @param array<mixed> $a @param list<string> $keys */
	private static function exactKeys(mixed $a, array $keys, string $what): void
	{
		self::check(is_array($a), "{$what} must be an object");
		$have = array_keys($a);
		sort($have);
		sort($keys);
		self::check($have === $keys, "{$what}: keys " . json_encode($have) . ' must be exactly ' . json_encode($keys));
	}

	/** @param array<string, mixed> $row @param array<string, true> $seen */
	private static function checkId(array $row, array &$seen): void
	{
		self::check(is_string($row['id']) && $row['id'] !== '', 'id must be a non-empty string');
		self::check(is_string($row['description']) && $row['description'] !== '', "{$row['id']}: description must be a non-empty string");
		self::check(!isset($seen[$row['id']]), "duplicate id {$row['id']}");
		$seen[$row['id']] = TRUE;
	}

	/** @param array<string, true> $seen */
	private static function checkCase(mixed $case, array &$seen): void
	{
		self::exactKeys($case, ['id', 'description', 'config', 'rows'], 'case');
		self::checkId($case, $seen);
		$id = $case['id'];
		self::exactKeys($case['config'], ['vtype', 'pftype', 'custom', 'cidr_floor_v4', 'cidr_floor_v6', 'suppression'], "{$id} config");
		$c = $case['config'];
		self::check(in_array($c['vtype'], ['_v4', '_v6'], TRUE) && in_array($c['pftype'], ['auto', 'regex'], TRUE), "{$id}: vtype/pftype");
		self::check(is_bool($c['custom']) && is_bool($c['suppression']), "{$id}: custom and suppression are booleans");
		self::check(is_string($c['cidr_floor_v4']) && is_string($c['cidr_floor_v6']), "{$id}: floors are strings");
		self::check(is_array($case['rows']) && $case['rows'] !== [] && array_is_list($case['rows']), "{$id}: rows must be a non-empty list");
		foreach ($case['rows'] as $n => $row) {
			self::check(is_array($row) && count($row) === 2 && isset($row['expect']), "{$id} row {$n}: line and expect");
			self::check(array_key_exists('line', $row) !== array_key_exists('line_hex', $row), "{$id} row {$n}: exactly one of line, line_hex");
			self::check(array_key_exists('line', $row) ? is_string($row['line']) : (is_string($row['line_hex']) && preg_match('/^(?:[0-9a-f]{2})*$/', $row['line_hex']) === 1), "{$id} row {$n}: line bytes");
			$e = $row['expect'];
			self::check(is_array($e), "{$id} row {$n}: expect object");
			$keys = ['entries', 'suppressed', 'parse_fail', 'detailed_parse_fail'];
			$keys[] = array_key_exists('line', $e) ? 'line' : 'line_hex';
			$keys[] = array_key_exists('messages', $e) ? 'messages' : 'messages_hex';
			self::exactKeys($e, $keys, "{$id} row {$n} expect");
			self::check(is_array($e['entries']) && array_is_list($e['entries']), "{$id} row {$n}: entries list");
			self::check(is_bool($e['suppressed']) && is_bool($e['detailed_parse_fail']) && is_int($e['parse_fail']), "{$id} row {$n}: counters");
		}
	}

	private static function bytes(array $o, string $key): string
	{
		return array_key_exists($key, $o) ? $o[$key] : (string) hex2bin($o[$key . '_hex']);
	}

	/** @return array<string, array{array<string, mixed>}> */
	public static function caseProvider(): array
	{
		$cases = [];
		foreach (self::corpus()['cases'] as $case) {
			$cases[$case['id']] = [$case];
		}
		return $cases;
	}

	/** @return array<string, array{array<string, mixed>}> */
	public static function typeProvider(): array
	{
		$types = [];
		foreach (self::corpus()['types'] as $type) {
			$types[$type['id']] = [$type];
		}
		return $types;
	}

	/** One row as the replay returns it, in the corpus' own terms (bytes shown escaped). */
	private static function show(string $line, array $r): string
	{
		return json_encode(['line' => bin2hex($line) . ' ' . addcslashes($line, "\0..\37\177..\377"), 'entries' => $r['entries'], 'log' => addcslashes($r['line'], "\0..\37\177..\377"),
			'suppressed' => $r['suppressed'], 'parse_fail' => $r['parse_fail'], 'detailed_parse_fail' => $r['detailed_parse_fail'],
			'messages' => array_map(static fn(string $m): string => addcslashes($m, "\0..\37\177..\377"), $r['messages'])], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
	}

	/** @param array<string, mixed> $case */
	#[DataProvider('caseProvider')]
	public function testCase(array $case): void
	{
		$c = $case['config'];
		$config = pfb_ip_regex_config() + [
			'vtype'         => $c['vtype'],
			'pftype'        => $c['pftype'],
			'custom'        => $c['custom'],
			'cidr_floor_v4' => $c['cidr_floor_v4'],
			'cidr_floor_v6' => $c['cidr_floor_v6'],
			'suppression'   => $c['suppression'] ? 'on' : 'off',
		];
		$expected = [];
		$actual = [];
		set_error_handler(static function (int $no, string $str): bool {
			if (($no & (E_DEPRECATED | E_USER_DEPRECATED)) !== 0) {
				return TRUE;
			}
			throw new RuntimeException("PHP diagnostic while replaying: {$str}");
		});
		try {
			foreach ($case['rows'] as $n => $row) {
				$line = self::bytes($row, 'line');
				$e = $row['expect'];
				$expected[] = self::show($line, [
					'entries' => $e['entries'], 'line' => self::bytes($e, 'line'), 'suppressed' => $e['suppressed'], 'parse_fail' => $e['parse_fail'],
					'detailed_parse_fail' => $e['detailed_parse_fail'],
					'messages' => array_key_exists('messages', $e) ? $e['messages'] : array_map('hex2bin', $e['messages_hex']),
				]);
				$data = '';
				$r = pfb_ip_parse_line_replay($line, $config, 0, $data, FALSE, 0);
				$actual[] = self::show($line, [
					'entries' => $data === '' ? [] : explode("\n", substr($data, 0, -1)), 'line' => $r['line'], 'suppressed' => $r['ip_suppressed'],
					'parse_fail' => $r['parse_fail'], 'detailed_parse_fail' => $r['detailed_parse_fail'], 'messages' => $r['messages'],
				]);
			}
		} finally {
			restore_error_handler();
		}
		$this->assertSame($expected, $actual, "{$case['id']}: {$case['description']}");
	}

	/** The apply script's inline parser-type dispatch, cut out verbatim (it is not a function). */
	private static function dispatchSnippet(): string
	{
		static $snippet = NULL;
		if ($snippet === NULL) {
			$src = (string) file_get_contents(self::APPLY);
			$from = strpos($src, "// Set 'auto' format for all lists, except for lists that require 'regex' parsing.");
			$to = strpos($src, '// issue #1925: normalize once per file; the parse below reads .norm');
			self::check($from !== FALSE && $to !== FALSE && $from < $to, 'the parser-type dispatch block was not found in the apply script');
			$snippet = substr($src, $from, $to - $from);
		}
		return $snippet;
	}

	/** @param array<string, mixed> $type */
	#[DataProvider('typeProvider')]
	public function testParseType(array $type): void
	{
		$snippet = self::dispatchSnippet();
		$pftype = (static function (string $snippet, string $format, string $url): string {
			// The block reads an undefined array key for an extension-less URL, as it does in production.
			set_error_handler(static fn(): bool => TRUE);
			try {
				$row = ['format' => $format, 'url' => $url];
				eval($snippet);
			} finally {
				restore_error_handler();
			}
			return $pftype;
		})($snippet, $type['format'], $type['url']);
		$this->assertSame($type['expect'], $pftype, "{$type['id']}: {$type['description']} ({$type['format']} {$type['url']})");
	}

	/** @return array<string, array{string}> */
	public static function malformedProvider(): array
	{
		$row = '{"line": "1.2.3.4\n", "expect": {"entries": ["1.2.3.4"], "line": "1.2.3.4", "suppressed": false, "parse_fail": 0, "detailed_parse_fail": false, "messages": []}}';
		$config = '{"vtype": "_v4", "pftype": "auto", "custom": false, "cidr_floor_v4": "Disabled", "cidr_floor_v6": "Disabled", "suppression": false}';
		$case = static fn(string $id, string $extra = ''): string => '{"id": "' . $id . '", "description": "d", "config": ' . $config . ', "rows": [' . $row . ']' . $extra . '}';
		$type = '{"id": "t", "description": "d", "format": "auto", "url": "u", "expect": "auto"}';
		$doc = static fn(string $cases, string $types): string => '{"schema": 1, "cases": [' . $cases . '], "types": [' . $types . ']}';
		return [
			'unknown case key'    => [$doc($case('a', ', "extra": 1'), $type)],
			'duplicate id'        => [$doc($case('a') . ',' . $case('a'), $type)],
			'unknown config key'  => [$doc(str_replace('"custom": false', '"custom": false, "x": 1', $case('a')), $type)],
			'missing config key'  => [$doc(str_replace('"custom": false, ', '', $case('a')), $type)],
			'unknown expect key'  => [$doc(str_replace('"parse_fail": 0', '"parse_fail": 0, "x": 1', $case('a')), $type)],
			'missing expect key'  => [$doc(str_replace('"suppressed": false, ', '', $case('a')), $type)],
			'line and line_hex'   => [$doc(str_replace('{"line": "1.2.3.4\n",', '{"line": "1.2.3.4\n", "line_hex": "00",', $case('a')), $type)],
			'unknown row key'     => [$doc(str_replace('{"line": "1.2.3.4\n",', '{"x": 1, "line": "1.2.3.4\n",', $case('a')), $type)],
			'unknown type key'    => [$doc($case('a'), str_replace('"url": "u"', '"url": "u", "x": 1', $type))],
			'type duplicate id'   => [$doc($case('a'), $type . ',' . $type)],
			'unknown top key'     => [str_replace('"schema": 1', '"schema": 1, "x": 1', $doc($case('a'), $type))],
			'empty description'   => [$doc(str_replace('"description": "d"', '"description": ""', $case('a')), $type)],
			'upper-case hex line' => [$doc(str_replace('{"line": "1.2.3.4\n",', '{"line_hex": "0A",', $case('a')), $type)],
		];
	}

	public function testLoaderAcceptsAWellFormedDocument(): void
	{
		$row = '{"line": "1.2.3.4\n", "expect": {"entries": ["1.2.3.4"], "line": "1.2.3.4", "suppressed": false, "parse_fail": 0, "detailed_parse_fail": false, "messages": []}}';
		$config = '{"vtype": "_v4", "pftype": "auto", "custom": false, "cidr_floor_v4": "Disabled", "cidr_floor_v6": "Disabled", "suppression": false}';
		$type = '{"id": "t", "description": "d", "format": "auto", "url": "u", "expect": "auto"}';
		self::validate(json_decode('{"schema": 1, "cases": [{"id": "a", "description": "d", "config": ' . $config . ', "rows": [' . $row . ']}], "types": [' . $type . ']}', TRUE, 512, JSON_THROW_ON_ERROR));
		$this->addToAssertionCount(1);
	}

	#[DataProvider('malformedProvider')]
	public function testLoaderIsStrict(string $json): void
	{
		$this->expectException(RuntimeException::class);
		self::validate(json_decode($json, TRUE, 512, JSON_THROW_ON_ERROR));
	}
}
