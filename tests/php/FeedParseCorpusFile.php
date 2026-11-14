<?php

declare(strict_types=1);

/**
 * Strict reader of the per-feed parity corpus files (feed.json, normcache.json, prescript.json in
 * go/pfb_core/feedparse/testdata/, schema in that directory's README.md). An unknown or missing key, a duplicate id,
 * and a byte field in the wrong form are errors, never skips; the Go runners hold the same rules.
 */
final class FeedParseCorpusFile
{
	/**
	 * A corpus file: {"schema": 1} plus the non-empty case lists $lists, each case with a unique id and a non-empty description.
	 *
	 * @param list<string> $lists
	 * @return array<string, mixed>
	 */
	public static function load(string $file, array $lists): array
	{
		$json = file_get_contents($file);
		if ($json === FALSE) {
			throw new RuntimeException("corpus unreadable: {$file}");
		}
		$doc = json_decode($json, TRUE, 64, JSON_THROW_ON_ERROR);
		self::keys($doc, array_merge(['schema'], $lists), basename($file));
		if ($doc['schema'] !== 1) {
			throw new RuntimeException(basename($file) . ': schema must be 1');
		}
		$seen = [];
		foreach ($lists as $list) {
			if (!is_array($doc[$list]) || $doc[$list] === [] || !array_is_list($doc[$list])) {
				throw new RuntimeException(basename($file) . ": {$list} must be a non-empty list");
			}
			foreach ($doc[$list] as $i => $case) {
				if (!is_array($case) || !is_string($case['id'] ?? NULL) || $case['id'] === '' || !is_string($case['description'] ?? NULL) || $case['description'] === '') {
					throw new RuntimeException(basename($file) . ": {$list} #{$i} needs a non-empty id and description");
				}
				if (isset($seen[$case['id']])) {
					throw new RuntimeException(basename($file) . ": duplicate id {$case['id']}");
				}
				$seen[$case['id']] = TRUE;
			}
		}
		return $doc;
	}

	/** The key set of $o must be exactly $keys. @param list<string> $keys */
	public static function keys(mixed $o, array $keys, string $where): void
	{
		if (!is_array($o)) {
			throw new RuntimeException("{$where}: object expected");
		}
		$have = array_keys($o);
		sort($have);
		sort($keys);
		if ($have !== $keys) {
			throw new RuntimeException("{$where}: keys [" . implode(',', $have) . '] must be exactly [' . implode(',', $keys) . ']');
		}
	}

	/** A bool-only object with exactly the keys $keys. @param list<string> $keys */
	public static function flags(mixed $o, array $keys, string $where): void
	{
		self::keys($o, $keys, $where);
		foreach ($o as $k => $v) {
			if (!is_bool($v)) {
				throw new RuntimeException("{$where}.{$k}: must be a bool");
			}
		}
	}

	/** The bytes of field $key: a text key, or the lower-case hex key `{$key}_hex` when (and only when) they are not valid UTF-8. */
	public static function bytes(array $o, string $key, string $where): string
	{
		$text = array_key_exists($key, $o);
		$hex = array_key_exists("{$key}_hex", $o);
		if ($text === $hex) {
			throw new RuntimeException("{$where}: exactly one of {$key} and {$key}_hex is required");
		}
		if ($text) {
			if (!is_string($o[$key])) {
				throw new RuntimeException("{$where}: {$key} must be a string");
			}
			return $o[$key];
		}
		return self::hexBytes($o["{$key}_hex"], "{$where} {$key}_hex");
	}

	/** One list element holding bytes: a string, or {"hex": "..."} for bytes that are not valid UTF-8. */
	public static function item(mixed $v, string $where): string
	{
		if (is_string($v)) {
			return $v;
		}
		self::keys($v, ['hex'], $where);
		return self::hexBytes($v['hex'], "{$where} hex");
	}

	/** The feed bytes of a case: `input`, `input_hex`, or `input_parts` (strings and {"repeat": text, "count": n}). */
	public static function input(array $case, string $where): string
	{
		if (!array_key_exists('input_parts', $case)) {
			return self::bytes($case, 'input', $where);
		}
		if (array_key_exists('input', $case) || array_key_exists('input_hex', $case) || !is_array($case['input_parts']) || !array_is_list($case['input_parts'])) {
			throw new RuntimeException("{$where}: input_parts must be a list and the only input form");
		}
		$out = '';
		foreach ($case['input_parts'] as $i => $part) {
			if (is_string($part)) {
				$out .= $part;
				continue;
			}
			self::keys($part, ['repeat', 'count'], "{$where} input_parts #{$i}");
			if (!is_string($part['repeat']) || $part['repeat'] === '' || !is_int($part['count']) || $part['count'] < 1) {
				throw new RuntimeException("{$where} input_parts #{$i}: repeat is a non-empty string and count a positive int");
			}
			$out .= str_repeat($part['repeat'], $part['count']);
		}
		return $out;
	}

	private static function hexBytes(mixed $hex, string $where): string
	{
		$raw = is_string($hex) && preg_match('/^(?:[0-9a-f]{2})+$/', $hex) === 1 ? hex2bin($hex) : FALSE;
		if ($raw === FALSE || mb_check_encoding($raw, 'UTF-8')) {
			throw new RuntimeException("{$where} must be lower-case hex of bytes that are not valid UTF-8");
		}
		return $raw;
	}
}
