<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3906 (map #3813): replays the feed-normalize parity corpus, go/pfb_core/feedparse/testdata/normalize.json
 * (schema: that directory's README.md), through the REAL pfb_feed_normalize_generate() + pfb_ensure_trailing_newline(),
 * the old path that Core's Go port (feedparse.Normalize) must match byte for byte. The Go runner replays the same file.
 *
 * A case the old path answers per platform (`appliance`: FreeBSD C.UTF-8 class data) or per sed (an asserted result that
 * is not valid UTF-8 needs a sed passing invalid sequences through) is skipped where the host's probe differs.
 */
#[CoversFunction('pfb_feed_normalize_generate')]
#[CoversFunction('pfb_ensure_trailing_newline')]
#[CoversFunction('pfb_feed_convert_encoding')]
final class FeedParseNormalizeCorpusTest extends TestCase
{
	private const CORPUS = __DIR__ . '/../../go/pfb_core/feedparse/testdata/normalize.json';
	private const SED_EXPR = "s/[^[:print:]\t]+|[[:space:]]+\$//g";
	/** Byte keys of a case: name => required (a text key `x` or a lower-case hex key `x_hex`, exactly one of them). */
	private const BYTE_KEYS = ['input' => TRUE, 'expect' => TRUE, 'old_expect' => FALSE];

	private string $dir;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_fpnorm_' . getmypid() . '_' . bin2hex(random_bytes(4));
		mkdir($this->dir, 0777, TRUE);
	}

	protected function tearDown(): void
	{
		foreach (glob("{$this->dir}/*") ?: [] as $f) {
			@unlink($f);
		}
		@rmdir($this->dir);
	}

	/**
	 * @return array<string, array{array{id: string, description: string, converter: bool, appliance: bool, input: string, expect: string, old_expect: ?string}}>
	 */
	public static function cases(): array
	{
		$doc = json_decode((string) file_get_contents(self::CORPUS), TRUE, 16, JSON_THROW_ON_ERROR);
		if (!is_array($doc) || array_keys($doc) !== ['schema', 'cases'] || $doc['schema'] !== 1
			|| !is_array($doc['cases']) || $doc['cases'] === [] || !array_is_list($doc['cases'])) {
			throw new RuntimeException('normalize.json must be {"schema": 1, "cases": [non-empty list]}');
		}
		$out = [];
		foreach ($doc['cases'] as $i => $raw) {
			$case = self::validCase($raw, $i);
			if (isset($out[$case['id']])) {
				throw new RuntimeException("normalize.json: duplicate id {$case['id']}");
			}
			$out[$case['id']] = [$case];
		}
		return $out;
	}

	/**
	 * @return array{id: string, description: string, converter: bool, appliance: bool, input: string, expect: string, old_expect: ?string}
	 */
	private static function validCase(mixed $raw, int $i): array
	{
		if (!is_array($raw)) {
			throw new RuntimeException("normalize.json: case #{$i} is not an object");
		}
		$allowed = ['id', 'description', 'converter', 'appliance'];
		foreach (array_keys(self::BYTE_KEYS) as $k) {
			array_push($allowed, $k, "{$k}_hex");
		}
		$unknown = array_diff(array_keys($raw), $allowed);
		if ($unknown !== []) {
			throw new RuntimeException("normalize.json: case #{$i} has unknown keys: " . implode(', ', $unknown));
		}
		foreach (['id', 'description'] as $k) {
			if (!isset($raw[$k]) || !is_string($raw[$k]) || $raw[$k] === '') {
				throw new RuntimeException("normalize.json: case #{$i} needs a non-empty string {$k}");
			}
		}
		if (!isset($raw['converter']) || !is_bool($raw['converter']) || (isset($raw['appliance']) && !is_bool($raw['appliance']))) {
			throw new RuntimeException("normalize.json: case {$raw['id']} needs a bool converter and, if present, a bool appliance");
		}
		$case = ['id' => $raw['id'], 'description' => $raw['description'], 'converter' => $raw['converter'],
			'appliance' => $raw['appliance'] ?? FALSE];
		foreach (self::BYTE_KEYS as $k => $required) {
			$case[$k] = self::bytesOf($raw, $k, $required);
		}
		if ($case['input'] === NULL || $case['expect'] === NULL) {
			throw new RuntimeException("normalize.json: case {$raw['id']} lacks input or expect");
		}
		return $case;
	}

	/** @param array<mixed> $raw */
	private static function bytesOf(array $raw, string $k, bool $required): ?string
	{
		$text = array_key_exists($k, $raw);
		$hex = array_key_exists("{$k}_hex", $raw);
		if ($text && $hex) {
			throw new RuntimeException("normalize.json: case {$raw['id']} holds both {$k} and {$k}_hex");
		}
		if (!$text && !$hex) {
			if ($required) {
				throw new RuntimeException("normalize.json: case {$raw['id']} lacks {$k}");
			}
			return NULL;
		}
		$v = $raw[$text ? $k : "{$k}_hex"];
		if (!is_string($v)) {
			throw new RuntimeException("normalize.json: case {$raw['id']} {$k} is not a string");
		}
		if ($text) {
			return $v;
		}
		if (preg_match('/^(?:[0-9a-f]{2})*$/', $v) !== 1) {
			throw new RuntimeException("normalize.json: case {$raw['id']} {$k}_hex is not lower-case hex");
		}
		$bytes = (string) hex2bin($v);
		if (mb_check_encoding($bytes, 'UTF-8')) {
			throw new RuntimeException("normalize.json: case {$raw['id']} {$k}_hex is valid UTF-8, write it as text");
		}
		return $bytes;
	}

	/**
	 * @param array{id: string, description: string, converter: bool, appliance: bool, input: string, expect: string, old_expect: ?string} $case
	 */
	#[DataProvider('cases')]
	public function testNormalizeMatchesTheCorpus(array $case): void
	{
		$want = $case['old_expect'] ?? $case['expect'];
		if ($case['appliance'] && !$this->hostClassesMatchAppliance()) {
			$this->markTestSkipped('host sed lacks the appliance C.UTF-8 classes (BOM/ZWJ non-printable, NBSP as [:space:]); the case pins the appliance result');
		}
		if (!mb_check_encoding($want, 'UTF-8') && !$this->hostSedPassesInvalidBytes()) {
			$this->markTestSkipped('host sed does not pass invalid UTF-8 sequences through, as the appliance sed does');
		}
		$interpreter = '';
		if ($case['converter']) {
			$interpreter = self::converterInterpreter();
			if ($interpreter === null) {
				$this->markTestSkipped('no python3 with charset_normalizer on this host (the CI image installs it)');
			}
		}

		$got = $this->oldPath($case['input'], $interpreter);
		$this->assertTrue($want === $got, "case {$case['id']}: {$case['description']}\n" . self::lineDiff($want, $got));
	}

	private function oldPath(string $orig_bytes, string $interpreter): string
	{
		$src = "{$this->dir}/feed.orig";
		$dst = "{$this->dir}/feed.norm";
		file_put_contents($src, $orig_bytes);
		$this->assertTrue(pfb_feed_normalize_generate($src, $dst, $interpreter), 'pfb_feed_normalize_generate() reported failure');
		pfb_ensure_trailing_newline($dst);
		return (string) file_get_contents($dst);
	}

	/** The production sed pass over $bytes, read from a file as production does (escapeshellarg would mangle invalid bytes). */
	private function hostSed(string $bytes): string
	{
		$in = "{$this->dir}/probe.in";
		$out = "{$this->dir}/probe.out";
		file_put_contents($in, $bytes);
		exec('LC_ALL=C.UTF-8 /usr/bin/sed -E ' . escapeshellarg(self::SED_EXPR) . ' < ' . escapeshellarg($in) . ' > ' . escapeshellarg($out) . ' 2>/dev/null');
		return (string) @file_get_contents($out);
	}

	private function hostClassesMatchAppliance(): bool
	{
		return $this->hostSed("\xEF\xBB\xBFa\xE2\x80\x8Db") === 'ab' && $this->hostSed("end\xC2\xA0") === 'end';
	}

	private function hostSedPassesInvalidBytes(): bool
	{
		return $this->hostSed("caf\xE9\x07") === "caf\xE9";
	}

	private static function converterInterpreter(): ?string
	{
		$py = trim((string) shell_exec('command -v python3 2>/dev/null'));
		if ($py === '') {
			return null;
		}
		exec(escapeshellarg($py) . ' -c "import charset_normalizer" 2>/dev/null', $o, $ret);
		return $ret === 0 ? $py : null;
	}

	private static function visible(?string $line): string
	{
		if ($line === NULL) {
			return '(no such line)';
		}
		$cut = strlen($line) > 160;
		$shown = (string) preg_replace_callback('/[^\x20-\x5b\x5d-\x7e]/', static fn (array $m): string => sprintf('\\x%02x', ord($m[0])), substr($line, 0, 160));
		return $shown . ($cut ? '... (' . strlen($line) . ' bytes)' : '');
	}

	private static function lineDiff(string $want, string $got): string
	{
		$w = explode("\n", $want);
		$g = explode("\n", $got);
		$msg = sprintf("expected %d bytes, got %d\n", strlen($want), strlen($got));
		$shown = 0;
		for ($i = 0, $n = max(count($w), count($g)); $i < $n && $shown < 20; $i++) {
			if (($w[$i] ?? NULL) !== ($g[$i] ?? NULL)) {
				$msg .= sprintf("line %d\n  expected: %s\n  actual:   %s\n", $i + 1, self::visible($w[$i] ?? NULL), self::visible($g[$i] ?? NULL));
				$shown++;
			}
		}
		return $msg;
	}
}
