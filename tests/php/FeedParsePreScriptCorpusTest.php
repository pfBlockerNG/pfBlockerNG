<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

// The data providers run before setUpBeforeClass().
require_once __DIR__ . '/FeedParseCorpusFile.php';

/**
 * The pre-script parity corpus (issue #3976, go/pfb_core/feedparse/testdata/prescript.json, schema in that directory's
 * README.md): a list's pre-script run on a staged copy of the normalized feed, through the production
 * pfb_list_pre_script_run() and, once the feed is parsed, pfb_list_script_cleanup_staged(). The Go runner replays the same
 * file against Core's RunPreScript, which runs the script without a shell where the PHP path goes through sh: the hostile
 * script names pin that the shell's escaping gives the same result.
 *
 * The reason of a failure is read back from the log line the production code wrote. A script that blocks reads a fifo
 * nobody writes; the PHP path ends it with timeout(1), whose budget the runner shortens (a seam of pfb_list_script_exec()).
 */
#[CoversFunction('pfb_list_pre_script_run')]
#[CoversFunction('pfb_list_script_exec')]
#[CoversFunction('pfb_list_script_cleanup_staged')]
final class FeedParsePreScriptCorpusTest extends TestCase
{
	private const CORPUS = __DIR__ . '/../../go/pfb_core/feedparse/testdata/prescript.json';
	/** The smallest well-formed case: the loader tests break one thing at a time. */
	private const WELL = '{"id": "a", "description": "d", "setup": {"norm": "a.example\n"}, "script": {"name": "s.sh", "body": "true", "mode": "exec"}, "list_type": "_v4", "blocks": false, "expect": {"ok": true, "reason": "", "status": 0, "files": {"norm": "a.example\n", "staged": "a.example\n"}}}';

	private string $dir;
	private string $logs;
	private mixed $savedPfb = NULL;
	/** @var array<string, string|false> */
	private array $savedEnv = [];

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_fpps_' . getmypid() . '_' . bin2hex(random_bytes(4));
		mkdir("{$this->dir}/bin", 0700, TRUE);
		$this->logs = "{$this->dir}.log";
		$this->savedPfb = $GLOBALS['pfb'] ?? NULL;
		$GLOBALS['pfb'] = ['log' => $this->logs, 'errlog' => "{$this->logs}.err"];
		foreach (['PFB_TEST_CANARY', 'PFB_TEST_BLOCK'] as $k) {
			$this->savedEnv[$k] = getenv($k);
		}
	}

	protected function tearDown(): void
	{
		foreach (array_merge(glob("{$this->dir}/*") ?: [], glob("{$this->dir}/bin/*") ?: []) as $f) {
			@unlink($f);
		}
		@rmdir("{$this->dir}/bin");
		@rmdir($this->dir);
		@unlink($this->logs);
		@unlink("{$this->logs}.err");
		$GLOBALS['pfb'] = $this->savedPfb;
		foreach ($this->savedEnv as $k => $v) {
			putenv($v === FALSE ? $k : "{$k}={$v}");
		}
	}

	/** @return array<string, array{array<string, mixed>}> */
	public static function cases(): array
	{
		$out = [];
		foreach (FeedParseCorpusFile::load(self::CORPUS, ['cases'])['cases'] as $case) {
			self::checkCase($case);
			$out[$case['id']] = [$case];
		}
		return $out;
	}

	/** @param array<string, mixed> $case */
	private static function checkCase(array $case): void
	{
		$w = "case {$case['id']}";
		FeedParseCorpusFile::keys($case, ['id', 'description', 'setup', 'script', 'list_type', 'blocks', 'expect'], $w);
		self::checkFiles($case['setup'], ['norm', 'staged'], "{$w} setup");
		FeedParseCorpusFile::keys($case['script'], ['name', 'body', 'mode'], "{$w} script");
		$s = $case['script'];
		if (!is_string($s['name']) || $s['name'] === '' || str_contains($s['name'], '/') || str_contains($s['name'], "\0") || !is_string($s['body'])
		    || !in_array($s['mode'], ['exec', 'noexec', 'absent'], TRUE)) {
			throw new RuntimeException("{$w} script: a name without / or NUL, a body, and the mode exec, noexec or absent");
		}
		if (!in_array($case['list_type'], ['_v4', '_v6', 'dnsbl'], TRUE) || !is_bool($case['blocks'])) {
			throw new RuntimeException("{$w}: list_type is _v4, _v6 or dnsbl, blocks a bool");
		}
		$e = $case['expect'];
		FeedParseCorpusFile::keys($e, ['ok', 'reason', 'status', 'files'], "{$w} expect");
		if (!is_bool($e['ok']) || !in_array($e['reason'], ['', 'stage', 'exit', 'timeout', 'deleted'], TRUE) || !is_int($e['status'])
		    || ($e['ok'] !== ($e['reason'] === '')) || ($e['reason'] !== 'exit' && $e['status'] !== 0) || ($e['reason'] === 'exit' && $e['status'] === 0)) {
			throw new RuntimeException("{$w} expect: ok is true exactly when reason is empty, and status is non-zero exactly when reason is exit");
		}
		self::checkFiles($e['files'], ['norm', 'staged'], "{$w} expect.files");
	}

	/** A directory state: a subset of $names, each a bytes field in its text or hex form. @param list<string> $names */
	private static function checkFiles(mixed $files, array $names, string $where): void
	{
		if (!is_array($files)) {
			throw new RuntimeException("{$where}: object expected");
		}
		$allowed = [];
		foreach ($names as $k) {
			array_push($allowed, $k, "{$k}_hex");
		}
		$unknown = array_diff(array_keys($files), $allowed);
		if ($unknown !== []) {
			throw new RuntimeException("{$where}: unknown keys " . implode(', ', $unknown));
		}
		foreach ($names as $k) {
			if (array_key_exists($k, $files) || array_key_exists("{$k}_hex", $files)) {
				FeedParseCorpusFile::bytes($files, $k, "{$where} {$k}");
			}
		}
	}

	/** @param array<string, mixed> $files @param list<string> $names @return array<string, string> */
	private static function stateBytes(array $files, array $names): array
	{
		$out = [];
		foreach ($names as $k) {
			if (array_key_exists($k, $files) || array_key_exists("{$k}_hex", $files)) {
				$out[$k] = FeedParseCorpusFile::bytes($files, $k, '');
			}
		}
		return $out;
	}

	/** @param array<string, mixed> $case */
	#[DataProvider('cases')]
	public function testCaseMatchesPfbListPreScriptRun(array $case): void
	{
		$e = $case['expect'];
		$files = self::stateBytes($e['files'], ['norm', 'staged']);
		ksort($files);
		$want = ['ok' => $e['ok'], 'reason' => $e['reason'], 'status' => $e['status'], 'files' => $files];
		$got = $this->replay($case);
		$this->assertFalse($got['injected'], 'the script name reached a shell as code');
		$this->assertFalse($got['leftover'], 'the staged copy outlives the parse');
		unset($got['injected'], $got['leftover']);
		$this->assertSame($want, $got, "{$case['id']}: {$case['description']}");
	}

	/**
	 * Set up the case, run the production functions, and report what they returned, what the directory holds, and the two
	 * things that must never happen: the script name running as shell code, and the staged copy outliving the parse.
	 *
	 * @param array<string, mixed> $case
	 * @return array<string, mixed>
	 */
	private function replay(array $case): array
	{
		$norm = "{$this->dir}/feed.norm";
		$staged = "{$this->dir}/feed.pre";
		file_put_contents($this->logs, '');
		foreach (self::stateBytes($case['setup'], ['norm', 'staged']) as $k => $bytes) {
			file_put_contents($k === 'norm' ? $norm : $staged, $bytes);
		}
		$s = $case['script'];
		$script = "{$this->dir}/bin/{$s['name']}";
		if ($s['mode'] !== 'absent') {
			file_put_contents($script, "#!/bin/sh\n{$s['body']}\n");
			chmod($script, $s['mode'] === 'exec' ? 0755 : 0644);
		}
		$canary = "{$this->dir}/canary";
		putenv("PFB_TEST_CANARY={$canary}");
		if ($case['blocks']) {
			$fifo = "{$this->dir}/block.fifo";
			if (!posix_mkfifo($fifo, 0600)) {
				throw new RuntimeException('cannot make the fifo');
			}
			putenv("PFB_TEST_BLOCK={$fifo}");
		}
		$r = pfb_list_pre_script_run($norm, $staged, $script, $s['name'], 'hdr',
			escapeshellarg($staged) . " {$case['list_type']} > /dev/null 2>&1", $case['blocks'] ? '/usr/bin/timeout -s TERM -k 1 1 ' : NULL);

		$log = (string) file_get_contents($this->logs);
		$reason = '';
		$status = 0;
		if (str_contains($log, 'could not stage its input')) {
			$reason = 'stage';
		} elseif (str_contains($log, 'TIMED OUT')) {
			$reason = 'timeout';
		} elseif (preg_match('/exited non-zero \[ (\d+) \]/', $log, $m) === 1) {
			[$reason, $status] = ['exit', (int) $m[1]];
		} elseif (str_contains($log, 'deleted its staged input')) {
			$reason = 'deleted';
		}
		$files = [];
		foreach (['norm' => $norm, 'staged' => $staged] as $k => $path) {
			if (is_file($path)) {
				$files[$k] = (string) file_get_contents($path);
			}
		}
		ksort($files);
		$expectedPath = $r['ok'] ? $staged : $norm;
		$this->assertSame($expectedPath, $r['path'], 'the path to parse: the staged copy when the transform ran, else the normalized feed');

		// The parse is over: the apply script's cleanup of the staged copy.
		pfb_list_script_cleanup_staged($r['path'], $r['ok'] ? $r['path'] : NULL, $staged);
		return ['ok' => $r['ok'], 'reason' => $reason, 'status' => $status, 'files' => $files, 'injected' => file_exists($canary), 'leftover' => file_exists($staged)];
	}

	/** @return array<string, array{string}> */
	public static function malformedProvider(): array
	{
		$ok = self::WELL;
		$doc = static fn(string $case): string => '{"schema": 1, "cases": [' . $case . ']}';
		return [
			'unknown top key'       => [str_replace('"schema": 1', '"schema": 1, "x": 1', $doc($ok))],
			'unknown case key'      => [$doc(str_replace('"description": "d",', '"description": "d", "x": 1,', $ok))],
			'unknown setup key'     => [$doc(str_replace('"setup": {"norm"', '"setup": {"x": "y", "norm"', $ok))],
			'norm and norm_hex'     => [$doc(str_replace('"setup": {"norm": "a.example\n"}', '"setup": {"norm": "a", "norm_hex": "ff"}', $ok))],
			'unknown script key'    => [$doc(str_replace('"mode": "exec"}', '"mode": "exec", "x": 1}', $ok))],
			'script name with /'    => [$doc(str_replace('"name": "s.sh"', '"name": "a/b"', $ok))],
			'bad mode'              => [$doc(str_replace('"mode": "exec"', '"mode": "x"', $ok))],
			'bad list type'         => [$doc(str_replace('"list_type": "_v4"', '"list_type": "x"', $ok))],
			'blocks not a bool'     => [$doc(str_replace('"blocks": false', '"blocks": 0', $ok))],
			'ok with a reason'      => [$doc(str_replace('"reason": ""', '"reason": "exit"', $ok))],
			'exit without status'   => [$doc(str_replace('"ok": true, "reason": ""', '"ok": false, "reason": "exit"', $ok))],
			'status without exit'   => [$doc(str_replace('"status": 0', '"status": 3', $ok))],
			'unknown reason'        => [$doc(str_replace('"ok": true, "reason": ""', '"ok": false, "reason": "x"', $ok))],
			'unknown files key'     => [$doc(str_replace('"staged": "a.example\n"}}}', '"staged": "a.example\n", "x": "y"}}}', $ok))],
			'duplicate id'          => ['{"schema": 1, "cases": [' . $ok . ',' . $ok . ']}'],
			'empty cases'           => ['{"schema": 1, "cases": []}'],
		];
	}

	public function testLoaderAcceptsAWellFormedDocument(): void
	{
		foreach (FeedParseCorpusFile::load(self::scratch('{"schema": 1, "cases": [' . self::WELL . ']}'), ['cases'])['cases'] as $case) {
			self::checkCase($case);
		}
		$this->addToAssertionCount(1);
	}

	#[DataProvider('malformedProvider')]
	public function testLoaderIsStrict(string $json): void
	{
		$this->expectException(RuntimeException::class);
		foreach (FeedParseCorpusFile::load(self::scratch($json), ['cases'])['cases'] as $case) {
			self::checkCase($case);
		}
	}

	private static function scratch(string $json): string
	{
		$path = (string) tempnam(sys_get_temp_dir(), 'pfb_fpps_doc_');
		file_put_contents($path, $json);
		register_shutdown_function(static fn() => @unlink($path));
		return $path;
	}
}
