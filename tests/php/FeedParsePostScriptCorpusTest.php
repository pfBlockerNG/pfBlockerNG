<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

// The data providers run before setUpBeforeClass().
require_once __DIR__ . '/FeedParseCorpusFile.php';

/**
 * The post-script parity corpus (issue #4035, go/pfb_core/feedparse/testdata/postscript.json, schema in that directory's
 * README.md): a list's post-script, DNSBL on a staged copy of the download, IP on the download with a restore point. The
 * runner evaluates the two call sites of sync_package_pfblockerng() verbatim, cut out of pfblockerng_apply.inc, so it drives
 * today's code and not a copy; the Go runner replays the same file against Core's PostScript. Where Core differs on purpose
 * the case holds today's answer in old_expect, which this runner asserts.
 *
 * A script that blocks sends SIGALRM to its parent, timeout(1), whose alarm handler is the timeout firing: the kill is
 * driven by that event, never by a shortened budget or a sleep.
 */
#[CoversFunction('pfb_list_script_exec')]
#[CoversFunction('pfb_list_post_script_stage')]
#[CoversFunction('pfb_resolve_list_script')]
#[CoversFunction('pfb_script_output_exec')]
final class FeedParsePostScriptCorpusTest extends TestCase
{
	private const CORPUS = __DIR__ . '/../../go/pfb_core/feedparse/testdata/postscript.json';
	private const APPLY = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';
	private const ENTRY = ['body', 'mode', 'shebang', 'link', 'dir'];
	/** reason and status are the Go result's (PostScriptResult): this runner checks only that they are there. */
	private const EXPECT = ['files', 'between', 'seen', 'log', 'errors', 'transcript', 'failed', 'reason', 'status', 'alive'];
	/** How long a process the case expects gone may take to go: only a hung case waits this long, and then it fails. */
	private const GONE_CAP = 30.0;

	private string $root;
	private mixed $savedPfb = NULL;
	/** @var array<string, string|false> */
	private array $savedEnv = [];
	private int $child = 0;

	public static function setUpBeforeClass(): void
	{
		require_once self::APPLY;
	}

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb_post_' . getmypid() . '_' . bin2hex(random_bytes(4));
		foreach (['list', 'pkg', 'outside', 'feed', 'test', 'db'] as $d) {
			mkdir("{$this->root}/{$d}", 0700, TRUE);
		}
		$this->savedPfb = $GLOBALS['pfb'] ?? NULL;
		foreach (['PFB_TEST_SEEN', 'PFB_TEST_ENV', 'PFB_TEST_BLOCK', 'PFB_TEST_ALARM', 'PFB_TEST_READY', 'PFB_TEST_CHILD',
		    'PFB_TEST_ALIVE', 'PFB_TEST_PID'] as $k) {
			$this->savedEnv[$k] = getenv($k);
		}
	}

	protected function tearDown(): void
	{
		if ($this->child > 0) {
			posix_kill($this->child, SIGKILL);
		}
		exec('rm -rf ' . escapeshellarg($this->root));
		$GLOBALS['pfb'] = $this->savedPfb;
		foreach ($this->savedEnv as $k => $v) {
			putenv($v === FALSE ? $k : "{$k}={$v}");
		}
	}

	/** @return array<string, mixed> */
	private static function corpus(): array
	{
		$doc = json_decode((string) file_get_contents(self::CORPUS), TRUE, 64, JSON_THROW_ON_ERROR);
		FeedParseCorpusFile::keys($doc, ['schema', 'prefix', 'env', 'header', 'cases'], 'postscript.json');
		if ($doc['schema'] !== 1 || !is_string($doc['prefix']) || !is_string($doc['env']) || !is_string($doc['header'])
		    || !is_array($doc['cases']) || $doc['cases'] === [] || !array_is_list($doc['cases'])) {
			throw new RuntimeException('postscript.json: schema 1, a prefix, env and header string, and a non-empty case list');
		}
		return $doc;
	}

	/** @return array<string, array{array<string, mixed>}> */
	public static function cases(): array
	{
		$out = [];
		foreach (self::corpus()['cases'] as $case) {
			self::checkCase($case);
			if (isset($out[$case['id']])) {
				throw new RuntimeException("duplicate id {$case['id']}");
			}
			$out[$case['id']] = [$case];
		}
		return $out;
	}

	/** @param array<string, mixed> $case */
	private static function checkCase(array $case): void
	{
		$w = 'case ' . ($case['id'] ?? '?');
		$keys = ['id', 'description', 'list_type', 'name', 'tree', 'feed', 'blocks', 'expect'];
		FeedParseCorpusFile::keys($case, array_key_exists('old_expect', $case) ? [...$keys, 'old_expect', 'departure'] : $keys, $w);
		if (!is_string($case['id']) || $case['id'] === '' || !is_string($case['description']) || $case['description'] === ''
		    || !in_array($case['list_type'], ['dnsbl', '_v4', '_v6'], TRUE) || !is_string($case['name']) || !is_bool($case['blocks'])) {
			throw new RuntimeException("{$w}: id and description, list_type dnsbl, _v4 or _v6, a name, blocks a bool");
		}
		foreach ($case['tree'] as $path => $entry) {
			$parts = explode('/', (string) $path);
			if (count($parts) !== 2 || !in_array($parts[0], ['list', 'pkg', 'outside'], TRUE) || $parts[1] === '' || !is_array($entry)
			    || array_diff(array_keys($entry), self::ENTRY) !== []) {
				throw new RuntimeException("{$w} tree {$path}: list/, pkg/ or outside/ and a name, an entry of " . implode(', ', self::ENTRY));
			}
		}
		$ip = $case['list_type'] !== 'dnsbl';
		FeedParseCorpusFile::keys($case['expect'], $ip ? self::EXPECT : array_values(array_diff(self::EXPECT, ['between'])), "{$w} expect");
		if (array_key_exists('old_expect', $case)) {
			if (!is_array($case['old_expect']) || $case['old_expect'] === [] || array_diff(array_keys($case['old_expect']), self::EXPECT) !== []
			    || !is_string($case['departure']) || $case['departure'] === '') {
				throw new RuntimeException("{$w}: old_expect holds expect keys, and departure says why");
			}
		}
	}

	/**
	 * The code between $anchor and the end of the first block it opens, verbatim: braces are counted on PHP tokens, so the
	 * "{$var}" of a string is no block.
	 */
	private static function block(string $source, string $anchor): string
	{
		if (substr_count($source, $anchor) !== 1) {
			throw new RuntimeException("the call site moved: '{$anchor}' must occur once in pfblockerng_apply.inc");
		}
		$from = strpos($source, $anchor);
		$tail = substr($source, $from);
		$offset = -6;
		$stack = [];
		foreach (token_get_all('<?php ' . $tail) as $token) {
			$text = is_array($token) ? $token[1] : $token;
			$offset += strlen($text);
			if ($offset <= 0) {
				continue;
			}
			if ($token === '{' || (is_array($token) && in_array($token[0], [T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES], TRUE))) {
				$stack[] = $token === '{';
			} elseif ($token === '}' && array_pop($stack) === TRUE && $stack === []) {
				return substr($tail, 0, $offset);
			}
		}
		throw new RuntimeException("no block after '{$anchor}'");
	}

	/** The listing of the feed folder: content, or what else each entry is. @return array<string, mixed> */
	private function files(): array
	{
		$out = [];
		foreach (scandir("{$this->root}/feed") ?: [] as $name) {
			$path = "{$this->root}/feed/{$name}";
			if ($name === '.' || $name === '..') {
				continue;
			}
			$out[$name] = match (TRUE) {
				is_link($path) => ['link' => readlink($path)],
				is_dir($path) => ['type' => 'dir'],
				filetype($path) === 'fifo' => ['type' => 'fifo'],
				default => (string) file_get_contents($path),
			};
		}
		ksort($out);
		return $out;
	}

	/** A log with pfb_logger()'s stamps removed. */
	private function log(string $path): string
	{
		return (string) preg_replace('/(?<=^|\n)\d{4}-\d\d-\d\d \d\d:\d\d:\d\d /', '', (string) @file_get_contents($path));
	}

	/** An expected text: a string, or {prefix, repeat, times, suffix}. */
	private function text(mixed $want): string
	{
		if (is_string($want)) {
			return $this->expand($want);
		}
		FeedParseCorpusFile::keys($want, ['prefix', 'repeat', 'times', 'suffix'], 'text');
		return $this->expand($want['prefix']) . str_repeat($want['repeat'], $want['times']) . $this->expand($want['suffix']);
	}

	private function expand(string $s): string
	{
		return strtr($s, ['{root}' => $this->root, '{cwd}' => (string) realpath((string) getcwd())]);
	}

	/** @param array<string, mixed> $state @return array<string, mixed> */
	private static function sorted(array $state): array
	{
		ksort($state);
		return $state;
	}

	/** Whether the child the script recorded is alive; a child expected gone is given until it is (a hung case fails). */
	private function alive(bool $want): bool
	{
		$this->child = (int) trim((string) @file_get_contents("{$this->root}/test/pid"));
		$running = fn(): bool => $this->child > 0 && posix_kill($this->child, 0)
			&& !str_contains((string) @file_get_contents("/proc/{$this->child}/stat"), ') Z ');
		for ($deadline = microtime(TRUE) + self::GONE_CAP; !$want && $running() && microtime(TRUE) < $deadline; usleep(10000)) {
		}
		return $running();
	}

	/** @param array<string, mixed> $case */
	#[DataProvider('cases')]
	public function testCaseMatchesTheCallSites(array $case): void
	{
		global $pfb;
		$doc = self::corpus();
		$source = (string) file_get_contents(self::APPLY);
		$this->assertSame(2, substr_count($source, "!empty(\$list['script_post'])) {"), 'each loop resolves a set post-script only');
		$this->assertSame(2, substr_count($source, "pfb_resolve_list_script(\$list['script_post'])"), 'each loop resolves the post-script');
		$this->assertSame(1, substr_count($source, '$pfb_row_script_post = $pfb_dnsbl_script_post;'), 'the DNSBL row takes the group\'s script');

		foreach ($case['tree'] as $path => $entry) {
			$file = "{$this->root}/{$path}";
			if (isset($entry['link'])) {
				symlink($entry['link'], $file);
			} elseif (isset($entry['dir'])) {
				mkdir($file);
			} else {
				file_put_contents($file, (($entry['shebang'] ?? TRUE) ? "#!/bin/sh\n" : '') . $doc['prefix'] . "{$entry['body']}\n");
				chmod($file, $entry['mode'] === 'exec' ? 0755 : 0644);
			}
		}
		foreach ($case['feed'] as $name => $entry) {
			$file = "{$this->root}/feed/{$name}";
			match (TRUE) {
				is_string($entry) => file_put_contents($file, $entry),
				is_array($entry) && array_keys($entry) === ['link'] => symlink($entry['link'], $file),
				$entry === ['type' => 'dir'] => mkdir($file),
				default => throw new RuntimeException("feed {$name}: a string, {link} or {type: dir}"),
			};
		}
		foreach (['block', 'child', 'alive'] as $f) {
			$this->assertTrue(posix_mkfifo("{$this->root}/test/{$f}", 0600), "mkfifo {$f}");
		}
		$t = "{$this->root}/test";
		foreach (['SEEN' => "{$t}/seen", 'ENV' => $doc['env'], 'BLOCK' => "{$t}/block", 'CHILD' => "{$t}/child",
		    'ALIVE' => "{$t}/alive", 'PID' => "{$t}/pid"] as $k => $v) {
			putenv("PFB_TEST_{$k}={$v}");
		}
		putenv('PFB_TEST_READY');
		putenv($case['blocks'] ? 'PFB_TEST_ALARM=1' : 'PFB_TEST_ALARM');
		$pfb = ['log' => "{$t}/main.log", 'errlog' => "{$t}/error.log", 'runlog' => "{$t}/run.log", 'runlog_active' => TRUE,
			'run_stdout_override' => FALSE, 'dbdir' => "{$this->root}/db"];

		// The loop's variables, as sync_package_pfblockerng() sets them for one feed row.
		$list = ['script_post' => $this->expand($case['name']), 'vtype' => $case['list_type']];
		$dirs = ["{$this->root}/list", "{$this->root}/pkg"];
		$resolved = empty($list['script_post']) ? FALSE : pfb_resolve_list_script($list['script_post'], $dirs);
		$file_dwn = "{$this->root}/feed/feed";
		$alias = 'pfB_Test';
		$header = $doc['header'];
		$pfb_script_state = ['failed' => FALSE];
		$between = NULL;
		if ($case['list_type'] === 'dnsbl') {
			$pfb_row_script_post = $resolved;
			eval(self::block($source, 'if ($pfb_row_script_post && is_file("{$pfb_row_script_post}")) {'));
		} else {
			$pfb_script_post = $resolved;
			eval(self::block($source, '$pfb_post_staged = FALSE;'));
			$between = $this->files();
			// The caller's empty-feed check runs here; then the loop's restore.
			eval(self::block($source, 'if ($pfb_post_staged && file_exists("{$file_dwn}.orig.post")) {'));
		}

		$want = array_merge($case['expect'], $case['old_expect'] ?? []);
		$got = ['files' => $this->files()];
		$expected = ['files' => self::sorted($want['files'])];
		if ($between !== NULL) {
			$got['between'] = $between;
			$expected['between'] = self::sorted($want['between']);
		}
		$got += ['seen' => is_file("{$t}/seen") ? (string) file_get_contents("{$t}/seen") : NULL, 'log' => $this->log($pfb['log']),
			'errors' => $this->log($pfb['errlog']), 'transcript' => $this->log($pfb['runlog']), 'failed' => $pfb_script_state['failed']];
		$expected += ['seen' => $want['seen'] === NULL ? NULL : $this->expand($want['seen']), 'log' => $this->text($want['log']),
			'errors' => $this->text($want['errors']), 'transcript' => $this->text($want['transcript']), 'failed' => $want['failed']];
		if ($want['alive'] !== NULL) {
			$got['alive'] = $this->alive($want['alive']);
			$expected['alive'] = $want['alive'];
		}
		$this->assertSame($expected, $got, "{$case['id']}: {$case['description']}");
	}
}
