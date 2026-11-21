<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The corpus of `pfb-core --run-hooks` (#4035 slice 6c) driven through today's two callers of pfb_run_hooks() outside
 * an Update: the runhooks verb of pfblockerng.php, whose own block is evaluated with the scenario's arguments, and the
 * uninstall disable pass, whose hooks run with $pfb['hook_lifecycle'] = 'uninstall' under a pkg process. Each scenario
 * runs in a fresh PHP process. go/pfb_core/hooks/oneshot_test.go runs the one-shot binary on the same files, with the
 * scenario's stdin, and compares the same recorded invocations, the main log with its stderr, and the console with its
 * stdout.
 *
 * A scenario (the Go side refuses unknown keys):
 *   description  what it pins; departure says why Go differs when old_expect is present.
 *   caller       "runhooks": argv are the verb's arguments after runhooks. "uninstall": vars is the context the disable
 *                pass gives pfb_run_hooks() and pkgOp the operation of the pkg process it runs under.
 *   when         the fire point, the one-shot's argument. stdin: the one-shot's context object, a content.
 *   python, rows, files  as in tests/hooks/fixtures/runner (HookRunnerCorpusTest documents them).
 *   expect       runs (each recorded invocation's script, wrapped, args and PFB_* environment, in order), log (the main
 *                log, without pfb_logger()'s time stamps), console (what reached stdout, each time stamp written as
 *                {stamp}), absent (canary files that must not exist).
 *   old_expect   today's answer where Go deliberately differs: its keys replace expect's here.
 * A content is a string or {"prefix", "repeat", "times", "suffix"}; {root} in it is the scenario root.
 */
#[CoversFunction('pfb_run_hooks')]
final class HookOneShotCorpusTest extends TestCase
{
	private const STAMP = '/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} /m';
	private const PKG_ARGV = ['delete' => 'pkg delete pfSense-pkg-pfBlockerNG'];

	private string $root = '';

	public static function corpus(): array
	{
		$cases = [];
		foreach (glob(__DIR__ . '/../hooks/fixtures/oneshot/*.json') ?: [] as $file) {
			$cases[basename($file, '.json')] = [$file];
		}
		return $cases;
	}

	protected function setUp(): void
	{
		$base = sys_get_temp_dir() . '/pfb_hook_oneshot_' . getmypid() . '_' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir($base, 0700, TRUE));
		$this->root = (string) realpath($base);
	}

	protected function tearDown(): void
	{
		exec('rm -rf ' . escapeshellarg($this->root));
	}

	/** @param array<string,mixed>|string $content */
	private function content(array|string $content): string
	{
		$expand = fn(string $text): string
			=> str_replace(['{record}', '{root}'], [". '{root}/record.sh'", $this->root], $text);
		if (is_string($content)) {
			return $expand($content);
		}
		return $expand($content['prefix'] ?? '') . str_repeat($content['repeat'], $content['times'])
			. $expand($content['suffix'] ?? '');
	}

	/** @param array<string,mixed> $sc */
	private function stage(array $sc): void
	{
		$root = $this->root;
		$this->assertTrue(mkdir("{$root}/hooks", 0755));
		file_put_contents("{$root}/record.sh", "{\n\tprintf 'script=%s\\000' \"\${0##*/}\"\n"
			. "\tprintf 'wrapped=%s\\000' \"\${HOOK_TEST_WRAPPED:-0}\"\n"
			. "\tfor arg in \"\$@\"; do printf 'arg=%s\\000' \"\$arg\"; done\n"
			. "\tenv -0\n\tprintf 'end\\000'\n} >> '{$root}/record'\n");
		$interpreter = ($sc['python'] ?? '') === 'none' ? "\texit 127\n" : "\tprintf '/fixture/interpreter\\n'\n\texit 0\n";
		file_put_contents("{$root}/wrapper.sh", "#!/bin/sh\nif [ \"\$1\" = --print-interpreter ]; then\n{$interpreter}fi\n"
			. "HOOK_TEST_WRAPPED=1 exec /bin/sh \"\$@\"\n");
		chmod("{$root}/wrapper.sh", 0755);
		foreach ($sc['files'] ?? [] as $path => $file) {
			$target = "{$root}/{$path}";
			$this->assertNotFalse(file_put_contents($target, $this->content($file['body'])));
			$this->assertTrue(chmod($target, intval($file['mode'] ?? '0755', 8)));
		}
	}

	/** @return list<array{script:string, wrapped:bool, args:list<string>, env:array<string,string>}> */
	private function runs(): array
	{
		$runs = [];
		$current = ['script' => '', 'wrapped' => FALSE, 'args' => [], 'env' => []];
		foreach (explode("\0", (string) @file_get_contents("{$this->root}/record")) as $entry) {
			if ($entry === 'end') {
				ksort($current['env'], SORT_STRING);
				$runs[] = $current;
				$current = ['script' => '', 'wrapped' => FALSE, 'args' => [], 'env' => []];
			} elseif (str_starts_with($entry, 'script=')) {
				$current['script'] = substr($entry, 7);
			} elseif (str_starts_with($entry, 'wrapped=')) {
				$current['wrapped'] = substr($entry, 8) === '1';
			} elseif (str_starts_with($entry, 'arg=')) {
				$current['args'][] = substr($entry, 4);
			} elseif (str_starts_with($entry, 'PFB_')) {
				[$name, $value] = explode('=', $entry, 2);
				$current['env'][$name] = $value;
			}
		}
		return $runs;
	}

	#[DataProvider('corpus')]
	public function testScenario(string $file): void
	{
		$sc = json_decode((string) file_get_contents($file), TRUE, 512, JSON_THROW_ON_ERROR);
		if (isset($sc['old_expect'])) {
			$this->assertNotSame('', $sc['departure'] ?? '', 'a scenario with old_expect names its departure');
		}
		$this->assertContains($sc['caller'], ['runhooks', 'uninstall']);
		$this->assertJson($this->content($sc['stdin']), 'the one-shot gets one JSON object');
		$this->stage($sc);
		$root = $this->root;
		$vars = [];
		foreach ($sc['vars'] ?? [] as $name => $value) {
			$vars[(string) $name] = $this->content($value);
		}
		$argv = array_map(fn(string $arg): string => $this->content($arg), $sc['argv'] ?? []);
		file_put_contents("{$root}/scenario.json", json_encode(['caller' => $sc['caller'], 'when' => $sc['when'],
			'argv' => $argv, 'vars' => $vars, 'rows' => $sc['rows']], JSON_THROW_ON_ERROR));
		$repo = dirname(__DIR__, 2);
		// the extract below starts at the first occurrence of its start string, inside the verb's block: the verb's guard must
		// be right before that occurrence
		$page = (string) file_get_contents("{$repo}/src/usr/local/www/pfblockerng/pfblockerng.php");
		$start = strpos($page, "\$when = (\$argv[2] ?? '')");
		$this->assertIsInt($start, 'the extract has its start string');
		$this->assertMatchesRegularExpression('/elseif \(\$argv\[1\] == \'runhooks\'\) \{\s*\z/', substr($page, 0, $start),
			'the runhooks verb guards the extract');
		file_put_contents("{$root}/worker.php", <<<'PHP'
<?php
[, $root, $repo] = $argv;
define('PFB_HOOK_SCRIPT_DIR', "{$root}/hooks");
define('PFB_PYTHON_WRAPPER', "{$root}/wrapper.sh");
define('PFB_HOOK_KILL_GRACE', 1);
require "{$repo}/tests/php/bootstrap.php";
require_once "{$repo}/tests/php/PageStatementLoader.php";
$sc = json_decode((string) file_get_contents("{$root}/scenario.json"), TRUE);
foreach (array_keys(getenv()) as $name) {
	if (str_starts_with($name, 'PFB_')) {
		putenv($name);	// a hook inherits the runner's environment: only the scenario's PFB_* may reach it
	}
}
$pfb =& $GLOBALS['pfb'];
foreach (['log' => 'main.log', 'errlog' => 'error.log'] as $key => $name) {
	$pfb[$key] = "{$root}/{$name}";
	file_put_contents($pfb[$key], '');
}
$pfb['tmp'] = $root;
$pfb['runlog_active'] = FALSE;
unset($pfb['core_update'], $pfb['hook_lifecycle'], $pfb['run_stdout_override']);
$GLOBALS['config']['installedpackages']['pfblockerng']['config'][0] = ['hooks' => ['row' => $sc['rows']]];
if ($sc['caller'] === 'uninstall') {
	$pfb['hook_lifecycle'] = 'uninstall';	// as pfblockerng_php_pre_deinstall_command() sets it before its disable pass
	pfb_run_hooks($sc['when'], $sc['vars']);
	exit(0);
}
$argv = array_merge(['pfblockerng.php', 'runhooks'], $sc['argv']);
eval(pfb_test_page_block_from('src/usr/local/www/pfblockerng/pfblockerng.php', "\$when = (\$argv[2] ?? '')"));
PHP);
		// LC_ALL=C: timeout(1) quotes the path in its own messages by locale.
		$command = 'LC_ALL=C ' . escapeshellarg((string) $GLOBALS['pfb_test_timeout']) . ' --foreground -k 5 120 ';
		if (isset($sc['pkgOp'])) {
			// pfb_pkg_operation() walks the ancestors in the process table: perl's $0 stands in for the pkg process.
			$command .= 'perl -e ' . escapeshellarg('$0 = shift; exit(system(@ARGV) >> 8)') . ' '
				. escapeshellarg(self::PKG_ARGV[$sc['pkgOp']]) . ' ';
		}
		$command .= escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg("{$root}/worker.php") . ' ' . escapeshellarg($root)
			. ' ' . escapeshellarg($repo) . ' > ' . escapeshellarg("{$root}/worker.out")
			. ' 2> ' . escapeshellarg("{$root}/worker.err");
		exec($command, $discard, $status);
		$this->assertSame(0, $status, 'worker: ' . file_get_contents("{$root}/worker.err"));

		$expect = array_replace($sc['expect'], $sc['old_expect'] ?? []);
		$want = [];
		foreach ($expect['runs'] as $run) {
			$env = array_map(fn(string $value): string => $this->content($value), $run['env']);
			ksort($env, SORT_STRING);
			$want[] = ['script' => $run['script'], 'wrapped' => $run['wrapped'], 'args' => $run['args'], 'env' => $env];
		}
		$this->assertSame($want, $this->runs(), 'recorded invocations: order, launcher, arguments, PFB_* environment');
		$this->assertSame($this->content($expect['log']),
			preg_replace(self::STAMP, '', (string) file_get_contents("{$root}/main.log")), 'main log without time stamps');
		$this->assertSame($this->content($expect['console']),
			preg_replace(self::STAMP, '{stamp} ', (string) file_get_contents("{$root}/worker.out")), 'console');
		foreach ($expect['absent'] ?? [] as $canary) {
			$this->assertFileDoesNotExist("{$root}/{$canary}", 'an unevaluated value was evaluated');
		}
	}
}
