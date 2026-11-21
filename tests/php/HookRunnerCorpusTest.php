<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The ADR-12 hook runner corpus (#4035 slice 6a) driven through today's pfb_run_hooks(): every scenario under
 * tests/hooks/fixtures/runner runs in a fresh PHP process that defines the hook directory, the Python wrapper and a 1 s
 * kill grace, loads the real pfblockerng.inc, stores the scenario's rows as config.xml holds them and fires the hooks.
 * go/pfb_core/hooks runs the same files (runner_corpus_test.go there); a scenario that passes here and fails there, or the
 * reverse, is a divergence.
 *
 * A scenario (the Go runner refuses unknown keys):
 *   description  what it pins; departure says why Go differs when old_expect is present.
 *   when         the fire point. rows: the stored hook rows. vars: the context (name => value), as pfb_run_hooks() takes it.
 *   trigger      the request trigger: pfb_req_to_hook_trigger() of it must be vars.TRIGGER.
 *   lifecycle    $pfb['hook_lifecycle']. pkgOp: the operation of a pkg process the run is under (install, upgrade, reinstall,
 *                delete), as pfb_pkg_operation() reads it from the process table.
 *   python       "none": the wrapper reports no interpreter; else it reports one and runs a .py hook through /bin/sh.
 *   files        path under the scenario root => {body, mode} (mode octal, 0755 by default), {symlink} or {dir}. The hook
 *                directory is hooks/. {root} in any string is the scenario root; {record} in a body sources the recorder,
 *                which appends the script's name, whether the wrapper ran it, its arguments and its environment.
 *   expect       runs (each recorded invocation's script, wrapped, args and PFB_* environment, in order), log (the main
 *                log), errors (the error log), transcript (the viewer), all without pfb_logger()'s time stamps; absent
 *                (canary files that must not exist), alive and dead (pid files of processes that must be running, or
 *                gone, when the run returns), throws (the class of what pfb_run_hooks() threw, "" for nothing).
 *   old_expect   today's answer where Go deliberately differs: its keys replace expect's here.
 * A content is a string, {"b64": bytes} or {"prefix", "repeat", "times", "suffix"}.
 *
 * Three scenarios store "timeout": "1" (child-of-a-timed-out-hook-is-left-alone, hook-that-ignores-term-is-killed,
 * post-hook-past-its-timeout-is-killed-and-the-next-runs): the timeout is the behaviour under test, and one second is
 * its smallest value. Each of their hooks writes the pid file the scenario reads only once its setup is done (its TERM
 * trap installed, its child running), and a missing or empty pid file fails the scenario, so a hook too slow to set up
 * within the second fails loudly instead of passing for the wrong reason.
 */
#[CoversFunction('pfb_run_hooks')]
#[CoversFunction('pfb_req_to_hook_trigger')]
final class HookRunnerCorpusTest extends TestCase
{
	private const STAMP = '/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} /m';
	private const PKG_ARGV = ['install' => 'pkg install pfSense-pkg-pfBlockerNG', 'reinstall' => 'pkg install -f pfSense-pkg-pfBlockerNG',
		'upgrade' => 'pkg upgrade pfSense-pkg-pfBlockerNG', 'delete' => 'pkg delete pfSense-pkg-pfBlockerNG'];

	private string $root = '';

	public static function corpus(): array
	{
		$cases = [];
		foreach (glob(__DIR__ . '/../hooks/fixtures/runner/*.json') ?: [] as $file) {
			$cases[basename($file, '.json')] = [$file];
		}
		return $cases;
	}

	protected function setUp(): void
	{
		$base = sys_get_temp_dir() . '/pfb_hook_corpus_' . getmypid() . '_' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir($base, 0700, TRUE));
		$this->root = (string) realpath($base);
	}

	protected function tearDown(): void
	{
		foreach (glob("{$this->root}/*.pid") ?: [] as $pidfile) {
			$pid = (int) trim((string) file_get_contents($pidfile));
			if ($pid > 1) {
				exec('kill -KILL ' . $pid . ' 2>/dev/null');
			}
		}
		exec('rm -rf ' . escapeshellarg($this->root));
	}

	private function expand(string $text): string
	{
		return str_replace(['{record}', '{root}'], [". '{root}/record.sh'", $this->root], $text);
	}

	/** @param array<string,mixed>|string $content */
	private function content(array|string $content): string
	{
		if (is_string($content)) {
			return $this->expand($content);
		}
		if (isset($content['b64'])) {
			return (string) base64_decode($content['b64'], TRUE);
		}
		return $this->expand($content['prefix'] ?? '') . str_repeat($content['repeat'], $content['times'])
			. $this->expand($content['suffix'] ?? '');
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
			if (!is_dir(dirname($target))) {
				$this->assertTrue(mkdir(dirname($target), 0755, TRUE));
			}
			if (isset($file['symlink'])) {
				$this->assertTrue(symlink($this->expand($file['symlink']), $target));
			} elseif (!empty($file['dir'])) {
				$this->assertTrue(mkdir($target, 0755));
			} else {
				$this->assertNotFalse(file_put_contents($target, $this->content($file['body'])));
				$this->assertTrue(chmod($target, intval($file['mode'] ?? '0755', 8)));
			}
		}
	}

	/** @return list<array{script:string, wrapped:bool, args:list<string>, env:array<string,string>}> */
	private function runs(): array
	{
		$record = @file_get_contents("{$this->root}/record");
		$runs = [];
		$current = ['script' => '', 'wrapped' => FALSE, 'args' => [], 'env' => []];
		foreach (explode("\0", (string) $record) as $entry) {
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

	private function alive(string $pidfile): bool
	{
		$pid = (int) trim((string) @file_get_contents($pidfile));
		$this->assertGreaterThan(1, $pid, "pid file {$pidfile} holds no pid");
		exec('kill -0 ' . $pid . ' 2>/dev/null', $discard, $rc);
		return $rc === 0;
	}

	#[DataProvider('corpus')]
	public function testScenario(string $file): void
	{
		$sc = json_decode((string) file_get_contents($file), TRUE, 512, JSON_THROW_ON_ERROR);
		if (isset($sc['old_expect'])) {
			$this->assertNotSame('', $sc['departure'] ?? '', 'a scenario with old_expect names its departure');
		}
		$vars = [];
		foreach ($sc['vars'] as $name => $value) {
			$vars[(string) $name] = $this->content($value);
		}
		if (array_key_exists('trigger', $sc)) {
			$this->assertSame($vars['TRIGGER'] ?? NULL, pfb_req_to_hook_trigger($sc['trigger']),
				"vars.TRIGGER is what pfb_req_to_hook_trigger() makes of trigger {$sc['trigger']}");
		}
		$this->stage($sc);
		$root = $this->root;
		$rows = json_decode($this->expand(json_encode($sc['rows'], JSON_THROW_ON_ERROR)), TRUE, 512, JSON_THROW_ON_ERROR);
		file_put_contents("{$root}/scenario.json", json_encode(['when' => $sc['when'], 'rows' => $rows, 'vars' => $vars,
			'lifecycle' => $sc['lifecycle'] ?? NULL], JSON_THROW_ON_ERROR));
		$repo = dirname(__DIR__, 2);
		file_put_contents("{$root}/worker.php", <<<'PHP'
<?php
[, $root, $repo] = $argv;
define('PFB_HOOK_SCRIPT_DIR', "{$root}/hooks");
define('PFB_PYTHON_WRAPPER', "{$root}/wrapper.sh");
define('PFB_HOOK_KILL_GRACE', 1);
require "{$repo}/tests/php/bootstrap.php";
$sc = json_decode((string) file_get_contents("{$root}/scenario.json"), TRUE);
foreach (array_keys(getenv()) as $name) {
	if (str_starts_with($name, 'PFB_')) {
		putenv($name);	// a hook inherits the runner's environment: only the scenario's PFB_* may reach it
	}
}
$pfb =& $GLOBALS['pfb'];
foreach (['log' => 'main.log', 'errlog' => 'error.log', 'runlog' => 'viewer.log'] as $key => $name) {
	$pfb[$key] = "{$root}/{$name}";
	file_put_contents($pfb[$key], '');
}
$pfb['tmp'] = $root;
$pfb['runlog_active'] = TRUE;
unset($pfb['core_update'], $pfb['hook_lifecycle']);
if ($sc['lifecycle'] !== NULL) {
	$pfb['hook_lifecycle'] = $sc['lifecycle'];
}
$GLOBALS['config']['installedpackages']['pfblockerng']['config'][0] = ['hooks' => ['row' => $sc['rows']]];
try {
	pfb_run_hooks($sc['when'], $sc['vars']);
} catch (Throwable $e) {
	file_put_contents("{$root}/throws", get_class($e));
}
PHP);
		// LC_ALL=C: timeout(1) quotes the path in its own messages by locale.
		$command = 'LC_ALL=C ' . escapeshellarg((string) $GLOBALS['pfb_test_timeout']) . ' --foreground -k 5 120 ';
		if (isset($sc['pkgOp'])) {
			// pfb_pkg_operation() walks the ancestors in the process table: perl's $0 stands in for the pkg process.
			$command .= 'perl -e ' . escapeshellarg('$0 = shift; exit(system(@ARGV) >> 8)') . ' '
				. escapeshellarg(self::PKG_ARGV[$sc['pkgOp']]) . ' ';
		}
		$command .= escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg("{$root}/worker.php") . ' ' . escapeshellarg($root) . ' '
			. escapeshellarg($repo) . ' > ' . escapeshellarg("{$root}/worker.out") . ' 2>&1';
		exec($command, $discard, $status);
		$this->assertSame(0, $status, 'worker: ' . file_get_contents("{$root}/worker.out"));

		$expect = array_replace($sc['expect'], $sc['old_expect'] ?? []);
		$want = [];
		foreach ($expect['runs'] as $run) {
			$env = [];
			foreach ($run['env'] as $name => $value) {
				$env[$name] = $this->expand($value);
			}
			ksort($env, SORT_STRING);
			$want[] = ['script' => $run['script'], 'wrapped' => $run['wrapped'], 'args' => $run['args'], 'env' => $env];
		}
		$this->assertSame($want, $this->runs(), 'recorded invocations: order, launcher, arguments, PFB_* environment');
		$this->assertSame($expect['throws'] ?? '', (string) @file_get_contents("{$root}/throws"));
		foreach (['log' => 'main.log', 'errors' => 'error.log', 'transcript' => 'viewer.log'] as $key => $name) {
			$this->assertSame($this->content($expect[$key]),
				preg_replace(self::STAMP, '', (string) file_get_contents("{$root}/{$name}")), "{$name} without time stamps");
		}
		foreach ($expect['absent'] ?? [] as $canary) {
			$this->assertFileDoesNotExist("{$root}/{$canary}", 'an unvetted or unevaluated script ran');
		}
		foreach ($expect['alive'] ?? [] as $pidfile) {
			$this->assertTrue($this->alive("{$root}/{$pidfile}"), "{$pidfile}: the process must outlive the run");
		}
		foreach ($expect['dead'] ?? [] as $pidfile) {
			$this->assertFalse($this->alive("{$root}/{$pidfile}"), "{$pidfile}: the process must be gone when the run returns");
		}
	}
}
