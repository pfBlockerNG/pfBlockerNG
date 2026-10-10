<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3469 -- pfblockerng.php is the root-privileged CLI verb dispatcher, yet it
 * sits under the webConfigurator docroot with no auth gate. Its verbs read the bare
 * $argv global, which PHP fills on the CLI SAPI alone; a non-CLI request must exit
 * before any include, pfb_global() or verb. The localhost ?pfb= alias-table branch
 * precedes that guard and keeps serving over HTTP.
 *
 * Every case runs the real file in a subprocess (php-cgi is the non-CLI SAPI). The
 * tripwire util.inc -- the file's first require_once -- stands in for "the request got
 * past the guard": it prints TRIPWIRE and exits 99, so reaching the includes is
 * observable and harmless. The alias case runs a copy of the file whose hardcoded
 * /var/db/aliastables/ prefix points at a sandbox; no other byte differs.
 */
final class PfblockerngSapiGuardTest extends TestCase
{
	private const SALVAGE_SECONDS = 10;
	private const TRIPWIRE = "TRIPWIRE: includes reached\n";
	private const TRIPWIRE_EXIT = 99;
	private const ALIAS = 'pfbtest3469';
	private const ALIAS_CONTENT = "192.0.2.1\n192.0.2.2\n";

	private string $dir;
	private string $php_cgi;
	private string $script;

	protected function setUp(): void
	{
		$this->script = dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng.php';
		$this->assertFileExists($this->script);

		$cgi = NULL;
		foreach ([dirname(PHP_BINARY), ...explode(PATH_SEPARATOR, (string) getenv('PATH'))] as $bindir) {
			if (is_executable("{$bindir}/php-cgi")) {
				$cgi = "{$bindir}/php-cgi";
				break;
			}
		}
		$this->assertNotNull($cgi, 'php-cgi not found: it is the non-CLI SAPI these tests need '
			. '(CI setup-php ships it; Debian/Ubuntu: apt install php-cgi)');
		$this->php_cgi = $cgi;

		$this->dir = sys_get_temp_dir() . '/pfb_sapi_guard_' . getmypid() . '_' . uniqid();
		$this->assertTrue(mkdir("{$this->dir}/include", 0777, TRUE));
		$this->assertTrue(mkdir("{$this->dir}/aliastables", 0777, TRUE));
		file_put_contents("{$this->dir}/include/util.inc",
			'<?php echo ' . var_export(self::TRIPWIRE, TRUE) . '; exit(' . self::TRIPWIRE_EXIT . ');');
		file_put_contents("{$this->dir}/aliastables/" . self::ALIAS . '_v4.txt', self::ALIAS_CONTENT);
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->dir);
	}

	/**
	 * Given a request under the CGI SAPI whose query string spells a verb (PHP then
	 *   fills $_SERVER['argv'] from it, but not the $argv global),
	 * When it comes from a remote client, or from loopback without a usable ?pfb=,
	 * Then the process exits 0 with an empty body before the first require_once --
	 *   pre-fix the request reaches the includes (the tripwire fires, exit 99).
	 *
	 * @return array<string, array{string, string}>
	 */
	public static function nonCliVerbRequests(): array
	{
		return [
			'remote client, bare verb' => ['10.0.0.5', 'clearip'],
			'remote client, verb with argument' => ['10.0.0.5', 'dnsbl-control+disable'],
			'loopback client, bare verb' => ['127.0.0.1', 'clearip'],
			'loopback client, empty pfb falls through to the verbs' => ['127.0.0.1', 'pfb=&cleardnsbl'],
		];
	}

	#[DataProvider('nonCliVerbRequests')]
	public function testNonCliRequestExitsBeforeIncludesAndVerbs(string $remote, string $query): void
	{
		$run = $this->runCgi($this->script, $remote, $query);

		$this->assertSame('', $run['stdout'],
			"a non-CLI request must produce no output and never reach the includes:\n{$run['stdout']}");
		$this->assertSame(0, $run['status'], "non-CLI request must exit 0, got {$run['status']}:\n{$run['stderr']}");
	}

	/**
	 * Given a request under the CGI SAPI from loopback (the URL-table alias fetch) for
	 *   an alias whose table file exists,
	 * When the localhost ?pfb= branch runs ahead of the guard,
	 * Then the table content is the whole response -- the guard did not swallow it and
	 *   nothing past it ran.
	 */
	public function testNonCliLoopbackAliasRequestStillServesTheAliasTable(): void
	{
		$source = file_get_contents($this->script);
		$this->assertNotFalse($source);
		$sandboxed = str_replace('/var/db/aliastables/', "{$this->dir}/aliastables/", $source, $count);
		$this->assertSame(1, $count, 'the alias-table directory literal in pfblockerng.php changed: '
			. 'update the sandbox mapping of this test');
		$copy = "{$this->dir}/pfblockerng.php";
		file_put_contents($copy, $sandboxed);

		$run = $this->runCgi($copy, '127.0.0.1', 'pfb=' . self::ALIAS);

		$this->assertSame(self::ALIAS_CONTENT, $run['stdout'], "stderr:\n{$run['stderr']}");
		$this->assertSame(0, $run['status'], "alias request must exit 0, got {$run['status']}:\n{$run['stderr']}");
	}

	/**
	 * Given the CLI SAPI with a verb in $argv (how cron, mwexec_bg and daemon(8) call it),
	 * When pfblockerng.php runs,
	 * Then it proceeds past the guard to the includes -- the tripwire fires.
	 */
	public function testCliVerbStillReachesTheIncludes(): void
	{
		$run = $this->spawn(PHP_BINARY, [$this->script, 'dnsbl-control', 'disable'], []);

		$this->assertSame(self::TRIPWIRE, $run['stdout'], "stderr:\n{$run['stderr']}");
		$this->assertSame(self::TRIPWIRE_EXIT, $run['status'], "stderr:\n{$run['stderr']}");
	}

	/** @return array{status: int, stdout: string, stderr: string} stdout is the CGI response body */
	private function runCgi(string $script, string $remote, string $query): array
	{
		$run = $this->spawn($this->php_cgi, ['-d', 'cgi.force_redirect=0'], [
			'REQUEST_METHOD' => 'GET',
			'SCRIPT_FILENAME' => $script,
			'QUERY_STRING' => $query,
			'REMOTE_ADDR' => $remote,
		]);
		$response = explode("\r\n\r\n", $run['stdout'], 2);
		$this->assertCount(2, $response, "php-cgi sent no CGI header block:\n{$run['stdout']}\n{$run['stderr']}");
		$run['stdout'] = $response[1];

		return $run;
	}

	/**
	 * PHP errors go to stderr (log_errors) so a CGI body holds script output only.
	 *
	 * @param list<string> $args
	 * @param array<string, string> $env
	 * @return array{status: int, stdout: string, stderr: string}
	 */
	private function spawn(string $binary, array $args, array $env): array
	{
		$timeout = (string) ($GLOBALS['pfb']['timeout'] ?? '/usr/bin/timeout');
		$stderr_file = "{$this->dir}/stderr.txt";
		$process = proc_open(
			[$timeout, '-s', 'TERM', '-k', '2', (string) self::SALVAGE_SECONDS, $binary, '-n',
				'-d', "include_path={$this->dir}/include", '-d', 'display_errors=0', '-d', 'log_errors=1',
				'-d', 'error_reporting=-1', ...$args],
			[0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['file', $stderr_file, 'w']],
			$pipes,
			$this->dir,
			['PATH' => '/usr/bin:/bin'] + $env
		);
		$this->assertIsResource($process);
		$stdout = (string) stream_get_contents($pipes[1]);
		fclose($pipes[1]);
		$status = proc_close($process);

		return ['status' => $status, 'stdout' => $stdout, 'stderr' => (string) file_get_contents($stderr_file)];
	}
}
