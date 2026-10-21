<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #3539 — only the apply pass decides whether the DNSBL web server runs. The resolver reload
 * (pfb_update_unbound() with a config change) and the dashboard widget's query-frequency save used to
 * restart it; with no VIP demand that would launch nothing useful, and with it the apply already restarts
 * it when its conf changed, so neither restarts it any more.
 */
#[CoversFunction('pfb_update_unbound')]
final class DnsblWebServerNoRestartTest extends TestCase
{
	private const ROOT = __DIR__ . '/../..';
	private const WIDGET = self::ROOT . '/src/usr/local/www/widgets/widgets/pfblockerng.widget.php';

	private string $dir = '';
	/** @var array<string,array{bool,mixed}> */
	private array $savedGlobals = [];

	protected function setUp(): void
	{
		foreach (['pfb', 'config', 'g'] as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
		$this->dir = sys_get_temp_dir() . '/pfb_no_restart_' . getmypid() . '_' . bin2hex(random_bytes(6));
		mkdir("{$this->dir}/dnsdir", 0777, TRUE);
	}

	protected function tearDown(): void
	{
		foreach ($this->savedGlobals as $name => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
		$this->savedGlobals = [];
		unset($GLOBALS['pfb_test_service_calls'], $GLOBALS['pfb_test_process_running'], $GLOBALS['pfb_test_file_notices']);
		rmdir_recursive($this->dir);
	}

	public function testAResolverReloadThatChangesConfigDoesNotRestartTheWebServer(): void
	{
		// GIVEN an enabled DNSBL whose reload carries a config change (the restart path), with a resolver that restarts cleanly
		$dir = $this->dir;
		$GLOBALS['pfb'] = array_replace($GLOBALS['pfb'] ?? [], [
			'dnsbldir' => $dir, 'dbdir' => $dir, 'dnsbl_file' => "{$dir}/pfb_dnsbl", 'dnsdir' => "{$dir}/dnsdir",
			'dnsbl_cache' => "{$dir}/pfb_py_cache.sqlite", 'unbound_py_count' => "{$dir}/pfb_py_count",
			'unbound_py_sources' => "{$dir}/pfb_py_sources.json", 'unbound_py_rawdir' => "{$dir}/pfb_py_raw",
			'unbound_py_reject_stats' => "{$dir}/pfb_py_reject_stats.json", 'chroot_cmd' => '/bin/echo',
			'dnsbl_python_unmount' => FALSE, 'dnsbl_res_cache' => PfbToggle::On, 'dnsbl_cache_flush' => PfbToggle::Off,
			'enable' => PfbToggle::On, 'dnsbl' => PfbToggle::On, 'save' => TRUE, 'dnsbl_tld_wildcard' => FALSE,
			'domain_update' => FALSE, 'reuse_dnsbl' => '', 'dnsbl_unlock' => "{$dir}/dnsbl_unlock", 'keep' => PfbToggle::On,
			'install' => FALSE, 'errlog' => "{$dir}/error.log", 'log' => "{$dir}/pfblockerng.log", 'php' => PHP_BINARY,
		]);
		$GLOBALS['config'] = [];
		$GLOBALS['g']['varrun_path'] = $dir;
		$GLOBALS['pfb_test_file_notices'] = [];
		$GLOBALS['pfb_test_service_calls'] = [];
		$GLOBALS['pfb_test_process_running'] = ['unbound' => static function (): bool {
			foreach (debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS) as $frame) {
				if (($frame['function'] ?? '') === 'pfb_stop_start_unbound') {
					return FALSE;
				}
			}
			return TRUE;
		}];
		file_put_contents($GLOBALS['pfb']['unbound_py_count'], "10\n");
		file_put_contents($GLOBALS['pfb']['unbound_py_sources'], '{"version":1,"config":{},"feeds":[]}');
		file_put_contents($GLOBALS['pfb']['unbound_py_reject_stats'], '[]');
		file_put_contents("{$dir}/unbound.conf", "python-script: pfb_unbound.py\n");

		// WHEN the reload runs with a pending config change ($pfbpython)
		set_error_handler(static fn (int $severity, string $message): bool => $severity === E_NOTICE && str_contains($message, 'tempnam(): file created in the system'));
		try {
			pfb_update_unbound('enabled', FALSE, TRUE);
		} finally {
			restore_error_handler();
		}

		// THEN the reload ran to its end, and the web server was not restarted by it
		$this->assertStringContainsString('DNSBL update [ feed lines', (string) @file_get_contents($GLOBALS['pfb']['log']));
		$this->assertNotContains(['restart_service', 'pfb_dnsbl'], $GLOBALS['pfb_test_service_calls']);
	}

	public function testSavingTheWidgetQueryFrequencyDoesNotRestartTheWebServer(): void
	{
		// GIVEN the dashboard widget and a Query frequency that differs from the stored one
		// WHEN the widget saves it
		$result = $this->runWidget(['pfb_submit' => 'save', 'pfb_dnsblquery' => '77']);

		// THEN the save ran (the new frequency is stored)
		$this->assertSame(0, $result['status'], $result['stderr']);
		$this->assertSame('77', $result['query'], 'the widget did not store the new Query frequency');
		// AND the web server was not restarted
		$this->assertNotContains(['restart_service', 'pfb_dnsbl'], $result['calls']);
	}

	/** @return array{status:int,stderr:string,query:mixed,calls:list<array{string,string}>} */
	private function runWidget(array $post): array
	{
		$root     = var_export(self::ROOT, TRUE);
		$widget   = var_export(self::WIDGET, TRUE);
		$postCode = var_export($post, TRUE);
		$shim     = var_export("{$this->dir}/shim", TRUE);
		$script   = <<<PHP
require {$root} . '/tests/php/bootstrap.php';
\$_GET = [];
\$_POST = {$postCode};
\$_SERVER = ['HTTP_SEC_FETCH_SITE' => 'same-origin'];
\$widgetname = 'pfblockerng';
mkdir({$shim}, 0700, TRUE);
file_put_contents({$shim} . '/guiconfig.inc', '<?php');
set_include_path({$shim} . PATH_SEPARATOR . get_include_path());
set_error_handler(static function (int \$severity, string \$message): bool {
	fwrite(STDERR, \$severity . ': ' . \$message . "\\n");
	return TRUE;
});
register_shutdown_function(static function (): void {
	echo "\\n__PFB_RESULT__" . json_encode([
		'query' => \$GLOBALS['pfb']['wglobal']['widget-dnsblquery'] ?? NULL,
		'calls' => \$GLOBALS['pfb_test_service_calls'] ?? [],
	]);
});
require {$widget};
PHP;
		$process = proc_open([PHP_BINARY, '-r', $script], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
		$this->assertIsResource($process);
		$stdout = (string) stream_get_contents($pipes[1]);
		$stderr = (string) stream_get_contents($pipes[2]);
		fclose($pipes[1]);
		fclose($pipes[2]);
		$status = proc_close($process);
		$marker = strrpos($stdout, '__PFB_RESULT__');
		$this->assertIsInt($marker, $stdout);
		$state = json_decode(substr($stdout, $marker + strlen('__PFB_RESULT__')), TRUE, 512, JSON_THROW_ON_ERROR);
		return ['status' => $status, 'stderr' => $stderr, 'query' => $state['query'], 'calls' => $state['calls']];
	}
}
