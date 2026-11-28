<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * #3977 (spec section 5): hooks outside an Update (the `runhooks` verb, the uninstall disable pass) run through this machine's
 * `pfb-core --run-hooks`, with the context as one JSON object on stdin and the one-shot's stderr appended to the main log. No PHP
 * hook runner remains: a package without the binary logs that once and runs no hook (a hostile-input row of #3977).
 */
#[CoversFunction('pfb_core_run_hooks')]
#[CoversFunction('pfb_hook_oneshot_context')]
final class CoreRunHooksTest extends TestCase
{
	private string $dir;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_runhooks_' . bin2hex(random_bytes(6));
		mkdir("{$this->dir}/core/bin/freebsd-amd64", 0o755, TRUE);
		$GLOBALS['pfb']['log'] = "{$this->dir}/pfblockerng.log";
	}

	protected function tearDown(): void
	{
		exec('rm -rf ' . escapeshellarg($this->dir));
	}

	/** A stand-in pfb-core: records its arguments and stdin, writes one line to stderr, exits with $status. */
	private function standIn(int $status = 0): void
	{
		$bin = "{$this->dir}/core/bin/freebsd-amd64/pfb-core";
		file_put_contents($bin, "#!/bin/sh\nprintf '%s\\n' \"\$@\" > {$this->dir}/args\ncat > {$this->dir}/stdin\n" .
			"echo 'a hook ran' >&2\nexit {$status}\n");
		chmod($bin, 0o755);
	}

	public function testItRunsTheOneShotWithTheContextOnStdin(): void
	{
		$this->standIn();
		$status = pfb_core_run_hooks('post', ['trigger' => 'manual-test', 'ipChanged' => FALSE], "{$this->dir}/core", 'amd64');
		$this->assertSame(0, $status);
		$this->assertSame(['--run-hooks', 'post', '--hook-dir', PFB_HOOK_SCRIPT_DIR, '--settings-backend-cmd', PFB_CORE_SETTINGS_CMD,
			'--python-wrapper', PFB_PYTHON_WRAPPER], file("{$this->dir}/args", FILE_IGNORE_NEW_LINES));
		$this->assertSame(['trigger' => 'manual-test', 'ipChanged' => FALSE], json_decode((string) file_get_contents("{$this->dir}/stdin"), TRUE));
		$this->assertStringContainsString('a hook ran', (string) file_get_contents($GLOBALS['pfb']['log']), 'stderr is the main log');
	}

	public function testTheOneShotsStatusIsReturned(): void
	{
		$this->standIn(1);
		$this->assertSame(1, pfb_core_run_hooks('pre', ['trigger' => 'x'], "{$this->dir}/core", 'amd64'));
	}

	public function testAnEmptyContextIsSentAsAnObject(): void
	{
		$this->standIn();
		pfb_core_run_hooks('pre', [], "{$this->dir}/core", 'amd64');
		$this->assertSame('{}', trim((string) file_get_contents("{$this->dir}/stdin")));
	}

	public function testWithoutTheBinaryNoHookRunsAndThatIsLoggedOnce(): void
	{
		$this->assertSame(1, pfb_core_run_hooks('pre', ['trigger' => 'x'], "{$this->dir}/core", 'arm64'));
		$log = (string) file_get_contents($GLOBALS['pfb']['log']);
		$this->assertSame(1, substr_count($log, 'no pfb-core'), $log);
	}

	/** The `runhooks` verb: its synthetic context goes to the one-shot (protocol "Hooks outside an Update"), its status is the exit. */
	public function testTheRunhooksVerbRunsTheOneShot(): void
	{
		$src = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng.php');
		$start = strpos($src, "elseif (\$argv[1] == 'runhooks')");
		$this->assertNotFalse($start);
		$verb = substr($src, $start, (int) strpos($src, 'exit(', $start) - $start + 60);
		$this->assertStringContainsString("\$ctx = array('trigger' => (\$argv[3] ?? 'manual-test'));", $verb);
		$this->assertStringContainsString("\$ctx += array('ipChanged' => FALSE, 'dnsblChanged' => FALSE, 'changedIpAliases' => '', 'changedDnsblGroups' => '');", $verb);
		$this->assertStringContainsString('exit(pfb_core_run_hooks($when, $ctx));', $verb);
		$this->assertStringNotContainsString('pfb_run_hooks(', $verb);
	}

	/** The uninstall disable pass's hook context, as the one-shot takes it (the corpus's uninstall scenarios). */
	public function testThePassContextBecomesTheOneShotsStdin(): void
	{
		$this->assertSame(['trigger' => 'update', 'lifecycle' => 'uninstall', 'pkgOp' => 'delete'],
			pfb_hook_oneshot_context(['TRIGGER' => 'update'], 'delete'));
		$this->assertSame(['trigger' => 'update', 'lifecycle' => 'uninstall', 'pkgOp' => 'delete', 'ipChanged' => TRUE,
			'dnsblChanged' => FALSE, 'changedIpAliases' => 'pfB_Alpha_v4 pfB_Beta_v6', 'changedDnsblGroups' => 'Ads'],
			pfb_hook_oneshot_context(['TRIGGER' => 'update', 'IP_CHANGED' => '1', 'DNSBL_CHANGED' => '0', 'STATUS' => 'ok',
				'CHANGED_IP_ALIASES' => 'pfB_Alpha_v4 pfB_Beta_v6', 'CHANGED_DNSBL_GROUPS' => 'Ads'], 'delete'));
	}

	/** The disable pass fires its hooks through pfb-core alone, with the uninstall context (#3977): no PHP hook runner remains. */
	public function testThePassFiresItsHooksThroughCoreAlone(): void
	{
		$apply = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc');
		$this->assertSame(2, substr_count($apply, 'pfb_pass_hooks('));
		$inc = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc');
		$this->assertMatchesRegularExpression("~function pfb_pass_hooks\\(string \\\$when, array \\\$ctx\\): void \\{ pfb_core_run_hooks\\(\\\$when, pfb_hook_oneshot_context\\(\\\$ctx, pfb_pkg_operation\\(\\)\\)\\); \\}~", $inc);
	}
}
