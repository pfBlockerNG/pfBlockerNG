<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class WidgetPostAllowedTest extends TestCase
{
	private const ROOT = __DIR__ . '/../..';
	private const WIDGET = self::ROOT . '/src/usr/local/www/widgets/widgets/pfblockerng.widget.php';

	/** @var list<string> Stale shim paths planted by runWidget(), swept after each test. */
	private array $planted = [];

	protected function tearDown(): void
	{
		foreach ($this->planted as $path) {
			@unlink($path . '/guiconfig.inc');
			@rmdir($path);
		}
		$this->planted = [];
	}

	public static function setUpBeforeClass(): void
	{
		require_once dirname(__DIR__, 2) . '/src/usr/local/www/widgets/include/widget-pfblockerng.inc';
	}

	/** @return array<string,array{array<string,string>,bool}> */
	public static function truthTableProvider(): array
	{
		return [
			'absent header' => [[], FALSE],
			'same-origin' => [['HTTP_SEC_FETCH_SITE' => 'same-origin'], TRUE],
			'none' => [['HTTP_SEC_FETCH_SITE' => 'none'], TRUE],
			'cross-site' => [['HTTP_SEC_FETCH_SITE' => 'cross-site'], FALSE],
			'same-site' => [['HTTP_SEC_FETCH_SITE' => 'same-site'], FALSE],
			'empty' => [['HTTP_SEC_FETCH_SITE' => ''], FALSE],
		];
	}

	#[DataProvider('truthTableProvider')]
	public function testGuardTruthTable(array $server, bool $expected): void
	{
		$this->assertSame($expected, pfb_widget_post_guard(['pfb_submit' => '1'], $server, 'pfb_submit'));
	}

	/** @return array<string,array{string}> */
	public static function mutationFields(): array
	{
		return [
			'settings' => ['pfb_submit'],
			'failed' => ['pfblockerngack'],
			'all counts' => ['pfblockerngclearall'],
			'ip counts' => ['pfblockerngclearip'],
			'dnsbl counts' => ['pfblockerngcleardnsbl'],
		];
	}

	#[DataProvider('mutationFields')]
	public function testEveryShippedMutationBranchStaysClosedWithoutFetchMetadata(string $field): void
	{
		$result = $this->runWidget([], [$field => '1']);
		$this->assertSame(0, $result['status'], $result['stderr']);
		$this->assertStringContainsString('<form id="formicons"', $result['stdout']);
	}

	/**
	 * Scenario: the include shim is per-invocation scratch.
	 * Given a render of the real widget,
	 * When the subprocess exits,
	 * Then the temp directory holds nothing keyed to that run -- a shim left
	 * behind is what lets a later run on a recycled PID collide (issue #2834).
	 */
	public function testWidgetRunLeavesNoShimResidue(): void
	{
		// A checkout without this fix, sharing the host, can already hold a bare
		// pfb_widget_shim_<pid>, so only what this run added counts.
		$before = glob(sys_get_temp_dir() . '/pfb_widget_shim_*') ?: [];
		$result = $this->runWidget([], []);
		$this->assertSame(0, $result['status'], $result['stderr']);
		$this->assertSame([], array_diff($this->shimResidue($result['pid']), $before));
	}

	/**
	 * Scenario: the OS recycles a PID an earlier suite run already used.
	 * Given a shim directory already sitting at this run's PID-keyed path,
	 * When the real widget renders,
	 * Then it renders as usual, never writes into the directory it inherited,
	 * and adds no residue of its own beside it.
	 */
	public function testWidgetSurvivesAShimLeftOverFromARecycledPid(): void
	{
		$result = $this->runWidget([], [], TRUE);
		$this->assertSame(0, $result['status'], $result['stderr']);
		$this->assertStringContainsString('<form id="formicons"', $result['stdout']);
		$this->assertSame([], glob($this->planted[0] . '/*') ?: [], 'a per-invocation shim path must never adopt an inherited directory');
		$this->assertSame([], array_diff($this->shimResidue($result['pid']), $this->planted));
	}

	/** @return list<string> Shim directories owned by child PID $pid, with or without a per-invocation suffix. */
	private function shimResidue(int $pid): array
	{
		$prefix = sys_get_temp_dir() . '/pfb_widget_shim_' . $pid;
		return array_merge(glob($prefix) ?: [], glob($prefix . '_*') ?: []);
	}

	/** @return array{status:int,stdout:string,stderr:string,pid:int} */
	private function runWidget(array $get, array $post, bool $plantStaleShim = FALSE): array
	{
		$root = var_export(self::ROOT, TRUE);
		$widget = var_export(self::WIDGET, TRUE);
		$getCode = var_export($get, TRUE);
		$postCode = var_export($post, TRUE);
		$script = <<<PHP
stream_get_contents(STDIN);
\$_GET = {$getCode};
\$_POST = {$postCode};
\$_SERVER = [];
\$widgetname = 'pfblockerng';
\$shim = sys_get_temp_dir() . '/pfb_widget_shim_' . getmypid() . '_' . bin2hex(random_bytes(8));
if (!mkdir(\$shim, 0700, TRUE)) {
	fwrite(STDERR, "widget include shim creation failed\\n");
	exit(1);
}
register_shutdown_function(static function () use (\$shim): void {
	@unlink(\$shim . '/guiconfig.inc');
	@rmdir(\$shim);
});
file_put_contents(\$shim . '/guiconfig.inc', "<?php");
set_include_path(\$shim . PATH_SEPARATOR . get_include_path());
require {$root} . '/tests/php/bootstrap.php';
require {$widget};
PHP;
		$descriptors = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
		$process = proc_open([PHP_BINARY, '-r', $script], $descriptors, $pipes);
		$this->assertIsResource($process);
		$pid = (int) proc_get_status($process)['pid'];
		if ($plantStaleShim) {
			// The child blocks on STDIN until the pipe is closed below, so the
			// plant always lands before it creates its own shim.
			$residue = sys_get_temp_dir() . '/pfb_widget_shim_' . $pid;
			$this->planted[] = $residue;
			@mkdir($residue, 0777, TRUE);
			$this->assertDirectoryExists($residue);
		}
		fclose($pipes[0]);
		$stdout = stream_get_contents($pipes[1]);
		$stderr = stream_get_contents($pipes[2]);
		fclose($pipes[1]);
		fclose($pipes[2]);
		$status = proc_close($process);
		return ['status' => $status, 'stdout' => (string) $stdout, 'stderr' => (string) $stderr, 'pid' => $pid];
	}
}
