<?php

declare(strict_types=1);

require_once __DIR__ . '/PidShimHarnessTrait.php';

use PHPUnit\Framework\TestCase;

final class WidgetGetTableArgOrderTest extends TestCase
{
	use PidShimHarnessTrait;

	private const ROOT = __DIR__ . '/../..';
	private const WIDGET = self::ROOT . '/src/usr/local/www/widgets/widgets/pfblockerng.widget.php';

	protected function pidShimPrefix(): string
	{
		return 'pfb_widget_shim_';
	}

	public function testAjaxWidgetBranchExecutesTheShippedTableCall(): void
	{
		$result = $this->runWidget(['getNewWidget' => '1'], []);
		$this->assertSame(0, $result['status'], $result['stderr']);
		$this->assertStringEndsWith('after-include', trim($result['stdout']));
	}

	public function testDefaultWidgetRenderExecutesTheShippedTableCall(): void
	{
		$result = $this->runWidget([], []);
		$this->assertSame(0, $result['status'], $result['stderr']);
		$this->assertStringContainsString('<tbody id="pfBNG-table">', $result['stdout']);
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
		$this->assertStringContainsString('<tbody id="pfBNG-table">', $result['stdout']);
		$this->assertSame([], glob($this->planted[0] . '/*') ?: [], 'a per-invocation shim path must never adopt an inherited directory');
		$this->assertSame([], array_diff($this->shimResidue($result['pid']), $this->planted));
	}

	/** @return array{status:int,stdout:string,stderr:string,pid:int} */
	private function runWidget(array $get, array $post, bool $plantStaleShim = FALSE): array
	{
		$root = var_export(self::ROOT, TRUE);
		$widget = var_export(self::WIDGET, TRUE);
		$getCode = var_export($get, TRUE);
		$postCode = var_export($post, TRUE);
		$preamble = $this->pidShimPreamble('widget include shim creation failed');
		$script = <<<PHP
stream_get_contents(STDIN);
\$GLOBALS['argv'] = ['widget'];
error_reporting(E_ERROR | E_PARSE);
\$_GET = {$getCode};
\$_POST = {$postCode};
\$_SERVER = [];\$widgetname = 'pfblockerng';
{$preamble}
require {$root} . '/tests/php/bootstrap.php';
require {$widget};
echo 'after-include';
PHP;
		$descriptors = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
		$process = proc_open([PHP_BINARY, '-r', $script], $descriptors, $pipes);
		$this->assertIsResource($process);
		$pid = (int) proc_get_status($process)['pid'];
		if ($plantStaleShim) {
			// The child blocks on STDIN until the pipe is closed below, so the
			// plant always lands before it creates its own shim.
			$this->plantStaleShim($pid);
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
