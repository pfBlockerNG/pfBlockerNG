<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class WidgetGetTableArgOrderTest extends TestCase
{
	private const ROOT = __DIR__ . '/../..';
	private const WIDGET = self::ROOT . '/src/usr/local/www/widgets/widgets/pfblockerng.widget.php';

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

	/** @return array{status:int,stdout:string,stderr:string} */
	private function runWidget(array $get, array $post): array
	{
		$root = var_export(self::ROOT, TRUE);
		$widget = var_export(self::WIDGET, TRUE);
		$getCode = var_export($get, TRUE);
		$postCode = var_export($post, TRUE);
		$script = <<<PHP
\$GLOBALS['argv'] = ['widget'];
error_reporting(E_ERROR | E_PARSE);
\$_GET = {$getCode};
\$_POST = {$postCode};
\$_SERVER = [];\$widgetname = 'pfblockerng';
\$shim = sys_get_temp_dir() . '/pfb_widget_shim_' . getmypid();
mkdir(\$shim, 0777, TRUE);
file_put_contents(\$shim . '/guiconfig.inc', "<?php");
set_include_path(\$shim . PATH_SEPARATOR . get_include_path());
require {$root} . '/tests/php/bootstrap.php';
require {$widget};
echo 'after-include';
PHP;
		$descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
		$process = proc_open([PHP_BINARY, '-r', $script], $descriptors, $pipes);
		$this->assertIsResource($process);
		$stdout = stream_get_contents($pipes[1]);
		$stderr = stream_get_contents($pipes[2]);
		fclose($pipes[1]);
		fclose($pipes[2]);
		$status = proc_close($process);
		return ['status' => $status, 'stdout' => (string) $stdout, 'stderr' => (string) $stderr];
	}
}
