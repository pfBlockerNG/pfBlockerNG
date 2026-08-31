<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** Issue #1064 — exercise the shipped widget submit branch, not its source text. */
final class WidgetSubmitPostGuardTest extends TestCase
{
	private const ROOT = __DIR__ . '/../..';
	private const WIDGET = self::ROOT . '/src/usr/local/www/widgets/widgets/pfblockerng.widget.php';

	public function testCraftedPostMissingAllFieldsRaisesNoWarnings(): void
	{
		$result = $this->runWidget(['pfb_submit' => 'save']);
		$this->assertSame(0, $result['status'], $result['stderr']);
		foreach (['pfb_popup', 'pfb_sortmix', 'pfb_show_agg', 'pfb_sortcolumn', 'pfb_sortdir',
			'pfb_clearip', 'pfb_cleardnsbl', 'pfb_dnsblquery', 'pfb_maxfails', 'pfb_maxheight'] as $field) {
			$this->assertStringNotContainsString('Undefined array key "' . $field . '"', $result['stderr']);
		}
		$this->assertSame('', $result['state']['widget-popup'] ?? NULL);
		$this->assertSame('', $result['state']['widget-sortmix'] ?? NULL);
		$this->assertSame('', $result['state']['widget-show_agg'] ?? NULL);
	}

	public function testFullPostStillAppliesValues(): void
	{
		$result = $this->runWidget([
			'pfb_submit' => 'save',
			'pfb_popup' => 'on',
			'pfb_sortmix' => 'on',
			'pfb_show_agg' => 'on',
			'pfb_sortcolumn' => 'alias',
			'pfb_sortdir' => 'asc',
			'pfb_clearip' => 'daily',
			'pfb_cleardnsbl' => 'weekly',
			'pfb_dnsblquery' => '60',
			'pfb_maxfails' => '5',
			'pfb_maxheight' => '200',
		]);
		$this->assertSame(0, $result['status'], $result['stderr']);
		$this->assertSame([
			'widget-popup' => 'on',
			'widget-sortmix' => 'on',
			'widget-show_agg' => 'on',
			'widget-sortcolumn' => 'alias',
			'widget-sortdir' => 'asc',
			'widget-clearip' => 'daily',
			'widget-cleardnsbl' => 'weekly',
			'widget-dnsblquery' => '60',
			'widget-maxfails' => '5',
			'widget-maxheight' => '200',
		], array_intersect_key($result['state'], array_flip([
			'widget-popup', 'widget-sortmix', 'widget-show_agg', 'widget-sortcolumn', 'widget-sortdir',
			'widget-clearip', 'widget-cleardnsbl', 'widget-dnsblquery', 'widget-maxfails', 'widget-maxheight',
		])));
	}

	/**
	 * Issue #2846 — the shim's shutdown hook is load-bearing only where the page exits.
	 *
	 * pfblockerng.widget.php ends in exit(0) at five points, every one of them inside a
	 * pfb_widget_post_guard() arm. This class is the only one that opens that guard, so it
	 * is the only place the mandated register_shutdown_function differs observably from a
	 * trailing cleanup statement: on an exit path a trailing statement is never reached and
	 * the shim directory survives the run.
	 *
	 * Both directions matter and both are here: assertSame(0, status) is the before-state,
	 * because a run where the shim was never created also leaves no residue and would pass
	 * the residue assertion vacuously -- removing the mkdir makes the child exit 255.
	 */
	public function testWidgetRunLeavesNoShimResidue(): void
	{
		$result = $this->runWidget(['pfb_submit' => 'save']);
		$this->assertSame(0, $result['status'], $result['stderr']);
		$this->assertSame([], $result['residue'],
			'the include shim outlived the widget run: ' . implode(', ', $result['residue']));
	}

	/** @return array{status:int,stderr:string,state:array<string,mixed>,residue:list<string>} */
	private function runWidget(array $post): array
	{
		$root = var_export(self::ROOT, TRUE);
		$widget = var_export(self::WIDGET, TRUE);
		$postCode = var_export($post, TRUE);
		// The child picks its own per-invocation shim name, as the exemplar mandates, but
		// underneath a base directory the PARENT owns -- otherwise the name is unknowable
		// here and residue cannot be observed at all. The mkdir guard, the random suffix
		// and the shutdown hook below are unchanged.
		$base = sys_get_temp_dir() . '/pfb_widget_shim_base_' . getmypid() . '_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($base, 0700, TRUE), 'shim base directory creation failed');
		$baseCode = var_export($base, TRUE);
		$script = <<<PHP
require {$root} . '/tests/php/bootstrap.php';
\$_GET = [];
\$_POST = {$postCode};
\$_SERVER = ['HTTP_SEC_FETCH_SITE' => 'same-origin'];
\$widgetname = 'pfblockerng';
\$shim = {$baseCode} . '/pfb_widget_shim_' . getmypid() . '_' . bin2hex(random_bytes(8));
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
set_error_handler(static function (int \$severity, string \$message): bool {
	fwrite(STDERR, \$severity . ': ' . \$message . "\\n");
	return TRUE;
});
register_shutdown_function(static function (): void {
	echo "\\n__PFB_STATE__" . json_encode(\$GLOBALS['pfb']['wglobal'] ?? []);
});
require {$widget};
PHP;
		$descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
		$process = proc_open([PHP_BINARY, '-r', $script], $descriptors, $pipes);
		$this->assertIsResource($process);
		$stdout = (string) stream_get_contents($pipes[1]);
		$stderr = (string) stream_get_contents($pipes[2]);
		fclose($pipes[1]);
		fclose($pipes[2]);
		$status = proc_close($process);
		$marker = strrpos($stdout, '__PFB_STATE__');
		$this->assertIsInt($marker, $stdout);
		$state = json_decode(substr($stdout, $marker + strlen('__PFB_STATE__')), TRUE, 512, JSON_THROW_ON_ERROR);
		$this->assertIsArray($state);
		$residue = array_values(array_diff((array) scandir($base), ['.', '..']));
		foreach ($residue as $leftover) {
			@unlink($base . '/' . $leftover . '/guiconfig.inc');
			@rmdir($base . '/' . $leftover);
		}
		@rmdir($base);
		return ['status' => $status, 'stderr' => $stderr, 'state' => $state, 'residue' => $residue];
	}
}
