<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** Issue #1064 — exercise the shipped widget submit branch, not its source text. */
final class WidgetSubmitPostGuardTest extends TestCase
{
	private const ROOT = __DIR__ . '/../..';
	private const WIDGET = self::ROOT . '/src/usr/local/www/widgets/widgets/pfblockerng.widget.php';

	/** @var list<string> shim base directories to sweep, recorded before creation */
	private array $bases = [];

	protected function tearDown(): void
	{
		foreach ($this->bases as $base) {
			rmdir_recursive($base);
		}
		$this->bases = [];
		parent::tearDown();
	}

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
	 * Two things, because the obvious one alone proves nothing. The child reports the path
	 * it used; the test asserts that path was inside the window the parent watches, and
	 * that the window is empty. Dropping the first lets a shim relocated out of the window
	 * pass while leaking -- absence of residue is not evidence of cleanup unless you also
	 * know something was there to clean.
	 */
	public function testWidgetRunLeavesNoShimResidue(): void
	{
		$result = $this->runWidget(['pfb_submit' => 'save']);
		$this->assertSame(0, $result['status'], $result['stderr']);
		// Location first, then absence. An empty residue list is equally satisfied by "the
		// hook ran" and "the shim was never in the window we watched" -- so a shim relocated
		// out of $base with the hook deleted would leave this green while leaking. Assert
		// where it was before asserting the window is empty.
		//
		// There is deliberately no assertDirectoryDoesNotExist($result['shim']) after the
		// location assertion below: runWidget() sweeps $base before it returns, so a path
		// already confirmed inside $base is gone whether or not the widget's hook ran.
		// Placed BEFORE the location assertion it would fire on a relocated shim -- but
		// that is the location assertion's job, and it reports the cause accurately.
		$this->assertStringStartsWith($result['base'] . '/', $result['shim'],
			'the shim must be created inside the observed base, or the residue check watches nothing');
		$this->assertSame([], $result['residue'],
			'the include shim outlived the widget run: ' . implode(', ', $result['residue']));
	}

	/** @return array{status:int,stderr:string,state:array<string,mixed>,residue:list<string>,shim:string,base:string} */
	private function runWidget(array $post): array
	{
		$root = var_export(self::ROOT, TRUE);
		$widget = var_export(self::WIDGET, TRUE);
		$postCode = var_export($post, TRUE);
		// The child names its shim under a base directory the PARENT owns. The sibling
		// classes instead glob sys_get_temp_dir() and filter by the child's PID from
		// proc_get_status(); that works, but the glob sees every concurrent class's shims,
		// so it needs a before/after snapshot and is still exposed to PID reuse. A private
		// base needs neither. #2849 extracts these five sites into one trait and should
		// take this shape, not the glob -- the exemplar deliberately diverges from its
		// four copies until then. The mkdir guard, the random suffix and the shutdown
		// hook are unchanged.
		//
		// Recorded for the tearDown() sweep before it is created: every assertion between
		// here and the cleanup below aborts the method and skips that cleanup, so a
		// parent-owned directory would leak on exactly the failure paths this class exists
		// to exercise -- a test about residue leaving residue. tearDown() runs regardless.
		$base = sys_get_temp_dir() . '/pfb_widget_shim_base_' . getmypid() . '_' . bin2hex(random_bytes(8));
		$this->bases[] = $base;
		if (!mkdir($base, 0700, TRUE)) {
			throw new RuntimeException("shim base directory creation failed: {$base}");
		}
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
register_shutdown_function(static function () use (\$shim): void {
	echo "\\n__PFB_SHIM__" . \$shim;
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
		// Captured BEFORE the cleanup below, which is what erases the evidence. Reversing
		// these two makes every residue assertion in this class vacuously true.
		$entries = scandir($base);
		$this->assertIsArray($entries, "shim base directory unreadable: {$base}");
		$residue = array_values(array_diff($entries, ['.', '..']));
		// Recursive: a leftover may be a file, or a shim holding more than guiconfig.inc, and
		// a hand-rolled two-step would leave exactly the residue this method reports on.
		// tearDown() repeats this for the paths that never reach here.
		rmdir_recursive($base);
		$shimMarker = strrpos($stdout, '__PFB_SHIM__');
		$this->assertIsInt($shimMarker, $stdout);
		$shim = trim(substr($stdout, $shimMarker + strlen('__PFB_SHIM__'), $marker - $shimMarker - strlen('__PFB_SHIM__')));
		return ['status' => $status, 'stderr' => $stderr, 'state' => $state, 'residue' => $residue,
			'shim' => $shim, 'base' => $base];
	}
}
