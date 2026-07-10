<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Sync page rowhelper array-POST guard + row-tracking (issue #1070).
 *
 * The XMLRPC-sync save loop ran scalar validators (preg_match/strlen/is_port)
 * on each rowhelper field; a PHP 8 array value ('varsyncusername-0[]=x')
 * threw TypeError before the input-errors gate (HTTP 500). The fix rejects a
 * non-scalar as an input error -- but it must still REGISTER the row in
 * $rowhelper_exist first, or the "remove all undefined rowhelpers" loop drops
 * an existing replication target whose only posted field was the invalid one.
 *
 * Like WidgetSubmitPostGuardTest, the page carries top-level execution and
 * cannot be require()d off-appliance, so the REAL rowhelper loop (through the
 * remove-undefined-rowhelpers loop) is eval-extracted verbatim.
 */
final class SyncRowhelperGuardTest extends TestCase
{
	private array $savedPost = [];
	private mixed $savedPfb = null;
	private mixed $savedConfig = null;

	public static function setUpBeforeClass(): void
	{
		$src = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_sync.php'
		);
		if ($src === false) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_sync.php');
		}

		if (!function_exists('pfb_sync_oracle_rowloop')) {
			if (!preg_match(
				'/\$rowhelper_exist = array\(\);\n(.*?)(?=\n\n\t\tif \(!\$input_errors\))/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: sync rowhelper loop not found');
			}
			eval(
				'function pfb_sync_oracle_rowloop(): array {'
				. ' global $pfb; $input_errors = array(); $rowhelper_exist = array(); '
				. $m[1]
				. ' return array($input_errors, array_keys($pfb[\'sconfig\'][\'row\'] ?? array())); }'
			);
		}
	}

	protected function setUp(): void
	{
		$this->savedPost   = $_POST;
		$this->savedPfb    = $GLOBALS['pfb'] ?? null;
		$this->savedConfig = $GLOBALS['config'] ?? null;
		$GLOBALS['config'] = [];
		// A pre-existing replication target at row index 0.
		$GLOBALS['pfb']['sconfig']['row'] = [
			0 => ['varsyncusername' => 'admin', 'varsyncdestinenable' => 'on'],
		];
		$_POST = [];
	}

	protected function tearDown(): void
	{
		$_POST = $this->savedPost;
		$GLOBALS['pfb'] = $this->savedPfb;
		if ($this->savedConfig === null) {
			unset($GLOBALS['config']);
		} else {
			$GLOBALS['config'] = $this->savedConfig;
		}
	}

	public function testArrayRowhelperValueIsRejectedWithoutThrowing(): void
	{
		// A crafted array value for the only posted rowhelper field of row 0.
		$_POST['varsyncusername-0'] = ['x'];

		[$errors, $rows] = pfb_sync_oracle_rowloop();

		// The array value is rejected as an input error (no TypeError 500)...
		$this->assertNotEmpty($errors, 'the array value must be rejected as an input error');
		// ...and row 0 is STILL tracked, so the remove loop does not delete the
		// pre-existing replication target (the Copilot-found regression).
		$this->assertContains(0, $rows, 'the existing replication target must survive an invalid field');
	}

	public function testValidRowhelperFieldStillSaves(): void
	{
		// Behaviour-preserving pin: a scalar username saves and the row survives.
		$_POST['varsyncusername-0'] = 'operator';

		[$errors, $rows] = pfb_sync_oracle_rowloop();

		$this->assertSame([], $errors);
		$this->assertContains(0, $rows);
		$this->assertSame('operator', $GLOBALS['pfb']['sconfig']['row'][0]['varsyncusername']);
	}
}
