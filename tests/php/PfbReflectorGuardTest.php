<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * pfblockerng.php's loopback file-reflector array-request guard (issue #1128).
 *
 * A crafted request submitting an array-valued 'pfb' field ('pfb[]=x')
 * reached strpos()/strstr() before any type check, TypeError-ing the
 * loopback-only endpoint. The fix adds is_string() to the entry guard.
 *
 * The file carries top-level execution and cannot be require()d
 * off-appliance, so the guarded block is eval-extracted verbatim from the
 * REAL source into a void oracle function that publishes its local $query
 * to the global scope (the block's own internal 'return;' just exits the
 * oracle early on success, same as it would exit the real top-level
 * script), anchored on text stable across both the pre-fix and post-fix
 * code so the same test file proves red on the old code and green on the
 * new.
 */
final class PfbReflectorGuardTest extends TestCase
{
	private array $savedRequest = [];
	private string $savedRemoteAddr = '';

	public static function setUpBeforeClass(): void
	{
		$src = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng.php'
		);
		if ($src === false) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng.php');
		}

		if (!function_exists('pfb_reflector_oracle')) {
			if (!preg_match(
				'/(if \(\$_SERVER\[\'REMOTE_ADDR\'\].*?\n\})\n\n\nrequire_once\(\'util\.inc\'\);/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: loopback reflector block not found');
			}
			eval(
				'function pfb_reflector_oracle(): void {'
				. ' global $query; $query = null;'
				. $m[1]
				. ' }'
			);
		}
	}

	protected function setUp(): void
	{
		$this->savedRequest    = $_REQUEST;
		$this->savedRemoteAddr = $_SERVER['REMOTE_ADDR'] ?? '';
		$_REQUEST = [];
		$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
	}

	protected function tearDown(): void
	{
		$_REQUEST = $this->savedRequest;
		$_SERVER['REMOTE_ADDR'] = $this->savedRemoteAddr;
	}

	public function testPfbArrayValueDoesNotThrowAndYieldsNoQuery(): void
	{
		$_REQUEST['pfb'] = ['x y'];
		try {
			pfb_reflector_oracle();
		} catch (\TypeError $e) {
			$this->fail('an array pfb value must not TypeError strpos(): ' . $e->getMessage());
		}
		$this->assertNull($GLOBALS['query'], 'an array pfb value must be rejected before $query is computed');
	}

	public function testPfbScalarValueStillResolvesQuery(): void
	{
		$_REQUEST['pfb'] = 'myquery extra';
		pfb_reflector_oracle();
		$this->assertSame('myquery', $GLOBALS['query'], 'a scalar pfb value must still resolve its query name');
	}

	public function testPfbMissingKeyDoesNotWarnAndYieldsNoQuery(): void
	{
		unset($_REQUEST['pfb']);
		try {
			pfb_reflector_oracle();
		} catch (\TypeError $e) {
			$this->fail('a missing pfb key must not TypeError: ' . $e->getMessage());
		}
		$this->assertNull($GLOBALS['query'], 'a missing pfb key must not enter the reflector block');
	}
}
