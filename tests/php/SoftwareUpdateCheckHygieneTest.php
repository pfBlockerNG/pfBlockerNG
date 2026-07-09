<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/SoftwareUpdateCheckTest.php';

/**
 * Issue #1063: SoftwareUpdateCheckTest's tearDown() unset the bootstrap-seeded
 * $GLOBALS['pfb']['dbdir'] (and $GLOBALS['config']) instead of restoring the
 * prior values, leaking broken global state into every later suite — under
 * --order-by=random, AliasDeltaApplyTest / PfctlTableOpTest then warn
 * 'Undefined array key "dbdir"'. This pins the restore contract by driving
 * the suite's own setUp()/tearDown() pair against sentinel globals.
 */
final class SoftwareUpdateCheckHygieneTest extends TestCase
{
	/** @var array{had: bool, val: mixed} */
	private array $outerDbdir = ['had' => false, 'val' => null];
	/** @var array{had: bool, val: mixed} */
	private array $outerConfig = ['had' => false, 'val' => null];

	protected function setUp(): void
	{
		$this->outerDbdir  = [
			'had' => isset($GLOBALS['pfb']) && array_key_exists('dbdir', $GLOBALS['pfb']),
			'val' => $GLOBALS['pfb']['dbdir'] ?? null,
		];
		$this->outerConfig = [
			'had' => array_key_exists('config', $GLOBALS),
			'val' => $GLOBALS['config'] ?? null,
		];
	}

	protected function tearDown(): void
	{
		if ($this->outerDbdir['had']) {
			$GLOBALS['pfb']['dbdir'] = $this->outerDbdir['val'];
		} else {
			unset($GLOBALS['pfb']['dbdir']);
		}
		if ($this->outerConfig['had']) {
			$GLOBALS['config'] = $this->outerConfig['val'];
		} else {
			unset($GLOBALS['config']);
		}
	}

	/** Run one full setUp()+tearDown() cycle of SoftwareUpdateCheckTest. */
	private function runLifecycle(): void
	{
		$suite = new SoftwareUpdateCheckTest('testLifecycleProbe');
		$ref   = new ReflectionClass($suite);
		$setUp = $ref->getMethod('setUp');
		$tear  = $ref->getMethod('tearDown');
		$setUp->invoke($suite);
		$tear->invoke($suite);
	}

	public function testDbdirRestoredAfterSuiteLifecycle(): void
	{
		$sentinel = '/nonexistent/pfb-dbdir-canary-1063';
		$GLOBALS['pfb']['dbdir'] = $sentinel;

		$this->runLifecycle();

		$this->assertArrayHasKey(
			'dbdir',
			$GLOBALS['pfb'],
			"tearDown must RESTORE the prior \$pfb['dbdir'], not unset it (issue #1063)"
		);
		$this->assertSame($sentinel, $GLOBALS['pfb']['dbdir']);
	}

	public function testConfigRestoredAfterSuiteLifecycle(): void
	{
		$sentinel = ['pfb_hygiene_canary_1063' => true];
		$GLOBALS['config'] = $sentinel;

		$this->runLifecycle();

		$this->assertArrayHasKey(
			'config',
			$GLOBALS,
			"tearDown must RESTORE the prior \$config, not unset it (issue #1063)"
		);
		$this->assertSame($sentinel, $GLOBALS['config']);
	}
}
