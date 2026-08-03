<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** The empty-capable _rep drep token must remain argv[4] at the shell boundary. */
final class ApplyDrepShellBoundaryTest extends TestCase
{
	public function testDrepTokenIsShellQuotedAtTheOnlyEmptyCapableCrossing(): void
	{
		$executable = php_strip_whitespace(__DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc');
		$binding = <<<'PHP'
$pfb_drep_token = $pfb['drep']->toStored(); exec("{$pfb['script']} {$args} {$header_esc} {$pfb['max']} " . escapeshellarg($pfb_drep_token) . " {$pfb['ccexclude']} {$pfb['ccwhite']} {$pfb['ccblack']} {$elog}");
PHP;
		$this->assertSame(1, substr_count($executable, $binding),
			'the drep token must stay quoted in argv[4] before ccexclude/ccwhite/ccblack'
		);
	}
}
