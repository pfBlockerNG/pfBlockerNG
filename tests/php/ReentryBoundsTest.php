<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #2016: the nested pfblockerng.php re-entry ceiling and target stay single-sourced in
 * pfblockerng.inc. The PHP re-entry seam (pfb_reentry_cmd/pfb_reentry_exec) and the Extras jobs
 * it bounded were removed with the Go cutover (#3977); the constants still feed the General page
 * and the PFB_REENTRY_TIMEOUT export.
 */
final class ReentryBoundsTest extends TestCase
{
	public function testSeamConstantsPinTheCeilingAndTheReentryTarget(): void
	{
		$this->assertTrue(defined('PFB_REENTRY_TIMEOUT'),
			'PFB_REENTRY_TIMEOUT (the nested re-entry ceiling) must be defined by pfblockerng.inc');
		$this->assertTrue(defined('PFB_REENTRY_SCRIPT'),
			'PFB_REENTRY_SCRIPT (the single-sourced re-entry target) must be defined by pfblockerng.inc');
		$this->assertSame(1800, PFB_REENTRY_TIMEOUT);
		$this->assertSame('/usr/local/www/pfblockerng/pfblockerng.php', PFB_REENTRY_SCRIPT);
	}
}
