<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** issue #2122: a parent dispatch must not alter scheduling before child lock success. */
final class UpdatePageLockTimeoutSafetyTest extends TestCase
{
	private function functionBody(string $source, string $start, string $end): string
	{
		$from = strpos($source, $start);
		$to = strpos($source, $end, $from);
		$this->assertNotFalse($from);
		$this->assertNotFalse($to);
		return substr($source, $from, $to - $from);
	}

	public function testDetachedParentsDoNotRemoveTickCronBeforeChildOwnsLock(): void
	{
		$source = php_strip_whitespace(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_update.php'
		);
		$this->assertNotFalse($source);
		$run = $this->functionBody($source, 'function pfb_runnow(', 'function pfb_runnow_forcecheck(');
		$force = $this->functionBody($source, 'function pfb_runnow_forcecheck(', '$pgtitle =');

		$this->assertStringNotContainsString('install_cron_job(', $run,
			'a timed-out Run Now child must not leave scheduled ticks disabled');
		$this->assertStringNotContainsString('install_cron_job(', $force,
			'a timed-out Force Check child must not leave scheduled ticks disabled');
	}
}
