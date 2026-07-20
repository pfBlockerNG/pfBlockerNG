<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class Top1mTeardownWiringTest extends TestCase
{
	private function functionBody(string $name): string
	{
		$function = new ReflectionFunction($name);
		$lines = file((string) $function->getFileName());
		$this->assertIsArray($lines);
		return implode('', array_slice(
			$lines,
			$function->getStartLine() - 1,
			$function->getEndLine() - $function->getStartLine() + 1
		));
	}

	public function testDisableAndUninstallWireTheSharedTeardown(): void
	{
		$this->assertStringContainsString(
			'pfb_unbound_py_teardown_raw_set();',
			$this->functionBody('sync_package_pfblockerng'),
			'DNSBL disable must remove the fixed TOP1M runtime set'
		);
		$this->assertMatchesRegularExpression(
			'/sync_package_pfblockerng\(\);\s+pfb_unbound_py_teardown_raw_set\(\);/',
			$this->functionBody('pfblockerng_php_pre_deinstall_command'),
			'package removal must tear down retained TOP1M runtime state after the disable pass'
		);
	}
}
