<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #3140 — every pfblockerng.sh invocation paid two read_xml_tag.sh execs
 * (~157 ms each on a 500 KB config) for values PHP already holds when it drives the
 * pass. pfb_script_env_export() hands the shell PFB_IP_PLACEHOLDER and
 * PFB_REENTRY_TIMEOUT once per sync pass; the init block prefers the environment and
 * falls back to read_xml_tag.sh when unset (boot-time and hand-run invocations).
 * Shell-side rows: tests/shell/pfblockerng_init_env_spec.sh.
 */
#[CoversFunction('pfb_script_env_export')]
final class ScriptEnvExportTest extends TestCase
{
	protected function tearDown(): void
	{
		putenv('PFB_IP_PLACEHOLDER');
		putenv('PFB_REENTRY_TIMEOUT');
	}

	public function testExportsBothValuesAsEnvironmentStrings(): void
	{
		pfb_script_env_export('127.1.7.7', 1800);

		$this->assertSame('127.1.7.7', getenv('PFB_IP_PLACEHOLDER'));
		$this->assertSame('1800', getenv('PFB_REENTRY_TIMEOUT'));
	}

	public function testSecondCallOverridesTheFirst(): void
	{
		pfb_script_env_export('10.0.0.1', 600);
		pfb_script_env_export('127.1.7.7', 1800);

		$this->assertSame('127.1.7.7', getenv('PFB_IP_PLACEHOLDER'), 'latest placeholder must win');
		$this->assertSame('1800', getenv('PFB_REENTRY_TIMEOUT'), 'latest budget must win');
	}

	/** #3140: the sync pass must export the two init values once the placeholder is resolved. */
	public function testSyncPassExportsTheTwoInitValues(): void
	{
		$source = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc');
		$this->assertStringContainsString(
			'pfb_script_env_export($pfb[\'ip_ph\'], pfb_reentry_budget(NULL))',
			$source,
			'sync_package_pfblockerng must export the two shell init values from the resolved placeholder'
		);
	}
}
