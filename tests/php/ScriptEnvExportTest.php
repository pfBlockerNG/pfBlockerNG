<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #3140 — every pfblockerng.sh invocation paid two read_xml_tag.sh execs for
 * values PHP already holds when it drives the pass. The sync pass exports
 * PFB_IP_PLACEHOLDER and PFB_REENTRY_TIMEOUT once; the shell init prefers the
 * environment and falls back to read_xml_tag.sh when unset (boot-time and hand-run
 * invocations). Shell-side rows: tests/shell/pfblockerng_init_env_spec.sh.
 */
final class ScriptEnvExportTest extends TestCase
{
	/** #3140: the sync pass exports both init values right after the placeholder is resolved. */
	public function testSyncPassExportsTheTwoInitValues(): void
	{
		$source = php_strip_whitespace(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc');
		$this->assertStringContainsString(
			'putenv("PFB_IP_PLACEHOLDER={$pfb[\'ip_ph\']}"); putenv(\'PFB_REENTRY_TIMEOUT=\' . pfb_reentry_budget(NULL));',
			$source,
			'sync_package_pfblockerng must export the two shell init values from the resolved placeholder'
		);
		$this->assertStringContainsString(
			'putenv(\'PFB_USE_MFS_TMPVAR=\' . (config_path_enabled(\'system\', \'use_mfs_tmpvar\') ? \'1\' : \'0\'));',
			$source,
			'sync_package_pfblockerng must export the RAM-disk presence flag for shell init'
		);
		$this->assertStringNotContainsString('pfb_script_env_export', $source, 'the export is inline; no wrapper');
	}
}
