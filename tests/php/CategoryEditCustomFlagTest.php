<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Category-edit custom-list update flag placement (issue #1080).
 *
 * When a saved alias's Custom List changed, the page touch()ed
 * "{$pfbarr['folder']}/{$aname}_custom{$suffix}.update" -- but an action with
 * no list folder (Disabled) leaves pfb_determine_list_detail()'s array empty,
 * so the flag landed at the FILESYSTEM ROOT ("/{$aname}_custom.update"; the
 * WebGUI runs as root, so the write succeeds). The flag is now set only for a
 * non-empty folder; the page touches it once the save is written (issue #3999,
 * GroupsPageConfigLockTest).
 *
 * Like WidgetSubmitPostGuardTest, the page carries top-level execution and
 * cannot be require()d off-appliance, so the REAL custom-flag block is
 * eval-extracted between its executable condition and following config write;
 * it returns the flag path it chose ('' for none).
 */
final class CategoryEditCustomFlagTest extends TestCase
{
	/** Saved globals, restored in tearDown. */
	private mixed $savedPfb = null;
	private mixed $savedPfbarr = null;
	private array $savedPost = [];
	private mixed $savedConfig = null;

	private string $workdir = '';

	public static function setUpBeforeClass(): void
	{
		$src = php_strip_whitespace(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_category_edit.php'
		);
		if ($src === '') {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_category_edit.php');
		}

		if (!function_exists('pfb_category_edit_oracle_customflag')) {
			if (!preg_match(
				'/(\$pfb_custom_marker = \x27\x27;\s*if \(base64_decode\(config_get_path\("installedpackages\/\{\$conf_type\}\/config\/\{\$rowid\}\/custom", \x27\x27\)\) != \$_POST\[\x27custom\x27\]\) \{'
				. '.*?\.update";\s*\}\s*\})'
				. '\s*config_set_path\("installedpackages\/\{\$conf_type\}\/config\/\{\$rowid\}\/custom", base64_encode/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: custom-flag block not found in category_edit source');
			}
			if (strpos($m[1], 'pfb_determine_list_detail($action, \'\', $conf_type, $rowid)') === FALSE) {
				throw new RuntimeException('test bootstrap: custom-flag executable boundary lost list-detail dispatch');
			}
			eval(
				'function pfb_category_edit_oracle_customflag(string $conf_type, int $rowid, string $suffix): string {'
				. ' global $pfb, $pfbarr; ' . $m[1] . ' return $pfb_custom_marker; }'
			);
		}
	}

	protected function setUp(): void
	{
		global $pfb, $pfbarr;
		$this->savedPfb    = $pfb ?? null;
		$this->savedPfbarr = $pfbarr ?? null;
		$this->savedPost   = $_POST;
		$this->savedConfig = $GLOBALS['config'] ?? null;
		$GLOBALS['config'] = [];

		$workdir = tempnam(sys_get_temp_dir(), 'pfbcat');
		$this->assertNotFalse($workdir);
		$this->assertTrue(unlink($workdir) && mkdir($workdir, 0700));
		$this->workdir = $workdir;
	}

	protected function tearDown(): void
	{
		global $pfb, $pfbarr;
		$pfb    = $this->savedPfb;
		$pfbarr = $this->savedPfbarr;
		$_POST  = $this->savedPost;
		if ($this->savedConfig === null) {
			unset($GLOBALS['config']);
		} else {
			$GLOBALS['config'] = $this->savedConfig;
		}
		if ($this->workdir !== '' && is_dir($this->workdir)) {
			foreach ((array) glob("{$this->workdir}/*") as $f) {
				@unlink((string) $f);
			}
			rmdir($this->workdir);
		}
	}

	/** @return array{string, list<string>} the flag path the extracted block chose ('' for none) and every PHP warning it raised */
	private function runFlagBlock(string $action, string $custom, string $suffix = ''): array
	{
		global $pfb;
		$_POST['action']    = $action;
		$_POST['aliasname'] = 'Cat1080';
		$_POST['custom']    = $custom;
		$pfb['reuse_dnsbl'] = $pfb['reuse_dnsbl'] ?? '';
		// The real save handler writes the full config row before the flag block
		// runs; pfb_determine_list_detail reads these keys from it. Seed the row
		// so the oracle sees the page's real pre-state (absent keys only add PHP 8
		// warning noise unrelated to the flag placement under test).
		foreach (['_in', '_out'] as $dir) {
			foreach (['autoproto', 'autonot', 'autoaddrnot', 'agateway', 'autoports', 'autoaddr'] as $k) {
				config_set_path("installedpackages/pfblockerngdnsbl/config/0/{$k}{$dir}", '');
			}
		}
		$warnings = [];
		set_error_handler(
			static function (int $errno, string $errstr) use (&$warnings): bool {
				$warnings[] = $errstr;
				return TRUE;
			},
			E_WARNING | E_NOTICE
		);
		try {
			$marker = pfb_category_edit_oracle_customflag('pfblockerngdnsbl', 0, $suffix);
		} finally {
			restore_error_handler();
		}
		return [$marker, $warnings];
	}

	public function testDisabledActionSetsNoFlagAndNoWarning(): void
	{
		// Given: no stored custom list, an incoming non-empty one, action Disabled
		// (no list folder). Before the guard the flag was /Cat1080_custom.update.
		[$marker, $warnings] = $this->runFlagBlock('Disabled', "custom.example.com\n");

		$this->assertSame('', $marker, 'no flag may land at the filesystem root');
		$this->assertSame([], $warnings, 'the guarded skip must be silent');
	}

	public function testFolderedActionStillSetsTheUpdateFlag(): void
	{
		// Behaviour-preserving pin: an action WITH a folder keeps setting the flag.
		global $pfb;
		$pfb['dnsdir'] = $this->workdir;
		[$marker, $warnings] = $this->runFlagBlock('unbound', "custom.example.com\n");

		$this->assertSame("{$this->workdir}/Cat1080_custom.update", $marker);
		$this->assertSame([], $warnings);
	}

	public function testUnchangedCustomListSkipsTheFlagEntirely(): void
	{
		// The branch only fires when the stored and posted lists differ.
		global $pfb;
		$pfb['dnsdir'] = $this->workdir;
		config_set_path(
			'installedpackages/pfblockerngdnsbl/config/0/custom',
			base64_encode("custom.example.com\n")
		);
		[$marker, $warnings] = $this->runFlagBlock('unbound', "custom.example.com\n");

		$this->assertSame('', $marker);
		$this->assertSame([], $warnings);
	}
}
