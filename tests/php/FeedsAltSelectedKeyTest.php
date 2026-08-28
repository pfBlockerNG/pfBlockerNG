<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Feeds page alt_selected config-key vetting (issue #1076).
 *
 * The save handler exploded the request field ``alt_selected`` and used each
 * raw token as part of a config_set_path() KEY
 * (``installedpackages/pfblockerngglobal/feed_alt_{$value}``). Only the
 * alt_ VALUE was filtered; a crafted token like ``a/b`` spliced a path
 * separator into the config tree, writing an unintended nested node. Each
 * token is now vetted through PFB_FILTER_WORD (every shipped feed header is
 * word-charset; audited against pfblockerng_feeds.json) before any key use.
 *
 * Like WidgetSubmitPostGuardTest, the page carries top-level execution and
 * cannot be require()d off-appliance, so the REAL alt_selected block is
 * eval-extracted verbatim (the executable ``if (isset($_POST['alt_selected']))``
 * start and following ``if ($config_mod)`` line are the unique anchors).
 */
final class FeedsAltSelectedKeyTest extends TestCase
{
	private array $savedPost = [];
	private mixed $savedConfig = null;
	private static string $altRegion;

	public static function setUpBeforeClass(): void
	{
		$src = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_feeds.php'
		);
		if ($src === false) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_feeds.php');
		}

		if (!function_exists('pfb_feeds_oracle_alt_selected')) {
			if (!preg_match(
				'/(if \(isset\(\$_POST\[\'alt_selected\'\]\)\) \{.*?)(?=\n\n\t\tif \(\$config_mod\))/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: alt_selected block not found in feeds source');
			}
			self::$altRegion = $m[1];
			eval(
				'function pfb_feeds_oracle_alt_selected(): array {'
				. ' $fconfig = array(); $input_errors = array(); $config_mod = FALSE; '
				. $m[1]
				. ' return $input_errors; }'
			);
		}
	}

	public function testExtractionStartsAtExecutableCodeNotProductionComment(): void
	{
		$this->assertStringStartsWith("if (isset(\$_POST['alt_selected']))", self::$altRegion);
		$this->assertStringNotContainsString('Save all', self::$altRegion);
	}

	protected function setUp(): void
	{
		$this->savedPost   = $_POST;
		$this->savedConfig = $GLOBALS['config'] ?? null;
		$GLOBALS['config'] = [];
	}

	protected function tearDown(): void
	{
		$_POST = $this->savedPost;
		if ($this->savedConfig === null) {
			unset($GLOBALS['config']);
		} else {
			$GLOBALS['config'] = $this->savedConfig;
		}
	}

	private function globalNodes(): array
	{
		$nodes = config_get_path('installedpackages/pfblockerngglobal');
		return is_array($nodes) ? $nodes : [];
	}

	/** Run the oracle while capturing PHP warnings/notices (PHPUnit passes them by default). */
	private function runOracleCapturingWarnings(array &$warnings): array
	{
		$warnings = [];
		set_error_handler(
			static function (int $errno, string $errstr) use (&$warnings): bool {
				$warnings[] = $errstr;
				return true;
			},
			E_WARNING | E_NOTICE
		);
		try {
			return pfb_feeds_oracle_alt_selected();
		} finally {
			restore_error_handler();
		}
	}

	public function testPathBearingTokenWritesNoConfigNode(): void
	{
		// Given: a crafted token carrying a path separator, with a matching
		// filtered-clean alt_ value so only the KEY vetting can stop the write.
		$_POST['alt_selected'] = 'a/b';
		$_POST['alt_a/b']      = 'EvilWord';

		$errors = pfb_feeds_oracle_alt_selected();

		// Then: nothing lands under pfblockerngglobal (before the fix, the raw
		// token spliced config_set_path into a nested feed_alt_a/b node) and the
		// token is rejected loudly.
		$this->assertSame([], $this->globalNodes(), 'a path-bearing token must write no config node');
		$this->assertNotEmpty($errors, 'the crafted token must be rejected as an input error');
	}

	public function testValidTokenStillSavesLowercasedKey(): void
	{
		// Behaviour-preserving pin, with empty CSV entries skipped on the way.
		$_POST['alt_selected']  = ',EasyList,';
		$_POST['alt_EasyList']  = 'EasyListAlt';

		$errors = pfb_feeds_oracle_alt_selected();

		$this->assertSame([], $errors);
		$this->assertSame(
			'EasyListAlt',
			config_get_path('installedpackages/pfblockerngglobal/feed_alt_easylist')
		);
	}

	public function testWordTokenWithMissingAltFieldIsRejectedNotFatal(): void
	{
		// A word-charset token with no matching alt_ field must produce the
		// existing 'Invalid Alternative Alias Name' error -- with NO PHP 8
		// "Undefined array key" warning (PHPUnit passes warnings by default,
		// so they are captured and asserted explicitly).
		$_POST['alt_selected'] = 'GhostAlias';
		unset($_POST['alt_GhostAlias']);

		$warnings = [];
		$errors = $this->runOracleCapturingWarnings($warnings);

		$this->assertSame([], $this->globalNodes());
		$this->assertNotEmpty($errors);
		$this->assertSame([], $warnings, 'the missing alt_ field read must not warn');
	}
}
