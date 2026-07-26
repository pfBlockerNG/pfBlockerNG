<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1732 source-scan pins for the lint-endpoint page
 * (pfblockerng_lint.php) and its priv.inc wiring. Same rationale as
 * EditHooksPageWiringTest: the page require_once()s guiconfig.inc, which needs
 * the full pfSense webConfigurator runtime this off-appliance PHPUnit tier does
 * not stand up, so the gate SHAPE is pinned at the source-text level instead of
 * an executed render.
 */
final class LintEndpointWiringTest extends TestCase
{
	private const PAGE_PATH = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_lint.php';
	private const PRIV_INC_PATH = __DIR__ . '/../../src/etc/inc/priv/pfblockerng.priv.inc';

	private static string $pageSrc;
	private static string $privSrc;

	public static function setUpBeforeClass(): void
	{
		parent::setUpBeforeClass();
		$pageSrc = file_get_contents(self::PAGE_PATH);
		$privSrc = file_get_contents(self::PRIV_INC_PATH);
		self::assertNotFalse($pageSrc, 'test oracle: failed to read ' . self::PAGE_PATH);
		self::assertNotFalse($privSrc, 'test oracle: failed to read ' . self::PRIV_INC_PATH);
		self::$pageSrc = $pageSrc;
		self::$privSrc = $privSrc;
	}

	private function firstDispatchCallPos(): int
	{
		$pos = strpos(self::$pageSrc, 'pfb_lint_diagnostics(');
		$this->assertNotFalse($pos, 'the endpoint must call pfb_lint_diagnostics(...)');
		return $pos;
	}

	public function testRegexGatePresentAndBeforeDispatch(): void
	{
		$gatePos = strpos(self::$pageSrc, "isAllowedPage('pfblockerng/pfblockerng_dnsbl.php')");
		$this->assertNotFalse(
			$gatePos,
			"the regex-lang gate must call isAllowedPage('pfblockerng/pfblockerng_dnsbl.php')"
		);
		$this->assertLessThan($this->firstDispatchCallPos(), $gatePos, 'the regex gate must run before the lint dispatch');
	}

	public function testShPyGatePresentAndBeforeDispatch(): void
	{
		$gatePos = strpos(self::$pageSrc, "isAllowedPage('diag_command.php')");
		$this->assertNotFalse($gatePos, "the sh/py-lang gate must call isAllowedPage('diag_command.php')");
		$this->assertLessThan($this->firstDispatchCallPos(), $gatePos, 'the sh/py gate must run before the lint dispatch');
	}

	public function testRegexGateStringAppearsExactlyOnce(): void
	{
		$this->assertSame(
			1,
			substr_count(self::$pageSrc, "'pfblockerng/pfblockerng_dnsbl.php'"),
			'no second, ungated dispatch path for lang=regex'
		);
	}

	public function testDiagCommandGateStringAppearsExactlyOnce(): void
	{
		$this->assertSame(
			1,
			substr_count(self::$pageSrc, "'diag_command.php'"),
			'no second, ungated dispatch path for lang=sh/py'
		);
	}

	public function testExactlyOneDispatchCallSite(): void
	{
		$this->assertSame(
			1,
			substr_count(self::$pageSrc, 'pfb_lint_diagnostics('),
			'exactly one dispatch call site -- no second ungated path'
		);
	}

	public function testLangAllowListRestrictedToRegexShPy(): void
	{
		$this->assertMatchesRegularExpression(
			"/in_array\\(\\\$lang,\\s*\\['regex',\\s*'sh',\\s*'py'\\]/",
			self::$pageSrc,
			'the lang allow-list must be restricted to regex|sh|py'
		);
	}

	public function testLangIsStringGuardPresent(): void
	{
		$this->assertStringContainsString(
			'is_string($lang)',
			self::$pageSrc,
			'a crafted lang[]= array must be rejected by an is_string() guard'
		);
	}

	public function testContentIsStringGuardPresent(): void
	{
		$this->assertStringContainsString(
			'is_string($content)',
			self::$pageSrc,
			'a crafted content[]= array must be rejected by an is_string() guard'
		);
	}

	public function testJsonContentTypeHeaderPresent(): void
	{
		$this->assertStringContainsString('Content-Type: application/json', self::$pageSrc);
	}

	public function testJsonContentTypeHeaderCarriesUtf8Charset(): void
	{
		$this->assertStringContainsString(
			"Content-Type: application/json; charset=utf-8",
			self::$pageSrc,
			'the JSON reply header must declare charset=utf-8'
		);
	}

	public function testJsonEncodeCarriesInvalidUtf8Substitute(): void
	{
		$this->assertMatchesRegularExpression(
			'/json_encode\([^)]*JSON_INVALID_UTF8_SUBSTITUTE/',
			self::$pageSrc,
			'json_encode(...) must pass JSON_INVALID_UTF8_SUBSTITUTE -- else a diagnostic ' .
				'message carrying invalid UTF-8 makes json_encode() return false (200 with an empty body)'
		);
	}

	public function testPostOnlyCheckPresent(): void
	{
		$this->assertStringContainsString('REQUEST_METHOD', self::$pageSrc);
		$this->assertStringContainsString("!== 'POST'", self::$pageSrc);
	}

	public function testSizeCapLiteralPresent(): void
	{
		$this->assertStringContainsString('1048576', self::$pageSrc);
	}

	public function testNeverCallsExecFamilyDirectly(): void
	{
		foreach (['proc_open(', 'exec(', 'shell_exec(', 'system(', 'passthru('] as $sink) {
			$this->assertStringNotContainsString(
				$sink,
				self::$pageSrc,
				"the endpoint must never call {$sink} directly -- launching lives in pfblockerng_extra.inc"
			);
		}
	}

	public function testNeverWritesSubmittedContentToDisk(): void
	{
		foreach (['file_put_contents(', 'fwrite('] as $sink) {
			$this->assertStringNotContainsString(
				$sink,
				self::$pageSrc,
				"the endpoint must never {$sink} the submitted content -- never written to disk"
			);
		}
	}

	public function testPrivIncHasExactlyOneLintMatchEntry(): void
	{
		$this->assertSame(
			1,
			substr_count(
				self::$privSrc,
				'$priv_list[\'page-firewall-pfblockerng\'][\'match\'][] = "pfblockerng/pfblockerng_lint.php";'
			),
			'the lint endpoint must have exactly one priv.inc match entry'
		);
	}

	public function testPrivIncStillExcludesEditHooksPage(): void
	{
		$this->assertStringNotContainsString(
			'"pfblockerng/pfblockerng_edit_hooks.php"',
			self::$privSrc,
			'pfblockerng_edit_hooks.php must stay out of the match list (existing invariant)'
		);
	}
}
