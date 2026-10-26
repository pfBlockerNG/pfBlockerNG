<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * Reports/Alerts save: a select the native form does not submit (the DNSBL-only pfbdnsblstat,
 * the DNS-reply-log-only reply selects) takes its declared default with no PHP diagnostic.
 * PHP 8.4+ deprecates array_key_exists(null), and the rendered-form PHP-log guard fails on it
 * (issue #3543).
 *
 * The page cannot be required off-appliance, so its real option arrays and select-validation
 * region are extracted from the shipped source and evaluated (PageStatementLoader.php).
 */
#[CoversNothing]
final class AlertsSelectOptionDefaultsTest extends TestCase
{
	private const PAGE = 'src/usr/local/www/pfblockerng/pfblockerng_alerts.php';

	private const SCALAR_DEFAULTS = [
		'pfbpageload'	=> 'unified',
		'pfbmaxtable'	=> '1000',
		'pfbextdns'	=> '8.8.8.8',
		'pfbchartcnt'	=> '24',
		'pfbchartstyle'	=> 'twotone',
	];

	private const MULTI_DEFAULTS = [
		'pfbreplytypes'		=> '',
		'pfbreplyrec'		=> '',
		'pfbblockstat'		=> '',
		'pfbpermitstat'		=> '',
		'pfbmatchstat'		=> '',
		'pfbdnsblstat'		=> '',
		'pfbdnsblreplystat'	=> '',
	];

	public static function setUpBeforeClass(): void
	{
		require_once __DIR__ . '/PageStatementLoader.php';
	}

	protected function setUp(): void
	{
		$_POST = [];
	}

	protected function tearDown(): void
	{
		$_POST = [];
	}

	/**
	 * Run the page's select validation over $post; returns what the page would store and every
	 * PHP diagnostic it raised.
	 *
	 * @param array<string, mixed> $post
	 * @return array{post: array<string, mixed>, diagnostics: list<string>}
	 */
	private static function validateSelects(array $post): array
	{
		$_POST = $post;
		$diagnostics = [];
		set_error_handler(static function (int $errno, string $errstr) use (&$diagnostics): bool {
			$diagnostics[] = $errstr;
			return TRUE;
		});
		try {
			pfb_test_page_eval(
				pfb_test_page_region(self::PAGE, '$options_pfbpageload', 'if (isset($_POST) && !empty($_POST)) {')
				. pfb_test_page_region(self::PAGE, '// Validate Select field options', '// Unified Log - Light/Dark Theme Hex settings'),
				[]
			);
		} finally {
			restore_error_handler();
		}
		return ['post' => $_POST, 'diagnostics' => $diagnostics];
	}

	public function testOmittedSelectsTakeDefaultsWithoutDiagnostics(): void
	{
		$result = self::validateSelects(['save' => '1']);

		$this->assertSame([], $result['diagnostics'], 'an omitted select must not log a PHP diagnostic');
		$this->assertSame(self::SCALAR_DEFAULTS, array_intersect_key($result['post'], self::SCALAR_DEFAULTS));
		$this->assertSame(self::MULTI_DEFAULTS, array_intersect_key($result['post'], self::MULTI_DEFAULTS));
	}

	public function testNullSelectsTakeDefaultsWithoutDiagnostics(): void
	{
		$nulls = array_fill_keys(array_merge(array_keys(self::SCALAR_DEFAULTS), array_keys(self::MULTI_DEFAULTS)), NULL);
		$result = self::validateSelects(['save' => '1'] + $nulls);

		$this->assertSame([], $result['diagnostics'], 'a null select must not log a PHP diagnostic');
		$this->assertSame(self::SCALAR_DEFAULTS, array_intersect_key($result['post'], self::SCALAR_DEFAULTS));
		$this->assertSame(self::MULTI_DEFAULTS, array_intersect_key($result['post'], self::MULTI_DEFAULTS));
	}

	public function testValidSelectsAreKeptWithoutDiagnostics(): void
	{
		$result = self::validateSelects([
			'save'			=> '1',
			'pfbmaxtable'		=> '5000',
			'pfbchartstyle'		=> 'greyscale',
			'pfbblockstat'		=> ['ipchart', 'srcipin'],
			'pfbdnsblstat'		=> ['dnsblchart'],
		]);

		$this->assertSame([], $result['diagnostics']);
		$this->assertSame('5000', $result['post']['pfbmaxtable']);
		$this->assertSame('greyscale', $result['post']['pfbchartstyle']);
		$this->assertSame(['ipchart', 'srcipin'], $result['post']['pfbblockstat']);
		$this->assertSame(['dnsblchart'], $result['post']['pfbdnsblstat']);
	}

	public function testInvalidSelectsFallBackToDefaults(): void
	{
		$result = self::validateSelects([
			'save'			=> '1',
			'pfbmaxtable'		=> 'bogus',
			'pfbblockstat'		=> ['ipchart', 'bogus'],
			'pfbdnsblstat'		=> 'bogus',
		]);

		$this->assertSame([], $result['diagnostics']);
		$this->assertSame('1000', $result['post']['pfbmaxtable']);
		$this->assertSame('', $result['post']['pfbblockstat']);
		$this->assertSame('', $result['post']['pfbdnsblstat']);
	}
}
