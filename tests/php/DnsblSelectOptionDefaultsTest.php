<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * DNSBL settings save: a select the browser does not submit (a `multiple` select with nothing
 * chosen, e.g. dnsbl_allow_int with no permit interface) takes its declared default with no PHP
 * diagnostic. Reading the absent $_POST key logged `Undefined array key` (issue #3936).
 *
 * The page cannot be required off-appliance, so its real select-validation region is extracted
 * from the shipped source and evaluated (PageStatementLoader.php) over stand-in option lists.
 */
#[CoversNothing]
final class DnsblSelectOptionDefaultsTest extends TestCase
{
	private const PAGE = 'src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php';

	private const DEFAULT_TLDS = ['com', 'net'];

	private const SCALAR_DEFAULTS = [
		'dnsbl_interface'	=> 'lo0',
		'global_log'		=> 'pconfig-log',
		'global_log_mode'	=> 'pconfig-mode',
		'dnsbl_webpage'		=> 'dnsbl_default.php',
		'top1m_source'		=> 'tranco',
		'top1m_count'		=> '1000',
		'action'		=> 'Disabled',
		'aliaslog'		=> 'enabled',
		'aliasports_in'		=> '',
		'aliasports_out'	=> '',
		'aliasaddr_in'		=> '',
		'aliasaddr_out'		=> '',
		'autoproto_in'		=> 'any',
		'autoproto_out'		=> 'any',
		'agateway_in'		=> 'default',
		'agateway_out'		=> 'default',
		'dnsbl_dot_block_action'=> 'reject',
	];

	public static function setUpBeforeClass(): void
	{
		require_once __DIR__ . '/PageStatementLoader.php';
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
	 * @return array{post: array<string, mixed>, diagnostics: list<string>, input_errors: list<string>}
	 */
	private static function validateSelects(array $post): array
	{
		$vars = [
			'pconfig'			=> ['global_log' => 'pconfig-log', 'global_log_mode' => 'pconfig-mode'],
			'default_tlds'			=> self::DEFAULT_TLDS,
			'options_dnsbl_allow_int'	=> ['lan' => 'LAN', 'opt1' => 'OPT1'],
			'options_top1m_inclusion'	=> ['com' => 'COM', 'net' => 'NET', 'org' => 'ORG'],
			'input_errors'			=> [],
		];
		foreach (self::SCALAR_DEFAULTS as $key => $default) {
			$vars["options_{$key}"] = ['other' => 'Other'];	// the default is not an option: an omitted field must be set to it
		}

		$_POST = $post;
		$diagnostics = [];
		set_error_handler(static function (int $errno, string $errstr) use (&$diagnostics): bool {
			$diagnostics[] = $errstr;
			return TRUE;
		});
		try {
			$scope = pfb_test_page_eval(
				pfb_test_page_region(self::PAGE, '// Validate Select field options', '// Validate DNSBL webserver block page'),
				$vars
			);
		} finally {
			restore_error_handler();
		}
		return ['post' => $_POST, 'diagnostics' => $diagnostics, 'input_errors' => $scope['input_errors']];
	}

	public function testOmittedSelectsTakeDefaultsWithoutDiagnostics(): void
	{
		$result = self::validateSelects(['save' => '1']);

		$this->assertSame([], $result['diagnostics'], 'an omitted select must not log a PHP diagnostic');
		$this->assertSame(self::SCALAR_DEFAULTS, array_intersect_key($result['post'], self::SCALAR_DEFAULTS));
		$this->assertSame('', $result['post']['dnsbl_allow_int']);
		$this->assertSame(self::DEFAULT_TLDS, $result['post']['top1m_inclusion']);
	}

	public function testValidSelectsAreKeptWithoutDiagnostics(): void
	{
		$post = ['save' => '1', 'dnsbl_allow_int' => ['lan', 'opt1'], 'top1m_inclusion' => ['org']]
			+ array_fill_keys(array_keys(self::SCALAR_DEFAULTS), 'other');
		$result = self::validateSelects($post);

		$this->assertSame([], $result['diagnostics']);
		$this->assertSame($post, $result['post']);
	}

	public function testInvalidSelectsFallBackToDefaults(): void
	{
		$result = self::validateSelects([
			'save'			=> '1',
			'action'		=> 'bogus',
			'top1m_source'		=> ['tranco'],
			'dnsbl_allow_int'	=> ['lan', 'bogus'],
			'top1m_inclusion'	=> 'bogus',
		]);

		$this->assertSame([], $result['diagnostics']);
		$this->assertSame('Disabled', $result['post']['action']);
		$this->assertSame('tranco', $result['post']['top1m_source']);
		$this->assertSame('', $result['post']['dnsbl_allow_int']);
		$this->assertSame(self::DEFAULT_TLDS, $result['post']['top1m_inclusion']);
	}

	/**
	 * A crafted POST nesting an array inside a multi-select (dnsbl_allow_int[0][]=x), past a valid
	 * or an unknown value or not, is refused with an input error, which blocks the save; array_key_exists() threw
	 * `Illegal offset type` on it (issue #3947).
	 */
	public function testNestedMultiSelectValueIsAnInputError(): void
	{
		foreach (['dnsbl_allow_int' => ['lan', ''], 'top1m_inclusion' => ['com', self::DEFAULT_TLDS]] as $field => [$valid, $default]) {
			foreach ([[['x']], [$valid, ['x']], ['bogus', ['x']]] as $value) {
				$result = self::validateSelects(['save' => '1', $field => $value]);

				$this->assertSame([], $result['diagnostics'], $field);
				$this->assertSame(["DNSBL: the {$field} selection is invalid!"], $result['input_errors'], $field);
				$this->assertSame($default, $result['post'][$field], $field);
			}
		}
	}

	/**
	 * The DoH/DoT/DoQ blocking selects on the same save: an array where the single select expects a
	 * string falls back to its default, and a nested value in the list is an input error (issue #3947).
	 *
	 * @param array<string, mixed> $post
	 * @return array{post: array<string, mixed>, diagnostics: list<string>, input_errors: list<string>}
	 */
	private static function validateDohSelects(array $post): array
	{
		$_POST = $post;
		$diagnostics = [];
		set_error_handler(static function (int $errno, string $errstr) use (&$diagnostics): bool {
			$diagnostics[] = $errstr;
			return TRUE;
		});
		try {
			$scope = pfb_test_page_eval(
				pfb_test_page_region(self::PAGE, '// Validate DoH/DoT/DoQ blocking fields', '// Validate DNS Redirect fields.'),
				[
					'options_safesearch_doh'	=> ['Disable' => 'Disable', 'Enable' => 'Enable'],
					'options_safesearch_doh_list'	=> ['dns.google' => 'Google', 'cloudflare-dns.com' => 'Cloudflare'],
					'input_errors'			=> [],
				]
			);
		} finally {
			restore_error_handler();
		}
		return ['post' => $_POST, 'diagnostics' => $diagnostics, 'input_errors' => $scope['input_errors']];
	}

	public function testNestedDohSelectValues(): void
	{
		$result = self::validateDohSelects(['save' => '1', 'safesearch_doh' => ['Enable'], 'safesearch_doh_list' => ['dns.google']]);
		$this->assertSame([], $result['diagnostics']);
		$this->assertSame([], $result['input_errors']);
		$this->assertSame('Disable', $result['post']['safesearch_doh']);

		foreach ([['dns.google', ['x']], ['bogus', ['x']]] as $value) {
			$result = self::validateDohSelects(['save' => '1', 'safesearch_doh' => 'Enable', 'safesearch_doh_list' => $value]);
			$this->assertSame([], $result['diagnostics']);
			$this->assertSame(['DNSBL: the safesearch_doh_list selection is invalid!'], $result['input_errors']);
			$this->assertSame('', $result['post']['safesearch_doh_list']);
		}
	}
}
