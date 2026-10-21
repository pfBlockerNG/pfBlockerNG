<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3539 D2 -- the Blacklist tab's Logging select joins the Default/Override policy: it offers
 * Default plus the seven mechanisms, prefills through the one shared Blacklist-logging projection,
 * and a junk POST stores 'default' (new configs inherit the global mechanism).
 *
 * The page cannot be required off-appliance, so its OWN prefill statement and select-validation
 * region are extracted from the shipped source and evaluated (PageStatementLoader.php); the live
 * round trip is pinned by tests/smoke/ui/test_blacklist.py and test_dnsbl_blocking_modes.py.
 */
#[CoversNothing]
final class BlacklistLoggingDefaultTest extends TestCase
{
	private const PAGE = 'src/usr/local/www/pfblockerng/pfblockerng_blacklist.php';

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

	/** @param array<string, mixed> $bconfig the stored Blacklist section */
	private function prefill(array $bconfig): mixed
	{
		$statement = pfb_test_page_statement(self::PAGE, "/\\\$pconfig\\['blacklist_logging'\\]\\s*=/");
		$scope     = pfb_test_page_eval($statement, ['pfb' => ['bconfig' => $bconfig], 'pconfig' => []]);
		return $scope['pconfig']['blacklist_logging'];
	}

	/** Run the page's select validation for a POSTed blacklist_logging; returns what the page would store. */
	private function storedAfterPost(mixed $posted): mixed
	{
		$_POST = ['blacklist_enable' => 'Enable', 'blacklist_lang' => 'EN', 'blacklist_freq' => 'Never', 'blacklist_logging' => $posted];
		pfb_test_page_eval(
			pfb_test_page_region(self::PAGE, '// Select field options', '// Unconditional (not just')
			. pfb_test_page_region(self::PAGE, '// Validate Select field options', '// Validate Select field (array) options'),
			[]
		);
		return $_POST['blacklist_logging'];
	}

	/** @return array<string, array{0: array<string, mixed>, 1: string}> */
	public static function prefillRows(): array
	{
		return [
			'absent joins the policy'       => [[], 'default'],
			'stored Default'                => [['blacklist_logging' => 'default'], 'default'],
			'empty is the legacy VIP marker' => [['blacklist_logging' => ''], 'enabled'],
			'explicit VIP'                  => [['blacklist_logging' => 'enabled'], 'enabled'],
			'explicit Null Blocking'        => [['blacklist_logging' => 'disabled'], 'disabled'],
			'NXDOMAIN keeps its token'      => [['blacklist_logging' => 'nxdomain_log'], 'nxdomain_log'],
			'junk fails safe'               => [['blacklist_logging' => 'bogus'], 'disabled_log'],
		];
	}

	/** @param array<string, mixed> $bconfig */
	#[DataProvider('prefillRows')]
	public function testPrefillResolvesTheStoredValueThroughTheSharedProjection(array $bconfig, string $expected): void
	{
		$this->assertSame($expected, $this->prefill($bconfig));
	}

	public function testEveryOfferedOptionPostsBackVerbatim(): void
	{
		foreach (['default', ...PFB_DNSBL_CONCRETE_MECHANISMS] as $token) {
			$this->assertSame($token, $this->storedAfterPost($token), "the {$token} option must be stored verbatim, never coerced");
		}
	}

	/** @return array<string, array{0: mixed}> */
	public static function junkPosts(): array
	{
		return [
			'unknown string' => ['bogus_value'],
			'empty string'   => [''],
			'array'          => [['enabled']],
		];
	}

	#[DataProvider('junkPosts')]
	public function testJunkPostIsStoredAsDefault(mixed $posted): void
	{
		$this->assertSame('default', $this->storedAfterPost($posted));
	}
}
