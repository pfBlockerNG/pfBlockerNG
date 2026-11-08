<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3539 -- the DNSBL WebServer/VIP response is deprecated on every surface that names it, and
 * every page reads ONE shared mechanism label map and ONE shared mechanism help. The seven tokens and
 * six of their labels are the #3288 vocabulary and stay exact; only the `enabled` label changes.
 *
 * Pages are hermetic-unreachable, so each page's OWN assignment/region is extracted from the shipped
 * source and evaluated (PageStatementLoader.php); the live render of the same markup is pinned by
 * tests/smoke/ui/test_dnsbl_blocking_modes.py.
 */
#[CoversFunction('pfb_dnsbl_mechanism_labels')]
#[CoversFunction('pfb_dnsbl_mechanism_help')]
final class DnsblMechanismSurfaceTest extends TestCase
{
	private const DNSBL_PAGE         = 'src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php';
	private const CATEGORY_EDIT_PAGE = 'src/usr/local/www/pfblockerng/pfblockerng_category_edit.php';
	private const CATEGORY_PAGE      = 'src/usr/local/www/pfblockerng/pfblockerng_category.php';
	private const BLACKLIST_PAGE     = 'src/usr/local/www/pfblockerng/pfblockerng_blacklist.php';

	private const VIP_LABEL = 'DNSBL WebServer/VIP (deprecated)';

	/** The six labels the deprecation must not touch. */
	private const UNCHANGED_LABELS = [
		'disabled_log' => 'Null Blocking (logging)',
		'disabled'     => 'Null Blocking (no logging)',
		'nxdomain_log' => 'NXDOMAIN (logging)',
		'nxdomain'     => 'NXDOMAIN (no logging)',
		'nodata_log'   => 'NODATA (logging)',
		'nodata'       => 'NODATA (no logging)',
	];

	public static function setUpBeforeClass(): void
	{
		require_once __DIR__ . '/PageStatementLoader.php';
	}

	// -----------------------------------------------------------------------
	// 1 -- the shared label map
	// -----------------------------------------------------------------------

	public function testLabelMapKeysAreTheSevenConcreteMechanismsInResolverOrder(): void
	{
		$this->assertSame(PFB_DNSBL_CONCRETE_MECHANISMS, array_keys(pfb_dnsbl_mechanism_labels()));
	}

	public function testVipLabelNamesTheResponseDeprecated(): void
	{
		$this->assertSame(self::VIP_LABEL, pfb_dnsbl_mechanism_labels()['enabled']);
	}

	public function testTheOtherSixLabelsStayExact(): void
	{
		$labels = pfb_dnsbl_mechanism_labels();
		unset($labels['enabled']);
		$this->assertSame(self::UNCHANGED_LABELS, $labels);
	}

	// -----------------------------------------------------------------------
	// 2 -- the shared help
	// -----------------------------------------------------------------------

	public function testHelpBulletsNameEveryLabel(): void
	{
		$help = pfb_dnsbl_mechanism_help();
		foreach (pfb_dnsbl_mechanism_labels() as $token => $label) {
			$this->assertStringContainsString("<strong>{$label}</strong>", $help, "the help has no bullet for the {$token} mechanism");
		}
	}

	// -----------------------------------------------------------------------
	// 3 -- every page uses the shared map / help
	// -----------------------------------------------------------------------

	public function testDnsblPageGlobalMechanismSelectUsesTheSharedMap(): void
	{
		$scope = pfb_test_page_eval(pfb_test_page_statement(self::DNSBL_PAGE, '/\$options_global_log\s*=/'), []);
		$this->assertSame(pfb_dnsbl_mechanism_labels(), $scope['options_global_log']);
	}

	public function testDnsblPageGlobalMechanismHelpEmbedsTheSharedHelp(): void
	{
		$scope = pfb_test_page_eval(pfb_test_page_statement(self::DNSBL_PAGE, '/\$options_global_log_txt\s*=/'), []);
		$this->assertStringContainsString(pfb_dnsbl_mechanism_help(), $scope['options_global_log_txt']);
	}

	public function testDnsblPageVipHelpAnnouncesTheDeprecation(): void
	{
		$scope = pfb_test_page_eval(pfb_test_page_statement(self::DNSBL_PAGE, '/\$pfb_vip_help\s*=/'), []);
		$this->assertStringContainsString('deprecated', strtolower($scope['pfb_vip_help']));
	}

	public function testGroupEditorLoggingSelectUsesTheSharedMapAfterDefault(): void
	{
		$scope = pfb_test_page_eval(pfb_test_page_statement(self::CATEGORY_EDIT_PAGE, '/\$options_logging\s*=/'), []);
		$this->assertSame(['default' => 'Default'] + pfb_dnsbl_mechanism_labels(), $scope['options_logging']);
	}

	public function testGroupEditorLoggingHelpEmbedsTheSharedHelp(): void
	{
		$scope = pfb_test_page_eval(pfb_test_page_statement(self::CATEGORY_EDIT_PAGE, '/\$log_text\s*=/'), []);
		$this->assertStringContainsString(pfb_dnsbl_mechanism_help(), $scope['log_text']);
	}

	/** @return array<string, array{0: PfbDnsblGlobalMode, 1: string, 2: array<string, string>}> */
	public static function groupListPolicies(): array
	{
		$labels = pfb_dnsbl_mechanism_labels();
		$base   = ['default' => 'Default'] + $labels;
		return [
			'Default policy, Null Blocking global' => [
				PfbDnsblGlobalMode::Default, 'disabled_log',
				array_replace($base, ['default' => 'Default (Null Blocking (logging))']),
			],
			'Default policy, VIP global' => [
				PfbDnsblGlobalMode::Default, 'enabled',
				array_replace($base, ['default' => 'Default (' . self::VIP_LABEL . ')']),
			],
			'Override policy, VIP enforced' => [
				PfbDnsblGlobalMode::Override, 'enabled',
				array_replace($base, ['enabled' => self::VIP_LABEL . ' (Override)']),
			],
			'Override policy, NODATA enforced' => [
				PfbDnsblGlobalMode::Override, 'nodata',
				array_replace($base, ['nodata' => 'NODATA (no logging) (Override)']),
			],
		];
	}

	/** @param array<string, string> $expected */
	#[DataProvider('groupListPolicies')]
	public function testGroupListLoggingSelectUsesTheSharedMapWithItsAnnotations(PfbDnsblGlobalMode $mode, string $global, array $expected): void
	{
		$region = pfb_test_page_region(self::CATEGORY_PAGE, "\$log_error = '';", '$selectadd = new Form_Select(');
		$scope  = pfb_test_page_eval($region, [
			'gtype' => 'dnsbl',
			'pfb'   => ['dnsbl_global_mode' => $mode, 'dnsbl_global_log' => $global],
		]);
		$this->assertSame($expected, $scope['log_options']);
	}

	public function testBlacklistLoggingSelectIsDefaultThenTheSharedMap(): void
	{
		$region = pfb_test_page_region(self::BLACKLIST_PAGE, '// Select field options', '// Unconditional (not just');
		$scope  = pfb_test_page_eval($region, []);
		$this->assertSame(['default' => 'Default'] + pfb_dnsbl_mechanism_labels(), $scope['options_blacklist_logging']);
	}

	public function testBlacklistLoggingHelpEmbedsTheSharedMechanismHelpBesideItsOwnDefaultLine(): void
	{
		$region = pfb_test_page_region(
			self::BLACKLIST_PAGE,
			"\$options_blacklist_logging\n))->setHelp(",
			")\n  ->setAttribute('style', 'width: auto');"
		);
		$help = pfb_test_page_eval('$help = ' . substr($region, (int) strpos($region, '->setHelp(') + strlen('->setHelp(')) . ';', [])['help'];

		foreach (pfb_dnsbl_mechanism_labels() as $token => $label) {
			$this->assertStringContainsString("<strong>{$label}</strong>", $help, "the Blacklist help has no bullet for the {$token} mechanism");
		}
	}

	public function testAlertsUnknownBlockingTypeLabelsUseTheSharedLabel(): void
	{
		$literal_unknown = pfb_test_page_region(
			'src/usr/local/www/pfblockerng/pfblockerng_alerts.php',
			"if (\$stat_type == 'dnsblagent' && \$data == 'Unknown') {",
			"if (\$stat_type == 'ipdstport') {"
		);
		$scope = pfb_test_page_eval($literal_unknown, ['stat_type' => 'dnsblagent', 'data' => 'Unknown', 'data_disp' => NULL]);
		$this->assertSame(pfb_dnsbl_mechanism_labels()['enabled'], $scope['data'], 'literal Unknown rows');
		$this->assertSame(pfb_dnsbl_mechanism_labels()['enabled'], $scope['data_disp']);
	}
}
