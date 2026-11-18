<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3539 -- every page reads ONE shared mechanism label map and ONE shared mechanism help. The tokens and their
 * labels are the #3288 vocabulary and stay exact; issue #4053 removed the WebServer/VIP response (`enabled`).
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

	/** The six labels. */
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

	public function testLabelMapKeysAreTheConcreteMechanismsInResolverOrder(): void
	{
		$this->assertSame(PFB_DNSBL_CONCRETE_MECHANISMS, array_keys(pfb_dnsbl_mechanism_labels()));
	}

	public function testTheSixLabelsStayExact(): void
	{
		$this->assertSame(self::UNCHANGED_LABELS, pfb_dnsbl_mechanism_labels());
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

	public function testGroupEditorLoggingSelectUsesTheSharedMapAfterDefault(): void
	{
		$scope = pfb_test_page_eval(pfb_test_page_statement(self::CATEGORY_EDIT_PAGE, '/\$options_logging\s*=/'), []);
		$this->assertSame(['default' => 'Default'] + pfb_dnsbl_mechanism_labels(), $scope['options_logging']);
	}

	/** Issue #4053: an existing group's bogus logging value falls back to Null Blocking (logging), never the VIP marker. */
	public function testGroupEditorLoggingFallbackIsNullBlockingForAnExistingGroup(): void
	{
		$statement = pfb_test_page_statement(self::CATEGORY_EDIT_PAGE, '/\$pfb_logging_default\s*=/');
		$this->assertSame('disabled_log', pfb_test_page_eval($statement, ['pfb_row_is_fresh' => FALSE])['pfb_logging_default']);
		$this->assertSame('default', pfb_test_page_eval($statement, ['pfb_row_is_fresh' => TRUE])['pfb_logging_default']);
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

	/** Issue #4053: with no block page, an event without a user agent is Unknown, not the removed VIP label. */
	public function testAlertsUnknownBlockingTypeIsLabelledUnknown(): void
	{
		require_once __DIR__ . '/AlertsPageLoader.php';
		require_once __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_stats.inc';
		pfb_test_load_alerts_page_functions();
		$panel = pfb_stats_panel('dnsblagent', ['', 'Found', 'Type(s)', FALSE, ''], ['Unknown' => 1], 'max', []);
		$this->assertStringContainsString('>Unknown</td>', $panel['html']);
	}
}
