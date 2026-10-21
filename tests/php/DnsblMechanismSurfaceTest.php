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

	/** Every help bullet whose label names WebServer/VIP, from its label to the next bullet or block end. */
	private static function vipBullets(string $html): array
	{
		$bullets = [];
		if (preg_match_all('/<strong>[^<]*WebServer\/VIP[^<]*<\/strong>/', $html, $matches, PREG_OFFSET_CAPTURE) === FALSE) {
			return [];
		}
		foreach ($matches[0] as [$label, $offset]) {
			$tail      = substr($html, (int) $offset + strlen($label));
			$end       = preg_match('/&#8226|<\/div>/', $tail, $stop, PREG_OFFSET_CAPTURE) === 1 ? (int) $stop[0][1] : strlen($tail);
			$bullets[] = $label . substr($tail, 0, $end);
		}
		return $bullets;
	}

	private function assertEveryVipBulletIsDeprecated(string $html, string $where): void
	{
		$bullets = self::vipBullets($html);
		$this->assertNotSame([], $bullets, "{$where}: no WebServer/VIP help bullet found -- the page lost its mechanism help");
		foreach ($bullets as $bullet) {
			$notice = substr($bullet, (int) strpos($bullet, '</strong>'));	// past the label: the bullet must say it, not just carry it
			$this->assertStringContainsString('deprecated', strtolower(strip_tags($notice)), "{$where}: a WebServer/VIP bullet lacks the notice: {$bullet}");
		}
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

	public function testVipBulletCarriesTheDeprecationNoticeBeyondItsLabel(): void
	{
		$bullets = self::vipBullets(pfb_dnsbl_mechanism_help());
		$this->assertCount(1, $bullets, 'exactly one bullet describes the WebServer/VIP response');
		$notice = strtolower(substr($bullets[0], strlen('<strong>' . self::VIP_LABEL . '</strong>')));
		foreach (['deprecated', 'null blocking', 'blacklist category', 'built-in'] as $part) {
			$this->assertStringContainsString($part, $notice, "the VIP bullet's notice must mention '{$part}'");
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

	public function testDnsblPageModeHelpNamesTheDeprecatedLabel(): void
	{
		$scope = pfb_test_page_eval(pfb_test_page_statement(self::DNSBL_PAGE, '/\$options_global_log_mode_txt\s*=/'), []);
		$this->assertStringContainsString(
			'Default policy with ' . self::VIP_LABEL,
			$scope['options_global_log_mode_txt'],
			'the grandfather sentence must name the response by its (deprecated) label'
		);
	}

	public function testDnsblPageMechanismExplanationMarksTheVipBulletDeprecated(): void
	{
		$scope = pfb_test_page_eval(pfb_test_page_statement(self::DNSBL_PAGE, '/\$dnsbl_text\s*=/'), []);
		$this->assertEveryVipBulletIsDeprecated($scope['dnsbl_text'], 'DNSBL page mechanism explanation');
	}

	public function testDnsblPageVipHelpAnnouncesTheDeprecation(): void
	{
		$scope = pfb_test_page_eval(pfb_test_page_statement(self::DNSBL_PAGE, '/\$pfb_vip_help\s*=/'), []);
		$this->assertStringContainsString('deprecated', strtolower($scope['pfb_vip_help']));
	}

	public function testDnsblPageWebserverSectionAnnouncesTheDeprecation(): void
	{
		$section = pfb_test_page_region(self::DNSBL_PAGE, "new Form_Section('DNSBL Webserver Configuration')", '$form->add($section);');
		$this->assertStringContainsString('deprecated', strtolower($section), 'the DNSBL Webserver Configuration section must carry the notice');
	}

	public function testDnsblPageWebserverSectionCarriesItsOwnNoticeApartFromTheVipHelp(): void
	{
		// The section's own notice (its first input), not the VIP select's help that the section region above also covers.
		$notice = pfb_test_page_region(self::DNSBL_PAGE, "new Form_Section('DNSBL Webserver Configuration');", '$section->addInput(new Form_Select(');
		$this->assertStringContainsString('deprecated', strtolower($notice), 'the section notice must say the response is deprecated');
		$this->assertStringContainsString('prefer Null Blocking', $notice, 'and name the replacement');
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
		$this->assertEveryVipBulletIsDeprecated($help, 'Blacklist logging help');
		$this->assertStringContainsString('Deprecated: prefer Null Blocking', $help, 'the VIP deprecation sentence');
		$this->assertStringContainsString('Default follows the global DNSBL blocking mechanism', strip_tags($help), 'the Blacklist-only Default line');
		$this->assertStringNotContainsString('Default: <strong>Default</strong>', $help, 'no second "Default:" header beside the mechanism help');
	}

	public function testAlertsUnknownBlockingTypeLabelsUseTheSharedLabel(): void
	{
		$empty_agent = pfb_test_page_region('src/usr/local/www/pfblockerng/pfblockerng_alerts.php', "if (\$alert_view != 'dnsbl_stat') {", "\$agent_cmd = '';");
		$scope       = pfb_test_page_eval($empty_agent, ['alert_view' => 'dnsbl_stat']);
		$this->assertSame(pfb_dnsbl_mechanism_labels()['enabled'], $scope['unknown_msg'], 'empty-agent rows');

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
