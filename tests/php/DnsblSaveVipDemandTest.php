<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3539 -- the DNSBL page's save asks for a VIP only when the configuration it is about to write
 * answers a block with the VIP. That candidate is the stored settings section overlaid with the
 * POSTed policy fields in their STORED form -- the one mapping the save itself persists with
 * (pfb_dnsbl_policy_from_post) -- judged by the same predicate the apply uses (pfb_dnsbl_vip_demand).
 *
 * The page cannot be required off-appliance: its OWN VIP-validation region is extracted from the
 * shipped source and evaluated with $_POST seeded (PageStatementLoader.php); the live save is pinned by
 * tests/smoke/test_smoke_dnsbl_vip_demand.py.
 */
#[CoversFunction('pfb_dnsbl_policy_from_post')]
#[CoversFunction('pfb_dnsbl_candidate_vip_demand')]
final class DnsblSaveVipDemandTest extends TestCase
{
	private const PAGE = 'src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php';

	private const NO_VIP_ERROR = 'DNSBL: no VIP configured';

	private mixed $savedConfig = NULL;
	private bool $hadConfig    = FALSE;

	public static function setUpBeforeClass(): void
	{
		require_once __DIR__ . '/PageStatementLoader.php';
	}

	protected function setUp(): void
	{
		$this->hadConfig   = array_key_exists('config', $GLOBALS);
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$GLOBALS['config'] = [];
		$_POST             = [];
	}

	protected function tearDown(): void
	{
		if ($this->hadConfig) {
			$GLOBALS['config'] = $this->savedConfig;
		} else {
			unset($GLOBALS['config']);
		}
		$_POST = [];
	}

	/** A DNSBL group the apply would process as deny. */
	private static function group(string $logging): array
	{
		return [
			'aliasname' => 'G1',
			'action'    => 'unbound',
			'logging'   => $logging,
			'row'       => [['url' => 'https://example.com/list.txt', 'state' => 'Enabled', 'header' => 'G1_a', 'format' => 'auto']],
		];
	}

	/** The page's save mapping for a box whose local TLD is 'local'. */
	private static function stored(array $post): array
	{
		return pfb_dnsbl_policy_from_post($post, 'local', ['arpa', 'local', 'com']);
	}

	/** A manual-mode settings POST with no VIP selected, on the no-demand policy (Default / Null Blocking). */
	private static function post(array $over = []): array
	{
		return array_replace([
			'save'                   => 'Save',
			'dnsbl_interface'        => 'lo0',
			'pfb_dnsvip4'            => 'none',
			'pfb_dnsvip6'            => 'none',
			'pfb_dnsport'            => '8081',
			'pfb_dnsport_ssl'        => '8443',
			'global_log'             => 'disabled_log',
			'global_log_mode'        => 'default',
			'pfb_regex'              => '',
			'pfb_regex_list'         => '',
			'pfb_idn'                => '',
			'tld_allow'              => '',
			'tld_wildcard'           => '',
			'tld_wildcard_blacklist' => '',
		], $over);
	}

	/** Run the page's VIP-validation region for $post; returns [$input_errors, $_POST afterwards]. */
	private function validate(array $post, array $stored = []): array
	{
		$_POST = $post;
		$scope = pfb_test_page_eval(
			pfb_test_page_region(self::PAGE, '// Validate DNSBL VIP address', "// Validate Adv. firewall rule 'Protocol' setting"),
			['pfb' => ['dconfig' => $stored], 'input_errors' => [], 'local_tld' => 'local', 'default_tlds' => ['arpa', 'local', 'com']]
		);
		return [$scope['input_errors'], $_POST];
	}

	private function seedGroups(string ...$loggings): void
	{
		config_set_path('installedpackages/pfblockerngdnsbl/config', array_map([self::class, 'group'], $loggings));
	}

	// -----------------------------------------------------------------------
	// The page's save validation
	// -----------------------------------------------------------------------

	public function testCandidateWithoutDemandNeedsNoVip(): void
	{
		[$errors] = $this->validate(self::post());

		$this->assertSame([], $errors);
	}

	public function testPostedVipMechanismWithADefaultGroupDemandsAVip(): void
	{
		$this->seedGroups('default');

		[$errors] = $this->validate(self::post(['global_log' => 'enabled']));

		$this->assertSame([self::NO_VIP_ERROR], $errors);
	}

	public function testPostedRegexListUnderTheVipMechanismDemandsAVip(): void
	{
		[$errors] = $this->validate(self::post(['global_log' => 'enabled', 'pfb_regex' => 'on', 'pfb_regex_list' => "ads\\..*"]));

		$this->assertSame([self::NO_VIP_ERROR], $errors);
	}

	public function testThePostedMechanismDecidesNotTheStoredOne(): void
	{
		// Given a stored configuration that answers with the VIP (global VIP, one Default group).
		$stored = ['global_log_mode' => 'default', 'global_log' => 'enabled'];
		$this->seedGroups('default');
		[$before] = $this->validate(self::post(['global_log' => 'enabled']), $stored);
		$this->assertSame([self::NO_VIP_ERROR], $before, 'before-state: the VIP is demanded');

		// When the save moves the global mechanism to Null Blocking.
		[$after] = $this->validate(self::post(['global_log' => 'disabled_log']), $stored);

		// Then nothing in the candidate answers with the VIP, so none is required.
		$this->assertSame([], $after);
	}

	public function testOverrideModeCandidateDemandsAVipEvenForAnExplicitNullGroup(): void
	{
		$this->seedGroups('disabled');

		[$errors] = $this->validate(self::post(['global_log' => 'enabled', 'global_log_mode' => 'override']));

		$this->assertSame([self::NO_VIP_ERROR], $errors, 'Override forces the global VIP mechanism onto every group');
	}

	public function testAutoVipSkipsTheValidationEvenWithDemand(): void
	{
		$this->seedGroups('default');

		[$errors] = $this->validate(self::post(['global_log' => 'enabled', 'pfb_dnsvip_auto' => 'on']));

		$this->assertSame([], $errors);
	}

	public function testNoneSentinelIsStillClearedWhenNoVipIsRequired(): void
	{
		[, $post] = $this->validate(self::post());

		$this->assertSame('', $post['pfb_dnsvip4'], 'the widget sentinel must never be stored as a VIP id');
		$this->assertSame('', $post['pfb_dnsvip6']);
	}

	public function testEmptyPortsAreAcceptedWithoutDemand(): void
	{
		[$errors] = $this->validate(self::post(['pfb_dnsport' => '', 'pfb_dnsport_ssl' => '']));

		$this->assertSame([], $errors);
	}

	public function testEmptyPortsAreRejectedWithDemand(): void
	{
		$this->seedGroups('default');

		[$errors] = $this->validate(self::post(['global_log' => 'enabled', 'pfb_dnsvip_auto' => 'on', 'pfb_dnsport' => '', 'pfb_dnsport_ssl' => '']));

		$this->assertSame(['DNSBL Port is invalid!', 'DNSBL SSL Port is invalid!'], $errors);
	}

	public function testAnInvalidPortIsRejectedWithoutDemand(): void
	{
		[$errors] = $this->validate(self::post(['pfb_dnsport' => 'abc', 'pfb_dnsport_ssl' => '70000']));

		$this->assertSame(['DNSBL Port is invalid!', 'DNSBL SSL Port is invalid!'], $errors);
	}

	public function testPostedTldAllowWithNoSelectionDemandsAVipThroughTheDefaultGtldBucket(): void
	{
		[$errors] = $this->validate(self::post(['global_log' => 'enabled', 'tld_allow' => 'on']));

		$this->assertSame([self::NO_VIP_ERROR], $errors, 'the save writes the default gTLD bucket, so TLD Allow answers with the VIP');
	}

	// -----------------------------------------------------------------------
	// The shared POST -> stored mapping and the candidate predicate
	// -----------------------------------------------------------------------

	public function testPolicyFromPostMapsThePolicyFieldsToTheirStoredForm(): void
	{
		$stored = self::stored([
			'global_log'             => 'nxdomain',
			'global_log_mode'        => 'override',
			'pfb_regex'              => 'on',
			'pfb_regex_list'         => "a.*\nb",
			'pfb_idn'                => 'confusable',
			'tld_allow'              => 'on',
			'tld_wildcard'           => 'on',
			'tld_wildcard_blacklist' => "zip\nmov",
			'tld_allow_gtld'         => ['io'],
			'tld_allow_cctld'        => ['uk', 'de'],
			'tld_allow_bgtld'        => ['app'],
		]);

		$this->assertSame([
			'global_log'             => 'nxdomain',
			'global_log_mode'        => 'override',
			'pfb_regex'              => 'on',
			'pfb_regex_list'         => base64_encode("a.*\nb"),
			'pfb_idn'                => 'confusable',
			'tld_allow'              => 'on',
			'tld_wildcard'           => 'on',
			'tld_wildcard_blacklist' => base64_encode("zip\nmov"),
			'tld_allow_gtld'         => 'arpa,local,io',
			'tld_allow_cctld'        => 'uk,de',
			'tld_allow_itld'         => '',
			'tld_allow_bgtld'        => 'app',
		], $stored);
	}

	public function testPolicyFromPostStoresAnUncheckedFormAsEmptyTokens(): void
	{
		$stored = self::stored(['global_log' => 'disabled_log', 'global_log_mode' => 'default']);

		$this->assertSame('', $stored['pfb_regex']);
		$this->assertSame('', $stored['pfb_regex_list']);
		$this->assertSame('', $stored['pfb_idn'], 'a missing IDN select is Off');
		$this->assertSame('', $stored['tld_allow']);
		$this->assertSame('', $stored['tld_wildcard']);
		$this->assertSame('', $stored['tld_wildcard_blacklist']);
		$this->assertSame('arpa,local,com', $stored['tld_allow_gtld'], 'an empty gTLD selection stores the default TLDs');
		$this->assertSame('', $stored['tld_allow_cctld']);
	}

	public function testPolicyFromPostCanonicalisesIdnThroughTheStoredEnum(): void
	{
		$this->assertSame('on', self::stored(['pfb_idn' => 'on'])['pfb_idn'], 'All is stored as on');
		$this->assertSame('', self::stored(['pfb_idn' => 'off'])['pfb_idn'], 'Off is stored as empty');
	}

	public function testPolicyFromPostDropsAnUnknownToggleValue(): void
	{
		$this->assertSame('', self::stored(['pfb_regex' => 'banana'])['pfb_regex']);
	}

	public function testPolicyFromPostStoresArrayValuedTextAreasAsEmptyWithoutWarning(): void
	{
		$warnings = [];
		set_error_handler(static function (int $errno, string $message) use (&$warnings): bool {
			$warnings[] = $message;
			return TRUE;
		});
		try {
			$stored = self::stored(['pfb_regex_list' => ['a.*'], 'tld_wildcard_blacklist' => ['zip']]);
		} finally {
			restore_error_handler();
		}

		$this->assertSame('', $stored['pfb_regex_list'], 'an array-valued Regex List must not become base64 of "Array"');
		$this->assertSame('', $stored['tld_wildcard_blacklist'], 'an array-valued TLD Blacklist must not become base64 of "Array"');
		$this->assertSame([], $warnings, 'array input must not raise an Array-to-string warning');
	}

	public function testPageMapsThosePolicyFieldsOnlyThroughTheSharedFunction(): void
	{
		$source = pfb_test_page_source(self::PAGE);
		foreach (['global_log', 'global_log_mode', 'pfb_regex', 'pfb_regex_list', 'pfb_idn', 'tld_allow', 'tld_wildcard', 'tld_wildcard_blacklist',
			'tld_allow_gtld', 'tld_allow_cctld', 'tld_allow_itld', 'tld_allow_bgtld'] as $key) {
			$this->assertSame(
				0,
				preg_match("/\\\$pfb\\['dconfig'\\]\\['{$key}'\\]\\s*=[^=]/", $source),
				"the page must not map {$key} from \$_POST itself: its stored form comes from pfb_dnsbl_policy_from_post()"
			);
		}
		$this->assertSame(1, substr_count($source, 'pfb_dnsbl_policy_from_post('), 'the page maps the POST once and reuses it for the candidate and the save');
	}

	public function testCandidateDemandReadsTheStoredGroupsAndBlacklist(): void
	{
		$posted = self::stored(['global_log' => 'enabled', 'global_log_mode' => 'default']);
		$this->assertFalse(pfb_dnsbl_candidate_vip_demand([], $posted), 'before-state: nothing uses the VIP mechanism');

		config_set_path('installedpackages/pfblockerngblacklist', [
			'blacklist_enable' => 'Enable', 'blacklist_selected' => 'ut1', 'item' => [['xml' => 'ut1', 'title' => 'UT1', 'selected' => 'adult']],
		]);

		$this->assertTrue(pfb_dnsbl_candidate_vip_demand([], $posted), 'the Blacklist category resolves Default to the posted VIP mechanism');
	}
}
