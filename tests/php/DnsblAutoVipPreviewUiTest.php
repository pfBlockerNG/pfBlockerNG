<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

if (!class_exists('Form_Checkbox', FALSE)) {
	/** Off-appliance stand-in for pfSense's checkbox widget: records what the page decides about it. */
	class Form_Checkbox
	{
		/** @var array<string,string> */
		public array $attributes = [];

		public function __construct(
			public string $name,
			public string $title,
			public string $text,
			public bool $checked = FALSE,
			public string $value = 'yes'
		) {
		}

		public function setAttribute(string $key, string $value): static
		{
			$this->attributes[$key] = $value;
			return $this;
		}
	}
}

/**
 * Issue #3565 -- the DNSBL page previews "the address Create VIPs automatically would use". A VIP the
 * package already created (descr pfB_AUTO_VIP_v4/_v6) is that address: the preview shows it, keeps the
 * checkbox usable and the pre-fill in step with the real VIP; only a family without one falls back to the
 * first free candidate, and only a family with every candidate held by someone else disables the checkbox.
 *
 * The page cannot be require()d off-appliance, so its own preview, help and pre-fill regions are
 * extracted from the shipped source and evaluated (PageStatementLoader.php); the live render of the same
 * markup is pinned by tests/smoke/ui/test_dnsbl_auto_vip_preview.py.
 *
 * Scenario R1: both families' own VIPs exist on a resolver that listens on IPv6
 *   Given  auto-create is stored on, marked VIPs sit at both first candidates and the resolver listens on IPv6
 *   When   the page is rendered
 *   Then   the checkbox is enabled and checked, and the pre-fill carries each VIP's own address
 *
 * Scenario R2: an own VIP at a later candidate is previewed as it is, not replaced by the first free pick
 * Scenario R3 (control): no own VIP, a user VIP at the first candidate -> the picker's next free candidate
 * Scenario R4 (control): no own VIP, every IPv4 candidate held by a user VIP -> checkbox disabled, warning shown
 */
final class DnsblAutoVipPreviewUiTest extends TestCase
{
	private const PAGE = 'src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php';
	private const V4_FIRST = '172.16.53.53';
	private const V4_SECOND = '192.168.53.53';
	private const V4_THIRD = '10.53.53.53';
	private const V6 = 'fd00:53:53:53:53:53:53:53';
	private const EXHAUSTED_WARNING = 'No free auto-create address is available';

	private mixed $savedConfig;

	public static function setUpBeforeClass(): void
	{
		require_once __DIR__ . '/PageStatementLoader.php';
	}

	protected function setUp(): void
	{
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$GLOBALS['config'] = [];
		unset($GLOBALS['pfb_test_vip_list'], $GLOBALS['pfb_test_specialnet'], $GLOBALS['pfb_test_configured_subnets'], $GLOBALS['pfb_test_configured_ipv6']);
	}

	protected function tearDown(): void
	{
		if ($this->savedConfig === NULL) {
			unset($GLOBALS['config']);
		} else {
			$GLOBALS['config'] = $this->savedConfig;
		}
		unset($GLOBALS['pfb_test_vip_list'], $GLOBALS['pfb_test_specialnet'], $GLOBALS['pfb_test_configured_subnets'], $GLOBALS['pfb_test_configured_ipv6']);
	}

	/** @return array<string,string> */
	private static function vip(string $uniqid, string $subnet, string $descr): array
	{
		return [
			'mode' => 'ipalias', 'interface' => 'lo0', 'type' => 'single', 'subnet' => $subnet,
			'subnet_bits' => str_contains($subnet, ':') ? '128' : '32', 'descr' => $descr, 'uniqid' => $uniqid,
		];
	}

	/**
	 * Render the page's preview, checkbox, warning and pre-fill for the stored auto-create setting.
	 *
	 * @param list<array<string,string>> $vips virtualip/vip rows, listed the way pfSense lists them
	 * @return array{vip4: ?string, vip6: ?string, checkbox: Form_Checkbox, help: string, js: string}
	 */
	private function render(array $vips, bool $resolverListensOnV6): array
	{
		$GLOBALS['config'] = [];
		unset($GLOBALS['pfb_test_configured_ipv6']);
		if ($vips !== []) {
			config_set_path('virtualip/vip', $vips);
		}
		$GLOBALS['pfb_test_vip_list'] = [];
		foreach ($vips as $vip) {
			$GLOBALS['pfb_test_vip_list']["_vip{$vip['uniqid']}"] = $vip['subnet'];
		}
		if ($resolverListensOnV6) {
			config_set_path('unbound', ['enable' => '']);
			$GLOBALS['pfb_test_configured_ipv6'] = ['lan' => '2001:db8:1::1'];
		}

		$section = new class {
			/** @var list<object> */
			public array $inputs = [];

			public function addInput(object $input): object
			{
				$this->inputs[] = $input;
				return $input;
			}
		};
		$scope = pfb_test_page_eval(
			pfb_test_page_region(self::PAGE, '$pfb_auto_iface', "\$group = new Form_Group('DNSBL Virtual IP');")
			. pfb_test_page_region(self::PAGE, '$pfb_vip_help = ', '$group->setHelp($pfb_vip_help);'),
			['pconfig' => ['dnsbl_interface' => 'lo0', 'pfb_dnsvip_auto' => 'on'], 'section' => $section]
		);

		ob_start();
		pfb_test_page_eval('?>' . pfb_test_page_region(self::PAGE, 'var pfb_auto_vip4 = ', 'function enable_dnsvip_auto()'), $scope);
		$js = (string) ob_get_clean();

		$checkboxes = array_values(array_filter($section->inputs, static fn (object $input): bool => $input instanceof Form_Checkbox));
		$this->assertCount(1, $checkboxes, 'the preview region adds exactly the auto-create checkbox');
		$this->assertSame('pfb_dnsvip_auto', $checkboxes[0]->name);

		return [
			'vip4' => $scope['pfb_auto_vip4'], 'vip6' => $scope['pfb_auto_vip6'],
			'checkbox' => $checkboxes[0], 'help' => $scope['pfb_vip_help'], 'js' => $js,
		];
	}

	// ---------- R1: the package's own VIPs on a resolver that listens on IPv6 ----------

	public function testOwnVipsAtBothFirstCandidatesKeepAutoCreateEnabledAndPrefillTheirAddresses(): void
	{
		// Given: before the VIPs exist the page offers the same addresses and an enabled, checked checkbox.
		$before = $this->render([], TRUE);
		$this->assertSame(self::V4_FIRST, $before['vip4'], 'Pre-condition: without VIPs the v4 preview is the first candidate');
		$this->assertSame(self::V6, $before['vip6'], 'Pre-condition: without VIPs the v6 preview is the ULA candidate');
		$this->assertTrue($before['checkbox']->checked, 'Pre-condition: the stored "on" renders checked');
		$this->assertArrayNotHasKey('disabled', $before['checkbox']->attributes, 'Pre-condition: the checkbox is usable');

		// When: the package's own VIPs sit at both addresses.
		$after = $this->render([
			self::vip('own4', self::V4_FIRST, PFB_AUTO_VIP_DESCR_V4),
			self::vip('own6', self::V6, PFB_AUTO_VIP_DESCR_V6),
		], TRUE);

		// Then: auto-create stays on and usable, and the pre-fill carries each VIP's own address.
		$this->assertArrayNotHasKey('disabled', $after['checkbox']->attributes,
			'The checkbox must stay enabled while the package holds its own VIPs. Attributes: ' . var_export($after['checkbox']->attributes, TRUE));
		$this->assertTrue($after['checkbox']->checked, 'The stored "on" must still render checked');
		$this->assertStringContainsString('var pfb_auto_vip4 = "' . self::V4_FIRST . '";', $after['js'],
			'The v4 pre-fill must be the package\'s own VIP. Got: ' . $after['js']);
		$this->assertStringContainsString('var pfb_auto_vip6 = "' . self::V6 . '";', $after['js'],
			'The v6 pre-fill must be the package\'s own VIP. Got: ' . $after['js']);
		$this->assertStringNotContainsString(self::EXHAUSTED_WARNING, $after['help']);
	}

	// ---------- R2: an own VIP at a later candidate ----------

	public function testOwnVipAtALaterCandidateIsPreviewedAsItIs(): void
	{
		// Given: before the VIP exists the preview is the first candidate.
		$this->assertSame(self::V4_FIRST, $this->render([], FALSE)['vip4'],
			'Pre-condition: without a VIP the picker returns the first candidate');

		// When: the package's own v4 VIP sits at the second candidate (v4-only resolver).
		$page = $this->render([self::vip('own4', self::V4_SECOND, PFB_AUTO_VIP_DESCR_V4)], FALSE);

		// Then: the preview is that VIP's own address, not the picker's first free one.
		$this->assertSame(self::V4_SECOND, $page['vip4'],
			'The preview must be the existing VIP\'s own address. Got: ' . var_export($page['vip4'], TRUE));
		$this->assertStringContainsString('var pfb_auto_vip4 = "' . self::V4_SECOND . '";', $page['js'],
			'The pre-fill must carry the existing VIP\'s own address. Got: ' . $page['js']);
		$this->assertNull($page['vip6'], 'A resolver without IPv6 previews no v6 address');
	}

	// ---------- R3: control -- no own VIP, a user VIP in the way ----------

	public function testUserVipAtTheFirstCandidateWithoutAnOwnVipPreviewsTheNextFreeCandidate(): void
	{
		// Given: a user's VIP holds the first candidate and the package has none.
		$page = $this->render([self::vip('user1', self::V4_FIRST, 'web server')], FALSE);

		// Then: the picker's next free candidate is previewed and auto-create stays usable.
		$this->assertSame(self::V4_SECOND, $page['vip4'],
			'The preview must skip a user\'s VIP. Got: ' . var_export($page['vip4'], TRUE));
		$this->assertArrayNotHasKey('disabled', $page['checkbox']->attributes, 'A free candidate remains, so the checkbox is usable');
		$this->assertTrue($page['checkbox']->checked);
	}

	// ---------- R4: control -- nothing free ----------

	public function testEveryV4CandidateHeldByUserVipsDisablesAutoCreateWithTheWarning(): void
	{
		// Given: before the user's VIPs exist auto-create is usable.
		$this->assertArrayNotHasKey('disabled', $this->render([], FALSE)['checkbox']->attributes,
			'Pre-condition: without VIPs the checkbox is usable');

		// When: user VIPs hold all three v4 candidates and the package has no VIP.
		$page = $this->render([
			self::vip('user1', self::V4_FIRST, 'one'),
			self::vip('user2', self::V4_SECOND, 'two'),
			self::vip('user3', self::V4_THIRD, 'three'),
		], FALSE);

		// Then: the checkbox is disabled and unchecked, the pre-fill is empty and the warning says why.
		$this->assertNull($page['vip4'], 'No candidate is free');
		$this->assertSame('disabled', $page['checkbox']->attributes['disabled'] ?? NULL,
			'The checkbox must be disabled. Attributes: ' . var_export($page['checkbox']->attributes, TRUE));
		$this->assertFalse($page['checkbox']->checked, 'A disabled checkbox must not render checked');
		$this->assertStringContainsString('var pfb_auto_vip4 = "";', $page['js']);
		$this->assertStringContainsString(self::EXHAUSTED_WARNING, $page['help'], 'The warning must say why. Got: ' . $page['help']);
	}
}
