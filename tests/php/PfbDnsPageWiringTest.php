<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * The pfB-DNS settings live on DNS > General (issue #3771): that page is reachable through the package privilege, owns the listener settings,
 * and keeps its enable toggle out of the DNSBL settings page. The old pfB-DNS URL still authenticates (it is a redirect stub).
 */
final class PfbDnsPageWiringTest extends TestCase
{
	/** The one page that holds the pfB-DNS settings since issue #3771. */
	private const PAGE = 'www/pfblockerng/pfblockerng_dns_general.php';

	/** The listener settings in the order the page shows them (issues #3513, #3538). */
	private const LISTENER_FIELDS = [
		'pfb_dns_interface', 'pfb_dns_sslcertref', 'pfb_dns_name',
		'pfb_dns_dot', 'pfb_dns_dot_port', 'pfb_dns_dot_port6', 'pfb_dns_dot_interface',
		'pfb_dns_doh', 'pfb_dns_doh_port', 'pfb_dns_doh_port6', 'pfb_dns_doh_interface', 'pfb_dns_doh_trusted',
		'pfb_dns_doq', 'pfb_dns_doq_port', 'pfb_dns_doq_port6', 'pfb_dns_doq_interface',
		'pfb_dns_ddr_doh_443_interfaces',
	];

	/** The DDR toggle, after the DoQ section (issue #3583); its DoH 443 selection follows it (issue #3694). */
	private const DDR_FIELDS = ['pfb_dns_ddr'];
	private const DOH_443_FIELD = 'pfb_dns_ddr_doh_443_interfaces';

	/** The ones pfB-DNS seeds once from the Resolver: the page shows the pending seed value through pfb_dns_proxy_setting() (issue #3538). */
	private const SEEDED_FIELDS = [
		'pfb_dns_interface', 'pfb_dns_sslcertref', 'pfb_dns_dot', 'pfb_dns_dot_port', 'pfb_dns_dot_interface',
		'pfb_dns_doh_interface', 'pfb_dns_doq_interface',
	];

	private static function src(string $relative): string
	{
		$text = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/' . $relative);
		self::assertIsString($text, "cannot read {$relative}");
		return $text;
	}

	public function testThePrivilegeReachesThePage(): void
	{
		$GLOBALS['priv_list'] = [];
		require dirname(__DIR__, 2) . '/src/etc/inc/priv/pfblockerng.priv.inc';

		$this->assertContains(
			'pfblockerng/pfblockerng_dns.php*',
			$GLOBALS['priv_list']['page-firewall-pfblockerng']['match'] ?? [],
			'the package privilege still matches the old pfB-DNS URL, so its redirect stub authenticates and no scoped operator is refused'
		);
		$this->assertContains('pfblockerng/pfblockerng_dns_general.php*',
			$GLOBALS['priv_list']['page-firewall-pfblockerng']['match'] ?? []);
		unset($GLOBALS['priv_list']);
	}

	public function testThePageCarriesTheEnableToggleAndAnExperimentalWarning(): void
	{
		$page = self::src(self::PAGE);

		$this->assertStringContainsString("'pfb_dns',", $page, 'the enable checkbox');
		$this->assertStringContainsString("PfbConfig::read('dns/pfb_dns')", $page, 'read through the gateway');
		$this->assertMatchesRegularExpression('/<strong>Experimental\./', $page, 'the help says so plainly, in bold');
	}

	public function testTheHelpNamesTheCustomOptionsLinesThatStopTheMove(): void
	{
		$page = self::src(self::PAGE);

		$this->assertStringContainsString('<code>include:</code>', $page, 'an include is named: the move refuses it');
	}

	public function testTheDnsblPageNoLongerCarriesTheToggleOrItsHelp(): void
	{
		$page = self::src('www/pfblockerng/pfblockerng_dnsbl.php');

		foreach (['pfb_dns_proxy', "'pfb_dns'", "dns/pfb_dns", 'DNS Proxy', 'pfBlockerNG DNS proxy'] as $needle) {
			$this->assertStringNotContainsString($needle, $page, "the DNSBL page has no trace of the toggle: {$needle}");
		}
	}

	public function testTheDnsblPageSavesUnderTheSameConfigLockAsThePfbDnsPage(): void
	{
		$page = self::src('www/pfblockerng/pfblockerng_dnsbl.php');

		$this->assertSame(1, substr_count($page, '$pfb_config_lock = pfb_dns_config_lock();'), 'its whole-section save runs under the lock the pfB-DNS save and the Resolver move take');
		$this->assertSame(1, substr_count($page, 'unlock($pfb_config_lock);'), 'released after write_config()');
	}

	public function testThePageCarriesTheTwelveListenerSettingsBelowTheEnableToggleReadAndSavedThroughTheDnsSection(): void
	{
		// Given the DNS General page
		$page = self::src(self::PAGE);

		// Then its enable toggle comes first and the twelve settings follow it in order, each read from its registered home
		$after = (int) strpos($page, "'pfb_dns',");
		$this->assertGreaterThan(0, $after, 'the enable checkbox');
		foreach (self::LISTENER_FIELDS as $field) {
			$at = strpos($page, "'{$field}',", $after);
			$this->assertNotFalse($at, "the page has the {$field} control below the previous one");
			$after = $at;
			$key = pfb_dns_config_key($field);
			$read = in_array($field, self::SEEDED_FIELDS, true) ? "pfb_dns_proxy_setting('{$field}')" : "PfbConfig::read('{$key}')";
			$this->assertStringContainsString($read, $page, "{$field} is read through the gateway from its registered section");
		}

		// And the save is validated, canonicalised and written to the registered sections, under the lock the snapshot needs
		$this->assertStringContainsString('pfb_validate_dns_proxy_listeners_post(', $page, 'the twelve fields are validated');
		$this->assertStringContainsString('pfb_dns_proxy_listeners_stored(', $page, 'and stored canonically');
		$this->assertStringContainsString('PfbConfig::write(pfb_dns_config_key($pfb_dns_key), $pfb_dns_value)', $page, 'into the registered local or shared section');
		$this->assertLessThan(
			(int) strpos($page, 'pfb_dns_proxy_listeners_stored('),
			(int) strpos($page, 'pfb_dns_config_lock()', (int) strpos($page, 'pfb_validate_dns_proxy_listeners_post(')),
			'the save takes the lock before anything is stored'
		);
	}


	public function testTheDnsNameInputFollowsTheCertificateSelectorDirectly(): void
	{
		// Given the page, in which the DNS Name is DDR's target and the name the certificate must cover (issue #3694)
		$page = self::src(self::PAGE);
		$this->assertSame(1, preg_match('/new Form_Select\(\s*\'pfb_dns_sslcertref\',/', $page, $selector, PREG_OFFSET_CAPTURE), 'the certificate selector');
		$cert = $selector[0][1];
		$name = (int) strpos($page, "'pfb_dns_name',", $cert);
		$this->assertGreaterThan($cert, $name, 'the DNS Name control is below the certificate selector');

		// Then nothing but the selector (or its no-certificate notice) stands between them, and the DNS Name is a text input
		$between = substr($page, $cert, $name - $cert);
		$this->assertSame(2, substr_count($between, '$section->addInput('), 'the no-certificate notice, then the DNS Name');
		$this->assertMatchesRegularExpression('/new Form_Input\(\s*\'pfb_dns_name\',\s*gettext\(\'DNS Name\'\),\s*\'text\',/', $page, 'a text input labelled DNS Name');
	}

	public function testThePageSanitizesTheDnsNameAtIngestionOnlyWhenItIsText(): void
	{
		$page = self::src(self::PAGE);

		// An array post stays as posted for the validator to refuse: casting it would raise a PHP warning
		$found = preg_match('/if \(is_string\(\$_POST\[\'pfb_dns_name\'\] \?\? \'\'\)\) \{\s*\$_POST\[\'pfb_dns_name\'\] = pfb_sanitize_text\(\(string\) \(\$_POST\[\'pfb_dns_name\'\] \?\? \'\'\)\);\s*\}/', $page, $guard, PREG_OFFSET_CAPTURE);
		$this->assertSame(1, $found, 'the name is sanitized once, and only when it is text');
		$this->assertLessThan((int) strpos($page, 'pfb_validate_dns_proxy_listeners_post('), $guard[0][1] ?? PHP_INT_MAX, 'before anything evaluates it');
	}

	public function testAFailedSaveBringsBackTheSubmittedDdrFields(): void
	{
		$page = self::src(self::PAGE);

		// The page restores each scalar field the form posted from $_POST when the save fails
		$found = preg_match('/foreach \(array\(([^)]*)\) as \$pfb_dns_field\) \{\s*\$pconfig\[\$pfb_dns_field\] = \$_POST\[\$pfb_dns_field\] \?\? \'\';/', $page, $restore);

		$this->assertSame(1, $found, 'the page restores its scalar fields on an input error');
		foreach ([...self::DDR_FIELDS, 'pfb_dns_dot_port6', 'pfb_dns_doh_port6', 'pfb_dns_doq_port6', 'pfb_dns_name'] as $field) {
			$this->assertStringContainsString("'{$field}'", $restore[1] ?? '', "{$field} is restored on an input error");
		}
	}

	/** Does the loop that prints the DDR certificate warnings come right after the pending-changes box, one 'warning' box per text, printed once? */
	private static function warningsFollowThePendingChangesBox(string $page): bool
	{
		return preg_match_all('/pfb_print_pending_changes_box\(\);\s*foreach \(pfb_dns_proxy_ddr_warnings\(\) as (\$\w+)\) \{\s*print_info_box\(\1, \'warning\', FALSE\);\s*\}/', $page) === 1
			&& substr_count($page, 'pfb_dns_proxy_ddr_warnings()') === 1;
	}

	public function testTheWarningsCheckSeesAMisplacedAWrongClassAnUnprintedAndADoubledLoop(): void
	{
		$loop = "foreach (pfb_dns_proxy_ddr_warnings() as \$w) {\n\tprint_info_box(\$w, 'warning', FALSE);\n}\n";

		$this->assertTrue(self::warningsFollowThePendingChangesBox("pfb_print_pending_changes_box();\n\n{$loop}"), 'the loop after the box');
		$this->assertFalse(self::warningsFollowThePendingChangesBox("{$loop}pfb_print_pending_changes_box();\n"), 'the loop before the box');
		$this->assertFalse(self::warningsFollowThePendingChangesBox("pfb_print_pending_changes_box();\n\$form = 1;\n{$loop}"), 'the loop somewhere below it');
		$this->assertFalse(self::warningsFollowThePendingChangesBox("pfb_print_pending_changes_box();\n" . str_replace("'warning'", "'success'", $loop)), 'another box class');
		$this->assertFalse(self::warningsFollowThePendingChangesBox("pfb_print_pending_changes_box();\n" . str_replace('$w, ', '"x", ', $loop)), 'a box that does not print the warning');
		$this->assertFalse(self::warningsFollowThePendingChangesBox("pfb_print_pending_changes_box();\n{$loop}{$loop}"), 'a second loop');
		$this->assertFalse(self::warningsFollowThePendingChangesBox("pfb_print_pending_changes_box();\n"), 'no loop');
	}

	public function testThePagePrintsTheDdrCertificateWarningsRightAfterThePendingChangesBox(): void
	{
		$this->assertTrue(
			self::warningsFollowThePendingChangesBox(self::src(self::PAGE)),
			'pfb_print_pending_changes_box() is followed by foreach (pfb_dns_proxy_ddr_warnings() as $w) { print_info_box($w, \'warning\', FALSE); }'
		);
	}

	/** Does the checkbox of this name carry the aria-label, on its own constructor call and no other control's? */
	private static function checkboxNamedBy(string $page, string $field, string $label): bool
	{
		return preg_match('/new Form_Checkbox\(\s*\'' . preg_quote($field, '/') . '\',(?:(?!new Form_).)*?\)\)->setAttribute\(\'aria-label\', gettext\(\'' . preg_quote($label, '/') . '\'\)\)/s', $page) === 1;
	}

	public function testTheNamedCheckboxCheckSeesAMissingAWrongAndAMisplacedLabel(): void
	{
		$head = "\$s->addInput(new Form_Checkbox('pfb_dns_ddr', gettext('DDR'), 'Enable', TRUE, 'on'))";
		$label = "->setAttribute('aria-label', gettext('DDR'))";

		$this->assertTrue(self::checkboxNamedBy("{$head}{$label}->setHelp('x');\n", 'pfb_dns_ddr', 'DDR'), 'named');
		$this->assertFalse(self::checkboxNamedBy("{$head}->setHelp('x');\n", 'pfb_dns_ddr', 'DDR'), 'no label');
		$this->assertFalse(self::checkboxNamedBy("{$head}->setAttribute('aria-label', gettext('Enable'))->setHelp('x');\n", 'pfb_dns_ddr', 'DDR'), 'another label');
		$this->assertFalse(self::checkboxNamedBy("{$head}->setHelp('x');\n\$s->addInput(new Form_Checkbox('other', 'o', 'o', TRUE, 'on')){$label};\n", 'pfb_dns_ddr', 'DDR'), 'the label on the next control');
	}

	public function testTheDdrCheckboxHasAnAccessibleNameBecauseItsGroupLabelHasNoFor(): void
	{
		$page = self::src(self::PAGE);

		$this->assertTrue(self::checkboxNamedBy($page, 'pfb_dns_ddr', 'DDR'), "the pfb_dns_ddr checkbox has aria-label gettext('DDR')");
	}

	public function testTheDohOn443SelectIsAMultipleSelectOfTheOptionsFunctionNamedForAssistiveTechnologyAndFollowsTheDdrCheckbox(): void
	{
		$page = self::src(self::PAGE);

		// Given the select that replaced the two per-family checkboxes (issue #3694): its options are the options function's, on the DoH list of the form
		$this->assertSame(1, preg_match('/\$options_ddr_doh_443 = pfb_dns_proxy_ddr_doh_443_options\(\$pconfig\[\'pfb_dns_doh_interface\'\] \?\? array\(\)\);/', $page), 'the options come from the options function, on the DoH list as posted');
		$this->assertSame(1, preg_match('/new Form_Select\(\s*\'pfb_dns_ddr_doh_443_interfaces\',\s*gettext\(\'Advertise DoH on port 443\'\),\s*\$pconfig\[\'pfb_dns_ddr_doh_443_interfaces\'\] \?\? \[\],\s*\$options_ddr_doh_443,\s*TRUE\s*\)\)([^;]*);/', $page, $select, PREG_OFFSET_CAPTURE), 'a multiple Form_Select of those options');
		$this->assertStringContainsString("setAttribute('aria-label', gettext('Advertise DoH on port 443'))", $select[1][0] ?? '', 'named for assistive technology, as the interface lists are');
		$this->assertSame(1, preg_match('/new Form_Checkbox\(\s*\'pfb_dns_ddr\',/', $page, $ddr, PREG_OFFSET_CAPTURE), 'the DDR checkbox');
		$this->assertGreaterThan($ddr[0][1], $select[0][1] ?? 0, 'the select is below the DDR checkbox');

		// And the two checkboxes and the lock that disabled one of them are gone
		foreach (['pfb_dns_ddr_doh_443_6', "'pfb_dns_ddr_doh_443'", 'pfb_dns_proxy_ddr_doh_443_locked'] as $gone) {
			$this->assertStringNotContainsString($gone, $page, "the page no longer carries {$gone}");
		}
	}

	public function testAFailedSaveBringsBackTheSubmittedDohOn443SelectionLikeTheInterfaceLists(): void
	{
		$page = self::src(self::PAGE);

		$found = preg_match('/foreach \(array\(([^)]*)\) as \$pfb_dns_field\) \{\s*\$pconfig\[\$pfb_dns_field\] = array_filter\(\(array\) \(\$_POST\[\$pfb_dns_field\] \?\? array\(\)\), \'is_string\'\);/', $page, $restore);

		$this->assertSame(1, $found, 'the page restores its interface lists on an input error');
		$this->assertStringContainsString("'" . self::DOH_443_FIELD . "'", $restore[1] ?? '', 'and the DoH 443 selection with them');
	}

	/**
	 * The top-level arguments of the one `new Form_Checkbox('<field>', ...)` call, or NULL when the page has none or several.
	 *
	 * @return list<string>|NULL
	 */
	private static function checkboxArguments(string $page, string $field): ?array
	{
		if (preg_match_all('/new Form_Checkbox\(\s*\'' . preg_quote($field, '/') . '\',/', $page, $found, PREG_OFFSET_CAPTURE) !== 1) {
			return NULL;
		}
		$args = [''];
		$depth = 0;
		$length = strlen($page);
		for ($i = $found[0][0][1] + strlen('new Form_Checkbox('); $i < $length; $i++) {
			$char = $page[$i];
			if ($char === "'") {
				$end = $i + 1;
				while ($end < $length && $page[$end] !== "'") {
					$end += ($page[$end] === '\\') ? 2 : 1;
				}
				$args[count($args) - 1] .= substr($page, $i, $end - $i + 1);
				$i = $end;
			} elseif (($char === ')' || $char === ']') && $depth === 0) {
				return array_map('trim', $args);
			} elseif ($char === ',' && $depth === 0) {
				$args[] = '';
			} else {
				$depth += ($char === '(' || $char === '[') ? 1 : (($char === ')' || $char === ']') ? -1 : 0);
				$args[count($args) - 1] .= $char;
			}
		}
		return NULL;
	}

	/** @return list<string> what is wrong with this field's checkbox: it is checked from its OWN field and carries the value 'on' */
	private static function checkboxProblems(string $page, string $field): array
	{
		$args = self::checkboxArguments($page, $field);
		if ($args === NULL) {
			return ["not exactly one new Form_Checkbox('{$field}', ...) call"];
		}
		if (count($args) !== 5) {
			return ['expected 5 arguments (name, label, text, checked, value), found ' . count($args)];
		}
		$problems = [];
		$checked = (string) preg_replace('/\s+/', ' ', $args[3]);
		$expected = "pfb_cfg_toggle_read(\$pconfig['{$field}'] ?? NULL) === PfbToggle::On";
		if ($checked !== $expected) {
			$problems[] = "checked is `{$checked}`, expected `{$expected}`";
		}
		if ($args[4] !== "'on'") {
			$problems[] = "value is `{$args[4]}`, expected `'on'`";
		}
		return $problems;
	}

	private static function checkboxFixture(string $field, string $checked, string $value, string $label = "gettext('X')"): string
	{
		return "\$s->addInput(new Form_Checkbox(\n\t'{$field}',\n\t{$label},\n\t'Enable',\n\t{$checked},\n\t{$value}\n))->setHelp('on');\n";
	}

	public function testTheCheckboxCheckSeesAWrongFieldAWrongValueAnAlwaysOffAndAMissingOrDoubledOrWidenedCall(): void
	{
		$own = "pfb_cfg_toggle_read(\$pconfig['pfb_dns_ddr'] ?? NULL) === PfbToggle::On";
		$good = self::checkboxFixture('pfb_dns_ddr', $own, "'on'");

		$this->assertSame([], self::checkboxProblems($good, 'pfb_dns_ddr'), 'a checkbox of its own field and the value on');
		$this->assertSame([], self::checkboxProblems(self::checkboxFixture('pfb_dns_ddr', $own, "'on'", "gettext('It\\'s a, (label)')"), 'pfb_dns_ddr'), 'commas, parentheses and an escaped quote in an argument');
		$this->assertNotSame([], self::checkboxProblems(self::checkboxFixture('pfb_dns_ddr', str_replace('pfb_dns_ddr', 'pfb_dns_ddr_doh_443', $own), "'on'"), 'pfb_dns_ddr'), 'checked from the other field');
		$this->assertNotSame([], self::checkboxProblems(self::checkboxFixture('pfb_dns_ddr', $own, "'yes'"), 'pfb_dns_ddr'), "the value yes");
		$this->assertNotSame([], self::checkboxProblems(self::checkboxFixture('pfb_dns_ddr', 'FALSE', "'on'"), 'pfb_dns_ddr'), 'checked always FALSE');
		$this->assertNotSame([], self::checkboxProblems(self::checkboxFixture('pfb_dns_ddr', str_replace('On', 'Off', $own), "'on'"), 'pfb_dns_ddr'), 'checked when Off');
		$this->assertNotSame([], self::checkboxProblems(self::checkboxFixture('pfb_dns_ddr', str_replace(' ?? NULL', '', $own), "'on'"), 'pfb_dns_ddr'), 'checked from a bare index');
		$this->assertNotSame([], self::checkboxProblems("\$x = 1;\n", 'pfb_dns_ddr'), 'no checkbox of that name');
		$this->assertNotSame([], self::checkboxProblems($good . $good, 'pfb_dns_ddr'), 'two checkboxes of that name');
		$this->assertNotSame([], self::checkboxProblems(str_replace("\n))", ",\n\t'extra'\n))", $good), 'pfb_dns_ddr'), 'a sixth argument');

		// The 'on' of a neighbouring checkbox must not stand in for this one's value
		$other = self::checkboxFixture('pfb_dns_ddr_doh_443', str_replace('pfb_dns_ddr', 'pfb_dns_ddr_doh_443', $own), "'on'");
		$yes = self::checkboxFixture('pfb_dns_ddr', $own, "'yes'");
		$this->assertNotSame([], self::checkboxProblems($yes . $other, 'pfb_dns_ddr'), 'the neighbour has the on');
		$this->assertSame([], self::checkboxProblems($yes . $other, 'pfb_dns_ddr_doh_443'), 'and is itself right');
	}

	public function testEachDdrCheckboxIsCheckedFromItsOwnFieldAndCarriesTheValueOn(): void
	{
		$page = self::src(self::PAGE);

		foreach (self::DDR_FIELDS as $field) {
			$this->assertSame([], self::checkboxProblems($page, $field), $field);
		}
	}

	public function testThePageSeedsItsListenerSettingsUnderTheLockOnLoadBeforeItReadsAny(): void
	{
		$page = self::src(self::PAGE);

		$from = 0;
		foreach ([
			'pfb_global();',
			'pfb_dns_proxy_seed_values() !== []',
			'pfb_dns_config_lock()',
			'pfb_dns_proxy_seed()',
			"write_config('[pfBlockerNG] pfB-DNS took its listener settings from the DNS Resolver')",
			'unlock(',
			'$pconfig = array();',
		] as $step) {
			$at = strpos($page, $step, $from);
			$this->assertNotFalse($at, "the load sequence has {$step} after the previous step");
			$from = $at + strlen($step);
		}
		$this->assertMatchesRegularExpression(
			'/\bfinally\s*\{\s*unlock\(/',
			substr($page, 0, (int) strpos($page, '$pconfig = array();')),
			'the seed lock is released in a finally'
		);
	}

	public function testTheDnsblPageCarriesNoneOfTheSevenSettingsAndNoCodeThatSavesThem(): void
	{
		// Given the DNSBL page, from which the settings moved
		$page = self::src('www/pfblockerng/pfblockerng_dnsbl.php');

		// Then neither the fields nor their old names nor their save code are left there
		foreach (self::LISTENER_FIELDS as $field) {
			$this->assertStringNotContainsString($field, $page, "the DNSBL page has no trace of {$field}");
		}
		foreach (['pfb_dns_proxy_do', 'pfb_validate_dns_proxy_listeners_post', 'pfb_dns_proxy_listeners_stored', 'options_dns_proxy_interface'] as $needle) {
			$this->assertStringNotContainsString($needle, $page, "the DNSBL page has no trace of {$needle}");
		}
	}

	public function testEveryDnsSubtabRowStartsWithGeneralAndKeepsAllExistingTabs(): void
	{
		foreach (['dns_general' => 'General', 'dnsbl' => 'DNSBL',
			'category' => 'DNSBL Groups', 'category_edit' => 'DNSBL Groups',
			'blacklist' => 'DNSBL Category', 'safesearch' => 'DNSBL SafeSearch'] as $suffix => $selected) {
			$path = dirname(__DIR__, 2) . "/src/usr/local/www/pfblockerng/pfblockerng_{$suffix}.php";
			$this->assertFileExists($path);
			$page = (string) file_get_contents($path);
			$this->assertSame(1, preg_match('/(\$tab_array\[\][^\n]*gettext\(\'General\'\)[^\n]*dns_general\.php[^\n]*\n)(.*?display_top_tabs)/s', $page, $row), $suffix);
			preg_match_all('/array\(gettext\(\'([^\']+)\'\),\s*([^,]+),\s*\'([^\']+)\'\)/', $row[0], $tabs, PREG_SET_ORDER);
			$this->assertSame(['General', 'DNSBL', 'DNSBL Groups', 'DNSBL Category', 'DNSBL SafeSearch'],
				array_column($tabs, 1), "{$suffix}: the row has no pfB-DNS entry");
			foreach ($tabs as $tab) {
				$this->assertSame($tab[1] === $selected, $tab[2] !== 'FALSE', "{$suffix}: {$tab[1]} selected");
			}
		}
	}

	public function testEveryPackageDnsTopTabOpensGeneral(): void
	{
		$root = dirname(__DIR__, 2) . '/src/usr/local/';
		$paths = glob($root . 'www/pfblockerng/*.php');
		$paths[] = $root . 'pkg/pfblockerng/pfblockerng_geoip.inc';
		foreach ($paths as $path) {
			foreach (explode("\n", (string) file_get_contents($path)) as $line) {
				if (str_contains($line, "array(gettext('DNS'),")) {
					$this->assertStringContainsString('/pfblockerng/pfblockerng_dns_general.php', $line, basename($path));
				}
			}
		}
	}

	public function testNoSourceStillNamesAnOldDohOrDoqSettingKey(): void
	{
		// The feature never shipped: the old names are gone from every reader, with no alias and no migration (the DoH port 443 test, issue #3694, is a function)
		$root = dirname(__DIR__, 2) . '/src';
		$found = [];
		$files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
		foreach ($files as $file) {
			if (!$file->isFile() || !preg_match('/\.(php|inc|xml|sh)$/', $file->getFilename())) {
				continue;
			}
			if (preg_match('/dnsbl\/pfb_dns_proxy_do[hq]|pfb_dns_proxy_do[hq](?!_port_443\()/', (string) file_get_contents($file->getPathname())) === 1) {
				$found[] = substr($file->getPathname(), strlen($root) + 1);
			}
		}
		$this->assertSame([], $found, 'files that still name pfb_dns_proxy_doh/doq');
	}

	public function testNoShippedSourceStillNamesTheRetiredGatewayBinary(): void
	{
		// The package ships pfb-dns (bin/<target>/pfb-dns, run through pfb_dns.sh); the single pfb_dns_gateway binary
		// never shipped, so no page, include, script or doc string in the package may still send an operator to it. The one use
		// that stays is the prefix the gateway puts on its fatal errors in dns_proxy.log (`pfb_dns_gateway: <error>`), which the
		// pfB-DNS startup check (issue #3538) matches to quote the last one: the name followed by a colon is that prefix.
		$root = dirname(__DIR__, 2) . '/src';
		$found = [];
		$files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
		foreach ($files as $file) {
			if (!$file->isFile() || !preg_match('/\.(php|inc|xml|sh|py)$/', $file->getFilename())) {
				continue;
			}
			if (preg_match('/pfb_dns_gateway(?!:)/', (string) file_get_contents($file->getPathname())) === 1) {
				$found[] = substr($file->getPathname(), strlen($root) + 1);
			}
		}
		$this->assertSame([], $found, 'files that still name pfb_dns_gateway');
	}
}
