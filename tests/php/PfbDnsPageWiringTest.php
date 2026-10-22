<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- pfB-DNS is a top-level pfBlockerNG tab of its own, placed directly after the DNSBL tab in every copy of
 * the tab bar (each page builds its own `$tab_array`; nothing shares one), reachable through the package privilege, and
 * the DNSBL page no longer carries the toggle.
 *
 * The tab bars are found by scanning the sources for the DNSBL tab entry, so a page that joins the package later and
 * copies the bar without the pfB-DNS entry fails here instead of silently missing the tab.
 */
final class PfbDnsPageWiringTest extends TestCase
{
	// The active flag is a literal on most pages and `$active['dnsbl']` on the two category pages.
	private const DNSBL_TAB = "/\\\$tab_array\\[\\]\\s*=\\s*array\\(gettext\\('DNSBL'\\),\\s*([^,]+),\\s*'\\/pfblockerng\\/pfblockerng_dnsbl\\.php'\\);/";
	private const DNS_TAB = "/^\\s*\\\$tab_array\\[\\]\\s*=\\s*array\\(gettext\\('pfB-DNS'\\),\\s*([A-Z]+),\\s*'\\/pfblockerng\\/pfblockerng_dns\\.php'\\);\\s*\$/";

	/** Every file that carries the main tab bar, with how many copies it holds: the 15 pages, the new one, geoip.inc twice. */
	private const TAB_BAR_COPIES = [
		'pkg/pfblockerng/pfblockerng_geoip.inc' => 2,
		'www/pfblockerng/pfblockerng_alerts.php' => 1,
		'www/pfblockerng/pfblockerng_blacklist.php' => 1,
		'www/pfblockerng/pfblockerng_category.php' => 1,
		'www/pfblockerng/pfblockerng_category_edit.php' => 1,
		'www/pfblockerng/pfblockerng_dns.php' => 1,
		'www/pfblockerng/pfblockerng_dnsbl.php' => 1,
		'www/pfblockerng/pfblockerng_edit_hooks.php' => 1,
		'www/pfblockerng/pfblockerng_feeds.php' => 1,
		'www/pfblockerng/pfblockerng_general.php' => 1,
		'www/pfblockerng/pfblockerng_hooks.php' => 1,
		'www/pfblockerng/pfblockerng_ip.php' => 1,
		'www/pfblockerng/pfblockerng_log.php' => 1,
		'www/pfblockerng/pfblockerng_safesearch.php' => 1,
		'www/pfblockerng/pfblockerng_software.php' => 1,
		'www/pfblockerng/pfblockerng_sync.php' => 1,
		'www/pfblockerng/pfblockerng_update.php' => 1,
	];

	/** The listener settings in the order the page shows them (issues #3513, #3538). */
	private const LISTENER_FIELDS = [
		'pfb_dns_interface', 'pfb_dns_sslcertref',
		'pfb_dns_dot', 'pfb_dns_dot_port', 'pfb_dns_dot_interface',
		'pfb_dns_doh', 'pfb_dns_doh_port', 'pfb_dns_doh_interface', 'pfb_dns_doh_trusted',
		'pfb_dns_doq', 'pfb_dns_doq_port', 'pfb_dns_doq_interface',
	];

	/** The DDR controls in the order the page shows them, after the DoQ section (issue #3583). */
	private const DDR_FIELDS = ['pfb_dns_ddr', 'pfb_dns_ddr_doh_443'];

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

	/** @return array<string,list<array{line:int,active:string,next:string}>> file => each DNSBL tab entry and the line after it */
	private static function dnsblTabEntries(): array
	{
		$found = [];
		foreach (array_merge(
			glob(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/*.php') ?: [],
			glob(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/*.inc') ?: []
		) as $path) {
			$lines = preg_split('/\R/', (string) file_get_contents($path)) ?: [];
			foreach ($lines as $index => $line) {
				if (preg_match(self::DNSBL_TAB, $line, $match) === 1) {
					$relative = str_replace(dirname(__DIR__, 2) . '/src/usr/local/', '', $path);
					$found[$relative][] = ['line' => $index + 1, 'active' => $match[1], 'next' => $lines[$index + 1] ?? ''];
				}
			}
		}
		ksort($found);
		return $found;
	}

	public function testEveryCopyOfTheTabBarListsPfbDnsRightAfterDnsbl(): void
	{
		$entries = self::dnsblTabEntries();

		$this->assertSame(
			self::TAB_BAR_COPIES,
			array_map('count', $entries),
			'the files (and copies per file) that carry the DNSBL tab: a new copy must carry the pfB-DNS tab too'
		);
		foreach ($entries as $file => $copies) {
			foreach ($copies as $copy) {
				$this->assertMatchesRegularExpression(
					self::DNS_TAB,
					$copy['next'],
					"{$file}:{$copy['line']}: the pfB-DNS tab follows the DNSBL tab directly"
				);
			}
		}
	}

	public function testOnlyThePfbDnsPageMarksItsOwnTabActive(): void
	{
		foreach (self::dnsblTabEntries() as $file => $copies) {
			foreach ($copies as $copy) {
				preg_match(self::DNS_TAB, $copy['next'], $next);
				$own = ($file === 'www/pfblockerng/pfblockerng_dns.php');
				$this->assertSame($own ? 'TRUE' : 'FALSE', $next[1] ?? NULL, "{$file}: the pfB-DNS tab is active only on its own page");
			}
		}
	}

	public function testThePrivilegeReachesThePage(): void
	{
		$GLOBALS['priv_list'] = [];
		require dirname(__DIR__, 2) . '/src/etc/inc/priv/pfblockerng.priv.inc';

		$this->assertContains(
			'pfblockerng/pfblockerng_dns.php*',
			$GLOBALS['priv_list']['page-firewall-pfblockerng']['match'] ?? [],
			'the package privilege matches the pfB-DNS page, or no scoped operator reaches it'
		);
		unset($GLOBALS['priv_list']);
	}

	public function testThePageCarriesTheEnableToggleAndAnExperimentalWarning(): void
	{
		$page = self::src('www/pfblockerng/pfblockerng_dns.php');

		$this->assertStringContainsString("'pfb_dns',", $page, 'the enable checkbox');
		$this->assertStringContainsString("PfbConfig::read('dns/pfb_dns')", $page, 'read through the gateway');
		$this->assertMatchesRegularExpression('/<strong>Experimental\./', $page, 'the help says so plainly, in bold');
	}

	public function testTheHelpNamesTheCustomOptionsLinesThatStopTheMove(): void
	{
		$page = self::src('www/pfblockerng/pfblockerng_dns.php');

		$this->assertStringContainsString('<code>include:</code>', $page, 'an include is named: the move refuses it');
		$this->assertStringContainsString('nothing is changed', $page, 'a refused move changes nothing, and the help says so');
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

		$this->assertSame(1, substr_count($page, '$pfb_config_lock = pfb_dns_config_lock();'), 'its whole-section save runs under the lock the pfB-DNS page and the Resolver move take');
		$this->assertSame(1, substr_count($page, 'unlock($pfb_config_lock);'), 'released after write_config()');
	}

	public function testThePageCarriesTheTwelveListenerSettingsBelowTheEnableToggleReadAndSavedThroughTheDnsSection(): void
	{
		// Given the pfB-DNS page
		$page = self::src('www/pfblockerng/pfblockerng_dns.php');

		// Then its enable toggle comes first and the twelve settings follow it in order, each read from the dns section
		$after = (int) strpos($page, "'pfb_dns',");
		$this->assertGreaterThan(0, $after, 'the enable checkbox');
		foreach (self::LISTENER_FIELDS as $field) {
			$at = strpos($page, "'{$field}',", $after);
			$this->assertNotFalse($at, "the page has the {$field} control below the previous one");
			$after = $at;
			$read = in_array($field, self::SEEDED_FIELDS, true) ? "pfb_dns_proxy_setting('{$field}')" : "PfbConfig::read('dns/{$field}')";
			$this->assertStringContainsString($read, $page, "{$field} is read through the gateway from the dns section");
		}

		// And the save is validated, canonicalised and written to the same section, under the lock the snapshot needs
		$this->assertStringContainsString('pfb_validate_dns_proxy_listeners_post(', $page, 'the twelve fields are validated');
		$this->assertStringContainsString('pfb_dns_proxy_listeners_stored(', $page, 'and stored canonically');
		$this->assertStringContainsString("PfbConfig::write('dns/' . ", $page, 'into the dns section');
		$this->assertLessThan(
			(int) strpos($page, 'pfb_dns_proxy_listeners_stored('),
			(int) strpos($page, 'pfb_dns_config_lock()', (int) strpos($page, 'pfb_validate_dns_proxy_listeners_post(')),
			'the save takes the lock before anything is stored'
		);
	}

	public function testThePageCarriesTheDdrSectionBetweenDoqAndReplyLoggingReadFromTheDnsSection(): void
	{
		// Given the pfB-DNS page
		$page = self::src('www/pfblockerng/pfblockerng_dns.php');
		$doq = strpos($page, "new Form_Section('DNS over QUIC (DoQ)')");
		$ddr = strpos($page, "new Form_Section('Discovery of Designated Resolvers (DDR)')");
		$log = strpos($page, "new Form_Section('DNS Reply Logging')");

		// Then the DDR section sits after DoQ and before DNS Reply Logging, with the DDR toggle first and the 443 toggle second
		$this->assertNotFalse($doq, 'the DoQ section');
		$this->assertNotFalse($ddr, 'the DDR section');
		$this->assertNotFalse($log, 'the DNS Reply Logging section');
		$this->assertLessThan($ddr, $doq, 'DDR comes after DoQ');
		$this->assertLessThan($log, $ddr, 'DDR comes before DNS Reply Logging');
		$section = substr($page, (int) $ddr, (int) $log - (int) $ddr);
		$after = 0;
		foreach (self::DDR_FIELDS as $field) {
			$at = strpos($section, "'{$field}',", $after);
			$this->assertNotFalse($at, "the DDR section has the {$field} control below the previous one");
			$after = $at;
			$this->assertStringContainsString("PfbConfig::read('dns/{$field}')", $page, "{$field} is read through the gateway from the dns section");
		}

		// And the controls carry the labels and help the operator sees
		foreach (["gettext('DDR')", "gettext('DoH on port 443')", "'Advertise DoH on port 443'", "'on'", '<strong>Experimental.</strong>', 'IP address SAN',
			'reverse proxy', 'no longer be reachable', 'next Update', 'Default: <strong>Disabled</strong>'] as $needle) {
			$this->assertStringContainsString($needle, $section, "the DDR section shows {$needle}");
		}
	}

	public function testAFailedSaveBringsBackTheSubmittedDdrFields(): void
	{
		$page = self::src('www/pfblockerng/pfblockerng_dns.php');

		// The page restores each scalar field the form posted from $_POST when the save fails
		$found = preg_match('/foreach \(array\(([^)]*)\) as \$pfb_dns_field\) \{\s*\$pconfig\[\$pfb_dns_field\] = \$_POST\[\$pfb_dns_field\] \?\? \'\';/', $page, $restore);

		$this->assertSame(1, $found, 'the page restores its scalar fields on an input error');
		foreach (self::DDR_FIELDS as $field) {
			$this->assertStringContainsString("'{$field}'", $restore[1] ?? '', "{$field} is restored on an input error");
		}
	}

	/** Does the restore-on-error block, right after the loop that brings back the posted scalar fields, show the STORED "DoH on port 443" toggle while the page disables that control, once? */
	private static function restoresLockedDohOn443FromStored(string $page): bool
	{
		return preg_match_all('/\$pconfig\[\$pfb_dns_field\] = \$_POST\[\$pfb_dns_field\] \?\? \'\';\s*\}\s*if \(pfb_dns_proxy_ddr_doh_443_locked\(\)\) \{\s*\$pconfig\[\'pfb_dns_ddr_doh_443\'\] = PfbConfig::read\(\'dns\/pfb_dns_ddr_doh_443\'\);[^\n]*\s*\}/', $page) === 1;
	}

	public function testTheRestoreCheckSeesAnUnguardedANegatedAPostedAWrongKeyAndAnEarlierRestore(): void
	{
		$loop = "\$pconfig[\$pfb_dns_field] = \$_POST[\$pfb_dns_field] ?? '';\n}\n";
		$restore = "if (pfb_dns_proxy_ddr_doh_443_locked()) {\n\t\$pconfig['pfb_dns_ddr_doh_443'] = PfbConfig::read('dns/pfb_dns_ddr_doh_443');\t// x\n}\n";

		$this->assertTrue(self::restoresLockedDohOn443FromStored($loop . $restore), 'the stored value restored under the lock, after the loop');
		$this->assertFalse(self::restoresLockedDohOn443FromStored($loop), 'never restored');
		$this->assertFalse(self::restoresLockedDohOn443FromStored($restore . $loop), 'restored before the loop, which then overwrites it with the empty post');
		$this->assertFalse(self::restoresLockedDohOn443FromStored($loop . str_replace('if (pfb_dns_proxy_ddr_doh_443_locked())', 'if (!pfb_dns_proxy_ddr_doh_443_locked())', $restore)), 'negated lock');
		$this->assertFalse(self::restoresLockedDohOn443FromStored($loop . str_replace('PfbConfig::read(\'dns/pfb_dns_ddr_doh_443\')', '$_POST[\'pfb_dns_ddr_doh_443\']', $restore)), 'the posted value');
		$this->assertFalse(self::restoresLockedDohOn443FromStored($loop . str_replace('dns/pfb_dns_ddr_doh_443', 'dns/pfb_dns_ddr', $restore)), 'the other toggle');
	}

	public function testAFailedSaveShowsTheStoredDohOn443ToggleWhileThePageDisablesIt(): void
	{
		$this->assertTrue(
			self::restoresLockedDohOn443FromStored(self::src('www/pfblockerng/pfblockerng_dns.php')),
			'a disabled checkbox posts nothing, so the restore must read dns/pfb_dns_ddr_doh_443 from the store while pfb_dns_proxy_ddr_doh_443_locked(), as the save keeps it'
		);
	}

	/** Is the 443 checkbox disabled exactly once, and only under the helper that says the stored DoH port is 443? */
	private static function disabledOnlyForDohPort443(string $page): bool
	{
		$guarded = preg_match_all('/if \(pfb_dns_proxy_ddr_doh_443_locked\(\)\) \{\s*\$pfb_ddr_doh_443->setAttribute\(\'disabled\', \'disabled\'\);\s*\}/', $page);
		return $guarded === 1 && substr_count($page, "\$pfb_ddr_doh_443->setAttribute('disabled'") === 1;
	}

	public function testTheDisabledCheckSeesAnUnguardedANegatedAnInlineAndADoubleDisable(): void
	{
		$guard = "if (pfb_dns_proxy_ddr_doh_443_locked()) {\n\t\$pfb_ddr_doh_443->setAttribute('disabled', 'disabled');\n}\n";

		$this->assertTrue(self::disabledOnlyForDohPort443($guard), 'the guarded disable');
		$this->assertFalse(self::disabledOnlyForDohPort443("\$pfb_ddr_doh_443->setAttribute('disabled', 'disabled');\n"), 'unguarded');
		$this->assertFalse(self::disabledOnlyForDohPort443(str_replace('if (pfb_dns_proxy_ddr_doh_443_locked())', 'if (!pfb_dns_proxy_ddr_doh_443_locked())', $guard)), 'negated guard');
		$this->assertFalse(self::disabledOnlyForDohPort443(str_replace('pfb_dns_proxy_ddr_doh_443_locked()', "pfb_dns_proxy_listener_port(PfbConfig::read('dns/pfb_dns_doh_port')) === '443'", $guard)), 'an inline condition the save does not share');
		$this->assertFalse(self::disabledOnlyForDohPort443($guard . "\$pfb_ddr_doh_443->setAttribute('disabled', 'disabled');\n"), 'disabled a second time');
		$this->assertFalse(self::disabledOnlyForDohPort443(''), 'never disabled');
	}

	public function testThePageDisablesTheDohOn443ToggleOnlyWhileTheStoredDohPortIs443(): void
	{
		$page = self::src('www/pfblockerng/pfblockerng_dns.php');

		$this->assertTrue(self::disabledOnlyForDohPort443($page), 'the 443 checkbox is disabled under the stored DoH port 443 and under nothing else');
		$this->assertStringContainsString("\$section->addInput(\$pfb_ddr_doh_443)", $page, 'and the disabled-or-not checkbox is the one added to the section');
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
			self::warningsFollowThePendingChangesBox(self::src('www/pfblockerng/pfblockerng_dns.php')),
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

	public function testTheTwoDdrCheckboxesHaveAnAccessibleNameBecauseTheirGroupLabelHasNoFor(): void
	{
		$page = self::src('www/pfblockerng/pfblockerng_dns.php');

		$this->assertTrue(self::checkboxNamedBy($page, 'pfb_dns_ddr', 'DDR'), "the pfb_dns_ddr checkbox has aria-label gettext('DDR')");
		$this->assertTrue(self::checkboxNamedBy($page, 'pfb_dns_ddr_doh_443', 'DoH on port 443'), "the pfb_dns_ddr_doh_443 checkbox has aria-label gettext('DoH on port 443')");
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
		$page = self::src('www/pfblockerng/pfblockerng_dns.php');

		foreach (self::DDR_FIELDS as $field) {
			$this->assertSame([], self::checkboxProblems($page, $field), $field);
		}
	}

	public function testThePageSeedsItsListenerSettingsUnderTheLockOnLoadBeforeItReadsAny(): void
	{
		$page = self::src('www/pfblockerng/pfblockerng_dns.php');

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

	public function testTheHelpSendsTheOperatorToTheCertificateSelectorAndNamesTheSeedAndTheMinimum(): void
	{
		$page = self::src('www/pfblockerng/pfblockerng_dns.php');

		foreach (["Requires the DNS Resolver\\'s SSL/TLS certificate", 'None selected: the Resolver', "the proxy serves DNS over TLS with the Resolver\\'s certificate instead"] as $gone) {
			$this->assertStringNotContainsString($gone, $page, "stale help: {$gone}");
		}
		foreach (['Requires the SSL/TLS Certificate selected above.', 'At least one entry is required.', 'pfB-DNS serves DNS over TLS from its own DoT settings below', 'are taken from the DNS Resolver once'] as $present) {
			$this->assertStringContainsString($present, $page, "help: {$present}");
		}
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

	public function testNoSourceStillNamesAnOldDohOrDoqSettingKey(): void
	{
		// The feature never shipped: the old names are gone from every reader, with no alias and no migration
		$root = dirname(__DIR__, 2) . '/src';
		$found = [];
		$files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
		foreach ($files as $file) {
			if (!$file->isFile() || !preg_match('/\.(php|inc|xml|sh)$/', $file->getFilename())) {
				continue;
			}
			if (preg_match('/dnsbl\/pfb_dns_proxy_do[hq]|pfb_dns_proxy_do[hq]/', (string) file_get_contents($file->getPathname())) === 1) {
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
