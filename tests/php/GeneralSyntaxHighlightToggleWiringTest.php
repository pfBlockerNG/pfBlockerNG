<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1669 slice C -- General-settings `pfb_syntax_highlight` toggle wiring on
 * pfblockerng_general.php (registered in pfb_cfg_registry(), default on; gates the
 * CodeMirror 6 live-highlight overlay wired on pfblockerng_dnsbl.php -- see
 * DnsblRegexHighlightWiringTest).
 *
 * pfblockerng_general.php carries top-level render execution (require_once('guiconfig.inc')
 * et al.) and cannot be require()d/rendered off-appliance -- same constraint documented on
 * FeedsUrlCompareIconRenderTest/CategoryEditReservedHeaderTest/DnsblRegexHighlightWiringTest.
 * No prior literal-source render test exists for this page, so this one is shaped minimally
 * like DnsblRegexHighlightWiringTest. pfb_syntax_highlight is a default-on checkbox on the
 * merged PfbToggle adapter (issue #1887: Off stores the explicit 'off' token, so the
 * default-on round trip is safe), mirroring this page's existing `pfb_keep`
 * field exactly: PfbConfig::read()->value on load, an explicit 'on'/'off' ternary on save
 * (not pfb_filter(..., PFB_FILTER_ON_OFF, ...) -- pfb_keep does not use it either), and
 * pfb_cfg_toggle_read(...) === PfbToggle::On on render (merged enum, issue #1887).
 */
final class GeneralSyntaxHighlightToggleWiringTest extends TestCase
{
	private static string $src;

	public static function setUpBeforeClass(): void
	{
		$path = dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_general.php';
		$src  = file_get_contents($path);
		if ($src === false) {
			throw new RuntimeException('failed to read pfblockerng_general.php');
		}
		self::$src = $src;
	}

	public function testLoadReadsThroughThePfbConfigGateway(): void
	{
		$this->assertMatchesRegularExpression(
			"#\\\$pconfig\\['pfb_syntax_highlight'\\]\\s*=\\s*PfbConfig::read\\(\\s*'pfb_syntax_highlight'\\s*\\)->value#",
			self::$src,
			'expected $pconfig[\'pfb_syntax_highlight\'] to be loaded via PfbConfig::read(\'pfb_syntax_highlight\')->value, matching the log_syslog precedent'
		);
	}

	public function testSaveWritesAnExplicitOnOffTernaryMatchingPfbKeep(): void
	{
		// pfb_keep (the exact same default-on-checkbox shape, merged PfbToggle) saves via
		// an explicit ternary, not pfb_filter(..., PFB_FILTER_ON_OFF, ...) -- an explicit
		// 'off' write (not '') is the whole point of the explicit Off token: it must survive
		// the live config round-trip distinguishably from a never-configured install.
		$this->assertMatchesRegularExpression(
			"#\\\$pfb\\['gconfig'\\]\\['pfb_syntax_highlight'\\]\\s*=\\s*\\(\\(\\s*\\\$_POST\\['pfb_syntax_highlight'\\]\\s*\\?\\?\\s*''\\s*\\)\\s*===\\s*'on'\\s*\\)\\s*\\?\\s*'on'\\s*:\\s*'off'#",
			self::$src,
			'expected the save handler to write an explicit \'on\'/\'off\' ternary for pfb_syntax_highlight, matching the pfb_keep precedent'
		);
	}

	public function testSaveIsIncludedInTheWriteSectionCall(): void
	{
		// The field must be assigned into $pfb['gconfig'] BEFORE the writeSection() call
		// so it is actually persisted (a bare PfbConfig::write() before writeSection()
		// would be clobbered, per the log_syslog / pfb_log_trim_margin_pct precedent).
		$saveIdx    = strpos(self::$src, "\$pfb['gconfig']['pfb_syntax_highlight']");
		$sectionIdx = strpos(self::$src, "PfbConfig::writeSection('installedpackages/pfblockerng/config/0', \$pfb['gconfig'])");
		$this->assertNotFalse($saveIdx, 'expected a $pfb[\'gconfig\'][\'pfb_syntax_highlight\'] save assignment');
		$this->assertNotFalse($sectionIdx, 'expected the writeSection() call to persist the general section');
		$this->assertLessThan($sectionIdx, $saveIdx,
			'expected the pfb_syntax_highlight save assignment to happen before writeSection() persists the section');
	}

	public function testCheckboxRendersWithTheTogglePrecedentIdiom(): void
	{
		$this->assertMatchesRegularExpression(
			"#new Form_Checkbox\\(\\s*'pfb_syntax_highlight',#",
			self::$src,
			'expected a Form_Checkbox(\'pfb_syntax_highlight\', ...) field'
		);
		$this->assertMatchesRegularExpression(
			"#pfb_cfg_toggle_read\\(\\\$pconfig\\['pfb_syntax_highlight'\\]\\)\\s*===\\s*PfbToggle::On#",
			self::$src,
			'expected the checkbox\'s checked state to be pfb_cfg_toggle_read($pconfig[\'pfb_syntax_highlight\']) === PfbToggle::On'
		);
	}

	public function testHelpTextMentionsSkippingAssetsWhenDisabled(): void
	{
		$this->assertStringContainsString(
			'skips loading the editor assets',
			self::$src,
			'expected the checkbox help text to document that disabling it skips loading the editor assets'
		);
	}

	/**
	 * issue #1888: the toggle gates the whole CM6 editor -- highlighting (#1669), the
	 * lineNumbers gutter (#1869), the server + Lezer bracket lint (#1732) and undo/redo
	 * history -- so its label is the editor, not one of its features.
	 */
	public function testCheckboxIsLabelledForTheWholeEditor(): void
	{
		$this->assertMatchesRegularExpression(
			"#new Form_Checkbox\\(\\s*'pfb_syntax_highlight',\\s*'Advanced Text Editor',#",
			self::$src,
			'expected the pfb_syntax_highlight checkbox to be labelled \'Advanced Text Editor\''
		);
		$this->assertStringNotContainsString(
			"'Syntax Highlighting',",
			self::$src,
			'expected no leftover \'Syntax Highlighting\' field label'
		);
	}

	/**
	 * issue #1888: the help text must name what the editor actually provides, not
	 * highlighting alone -- each feature is wired in tools/webassets/cm-shell.js
	 * (lineNumbers, history) and cm-lint.js (lintGutter + linter). Asserted against the
	 * field's OWN setHelp() argument, never the whole page: the page's comments talk
	 * about syntax highlighting too, so a whole-source assertion would pass vacuously.
	 */
	public function testHelpTextDocumentsTheEditorFeatures(): void
	{
		$matched = preg_match(
			"#new Form_Checkbox\\(\\s*'pfb_syntax_highlight',.*?\\)\\)->setHelp\\((.*?)\\);#s",
			self::$src,
			$m
		);
		$this->assertSame(1, $matched, 'expected a setHelp() call on the pfb_syntax_highlight checkbox');
		foreach ([
			'syntax highlighting',
			'line numbers',
			'linting',
			'undo/redo',
			'list and script fields',
			'plain text boxes',
			'server-side',
		] as $feature) {
			$this->assertStringContainsString(
				$feature,
				$m[1],
				"expected the checkbox help text to document the editor's {$feature}"
			);
		}
	}
}
