<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * DNSBL tab phase 3: AdBlock suffix handling + TLD Allow list rewrite.
 *
 * Pins the section split, the tld_allow gating rewrite (hideMultiClass ->
 * section show/hide), the extracted picker help, and the issue #2371 rule that
 * the two PSL feed-policy selects must not be hide-gated after the move.
 */
final class DnsblSuffixHandlingUiTest extends TestCase
{
	private static function source(): string
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php');
		if ($source === FALSE) {
			throw new RuntimeException('failed to read DNSBL page');
		}
		return $source;
	}

	public function testDomainSuffixHandlingSectionIsCollapsedAndNeverHideGated(): void
	{
		$source = self::source();
		$this->assertMatchesRegularExpression(
			"/new Form_Section\(\s*'AdBlock suffix handling'\s*,\s*'dnsbl_suffix'\s*,\s*COLLAPSIBLE\s*\|\s*SEC_CLOSED\s*\)/",
			$source,
			'AdBlock suffix handling must be its own collapsed Form_Section with id dnsbl_suffix'
		);
		// The suffix panel itself is never .hide()d — that would bury the
		// #2371 feed-policy selects behind tld_allow / Wildcard Blocking.
		$this->assertStringNotContainsString("$('#dnsbl_suffix').hide()", $source);
		$this->assertStringNotContainsString('$("#dnsbl_suffix").hide()', $source);
	}

	public function testTldAllowPickersAreASectionShownByTldAllow(): void
	{
		$source = self::source();
		$this->assertMatchesRegularExpression(
			"/new Form_Section\(\s*'TLD Allow list'\s*,\s*'tld_allow_pickers'\s*,\s*COLLAPSIBLE\s*\|\s*SEC_CLOSED\s*\)/",
			$source,
			'TLD Allow pickers must be a Form_Section with id tld_allow_pickers'
		);

		$this->assertStringContainsString(
			"$('#tld_allow_pickers').show();",
			$source,
			'enable_tld_allow() must .show() tld_allow_pickers when tld_allow is checked'
		);
		$this->assertStringContainsString(
			"$('#tld_allow_pickers').hide();",
			$source,
			'enable_tld_allow() must .hide() tld_allow_pickers when tld_allow is unchecked'
		);
		$this->assertStringContainsString("disableInput('pfb_psl_allow_private'", $source);
	}

	public function testPfbPythonHideMultiClassAndClassAreGone(): void
	{
		$source = self::source();
		$this->assertStringNotContainsString("hideMultiClass('pfb_python'", $source);
		$this->assertStringNotContainsString("addClass('pfb_python')", $source);
	}

	public function testTldAllowHelpIsExtractedFromSetHelp(): void
	{
		$source = self::source();
		$this->assertSame(
			1,
			preg_match(
				"/new Form_Checkbox\(\s*'tld_allow'.*?->setHelp\((.*?)\);/s",
				$source,
				$help
			),
			'tld_allow Form_Checkbox setHelp() must exist'
		);
		$this->assertStringNotContainsString(
			'dnsbl_python_tld_allow_text',
			$help[1],
			'#dnsbl_python_tld_allow_text must not live inside tld_allow setHelp()'
		);
		$this->assertStringContainsString(
			'id="dnsbl_python_tld_allow_text"',
			$source,
			'extracted picker help must keep id dnsbl_python_tld_allow_text'
		);
	}

	public function testFeedPolicySelectsLiveInSuffixSectionAndStayUngated(): void
	{
		$source = self::source();
		$suffixPos = strpos($source, "new Form_Section('AdBlock suffix handling'");
		$privatePos = strpos($source, "gettext('Feed entries at shared-hosting suffixes (PSL PRIVATE)')");
		$icannPos = strpos($source, "gettext('Feed entries at public suffixes (ICANN)')");
		$globalLogPos = strpos($source, "'Global Logging/Blocking Mode'");
		$wildcardPos = strpos($source, "gettext('Wildcard Blocking')");

		$this->assertNotFalse($suffixPos, 'AdBlock suffix handling section missing');
		$this->assertNotFalse($privatePos, 'PSL PRIVATE feed-policy label missing');
		$this->assertNotFalse($icannPos, 'ICANN feed-policy label missing');
		$this->assertNotFalse($globalLogPos, 'Global Logging/Blocking Mode missing');
		$this->assertNotFalse($wildcardPos, 'Wildcard Blocking missing');

		$this->assertLessThan($globalLogPos, $wildcardPos, 'Wildcard Blocking stays in section 1 before Global Logging');
		$this->assertLessThan($suffixPos, $globalLogPos, 'section 1 (Global Logging) closes before AdBlock suffix handling');
		$this->assertLessThan($privatePos, $suffixPos, 'PSL PRIVATE feed-policy select must be added inside AdBlock suffix handling');
		$this->assertLessThan($icannPos, $suffixPos, 'ICANN feed-policy select must be added inside AdBlock suffix handling');

		// issue #2371: moving the selects into a section is fine; hide-gating them is not.
		$this->assertStringContainsString('issue #2371:', $source);
		$this->assertStringContainsString('deliberately NOT behind a hideCheckbox()', $source);
		$this->assertStringNotContainsString("hideCheckbox('pfb_psl_feed_private_policy'", $source);
		$this->assertStringNotContainsString("hideCheckbox('pfb_psl_feed_icann_policy'", $source);
		$this->assertStringNotContainsString("hideInput('pfb_psl_feed_private_policy'", $source);
		$this->assertStringNotContainsString("hideInput('pfb_psl_feed_icann_policy'", $source);
		$this->assertSame(
			2,
			substr_count($source, '. $psl_feed_policy_help'),
			'both suffix-policy selects carry the folded option list'
		);
		$this->assertStringContainsString('<div class="infoblock"><ul>', $source);
	}
}
