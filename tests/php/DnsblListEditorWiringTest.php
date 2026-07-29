<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1875 step 2a (RED, test-first): mounting the CM6 editor on the DNSBL page's
 * five remaining plaintext-list fields (pfb_gp_bypass_list, pfb_noaaaa_list, suppression,
 * tldexclusion, tldblacklist) via a single `window.pfbCM && pfbCM.mountLists([...])` call,
 * gated by the SAME `$pfb_syntaxhl_on` boolean already established at line 38 (pinned by
 * DnsblRegexHighlightWiringTest) and living inside the SAME events.push() block as the
 * existing pfb_regex_list CM6 init.
 *
 * pfblockerng_dnsbl.php carries top-level render execution and cannot be require()d off-
 * appliance (same constraint as DnsblRegexHighlightWiringTest / FeedsUrlCompareIconRenderTest);
 * reading the real source file IS reading the render for this content -- this is the Tier-A
 * ui_render coverage for the mountLists rollout on this page.
 *
 * Split: the gate-shape / mountLists / vacuity-count assertions below are RED today (step 2b
 * has not landed -- pfbCM.mountLists( does not exist anywhere in the file yet). The five
 * Form_Textarea field pins are GREEN today by design: they pin the existing POST contract
 * (field ids/names the save handler keys off), which step 2b's client-side-only overlay must
 * not touch -- mixed red/green within this file is expected and is the point.
 */
final class DnsblListEditorWiringTest extends TestCase
{
	private static string $src;

	public static function setUpBeforeClass(): void
	{
		$path = dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php';
		$src  = file_get_contents($path);
		if ($src === false) {
			throw new RuntimeException('failed to read pfblockerng_dnsbl.php');
		}
		self::$src = $src;
	}

	public function testMountListsCallIsGatedInsideEventsPushBehindTheSyntaxHighlightBoolean(): void
	{
		// Tempered-dot gaps ((?:(?!endif).)*?), not bare .*? -- see
		// DnsblRegexHighlightWiringTest's rationale: a bare .*? can bridge past THIS gate's
		// own endif and land on a later, unrelated if($pfb_syntaxhl_on):...endif block.
		$this->assertMatchesRegularExpression(
			'#events\.push\(function\(\)\s*\{(?:(?!endif).)*?if\s*\(\s*\$pfb_syntaxhl_on\s*\)\s*:(?:(?!endif).)*?'
			. 'window\.pfbCM(?:(?!endif).)*?pfbCM\.mountLists\((?:(?!endif).)*?endif#s',
			self::$src,
			'expected a pfbCM.mountLists( call, guarded on window.pfbCM, inside the same '
			. 'events.push() block and the same if ($pfb_syntaxhl_on) gate as the existing '
			. 'pfb_regex_list CM6 init'
		);
	}

	public function testMountListsArrayContainsAllFiveTargetFieldIds(): void
	{
		// Each id must sit inside the mountLists([...]) array literal itself -- tempered-dot
		// bounded by the array's own closing bracket/paren so a match can't bridge past this
		// call onto an unrelated later array in the file.
		foreach ([
			'pfb_gp_bypass_list',
			'pfb_noaaaa_list',
			'suppression',
			'tldexclusion',
			'tldblacklist',
		] as $id) {
			$this->assertMatchesRegularExpression(
				"#pfbCM\\.mountLists\\(\\s*\\[(?:(?!\\]).)*?'" . preg_quote($id, '#') . "'(?:(?!\\]).)*?\\]\\s*\\)#s",
				self::$src,
				"expected '{$id}' inside the pfbCM.mountLists([...]) array argument"
			);
		}
	}

	/**
	 * Vacuity-safe "the rollout doesn't duplicate the existing gated emissions" proof, same
	 * rationale as DnsblRegexHighlightWiringTest::testCmRegexAssetAndFromTextareaCallEachAppearExactlyOnceInTheWholeFile.
	 * Disambiguation note: substr_count(self::$src, 'pfbCM.fromTextarea(') -- WITH the
	 * trailing '(' -- does NOT count a hypothetical 'pfbCM.fromTextareaList(' call, because
	 * the character immediately after 'fromTextarea' in that name is 'L', not '(': the
	 * literal needle fails to match at that position. The mountLists rollout is therefore
	 * free to add its own differently-named call without perturbing this count.
	 */
	public function testExistingGatedEmissionsStayExactlyOnceAfterTheRollout(): void
	{
		$this->assertSame(
			1,
			substr_count(self::$src, '<script src="vendor/codemirror/cm-regex.min.js?v='),
			'expected exactly one cm-regex.min.js <script> tag in the whole file -- the '
			. 'mountLists rollout must not add a second, unguarded include'
		);
		$this->assertSame(
			1,
			substr_count(self::$src, 'pfbCM.fromTextarea('),
			'expected exactly one pfbCM.fromTextarea( call in the whole file (the pre-existing '
			. 'pfb_regex_list init) -- see the disambiguation note in this test\'s docblock'
		);
		$this->assertSame(
			1,
			substr_count(self::$src, 'pfbCM.mountLists('),
			'expected exactly one pfbCM.mountLists( call in the whole file (the gated '
			. 'events.push init) -- a second, unguarded call would defeat the '
			. 'off-emits-nothing contract'
		);
	}

	public function testOriginalBypassListTextareaFieldIsUnchanged(): void
	{
		$this->assertMatchesRegularExpression(
			"#new Form_Textarea\\(\\s*'pfb_gp_bypass_list',#",
			self::$src,
			'expected the underlying pfb_gp_bypass_list Form_Textarea field to remain unchanged'
		);
	}

	public function testOriginalNoaaaaListTextareaFieldIsUnchanged(): void
	{
		$this->assertMatchesRegularExpression(
			"#new Form_Textarea\\(\\s*'pfb_noaaaa_list',#",
			self::$src,
			'expected the underlying pfb_noaaaa_list Form_Textarea field to remain unchanged'
		);
	}

	public function testOriginalSuppressionTextareaFieldIsUnchanged(): void
	{
		$this->assertMatchesRegularExpression(
			"#new Form_Textarea\\(\\s*'suppression',#",
			self::$src,
			'expected the underlying suppression Form_Textarea field to remain unchanged'
		);
	}

	public function testOriginalTldexclusionTextareaFieldIsUnchanged(): void
	{
		$this->assertMatchesRegularExpression(
			"#new Form_Textarea\\(\\s*'tldexclusion',#",
			self::$src,
			'expected the underlying tldexclusion Form_Textarea field to remain unchanged'
		);
	}

	public function testOriginalTldblacklistTextareaFieldIsUnchanged(): void
	{
		$this->assertMatchesRegularExpression(
			"#new Form_Textarea\\(\\s*'tldblacklist',#",
			self::$src,
			'expected the underlying tldblacklist Form_Textarea field to remain unchanged'
		);
	}
}
