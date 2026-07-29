<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1875 step 2a (RED, test-first): mounting the CM6 editor on the Category-Edit
 * page's custom-list field (custom), gated by the same `$pfb_syntaxhl_on` boolean idiom
 * pfblockerng_dnsbl.php already establishes
 * (`PfbConfig::read('pfb_syntax_highlight') === PfbLenient::On`).
 *
 * pfblockerng_category_edit.php has NO $pfb_syntaxhl_on boolean and NO cm-regex.min.js
 * include today (verified this session); the pre-existing events.push(function() {...})
 * block at ~line 1815 only wires source-row drag-reorder/add/delete, unrelated to CM6.
 * Step 2b must add the boolean, the gated script include, and the gated mountLists init
 * inside that SAME events.push() block.
 *
 * pfblockerng_category_edit.php carries top-level render execution and cannot be
 * require()d off-appliance (same constraint as CategoryEditReservedHeaderTest /
 * DnsblRegexHighlightWiringTest); reading the real source file IS reading the render for
 * this content -- this is the Tier-A ui_render coverage for this page's rollout.
 *
 * Split: every wiring assertion below is RED today (none of it exists yet). The
 * Form_Textarea field pin is GREEN today by design: it pins the existing POST contract,
 * which step 2b's client-side-only overlay must not touch -- mixed red/green within this
 * file is expected and is the point.
 */
final class CategoryEditCustomEditorWiringTest extends TestCase
{
	private static string $src;

	public static function setUpBeforeClass(): void
	{
		$path = dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_category_edit.php';
		$src  = file_get_contents($path);
		if ($src === false) {
			throw new RuntimeException('failed to read pfblockerng_category_edit.php');
		}
		self::$src = $src;
	}

	public function testGatingBooleanReadsThePfbSyntaxHighlightToggle(): void
	{
		// LENIENT, not PfbToggle -- same rationale as DnsblRegexHighlightWiringTest's
		// class docblock.
		$this->assertMatchesRegularExpression(
			"#\\\$pfb_syntaxhl_on\\s*=\\s*\\(?\\s*PfbConfig::read\\(\\s*'pfb_syntax_highlight'\\s*\\)\\s*===\\s*PfbLenient::On#",
			self::$src,
			'expected a $pfb_syntaxhl_on boolean derived from PfbConfig::read(\'pfb_syntax_highlight\') === PfbLenient::On'
		);
	}

	public function testCmRegexScriptIsIncludedWithCacheBustingInsideTheGate(): void
	{
		// Tempered-dot gaps ((?:(?!endif).)*?), not bare .*? -- see
		// DnsblRegexHighlightWiringTest's rationale for why bare .*? risks bridging past
		// this gate's own endif.
		$this->assertMatchesRegularExpression(
			'#if\s*\(\s*\$pfb_syntaxhl_on\s*\)\s*:(?:(?!endif).)*?'
			. '<script src="vendor/codemirror/cm-regex\.min\.js\?v=<\?=pfb_file_mtime\(\'/usr/local/www/pfblockerng/vendor/codemirror/cm-regex\.min\.js\'\)\?>"></script>'
			. '(?:(?!endif).)*?endif#s',
			self::$src,
			'expected the cm-regex.min.js include, with mtime cache-busting, wrapped inside an if ($pfb_syntaxhl_on) gate'
		);
	}

	public function testMountListsCallIsGatedInsideEventsPushBehindTheSyntaxHighlightBoolean(): void
	{
		$this->assertMatchesRegularExpression(
			'#events\.push\(function\(\)\s*\{(?:(?!endif).)*?if\s*\(\s*\$pfb_syntaxhl_on\s*\)\s*:(?:(?!endif).)*?'
			. 'window\.pfbCM(?:(?!endif).)*?pfbCM\.mountLists\((?:(?!endif).)*?endif#s',
			self::$src,
			'expected a pfbCM.mountLists( call, guarded on window.pfbCM, inside the '
			. 'existing events.push() block gated by if ($pfb_syntaxhl_on)'
		);
	}

	public function testMountListsArrayContainsTheTargetFieldId(): void
	{
		$this->assertMatchesRegularExpression(
			"#pfbCM\\.mountLists\\(\\s*\\[(?:(?!\\]).)*?'custom'(?:(?!\\]).)*?\\]\\s*\\)#s",
			self::$src,
			"expected 'custom' inside the pfbCM.mountLists([...]) array argument"
		);
	}

	/**
	 * Vacuity-safe "off emits nothing new" proof, same rationale as
	 * DnsblRegexHighlightWiringTest::testCmRegexAssetAndFromTextareaCallEachAppearExactlyOnceInTheWholeFile.
	 */
	public function testCmRegexAssetAndMountListsCallEachAppearExactlyOnceInTheWholeFile(): void
	{
		$this->assertSame(
			1,
			substr_count(self::$src, '<script src="vendor/codemirror/cm-regex.min.js?v='),
			'expected exactly one cm-regex.min.js <script> tag in the whole file (the gated include) -- '
			. 'a second, unguarded <script> tag would defeat the off-emits-nothing contract'
		);
		$this->assertSame(
			1,
			substr_count(self::$src, 'pfbCM.mountLists('),
			'expected exactly one pfbCM.mountLists( call in the whole file (the gated events.push init) -- '
			. 'a second, unguarded call would defeat the off-emits-nothing contract'
		);
	}

	public function testOriginalCustomTextareaFieldIsUnchanged(): void
	{
		$this->assertMatchesRegularExpression(
			"#new Form_Textarea\\(\\s*'custom',#",
			self::$src,
			'expected the underlying custom Form_Textarea field to remain unchanged'
		);
	}
}
