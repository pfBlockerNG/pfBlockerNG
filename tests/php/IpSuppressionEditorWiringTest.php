<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1875 step 2a (RED, test-first): mounting the CM6 editor on the IP page's two
 * suppression-list fields (v4suppression, v6suppression), gated by the same
 * `$pfb_syntaxhl_on` boolean idiom pfblockerng_dnsbl.php already establishes
 * (`pfb_editor_enabled()`, the issue #1887 named accessor).
 *
 * pfblockerng_ip.php has NO $pfb_syntaxhl_on boolean, NO cm-regex.min.js include, and NO
 * events.push() block at all today (verified this session) -- step 2b must introduce all
 * three from scratch on this page, unlike pfblockerng_dnsbl.php which already carries the
 * boolean and the gated script include for its pre-existing pfb_regex_list init.
 *
 * pfblockerng_ip.php carries top-level render execution and cannot be require()d off-
 * appliance (same constraint as DnsblRegexHighlightWiringTest); reading the real source file
 * IS reading the render for this content -- this is the Tier-A ui_render coverage for this
 * page's rollout.
 *
 * Split: every wiring assertion below is RED today (none of this exists yet). The two
 * Form_Textarea field pins are GREEN today by design: they pin the existing POST contract,
 * which step 2b's client-side-only overlay must not touch -- mixed red/green within this
 * file is expected and is the point.
 */
final class IpSuppressionEditorWiringTest extends TestCase
{
	private static string $src;

	public static function setUpBeforeClass(): void
	{
		$path = dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_ip.php';
		$src  = file_get_contents($path);
		if ($src === false) {
			throw new RuntimeException('failed to read pfblockerng_ip.php');
		}
		self::$src = $src;
	}

	public function testGatingBooleanReadsThePfbSyntaxHighlightToggle(): void
	{
		// LENIENT, not PfbToggle -- same rationale as DnsblRegexHighlightWiringTest's
		// class docblock (a default-on field's '' off value cannot survive the live
		// config round-trip under PfbToggle).
		$this->assertMatchesRegularExpression(
			"#\\\$pfb_syntaxhl_on\\s*=\\s*pfb_editor_enabled\\(\\)#",
			self::$src,
			'expected a $pfb_syntaxhl_on boolean derived from pfb_editor_enabled() (issue #1887 named accessor)'
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
			'expected a pfbCM.mountLists( call, guarded on window.pfbCM, inside an '
			. 'events.push() block gated by if ($pfb_syntaxhl_on)'
		);
	}

	public function testMountListsArrayContainsBothTargetFieldIds(): void
	{
		foreach (['v4suppression', 'v6suppression'] as $id) {
			$this->assertMatchesRegularExpression(
				"#pfbCM\\.mountLists\\(\\s*\\[(?:(?!\\]).)*?'" . preg_quote($id, '#') . "'(?:(?!\\]).)*?\\]\\s*\\)#s",
				self::$src,
				"expected '{$id}' inside the pfbCM.mountLists([...]) array argument"
			);
		}
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

	public function testOriginalV4suppressionTextareaFieldIsUnchanged(): void
	{
		$this->assertMatchesRegularExpression(
			"#new Form_Textarea\\(\\s*'v4suppression',#",
			self::$src,
			'expected the underlying v4suppression Form_Textarea field to remain unchanged'
		);
	}

	public function testOriginalV6suppressionTextareaFieldIsUnchanged(): void
	{
		$this->assertMatchesRegularExpression(
			"#new Form_Textarea\\(\\s*'v6suppression',#",
			self::$src,
			'expected the underlying v6suppression Form_Textarea field to remain unchanged'
		);
	}
}
