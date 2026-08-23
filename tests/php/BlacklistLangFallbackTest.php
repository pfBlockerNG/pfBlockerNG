<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1777: pfblockerng_blacklist.php's per-category language render
 * (:485/:516) reads $info[$pconfig['blacklist_lang']][1]/[0] directly. Most
 * *_global_usage providers carry a DESC line (index [0]) only for a subset of
 * languages (e.g. DE/IT/NL/ES/RU are frequently NAME-only, no DESC, for a
 * given category) -- an absent index raises an "Undefined array key"
 * diagnostic on every affected category/language combination, and the
 * pre-existing `?:` fallback to EN silently degrades to warn-then-fall-back
 * instead of a clean read.
 *
 * Both target expressions -- and the real parse loop that BUILDS $info
 * (:456-481) -- are eval-extracted VERBATIM from the real shipped page
 * source and exercised against the REAL shipped src/usr/local/pkg/
 * pfblockerng/ut1_global_usage provider file (dependency-free: no Form_*
 * pfSense UI classes are needed, since only the two bare expressions are
 * extracted, not the Form_Group/Form_Checkbox rendering around them).
 *
 * The fix restructures the read into `$l = $info[lang] ?? array(); $e =
 * $info['EN'] ?? array();` followed by `($l[i] ?? '') ?: ($e[i] ?? '')` --
 * unlike the other #1777 sites, this is a SHAPE change (2 new lines), not an
 * in-place `?? ''` insertion, so the extraction anchors on stable
 * before/after markers with a free-form (non-greedy, DOTALL) middle instead
 * of a single-line RHS pattern -- it captures 0 extra lines pre-fix and 2
 * post-fix, so the same regex (and this file) is red before the fix and
 * green after, unchanged.
 */
final class BlacklistLangFallbackTest extends TestCase
{
	private const BLACKLIST_PHP = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_blacklist.php';
	private const UT1_FILE = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/ut1_global_usage';
	private static string $parseRegion;

	/** Matches pfblockerng_blacklist.php's own $options_blacklist_lang (:143-144). */
	private const LANGS = ['EN', 'DE', 'FR', 'IT', 'NL', 'PT', 'ES', 'RU'];

	public static function setUpBeforeClass(): void
	{
		$src = file_get_contents(self::BLACKLIST_PHP);
		if ($src === FALSE) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_blacklist.php');
		}

		if (!function_exists('pfb_blacklist_oracle_parse_data')) {
			if (!preg_match(
				'/((?:\$data\s*=\s*array\(\);\n).*?\n\tksort\(\$data, SORT_NATURAL\);\n)/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: blacklist category/description parse block not found');
			}
			self::$parseRegion = $m[1];
			eval(
				'function pfb_blacklist_oracle_parse_data(array $contents): array {'
				. ' $type = \'x\'; $blacklist_types = [\'x\' => [\'CONTENTS\' => $contents]];'
				. $m[1]
				. ' return $data; }'
			);
		}

		if (!function_exists('pfb_blacklist_oracle_lang_fallback')) {
			if (!preg_match(
				'/foreach \(\$data as \$category => \$info\) \{\n(.*?\$category_lang = [^\n]*;\n)/s',
				$src,
				$m1
			)) {
				throw new RuntimeException('test bootstrap: $category_lang block not found');
			}
			// The SECOND Form_StaticText() call (identified by its ->setWidth(7)
			// suffix -- the first, using $category_lang, has none) wraps the
			// NAME-index (:0) expression as its bare 2nd constructor argument.
			if (!preg_match(
				'/Form_StaticText\(\s*\n\s*\'\',\s*\n\s*((?:(?!Form_StaticText).)*?)\n\s*\)\)->setWidth\(7\);/s',
				$src,
				$m2
			)) {
				throw new RuntimeException('test bootstrap: NAME-index Form_StaticText expression not found');
			}
			eval(
				'function pfb_blacklist_oracle_lang_fallback(array $info, string $lang): array {'
				. ' $pconfig = [\'blacklist_lang\' => $lang];'
				. $m1[1]
				. ' $name_lang = ' . $m2[1] . ';'
				. ' return [$category_lang, $name_lang]; }'
			);
		}
	}

	/**
	 * issue #2636: the shipped UT1 provider fetches over an authenticated transport.
	 *
	 * The feed URL decides how a blocklist archive reaches the firewall, and FTP
	 * neither authenticates the server nor protects the payload. Nothing else in the
	 * suite reads the shipped FEED line -- the live-VM case drives a mock origin -- so
	 * a revert to ftp:// would otherwise pass every gate.
	 */
	public function testShippedUt1FeedUsesHttps(): void
	{
		$raw = file(self::UT1_FILE, FILE_SKIP_EMPTY_LINES | FILE_IGNORE_NEW_LINES);
		$this->assertNotFalse($raw, 'test bootstrap: failed to read ut1_global_usage');

		// Read FEED exactly as the shipped discovery loop does
		// (pfblockerng_blacklist.php): skip comments/blanks, split once on ':', trim,
		// and take the FIRST match -- a later duplicate is ignored there, so this must
		// not invent a uniqueness rule the parser does not have.
		$feed = '';
		foreach ($raw as $line) {
			$line = trim($line);
			if ($line === '' || str_starts_with($line, '#')) {
				continue;
			}
			if (strpos($line, 'FEED:') !== FALSE) {
				$feed = trim(explode(':', $line, 2)[1]);
				break;
			}
		}

		$this->assertNotSame('', $feed, 'ut1_global_usage must declare a FEED line');
		$this->assertStringStartsWith(
			'https://',
			$feed,
			"the shipped UT1 feed must be fetched over HTTPS; found: {$feed}"
		);
	}


	public function testParseExtractionStartsAtExecutableCodeNotProductionComment(): void
	{
		$this->assertStringStartsWith('$data', self::$parseRegion);
		$this->assertStringNotContainsString('Build array of Blacklist categories', self::$parseRegion);
	}

	/**
	 * Replicates the provider-discovery loop's CONTENTS filtering (:52-101,
	 * unaffected by this fix): drop comments/blanks and the metadata (TITLE/
	 * DESCR/XML/FEED/SIZE/WEBSITE/LICENSE/REG) header lines, keeping the
	 * NAME:/DESC LANG:/NAME LANG: category lines the parse loop under test reads.
	 */
	private static function loadRealProviderContents(): array
	{
		$raw = file(self::UT1_FILE, FILE_SKIP_EMPTY_LINES | FILE_IGNORE_NEW_LINES);
		if ($raw === FALSE) {
			throw new RuntimeException('test bootstrap: failed to read ut1_global_usage');
		}
		$contents = [];
		foreach ($raw as $line) {
			$trimmed = trim($line);
			if ($trimmed === '' || str_starts_with($trimmed, '#')) {
				continue;
			}
			if (preg_match('/^(TITLE|DESCR|XML|FEED|SIZE|WEBSITE|LICENSE|REG):/', $trimmed)) {
				continue;
			}
			$contents[] = $line;
		}
		return $contents;
	}

	public function testEveryCategoryAndLanguageEmitsZeroDiagnosticsAndEnFallbackHolds(): void
	{
		$data = pfb_blacklist_oracle_parse_data(self::loadRealProviderContents());
		$this->assertNotEmpty($data, 'fixture sanity: the real ut1_global_usage must parse into at least one category');

		$diagnostics = [];
		set_error_handler(static function (int $errno, string $errstr) use (&$diagnostics): bool {
			$diagnostics[] = $errstr;
			return TRUE;
		});

		$missing0Proven = FALSE;
		$missing1Proven = FALSE;
		try {
			foreach ($data as $category => $info) {
				// fixture sanity: EN must be fully populated for every real category
				// (the fallback target must itself never be the thing that's missing).
				$this->assertArrayHasKey('EN', $info, "category '{$category}' has no EN entry at all");
				$this->assertArrayHasKey(0, $info['EN'], "category '{$category}' EN has no DESC (index 0)");
				$this->assertArrayHasKey(1, $info['EN'], "category '{$category}' EN has no NAME (index 1)");

				foreach (self::LANGS as $lang) {
					[$categoryLang, $nameLang] = pfb_blacklist_oracle_lang_fallback($info, $lang);

					if (!isset($info[$lang][1])) {
						$missing1Proven = TRUE;
						$this->assertSame($info['EN'][1], $categoryLang, "category '{$category}'/{$lang}: missing index 1 must fall back to EN's NAME");
					}
					if (!isset($info[$lang][0])) {
						$missing0Proven = TRUE;
						$this->assertSame($info['EN'][0], $nameLang, "category '{$category}'/{$lang}: missing index 0 must fall back to EN's DESC");
					}
				}
			}
		} finally {
			restore_error_handler();
		}

		// fixture sanity: the real provider file must actually exercise BOTH
		// missing-index branches at least once, or the fallback assertions above
		// never ran for real.
		$this->assertTrue($missing0Proven, 'fixture sanity: no category/language combo in ut1_global_usage is missing index 0 -- the EN-DESC-fallback branch was never exercised');
		$this->assertTrue($missing1Proven, 'fixture sanity: no category/language combo in ut1_global_usage is missing index 1 -- the EN-NAME-fallback branch was never exercised');

		$undefined = array_values(array_filter(
			$diagnostics,
			static fn (string $d): bool => str_contains($d, 'Undefined array key')
		));
		$this->assertSame(
			[],
			$undefined,
			"every category/language combination in the real ut1_global_usage must emit zero 'Undefined array key' diagnostics, got "
			. count($undefined) . ' (first: ' . ($undefined[0] ?? '') . ')'
		);
	}
}
