<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** Step3 UI contract: PSL policy controls use the gateway and exact operator language. */
final class DnsblPslPolicyUiTest extends TestCase
{
	private static function source(): string
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php');
		if ($source === FALSE) {
			throw new RuntimeException('failed to read DNSBL page');
		}
		return $source;
	}

	public function testPslLabelsAndHelpExplainPrivateBoundary(): void
	{
		$source = self::source();
		foreach ([
			'Wildcard Blocking',
			'Allow Only Selected Domain Suffixes',
			'IANA root TLDs',
			'Recognize Shared-Hosting Suffixes (PSL PRIVATE)',
			'Allow Shared-Hosting Suffixes (PSL PRIVATE)',
			'registrable',
			'suffix apex',
			'github.io',
			'private DNS',
		] as $term) {
			$this->assertStringContainsString($term, $source, "UI/help must contain '{$term}'");
		}
	}

	public function testPslControlsUseRegisteredGatewayKeysAndScopedVisibility(): void
	{
		$source = self::source();
		$this->assertStringContainsString("PfbConfig::read('dnsbl/pfb_psl_include_private')", $source);
		$this->assertStringContainsString("PfbConfig::read('dnsbl/pfb_psl_allow_private')", $source);
		$this->assertStringContainsString("PfbConfig::write('dnsbl/pfb_psl_include_private'", $source);
		$this->assertStringContainsString("PfbConfig::write('dnsbl/pfb_psl_allow_private'", $source);
		$this->assertStringContainsString("$('#tld_wildcard')", $source);
		$this->assertStringContainsString("$('#tld_allow')", $source);
		// Row-level visibility rides the page's hideCheckbox() idiom (hides the
		// whole form-group, label and help included), never a bare input hide().
		$this->assertStringContainsString("hideCheckbox('pfb_psl_include_private'", $source);
		$this->assertStringContainsString("hideCheckbox('pfb_psl_allow_private'", $source);
		$this->assertStringNotContainsString('psl-policy', $source);
		$this->assertStringNotContainsString("config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_psl_", $source);
		$this->assertStringNotContainsString("config_set_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_psl_", $source);
	}

	/**
	 * issue #2371 Step 3: the two feed-at-suffix policy selects render with their
	 * labels and all three option texts, plus the outcome-based help vocabulary.
	 */
	public function testFeedSuffixPolicySelectsRenderLabelsAndOptions(): void
	{
		$source = self::source();
		foreach ([
			'Feed entries at shared-hosting suffixes (PSL PRIVATE)',
			'Feed entries at public suffixes (ICANN)',
			'Ignore entirely',
			'Block the suffix apex only',
			'Honor list rules',
			// Runtime-effect vocabulary (issue #2371 Step 2): drop counted in the
			// reject stats; exact apex block only; honor including explicit wildcard.
			'reject stats',
			'exact suffix name is blocked',
			'explicit',
			'wildcard',
			// User-defined lists are never affected by this feed-only policy.
			'Custom List',
			'never affected',
			// Intentional whole-suffix blocking belongs in TLD Blacklist (dotted entries).
			'TLD Blacklist',
			'dotted entries',
			// PRIVATE-select-specific: PSL PRIVATE means shared domains, not private DNS.
			'github.io',
			'not private DNS',
		] as $term) {
			$this->assertStringContainsString($term, $source, "feed-suffix-policy UI must contain '{$term}'");
		}

		// The option ARRAY itself must carry all three value => label pairs: the
		// labels are also quoted in the help bullets, so a bare substring check
		// cannot see an option vanish from the <select>. Pin the array literal.
		$this->assertSame(
			1,
			preg_match('/\$psl_feed_policy_options\s*=\s*array\s*\((.*?)\);/s', $source, $optionsArray),
			'the $psl_feed_policy_options array literal must exist'
		);
		foreach ([
			"'ignore'" => "'Ignore entirely'",
			"'apex'" => "'Block the suffix apex only'",
			"'honor'" => "'Honor list rules'",
		] as $value => $label) {
			$this->assertMatchesRegularExpression(
				'/' . preg_quote($value, '/') . '\s*=>\s*' . preg_quote($label, '/') . '/',
				$optionsArray[1],
				"select option {$value} => {$label} must live in the options array itself"
			);
		}
	}

	/** Both selects are gateway-backed reads/writes; never a config_*_path bypass. */
	public function testFeedSuffixPolicySelectsUseRegisteredGatewayKeysOnly(): void
	{
		$source = self::source();
		$this->assertStringContainsString("PfbConfig::read('dnsbl/pfb_psl_feed_private_policy')", $source);
		$this->assertStringContainsString("PfbConfig::read('dnsbl/pfb_psl_feed_icann_policy')", $source);
		$this->assertStringContainsString("PfbConfig::write('dnsbl/pfb_psl_feed_private_policy'", $source);
		$this->assertStringContainsString("PfbConfig::write('dnsbl/pfb_psl_feed_icann_policy'", $source);
		$this->assertStringNotContainsString("config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_psl_feed_", $source);
		$this->assertStringNotContainsString("config_set_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_psl_feed_", $source);
	}

	/** The word "suppression" is never used anywhere on the page (issue #2371 wording rule). */
	public function testSuppressionWordNeverAppearsOnPage(): void
	{
		$source = self::source();
		$this->assertStringNotContainsStringIgnoringCase('suppression', $source);
	}

	/**
	 * POST sanitation: an unknown token must persist as Honor, never verbatim
	 * (issue #2371 Step 3 contract row 6). #993: the page's own POST/session-gated
	 * save branch has no PHPUnit harness, so the exact sanitizer binding shipped is
	 * pinned by source window here, and its behaviour is proven by driving the same
	 * real functions (pfb_filter() then PfbConfig::write(), whose write_adapter is
	 * pfb_cfg_feed_suffix_policy_write()) the page's save branch calls.
	 */
	public function testUnknownFeedSuffixPolicyTokenSanitizesToHonor(): void
	{
		$source = self::source();
		foreach ([
			'pfb_psl_feed_private_policy' => "\$psl_feed_private_policy = pfb_filter(\$_POST['pfb_psl_feed_private_policy'] ?? '', PFB_FILTER_WORD, 'dnsbl') ?: '';",
			'pfb_psl_feed_icann_policy' => "\$psl_feed_icann_policy = pfb_filter(\$_POST['pfb_psl_feed_icann_policy'] ?? '', PFB_FILTER_WORD, 'dnsbl') ?: '';",
		] as $bare => $needle) {
			$this->assertStringContainsString($needle, $source, "{$bare}: sanitizer binding missing");
			$this->assertStringContainsString("PfbConfig::write('dnsbl/{$bare}', \${$this->postVarFor($bare)})", $source, "{$bare}: gateway write missing");
		}

		// Behaviour: drive the exact chain the save binding invokes.
		$GLOBALS['config'] = [];
		$hostile = pfb_filter('bogus', PFB_FILTER_WORD, 'dnsbl') ?: '';
		$this->assertSame('bogus', $hostile, 'precondition: PFB_FILTER_WORD accepts the word-shaped hostile token');

		PfbConfig::write('dnsbl/pfb_psl_feed_private_policy', $hostile);
		PfbConfig::write('dnsbl/pfb_psl_feed_icann_policy', $hostile);

		$this->assertSame(PfbFeedSuffixPolicy::Honor, PfbConfig::read('dnsbl/pfb_psl_feed_private_policy'));
		$this->assertSame(PfbFeedSuffixPolicy::Honor, PfbConfig::read('dnsbl/pfb_psl_feed_icann_policy'));
		$this->assertSame(
			'honor',
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_psl_feed_private_policy')
		);
		$this->assertSame(
			'honor',
			config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/pfb_psl_feed_icann_policy')
		);
	}

	/** The page's local sanitized-variable name for a given registered field. */
	private function postVarFor(string $bare): string
	{
		return $bare === 'pfb_psl_feed_private_policy' ? 'psl_feed_private_policy' : 'psl_feed_icann_policy';
	}
}
