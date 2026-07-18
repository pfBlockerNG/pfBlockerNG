<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/PfbNoPhpWarningTrait.php';

/**
 * pfblockerng_category.php's `act=update` postdata foreach (issue #1496 defect 2):
 * an invalid variable-name prefix (a key like "bogus-0", e.g. a stale/hand-edited
 * AJAX payload) hits the `else` at the "Validate Variable names" check without the
 * `continue;` its sibling guard (the "Failed Value" `!is_string($value)` check,
 * a few lines below) already has. Execution falls through to `switch ($variable)`
 * with $variable never assigned on this iteration -- an undefined-variable warning,
 * PLUS a second, garbled "Failed variable name:" error appended on top of the
 * correct "Failed Variable:" one.
 *
 * The file carries top-level execution and cannot be require()d off-appliance
 * (house precedent: CountryNetworksCountGuardTest.php, PfbOptionsHeredocMultiContinentTest.php).
 * This test eval-extracts the postdata foreach fragment VERBATIM and POSITIONALLY
 * (anchored on the foreach's own open/close braces plus the next statement's
 * comment as an end-anchor) from the real shipped source, so it drives the actual
 * fix landing in the right place rather than a hand-copied guess.
 *
 * Feature: an invalid variable-name-prefix key must short-circuit its iteration
 *          with exactly one recorded error, never fall through to an undefined
 *          $variable switch
 *
 *   Scenario: postdata key "bogus-0" (unrecognized prefix) -> no PHP warning,
 *             $input_errors has exactly the one "Failed Variable" entry
 */
final class CategoryPostdataInvalidPrefixGuardTest extends TestCase
{
	use PfbNoPhpWarningTrait;

	public static function setUpBeforeClass(): void
	{
		if (function_exists('pfb_category_postdata_oracle')) {
			return;
		}

		$path = dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_category.php';
		$src = file_get_contents($path);
		if ($src === FALSE) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_category.php');
		}

		// Anchored on the foreach's own braces (5 tabs) plus the next statement's
		// comment as an end-anchor, so only the foreach block itself is captured --
		// not the enclosing `if (!empty($post_data)...)`'s own closing brace.
		if (!preg_match(
			'/(foreach \(\$post_data as \$key => \$value\) \{.*?\n\t{5}\})\n\t{4}\}\n\n\t{4}\/\/ Save new Table order format/s',
			$src,
			$m
		)) {
			throw new RuntimeException('oracle extraction failed: the postdata foreach block was not found in pfblockerng_category.php');
		}

		eval(
			'function pfb_category_postdata_oracle(array $post_data, string $gtype, array $cron_values, array $aliaslog_values): array {'
			. ' $rowid = 0; $rowdata = array(); $input_errors = array();'
			. $m[1]
			. ' return $input_errors;'
			. ' }'
		);
	}

	public function testInvalidPrefixKeyDoesNotWarnAndRecordsExactlyOneError(): void
	{
		$cron_values = array('Never', '01hour', '02hours', '03hours', '04hours', '06hours', '08hours', '12hours', 'EveryDay', 'Weekly');
		$aliaslog_values = array('enabled', 'disabled', 'disabled_log', 'nxdomain_log', 'nxdomain');

		$input_errors = $this->assertNoPhpWarning(static function () use ($cron_values, $aliaslog_values): array {
			return pfb_category_postdata_oracle(array('bogus-0' => 'somevalue'), 'ipv4', $cron_values, $aliaslog_values);
		});

		$this->assertSame(
			array('Failed Variable: bogus'),
			$input_errors,
			'an invalid variable-name prefix must short-circuit with exactly its own error, never fall through to an undefined $variable switch'
		);
	}
}
