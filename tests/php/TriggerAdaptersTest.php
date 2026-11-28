<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-43 Phase 3 — trigger API changes and deprecated verb adapters.
 *
 * pfb_verb_deprecation_warning() returns a non-empty message for the deprecated verbs and '' for
 * non-deprecated ones. The pfb_trigger_request() and pfb_req_to_hook_trigger() tests left with
 * those helpers in the Go cutover (#3977).
 */
#[CoversFunction('pfb_verb_deprecation_warning')]
final class TriggerAdaptersTest extends TestCase
{
	// -----------------------------------------------------------------------
	// pfb_verb_deprecation_warning — new pure helper (Phase 3)
	// -----------------------------------------------------------------------

	/**
	 * Deprecated verbs return a non-empty warning message containing the verb name.
	 *
	 * The verbs 'update', 'updateip', 'updatednsbl' are deprecated as string arguments to
	 * sync_package_pfblockerng(). Each must produce a distinct, non-empty deprecation string.
	 *
	 * RED before Phase 3: function undefined (fatal error).
	 */
	public function testDeprecatedVerbsHaveWarningMessages(): void
	{
		foreach (['update', 'updateip', 'updatednsbl'] as $verb) {
			$msg = pfb_verb_deprecation_warning($verb);
			$this->assertNotEmpty($msg,
				"verb '{$verb}' must produce a non-empty deprecation warning\ngot: " . json_encode($msg));
			$this->assertStringContainsString($verb, $msg,
				"deprecation warning for '{$verb}' must name the verb\ngot: " . json_encode($msg));
			$this->assertStringContainsString('DEPRECATED', $msg,
				"deprecation warning for '{$verb}' must contain 'DEPRECATED'\ngot: " . json_encode($msg));
		}
	}

	/**
	 * Non-deprecated verbs return '' (no warning).
	 *
	 * The strings 'cron', 'noupdates', '', and unknown verbs are NOT deprecated; they must
	 * return an empty string so sync_package_pfblockerng() skips the log call.
	 *
	 * RED before Phase 3: function undefined (fatal error).
	 */
	public function testNonDeprecatedVerbsHaveNoWarningMessage(): void
	{
		foreach (['cron', 'noupdates', '', 'bogus', 'CRON', 'pfb_trigger'] as $verb) {
			$msg = pfb_verb_deprecation_warning($verb);
			$this->assertSame('', $msg,
				"verb '{$verb}' must produce no deprecation warning\ngot: " . json_encode($msg));
		}
	}

	/**
	 * Each deprecated verb warning mentions its canonical replacement args.
	 *
	 * The replacement hint (e.g. 'scope=both force=false trigger=manual') must appear in
	 * the warning so operators know the new API to use.
	 */
	public function testDeprecatedVerbWarningsMentionReplacementArgs(): void
	{
		$expected_hints = [
			'update'      => 'scope=both force=false trigger=manual',
			'updateip'    => 'scope=ip force=true trigger=force',
			'updatednsbl' => 'scope=dnsbl force=true trigger=force',
		];
		foreach ($expected_hints as $verb => $hint) {
			$msg = pfb_verb_deprecation_warning($verb);
			$this->assertStringContainsString($hint, $msg,
				"deprecation warning for '{$verb}' must mention replacement '{$hint}'\ngot: " . json_encode($msg));
		}
	}
}
