<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Issue #1651 — the wizard "do not show this again" persist must never run on
 * a plain GET. csrf-magic validates only POSTs, so general.php's old
 * `?wizard=disable` handler (config_set_path + write_config straight from
 * $_GET) was a CSRF-forgeable state change: any attacker page could make an
 * authenticated admin's browser flip `pfb_wizard_skip`. The persist belongs in
 * the setup wizard's csrf-magic-validated POST handler (pfb_wizard_skip_check
 * -> pfb_wizard_persist_disable), leaving the ?wizard= GET on general.php
 * state-free.
 *
 * pfblockerng_general.php is a page (top-level execution) and cannot be
 * require()d off-appliance, so its wizard controller section is eval-extracted
 * VERBATIM between two stable anchors (the WidgetSubmitPostGuardTest idiom) —
 * no reimplementation. pfb_wizard_persist_disable() itself is loaded by the
 * bootstrap's wizard-function eval (pfblockerng_wizard.inc).
 */
final class WizardDisableCsrfTest extends TestCase
{
	/** Saved globals, restored in tearDown (issue #1063 hygiene). */
	private array $savedConfig = [];
	private array $savedGet = [];
	private array $savedWrites = [];

	public static function setUpBeforeClass(): void
	{
		if (function_exists('pfb_test_general_wizard_controller')) {
			return;
		}
		$src = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_general.php'
		);
		if ($src === false) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_general.php');
		}
		$start = strpos($src, "\n\$wizard_action = pfb_wizard_get_action");
		$end   = strpos($src, "\n\$pfb['gconfig']");
		if ($start === false || $end === false || $end <= $start) {
			throw new RuntimeException('test bootstrap: wizard controller section not found in pfblockerng_general.php');
		}
		// $pfb_wizard enters the section TRUE (general.php:31); return it so the
		// tests can assert the auto-launch decision alongside the (absent) writes.
		eval(
			'function pfb_test_general_wizard_controller(): bool { $pfb_wizard = TRUE; '
			. substr($src, $start + 1, $end - $start - 1)
			. ' return $pfb_wizard; }'
		);
	}

	protected function setUp(): void
	{
		$this->savedConfig = $GLOBALS['config'] ?? [];
		$this->savedGet    = $_GET;
		$this->savedWrites = $GLOBALS['pfb_test_write_config_calls'] ?? [];
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = $this->savedConfig;
		$_GET              = $this->savedGet;
		$GLOBALS['pfb_test_write_config_calls'] = $this->savedWrites;
	}

	/**
	 * Scenario: cross-site GET of general.php?wizard=disable (issue #1651).
	 *
	 * Given:  a fresh config with no pfb_wizard_skip flag persisted
	 * When:   the general.php wizard controller runs with $_GET['wizard']='disable'
	 * Then:   the flag stays unset and write_config() is never called — csrf-magic
	 *         cannot protect a GET, so the GET path must be state-free
	 */
	public function testWizardDisableGetIsStateFree(): void
	{
		$_GET = ['wizard' => 'disable'];

		pfb_test_general_wizard_controller();

		$this->assertNull(
			config_get_path('installedpackages/pfblockerng/pfb_wizard_skip'),
			'a plain GET must not persist pfb_wizard_skip (CSRF-forgeable state-changing GET)'
		);
		$this->assertSame(
			[],
			$GLOBALS['pfb_test_write_config_calls'],
			'a plain GET must not call write_config()'
		);
	}

	/**
	 * Scenario: the session-only ?wizard=skip GET keeps working, still state-free.
	 *
	 * Given:  a fresh config with no pfb_wizard_skip flag persisted
	 * When:   the general.php wizard controller runs with $_GET['wizard']='skip'
	 * Then:   the auto-launch is suppressed for THIS request only — nothing is
	 *         persisted and write_config() is never called
	 */
	public function testWizardSkipGetSuppressesThisRequestOnly(): void
	{
		$_GET = ['wizard' => 'skip'];

		$autolaunch = pfb_test_general_wizard_controller();

		$this->assertFalse($autolaunch, '?wizard=skip must still suppress the wizard auto-launch this request');
		$this->assertNull(
			config_get_path('installedpackages/pfblockerng/pfb_wizard_skip'),
			'?wizard=skip is session-only and must persist nothing'
		);
		$this->assertSame(
			[],
			$GLOBALS['pfb_test_write_config_calls'],
			'?wizard=skip must not call write_config()'
		);
	}

	/**
	 * Scenario: the corrected POST path persists the "do not show this again" choice.
	 *
	 * Given:  a fresh config with no pfb_wizard_skip flag persisted
	 * When:   pfb_wizard_persist_disable('disable') runs (as pfb_wizard_skip_check
	 *         calls it inside the wizard's csrf-magic-validated POST)
	 * Then:   pfb_wizard_skip is 'on' and exactly one write_config() persisted it
	 */
	public function testPostPathDisablePersistsFlag(): void
	{
		$GLOBALS['config']['pfblockerng_wizard'] = [
			'step2' => ['inbound_interface' => 'lan'],
		];

		pfb_wizard_persist_disable('disable');

		$this->assertSame(
			'on',
			config_get_path('installedpackages/pfblockerng/pfb_wizard_skip'),
			'the wizard POST path must persist pfb_wizard_skip'
		);
		$this->assertNull(
			config_get_path('pfblockerng_wizard'),
			'the persisted disable choice must remove the temporary wizard config'
		);
		$this->assertCount(
			1,
			$GLOBALS['pfb_test_write_config_calls'],
			'the wizard POST path must persist via exactly one write_config()'
		);
	}

	/**
	 * Scenario: a plain Skip (checkbox unticked) stays session-only on the POST path.
	 *
	 * Given:  a fresh config with no pfb_wizard_skip flag persisted
	 * When:   pfb_wizard_persist_disable('skip') runs
	 * Then:   nothing is persisted and write_config() is never called
	 */
	public function testPostPathSkipPersistsNothing(): void
	{
		pfb_wizard_persist_disable('skip');

		$this->assertNull(
			config_get_path('installedpackages/pfblockerng/pfb_wizard_skip'),
			'a session-only skip must not persist the flag'
		);
		$this->assertSame(
			[],
			$GLOBALS['pfb_test_write_config_calls'],
			'a session-only skip must not call write_config()'
		);
	}
}
