<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Issue #1064 — the widget's pfb_submit branch must tolerate a POST with
 * per-field keys omitted: the outer isset($_POST['pfb_submit']) gates the
 * branch, not the keys, and a crafted POST (or a normal save with a checkbox
 * unchecked — an unchecked checkbox posts no key) raised one PHP 8.3
 * "Undefined array key" warning per missing field.
 *
 * Like PfbWidgetOracleTest, the widget file carries top-level page execution
 * and cannot be require()d off-appliance, so this eval-extracts the REAL
 * per-field section of the pfb_submit branch verbatim (up to the cron
 * section, whose comment is the unique end-anchor) — no reimplementation.
 */
final class WidgetSubmitPostGuardTest extends TestCase
{
	/** Saved globals, restored in tearDown (issue #1063 hygiene). */
	private mixed $savedPfb = null;
	private array $savedPost = [];

	public static function setUpBeforeClass(): void
	{
		$src = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/widgets/widgets/pfblockerng.widget.php'
		);
		if ($src === false) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng.widget.php');
		}

		if (!function_exists('pfb_widget_oracle_submit')) {
			if (!preg_match(
				'/pfb_widget_post_allowed\(\$_SERVER\)\) \{\n(.*?)(?=\n\n\t\t\/\/ Define pfBlockerNG clear)/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: pfb_submit per-field section not found in widget source');
			}
			eval(
				'function pfb_widget_oracle_submit(): array { global $pfb; ' . $m[1]
				. ' return $pfb[\'wglobal\'] ?? []; }'
			);
		}
	}

	protected function setUp(): void
	{
		global $pfb;
		$this->savedPfb  = $pfb ?? null;
		$this->savedPost = $_POST;
		$pfb['wglobal']    = [];
		$pfb['dnsblquery'] = '60';
	}

	protected function tearDown(): void
	{
		global $pfb;
		$pfb   = $this->savedPfb;
		$_POST = $this->savedPost;
	}

	/** Run the extracted section, returning every PHP warning message it raised. */
	private function runSubmit(array $post): array
	{
		$_POST = $post;
		$warnings = [];
		set_error_handler(
			static function (int $errno, string $errstr) use (&$warnings): bool {
				$warnings[] = $errstr;
				return true;
			},
			E_WARNING | E_NOTICE
		);
		try {
			pfb_widget_oracle_submit();
		} finally {
			restore_error_handler();
		}
		return $warnings;
	}

	/**
	 * Scenario: crafted POST carrying only the submit marker.
	 *
	 * Given:  $_POST holding pfb_submit and none of the per-field keys
	 * When:   the pfb_submit per-field section runs
	 * Then:   no "Undefined array key" warning is raised for any field
	 */
	public function testCraftedPostMissingAllFieldsRaisesNoWarnings(): void
	{
		$warnings = $this->runSubmit(['pfb_submit' => 'save']);

		$undefined = array_values(array_filter(
			$warnings,
			static fn (string $w): bool => str_contains($w, 'Undefined array key')
		));
		$this->assertSame(
			[],
			$undefined,
			'per-field $_POST reads must tolerate omitted keys; got: ' . var_export($undefined, TRUE)
		);
	}

	/**
	 * Scenario: full well-formed POST still applies every field.
	 *
	 * Given:  $_POST holding pfb_submit plus every per-field key with a valid value
	 * When:   the pfb_submit per-field section runs
	 * Then:   each widget-* setting reflects the posted value (the ?? '' guards
	 *         must not swallow present fields)
	 */
	public function testFullPostStillAppliesValues(): void
	{
		$this->runSubmit([
			'pfb_submit'     => 'save',
			'pfb_popup'      => 'on',
			'pfb_sortmix'    => 'on',
			'pfb_show_agg'   => 'on',
			'pfb_sortcolumn' => 'alias',
			'pfb_sortdir'    => 'asc',
			'pfb_clearip'    => 'daily',
			'pfb_cleardnsbl' => 'weekly',
			'pfb_dnsblquery' => '60',
			'pfb_maxfails'   => '5',
			'pfb_maxheight'  => '200',
		]);

		global $pfb;
		$expected = [
			'widget-popup'      => 'on',
			'widget-sortmix'    => 'on',
			'widget-show_agg'   => 'on',
			'widget-sortcolumn' => 'alias',
			'widget-sortdir'    => 'asc',
			'widget-clearip'    => 'daily',
			'widget-cleardnsbl' => 'weekly',
			'widget-dnsblquery' => '60',
			'widget-maxfails'   => '5',
			'widget-maxheight'  => '200',
		];
		foreach ($expected as $key => $value) {
			$this->assertSame(
				$value,
				$pfb['wglobal'][$key] ?? null,
				"widget setting {$key} must reflect the posted value"
			);
		}
	}
}
