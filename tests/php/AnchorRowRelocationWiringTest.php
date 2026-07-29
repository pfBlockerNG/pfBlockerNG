<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1881 -- three page anchors used to be their own empty Form_StaticText rows, each
 * drawing a stray horizontal separator (every .form-group carries a theme border-bottom).
 * The issue's original "all three are dead, delete them" premise was falsified on the
 * issue: the dashboard widget builds "#Suppression"/"#Whitelist" links dynamically
 * (pfblockerng.widget.php, href=".../pfblockerng_{$d_type}.php#{$data}"), and
 * "#endofpage" is pfblockerng_log.php's own scrollIntoView() target. So the fix is
 * RELOCATION, not deletion:
 *
 *  - the widget links retarget the existing Form_Section ids
 *    (#IPv4_Suppression_customlist / #DNSBL_Whitelist_customlist -- section ids render as
 *    DOM ids, e.g. the dnsbl page's own $('#Python_Group_Policy') JS relies on that), and
 *    the two empty anchor rows are deleted;
 *  - the log page's #endofpage div moves out of the form (raw HTML after print($form)),
 *    so the scroll target survives with no .form-group around it.
 *
 * Source pins are the Tier-A coverage for pages carrying top-level render execution
 * (DnsblRegexHighlightWiringTest precedent); the visual empty-row absence and the live
 * scroll behaviour are Tier-B browser coverage.
 */
final class AnchorRowRelocationWiringTest extends TestCase
{
	private static function src(string $rel): string
	{
		$path = dirname(__DIR__, 2) . '/src/usr/local/www/' . $rel;
		$src  = file_get_contents($path);
		if ($src === false) {
			throw new RuntimeException("failed to read {$rel}");
		}
		return $src;
	}

	public function testDnsblPageNoLongerRendersTheEmptyWhitelistAnchorRow(): void
	{
		$this->assertStringNotContainsString(
			'<div id="Whitelist"></div>',
			self::src('pfblockerng/pfblockerng_dnsbl.php'),
			'expected the empty #Whitelist Form_StaticText anchor row to be gone from the DNSBL page'
		);
	}

	public function testIpPageNoLongerRendersTheEmptySuppressionAnchorRow(): void
	{
		$this->assertStringNotContainsString(
			'<div id="Suppression"></div>',
			self::src('pfblockerng/pfblockerng_ip.php'),
			'expected the empty #Suppression Form_StaticText anchor row to be gone from the IP page'
		);
	}

	public function testWidgetLinksTargetTheSectionIdsInsteadOfTheDeletedAnchors(): void
	{
		$widget = self::src('widgets/widgets/pfblockerng.widget.php');
		$this->assertStringContainsString(
			'IPv4_Suppression_customlist',
			$widget,
			'expected the widget Suppression link to target the IPv4 Suppression section id'
		);
		$this->assertStringContainsString(
			'DNSBL_Whitelist_customlist',
			$widget,
			'expected the widget Whitelist link to target the DNSBL Whitelist section id'
		);
		$this->assertStringNotContainsString(
			'.php#{$data}',
			$widget,
			'expected the raw #{$data} fragment (which produced the now-deleted #Suppression/#Whitelist anchors) to be gone'
		);
	}

	public function testLogPageEndofpageAnchorSurvivesOutsideTheForm(): void
	{
		$log = self::src('pfblockerng/pfblockerng_log.php');

		// The scroll target must still exist -- the page's own JS scrolls to it...
		$this->assertStringContainsString(
			'<div id="endofpage"></div>',
			$log,
			'expected the #endofpage scroll target to still exist on the Logs page'
		);
		$this->assertStringContainsString(
			'getElementById("endofpage")',
			$log,
			'expected the auto-scroll JS consumer of #endofpage to remain'
		);

		// ...but no longer as a Form_StaticText row inside the form: the div must render
		// AFTER print($form), where no .form-group (and thus no bordered row) wraps it.
		$divPos   = strpos($log, '<div id="endofpage"></div>');
		$printPos = strpos($log, 'print($form);');
		$this->assertNotFalse($printPos, 'expected print($form); in pfblockerng_log.php');
		$this->assertGreaterThan(
			$printPos,
			$divPos,
			'expected the #endofpage div to render after print($form) -- inside the form it is an '
			. 'empty Form_StaticText row drawing a stray separator'
		);
		// Vacuity guard for the relocation: the old in-form Form_StaticText carrier is gone.
		$this->assertSame(
			1,
			substr_count($log, '<div id="endofpage"></div>'),
			'expected exactly one #endofpage div (the relocated one) -- a leftover in-form copy would keep the stray row'
		);
	}
}
