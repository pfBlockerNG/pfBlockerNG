<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Pin the grouping behaviour of pfb_dnsbl_feed_group_cell() — the DNSBL/Unified
 * analogue of pfb_ip_feed_match_cell(): when a domain was previously blocked by a
 * different feed AND a different group the cell groups output by record (struck
 * previous pair first, then current pair); when only one has a previous value the
 * per-field layout is preserved.
 *
 * The function under test is loaded off-appliance via the same eval-extract
 * technique as AlertsFeedMatchCellGroupingTest: the alerts page source is read,
 * require_once() lines stripped, and only the function block eval'd.
 */
#[CoversFunction('pfb_dnsbl_feed_group_cell')]
final class AlertsDnsblFeedGroupCellGroupingTest extends TestCase
{
    public static function setUpBeforeClass(): void
    {
        if (function_exists('pfb_dnsbl_feed_group_cell')) {
            return;
        }
        $src = file_get_contents(
            dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_alerts.php'
        );
        if ($src === false) {
            throw new RuntimeException('failed to read pfblockerng_alerts.php');
        }
        $src = preg_replace('/^\s*require_once\(.*\);\s*$/m', '', $src);
        $start = strpos($src, "\nfunction ");
        $end   = strpos($src, "\n\$pgtitle = ");
        if ($start === false || $end === false || $end <= $start) {
            throw new RuntimeException('could not locate the function block in pfblockerng_alerts.php');
        }
        eval("\n" . substr($src, $start + 1, $end - $start - 1));
    }

    /**
     * No previous detection — both current values render at their normal sizes
     * (feed, then group in <small>) with no struck markup.
     */
    public function test_no_previous_renders_feed_then_group_in_small(): void
    {
        $result = pfb_dnsbl_feed_group_cell('', 'StevenBlack', '', 'Malicious');

        $this->assertSame('StevenBlack<br /><small>Malicious</small>', $result);
    }

    /**
     * Only the feed had a previous value — per-field layout: struck previous
     * feed, current feed, then the (unchanged) group wrapped in <small>.
     */
    public function test_only_feed_previous_shows_struck_prev_feed_then_cur_feed_then_group(): void
    {
        $result = pfb_dnsbl_feed_group_cell('OISD_Big', 'StevenBlack', '', 'Malicious');

        $this->assertSame(
            '<s>OISD_Big</s><br />StevenBlack<br /><small>Malicious</small>',
            $result
        );
    }

    /**
     * Only the group had a previous value — per-field layout: current feed at
     * normal size, then struck previous group followed by current group, both
     * inside <small>.
     */
    public function test_only_group_previous_shows_feed_then_struck_prev_group_and_cur_group(): void
    {
        $result = pfb_dnsbl_feed_group_cell('', 'StevenBlack', 'Ads', 'Malicious');

        $this->assertSame(
            'StevenBlack<br /><small><s>Ads</s><br />Malicious</small>',
            $result
        );
    }

    /**
     * Both feed and group had a previous value — groups by RECORD, not by field.
     *
     * Scenario: a domain re-detected under a different feed in a different group.
     *   Background:
     *     Given a domain previously blocked by OISD_Big in group Ads
     *     And now blocked by StevenBlack in group Malicious
     *
     *   When pfb_dnsbl_feed_group_cell is called with both previous values non-empty
     *
     *   Then the output groups by record: struck previous pair first, current pair
     *     second. The struck previous group (<s>Ads</s>) must appear BEFORE the
     *     current feed (StevenBlack) — proving the by-record grouping and
     *     distinguishing it from the old per-field layout (which placed StevenBlack
     *     before <s>Ads</s>).
     */
    public function test_both_previous_groups_by_record_struck_previous_pair_before_current_pair(): void
    {
        // Given / When
        $result = pfb_dnsbl_feed_group_cell('OISD_Big', 'StevenBlack', 'Ads', 'Malicious');

        // Then — full expected string (by-record grouping)
        $expected = '<s>OISD_Big</s><br /><small><s>Ads</s></small><br />StevenBlack<br /><small>Malicious</small>';
        $this->assertSame($expected, $result);

        // Structural proof: the struck previous group must come BEFORE the current
        // feed, so this assertion would FAIL on the old per-field layout where
        // StevenBlack appeared before <s>Ads</s>.
        $posStruckGroup = strpos($result, '<s>Ads</s>');
        $posCurrentFeed = strpos($result, 'StevenBlack');
        $this->assertNotFalse($posStruckGroup, 'struck previous group must be present');
        $this->assertNotFalse($posCurrentFeed, 'current feed must be present');
        $this->assertLessThan(
            $posCurrentFeed,
            $posStruckGroup,
            'struck previous group must appear before current feed (by-record grouping)'
        );
    }
}
