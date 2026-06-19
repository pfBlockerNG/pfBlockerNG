<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Pin the grouping behaviour of pfb_ip_feed_match_cell(): when both the feed
 * name and matched IP/CIDR were re-evaluated the cell groups output by record
 * (previous struck pair first, then current pair); when only one field changed
 * the per-field layout is preserved.
 *
 * The function under test is loaded off-appliance via the same eval-extract
 * technique as AlertsRowOutputEncodingTest: the alerts page source is read,
 * require_once() lines stripped, and only the function block eval'd.
 */
#[CoversFunction('pfb_ip_feed_match_cell')]
final class AlertsFeedMatchCellGroupingTest extends TestCase
{
    public static function setUpBeforeClass(): void
    {
        if (function_exists('pfb_ip_feed_match_cell')) {
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
     * Neither field changed — both values render at their normal sizes with no
     * struck markup.
     */
    public function test_neither_changed_renders_feed_then_match_in_small(): void
    {
        $result = pfb_ip_feed_match_cell('CINS_army_v4', '', '45.154.96.76', '');

        $this->assertSame('CINS_army_v4<br /><small>45.154.96.76</small>', $result);
    }

    /**
     * Only the feed changed — per-field layout: struck old feed, current feed,
     * then the (unchanged) match wrapped in <small>.
     */
    public function test_only_feed_changed_shows_struck_old_feed_then_new_feed_then_match(): void
    {
        $result = pfb_ip_feed_match_cell('CINS_army_v4', 'ET_Block_v4', '45.154.96.76', '');

        $this->assertSame(
            '<s>CINS_army_v4</s><br />ET_Block_v4<br /><small>45.154.96.76</small>',
            $result
        );
    }

    /**
     * Only the match changed — per-field layout: feed at normal size, then
     * struck old match followed by new match, both inside <small>.
     */
    public function test_only_match_changed_shows_feed_then_struck_old_match_and_new_match(): void
    {
        $result = pfb_ip_feed_match_cell('CINS_army_v4', '', '45.154.96.76', '45.154.96.0/24');

        $this->assertSame(
            'CINS_army_v4<br /><small><s>45.154.96.76</s><br />45.154.96.0/24</small>',
            $result
        );
    }

    /**
     * Both feed and match changed — groups by RECORD, not by field.
     *
     * Scenario: IP alert re-evaluated to a different feed and a broader CIDR.
     *   Background:
     *     Given a logged event for 45.154.96.76 matched by CINS_army_v4
     *     And a re-evaluation that matches ET_Block_v4 / 45.154.96.0/24 instead
     *
     *   When pfb_ip_feed_match_cell is called with both new values non-empty
     *
     *   Then the output groups by record: struck previous pair first, current pair second.
     *     The struck previous match (<s>45.154.96.76</s>) must appear BEFORE the
     *     current feed token (ET_Block_v4) — proving the by-record grouping and
     *     distinguishing it from the old per-field layout (which placed
     *     ET_Block_v4 before <s>45.154.96.76</s>).
     */
    public function test_both_changed_groups_by_record_struck_previous_pair_before_current_pair(): void
    {
        // Given
        $feed     = 'CINS_army_v4';
        $feedNew  = 'ET_Block_v4';
        $match    = '45.154.96.76';
        $matchNew = '45.154.96.0/24';

        // When
        $result = pfb_ip_feed_match_cell($feed, $feedNew, $match, $matchNew);

        // Then — full expected string (by-record grouping)
        $expected = '<s>CINS_army_v4</s><br /><small><s>45.154.96.76</s></small><br />ET_Block_v4<br /><small>45.154.96.0/24</small>';
        $this->assertSame($expected, $result);

        // Structural proof: the struck previous match must come BEFORE the current feed,
        // so this assertion would FAIL on the old per-field layout where ET_Block_v4
        // appeared before <s>45.154.96.76</s>.
        $posStruckMatch  = strpos($result, '<s>45.154.96.76</s>');
        $posCurrentFeed  = strpos($result, 'ET_Block_v4');
        $this->assertNotFalse($posStruckMatch, 'struck previous match must be present');
        $this->assertNotFalse($posCurrentFeed, 'current feed must be present');
        $this->assertLessThan(
            $posCurrentFeed,
            $posStruckMatch,
            'struck previous match must appear before current feed (by-record grouping)'
        );
    }
}
