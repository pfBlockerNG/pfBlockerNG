<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Pin the ordering of the DNSBL Reports-tab row-count limit gate in FILTER mode
 * (pfblockerng_alerts.php::convert_dnsbl_log()) after issue #809 hoisted the
 * counter/limit check to the top of the function for a performance win.
 *
 * B1 (PR #825 review): the hoist moved BOTH the non-filter AND the filter-mode
 * limit check ahead of pfb_match_filter_field(). On origin/devel the filter-mode
 * check ran only AFTER a row passed the filter match, so a non-matching row past
 * the limit fell through the match-return-FALSE path and the scan continued,
 * leaving $dnsblfilterlimit FALSE until (if ever) a further MATCHING row was
 * found. Hoisting the filter-mode half of the gate broke that: it now trips
 * $dnsblfilterlimit = TRUE on the first non-dup row of ANY kind past the limit,
 * changing the <tfoot> "Filter Limit setting reached" flag for a post-limit tail
 * of rows that never match the active filter. The fix restores the filter-mode
 * check to AFTER the match (keeping the non-filter hoist, which is order-
 * independent of the parse and the actual perf win).
 *
 * Feature: DNSBL Reports filter-mode row limit only trips on a MATCHING row
 *   Background:
 *     Given filter-mode is active with the per-filter row counter already at
 *           its configured limit
 *
 *   Scenario: a non-matching row past the limit must NOT trip the limit flag
 *     (the loop must keep scanning for a matching row instead)
 *   Scenario: a matching row past the limit DOES trip the limit flag
 *     (both sides of the branch are exercised, per the coverage mandate)
 *
 * The function under test is loaded off-appliance exactly like
 * AlertsRowOutputEncodingTest.php: the page source is read, its top-of-file
 * require_once() lines are stripped, and only the function definitions (from
 * the first `function ` keyword onward) are eval'd, so the page's top-level
 * render wiring never runs. No production file is modified to make it testable.
 */
#[CoversFunction('convert_dnsbl_log')]
final class AlertsDnsblLimitGateTest extends TestCase
{
    /** Saved globals the builder reads, restored in tearDown. */
    private array $savedGlobals = [];

    public static function setUpBeforeClass(): void
    {
        if (function_exists('convert_dnsbl_log')) {
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
        $end = strpos($src, "\n\$pgtitle = ");
        if ($start === false || $end === false || $end <= $start) {
            throw new RuntimeException('could not locate the row-builder function block in pfblockerng_alerts.php');
        }
        eval("\n" . substr($src, $start + 1, $end - $start - 1));
    }

    protected function setUp(): void
    {
        foreach ([
            'pfb', 'local_hosts', 'dnsbl_int', 'filterfieldsarray', 'clists',
            'dnsbl_unlock', 'dup', 'counter', 'pfbentries', 'skipcount',
            'dnsblfilterlimit', 'dnsblfilterlimitentries',
        ] as $g) {
            $this->savedGlobals[$g] = $GLOBALS[$g] ?? null;
        }

        // Filter mode ON, with the DNSBL counter already AT the configured
        // filter-mode limit (5), so the very next row exercises the gate.
        $GLOBALS['pfb'] = ['filterlogentries' => true];
        $GLOBALS['local_hosts'] = [];
        $GLOBALS['dnsbl_int'] = [];
        $GLOBALS['clists'] = ['dnsbl' => ['options' => []], 'dnsblwhitelist' => ['data' => []]];
        $GLOBALS['dnsbl_unlock'] = [];
        $GLOBALS['dup'] = ['DNSBL' => 0];
        $GLOBALS['counter'] = ['DNSBL' => 5, 'Unified' => 0];
        $GLOBALS['pfbentries'] = 1000; // Non-filter limit; irrelevant in filter mode.
        $GLOBALS['skipcount'] = 0;
        $GLOBALS['dnsblfilterlimit'] = false;
        $GLOBALS['dnsblfilterlimitentries'] = 5;
    }

    protected function tearDown(): void
    {
        foreach ($this->savedGlobals as $g => $v) {
            if ($v === null) {
                unset($GLOBALS[$g]);
            } else {
                $GLOBALS[$g] = $v;
            }
        }
    }

    /**
     * Build a python-mode dnsbl.log $fields row (skips pfb_dnsbl_parse()'s DB
     * dependency, mirroring AlertsRowOutputEncodingTest::dnsblFields()) blocked
     * by group $group, so the Group filter field (index 13 in the filter's
     * $pfbalertdnsbl view) can be steered to match or not match.
     */
    private function dnsblFields(string $group): array
    {
        return [
            0 => 'DNSBL-python',
            1 => '2026-01-01 00:00:00',
            2 => 'row-under-test.example.com',
            3 => '10.0.0.5',
            4 => '',
            5 => 'Python A', // contains 'Python' -> python path, skips the parse
            6 => $group,     // Group Name -> becomes $pfbalertdnsbl[13]
            7 => 'row-under-test.example.com',
            8 => 'SomeFeed',
            9 => 0,
            10 => 'A',
        ];
    }

    public function test_non_matching_row_past_filter_limit_does_not_trip_limit_flag(): void
    {
        // Given a filter on the Group field (index 13) that this row's group
        // will NOT satisfy,
        $GLOBALS['filterfieldsarray'] = [1 => [13 => 'NoMatchGroupXYZ']];
        $fields = $this->dnsblFields('UnrelatedGroup');

        // (before) the limit flag has not tripped yet.
        $this->assertFalse(
            $GLOBALS['dnsblfilterlimit'],
            "expected <dnsblfilterlimit=false> before the call but was <{$this->bstr($GLOBALS['dnsblfilterlimit'])}>"
        );

        // When the row is evaluated (counter is already AT the filter limit),
        $result = convert_dnsbl_log('non_unified', $fields);

        // Then the row is rejected for NOT matching the filter (the scan must
        // keep going -- FALSE, not the limit-reached TRUE),
        $this->assertFalse(
            $result,
            "expected convert_dnsbl_log() to return <false> (rejected by filter match) but was <{$this->bstr($result)}>"
        );
        // and the filter-mode limit gate must NOT have tripped on this
        // non-matching row -- restoring the origin/devel ordering (B1).
        $this->assertFalse(
            $GLOBALS['dnsblfilterlimit'],
            "expected <dnsblfilterlimit=false> after a non-matching row past the limit but was <{$this->bstr($GLOBALS['dnsblfilterlimit'])}>"
        );
    }

    public function test_matching_row_past_filter_limit_does_trip_limit_flag(): void
    {
        // Given a filter on the Group field (index 13) that this row's group
        // WILL satisfy,
        $GLOBALS['filterfieldsarray'] = [1 => [13 => 'MatchingGroup']];
        $fields = $this->dnsblFields('MatchingGroupHere');

        // (before) the limit flag has not tripped yet.
        $this->assertFalse(
            $GLOBALS['dnsblfilterlimit'],
            "expected <dnsblfilterlimit=false> before the call but was <{$this->bstr($GLOBALS['dnsblfilterlimit'])}>"
        );

        // When the row is evaluated (counter is already AT the filter limit),
        $result = convert_dnsbl_log('non_unified', $fields);

        // Then the row DOES match the filter, so the limit gate (still reached
        // AFTER the match, per the restored ordering) trips and rejects it.
        $this->assertTrue(
            $result,
            "expected convert_dnsbl_log() to return <true> (limit reached on a matching row) but was <{$this->bstr($result)}>"
        );
        $this->assertTrue(
            $GLOBALS['dnsblfilterlimit'],
            "expected <dnsblfilterlimit=true> after a matching row past the limit but was <{$this->bstr($GLOBALS['dnsblfilterlimit'])}>"
        );
    }

    /** Render a bool (or whatever convert_dnsbl_log() actually returned) for an assertion message. */
    private function bstr($v): string
    {
        if (is_bool($v)) {
            return $v ? 'true' : 'false';
        }
        return var_export($v, true);
    }
}
