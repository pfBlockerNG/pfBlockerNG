<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Differential coverage for the Alerts/Reports Pass-1/Pass-2 buffer-and-replay
 * arithmetic (issue #809 T2). This is the most intricate NEW logic the Phase 3a/3b
 * batching added to pfblockerng_alerts.php -- the DNSBL dup run-length compression
 * and the IP dup+gap-marker compression + replay -- and it shipped with ZERO
 * committed tests (inline top-level page code, never exercised by
 * AlertsRowOutputEncodingTest's harness). This is a BEHAVIOUR-PRESERVING
 * refactor: the compression/replay ARITHMETIC itself (previously inline in the
 * page) was extracted verbatim into pure functions
 * (pfb_alerts_dnsbl_buffer_push/replay_step, pfb_alerts_ip_buffer_push/replay_step
 * in pfblockerng.inc) that the page now calls -- no behaviour changed, only the
 * arithmetic's location.
 *
 * Strategy: a NAIVE reference simulates the ORIGINAL streamed (uncompressed)
 * per-line loop directly from an abstract sequence of line "kinds" (dup / render
 * for DNSBL; dup / reject / accept for IP). The COMPRESSED path builds a buffer
 * via the real extracted *_buffer_push() functions over the SAME kind sequence,
 * then replays it via the real extracted *_replay_step() functions. Asserting the
 * two effect sequences are IDENTICAL -- for a broad matrix of hand-picked edge
 * cases plus long deterministically-seeded pseudo-random sequences -- pins the
 * compression as a lossless, order-preserving rewrite of the naive semantics: a
 * regression guarantee per CLAUDE.md's behaviour-preserving test exception,
 * deliberately not red -> green, and still mandatory.
 *
 * Feature: the compressed buffer + replay reproduces the naive streamed effects
 *   Background:
 *     Given an abstract sequence of log-line "kinds" (never real CSV fields --
 *           the buffer/replay arithmetic is agnostic to field content, only to
 *           which of the three storage shapes (data row / int run / gap marker)
 *           an entry takes)
 *
 *   Scenario: DNSBL -- dup runs at every position, all-dup, alternating, long
 *             pseudo-random sequences
 *   Scenario: IP -- dup runs, reject runs, mixed dup/reject gaps, alternating,
 *             long pseudo-random sequences
 *   Scenario: buffer bound holds regardless of sequence length
 */
#[CoversFunction('pfb_alerts_dnsbl_buffer_push')]
#[CoversFunction('pfb_alerts_dnsbl_replay_step')]
#[CoversFunction('pfb_alerts_ip_buffer_push')]
#[CoversFunction('pfb_alerts_ip_replay_step')]
final class AlertsBufferReplayTest extends TestCase
{
    // ============================================================
    // Deterministic sequence generation -- NO Math.random/time (CLAUDE.md):
    // a hand-rolled LCG seeded by a fixed integer + the position index, so
    // the same $seed always yields the same sequence.
    // ============================================================

    /**
     * @param array<int, array{0:int,1:string}> $weightedAlphabet Cumulative
     *   [threshold, kind] pairs covering 0..99 (e.g. [[70,'dup'],[100,'render']]
     *   means 70% 'dup', 30% 'render').
     * @return string[]
     */
    private static function deterministicSequence(int $seed, int $length, array $weightedAlphabet): array
    {
        $seq = [];
        $state = $seed;
        for ($i = 0; $i < $length; $i++) {
            $state = ($state * 1103515245 + 12345 + $i) % 2147483648;
            $bucket = $state % 100;
            $kind = $weightedAlphabet[count($weightedAlphabet) - 1][1];
            foreach ($weightedAlphabet as $pair) {
                if ($bucket < $pair[0]) {
                    $kind = $pair[1];
                    break;
                }
            }
            $seq[] = $kind;
        }
        return $seq;
    }

    // ============================================================
    // DNSBL: kinds are 'dup' | 'render'.
    // ============================================================

    /** @param string[] $kinds @return array<int, array{dup:int, marker:string}> */
    private function dnsblBuildBuffer(array $kinds): array
    {
        $buf = [];
        $renderIndex = 0;
        foreach ($kinds as $kind) {
            if ($kind === 'dup') {
                pfb_alerts_dnsbl_buffer_push($buf, true, null);
                continue;
            }
            pfb_alerts_dnsbl_buffer_push($buf, false, "R{$renderIndex}");
            $renderIndex++;
        }
        return $buf;
    }

    /** @param array<int, mixed> $buf @return array<int, array{dup:int, marker:string}> */
    private function dnsblReplay(array $buf): array
    {
        $dup = 0;
        $effects = [];
        foreach ($buf as $entry) {
            $step = pfb_alerts_dnsbl_replay_step($entry);
            if (isset($step['dup'])) {
                $dup += $step['dup'];
                continue;
            }
            $effects[] = ['dup' => $dup, 'marker' => $step['render']];
            $dup = 0;
        }
        return $effects;
    }

    /**
     * Naive reference: the ORIGINAL streamed per-line loop, expressed directly
     * over the abstract kind sequence (no buffering). Each 'dup' increments the
     * badge; each 'render' emits an effect carrying the CURRENT badge value,
     * then resets it to 0 -- exactly the streamed loop's
     * `if ($fields[9] == '-') { $dup['DNSBL']++; continue; } ... $dup['DNSBL'] = 0;`
     * shape.
     *
     * @param string[] $kinds @return array<int, array{dup:int, marker:string}>
     */
    private function dnsblNaiveEffects(array $kinds): array
    {
        $dup = 0;
        $renderIndex = 0;
        $effects = [];
        foreach ($kinds as $kind) {
            if ($kind === 'dup') {
                $dup++;
                continue;
            }
            $effects[] = ['dup' => $dup, 'marker' => "R{$renderIndex}"];
            $dup = 0;
            $renderIndex++;
        }
        return $effects;
    }

    /**
     * Given a DNSBL kind sequence, assert the compressed buffer + replay
     * (the real pfb_alerts_dnsbl_buffer_push()/pfb_alerts_dnsbl_replay_step())
     * reproduces the naive streamed reference EXACTLY, and that the buffer
     * bound holds: <= (renders + 1) data entries, <= (renders + 2) markers.
     *
     * @param string[] $kinds
     */
    private function assertDnsblDifferential(array $kinds, string $scenario): void
    {
        $naive = $this->dnsblNaiveEffects($kinds);
        $buf = $this->dnsblBuildBuffer($kinds);
        $compressed = $this->dnsblReplay($buf);

        $this->assertSame(
            $naive,
            $compressed,
            "[DNSBL/{$scenario}] compressed+replay effects diverged from the naive streamed reference.\n"
            . 'sequence:            ' . var_export($kinds, true) . "\n"
            . 'expected (naive):    ' . var_export($naive, true) . "\n"
            . 'actual (compressed): ' . var_export($compressed, true)
        );

        $renders = count(array_filter($kinds, fn ($k) => $k === 'render'));
        $dataCount = 0;
        $markerCount = 0;
        foreach ($buf as $entry) {
            if (is_int($entry)) {
                $markerCount++;
            } else {
                $dataCount++;
            }
        }

        $this->assertLessThanOrEqual(
            $renders + 1,
            $dataCount,
            "[DNSBL/{$scenario}] expected <= " . ($renders + 1) . " buffered data entries for {$renders} renders "
            . "but the buffer held <{$dataCount}>"
        );
        $this->assertLessThanOrEqual(
            $renders + 2,
            $markerCount,
            "[DNSBL/{$scenario}] expected <= " . ($renders + 2) . " compressed markers for {$renders} renders "
            . "but the buffer held <{$markerCount}>"
        );
    }

    public function test_dnsbl_empty_sequence_has_no_renders(): void
    {
        // Given an empty log (EOF immediately),
        // Then the compressed replay produces no render effects, matching the
        // naive reference, and the (degenerate) buffer bound trivially holds.
        $this->assertDnsblDifferential([], 'empty');
    }

    public function test_dnsbl_all_dup_no_renders(): void
    {
        // Given a run of dup-marker lines with no render ever reached (e.g. the
        // buffer never sees a non-dup line before EOF),
        // Then the whole run compresses to a single int marker and the naive
        // dup accumulator (never consumed by a render) matches trivially (both
        // produce zero render effects).
        $this->assertDnsblDifferential(['dup', 'dup', 'dup', 'dup', 'dup'], 'all-dup');
    }

    public function test_dnsbl_dup_run_at_start(): void
    {
        // Given a dup run BEFORE the first render,
        $this->assertDnsblDifferential(['dup', 'dup', 'dup', 'render'], 'dup-run-at-start');
    }

    public function test_dnsbl_dup_run_in_middle(): void
    {
        // Given a dup run BETWEEN two renders,
        $this->assertDnsblDifferential(['render', 'dup', 'dup', 'dup', 'render'], 'dup-run-in-middle');
    }

    public function test_dnsbl_dup_run_at_end(): void
    {
        // Given a dup run AFTER the last render (trailing to EOF),
        $this->assertDnsblDifferential(['render', 'dup', 'dup', 'dup'], 'dup-run-at-end');
    }

    public function test_dnsbl_dup_run_abutting_render_both_sides(): void
    {
        // Given a dup run immediately preceded AND followed by a render (the
        // run must reset to badge 0 once consumed by the leading render, then
        // re-accumulate for the trailing render),
        $this->assertDnsblDifferential(['render', 'dup', 'dup', 'render'], 'dup-run-abutting-both-sides');
    }

    public function test_dnsbl_alternating_dup_and_render(): void
    {
        // Given dup/render strictly alternating (every render sees badge == 1),
        $this->assertDnsblDifferential(
            ['dup', 'render', 'dup', 'render', 'dup', 'render', 'dup', 'render'],
            'alternating'
        );
    }

    public function test_dnsbl_consecutive_renders_no_dups(): void
    {
        // Given consecutive renders with no dups between them (every badge is 0),
        $this->assertDnsblDifferential(['render', 'render', 'render', 'render'], 'consecutive-renders');
    }

    public function test_dnsbl_long_pseudo_random_sequences(): void
    {
        // Given several long (>= 200 element), deterministically-seeded
        // pseudo-random sequences biased dup-heavy (70% dup / 30% render,
        // mirroring real dnsbl.logs per the page's own comment),
        foreach ([101, 202, 303, 404, 505] as $seed) {
            $kinds = self::deterministicSequence($seed, 240, [[70, 'dup'], [100, 'render']]);

            // Then the compressed replay matches the naive reference and the
            // buffer bound holds, regardless of the sequence's length or
            // random dup/render interleaving.
            $this->assertDnsblDifferential($kinds, "long-pseudo-random-seed-{$seed}");
        }
    }

    // ============================================================
    // IP: kinds are 'dup' | 'reject' | 'accept'.
    // ============================================================

    /** @param string[] $kinds @return array<int, mixed> */
    private function ipBuildBuffer(array $kinds): array
    {
        $buf = [];
        $acceptIndex = 0;
        foreach ($kinds as $kind) {
            if ($kind === 'dup') {
                pfb_alerts_ip_buffer_push($buf, 'dup');
                continue;
            }
            if ($kind === 'reject') {
                pfb_alerts_ip_buffer_push($buf, 'reject');
                continue;
            }
            // 'accept' -- the accepted-row append stays inline in the page too;
            // mirror that here (not a compressible kind).
            $buf[] = ["A{$acceptIndex}", true];
            $acceptIndex++;
        }
        return $buf;
    }

    /** @param array<int, mixed> $buf @return array<int, array{dup:int, port:string, marker:string}> */
    private function ipReplay(array $buf): array
    {
        $dup = 0;
        $port = 'PORT_INIT';
        $acceptIndex = 0;
        $effects = [];
        foreach ($buf as $entry) {
            $step = pfb_alerts_ip_replay_step($entry);
            if (isset($step['dup_add'])) {
                $dup += $step['dup_add'];
                continue;
            }
            if (isset($step['gap'])) {
                $dup = $step['gap'];
                $port = '';
                continue;
            }
            $effects[] = ['dup' => $dup, 'port' => $port, 'marker' => $step['render']];
            $dup = 0;
            $acceptIndex++;
            // Models convert_ip_log()'s opaque, per-row $p_query_port reassignment
            // (the impure part that stays OUTSIDE the extracted pure helpers --
            // see pfb_alerts_ip_replay_step()'s docblock): a fresh, uniquely
            // identifiable port value after every accepted row.
            $port = "PORT_AFTER_ACCEPT_{$acceptIndex}";
        }
        return $effects;
    }

    /**
     * Naive reference: the ORIGINAL streamed per-line loop. Each 'dup'
     * increments the badge; each 'reject' resets the badge to 0 AND clears the
     * port (mirroring convert_ip_log()'s constant filter-reject effect,
     * `$dup[$rtype] = 0; return array(FALSE, '');`, followed by the caller's
     * `$p_query_port = ''`); each 'accept' emits an effect with the CURRENT
     * badge + port, resets the badge to 0, then receives a fresh port (the
     * opaque post-convert_ip_log() reassignment modeled the same way as
     * ipReplay()'s replay loop, so the two sides stay comparable).
     *
     * @param string[] $kinds @return array<int, array{dup:int, port:string, marker:string}>
     */
    private function ipNaiveEffects(array $kinds): array
    {
        $dup = 0;
        $port = 'PORT_INIT';
        $acceptIndex = 0;
        $effects = [];
        foreach ($kinds as $kind) {
            if ($kind === 'dup') {
                $dup++;
                continue;
            }
            if ($kind === 'reject') {
                $dup = 0;
                $port = '';
                continue;
            }
            // 'accept'
            $effects[] = ['dup' => $dup, 'port' => $port, 'marker' => "A{$acceptIndex}"];
            $dup = 0;
            $acceptIndex++;
            $port = "PORT_AFTER_ACCEPT_{$acceptIndex}";
        }
        return $effects;
    }

    /**
     * Given an IP kind sequence, assert the compressed buffer + replay (the
     * real pfb_alerts_ip_buffer_push()/pfb_alerts_ip_replay_step()) reproduces
     * the naive streamed reference EXACTLY (badge value AND port state per
     * accepted row), and that the buffer bound holds: <= (accepts + 1) data
     * entries, <= (accepts + 2) compressed markers.
     *
     * @param string[] $kinds
     */
    private function assertIpDifferential(array $kinds, string $scenario): void
    {
        $naive = $this->ipNaiveEffects($kinds);
        $buf = $this->ipBuildBuffer($kinds);
        $compressed = $this->ipReplay($buf);

        $this->assertSame(
            $naive,
            $compressed,
            "[IP/{$scenario}] compressed+replay effects diverged from the naive streamed reference.\n"
            . 'sequence:            ' . var_export($kinds, true) . "\n"
            . 'expected (naive):    ' . var_export($naive, true) . "\n"
            . 'actual (compressed): ' . var_export($compressed, true)
        );

        $accepts = count(array_filter($kinds, fn ($k) => $k === 'accept'));
        $dataCount = 0;
        $markerCount = 0;
        foreach ($buf as $entry) {
            if (is_int($entry) || (is_array($entry) && isset($entry['rej']))) {
                $markerCount++;
            } else {
                $dataCount++;
            }
        }

        $this->assertLessThanOrEqual(
            $accepts + 1,
            $dataCount,
            "[IP/{$scenario}] expected <= " . ($accepts + 1) . " buffered accepted-row entries for {$accepts} accepts "
            . "but the buffer held <{$dataCount}>"
        );
        $this->assertLessThanOrEqual(
            $accepts + 2,
            $markerCount,
            "[IP/{$scenario}] expected <= " . ($accepts + 2) . " compressed markers for {$accepts} accepts "
            . "but the buffer held <{$markerCount}>"
        );
    }

    public function test_ip_empty_sequence_has_no_accepts(): void
    {
        // Given an empty log,
        $this->assertIpDifferential([], 'empty');
    }

    public function test_ip_all_dup_no_accepts(): void
    {
        // Given a run of dup-marker lines with no accept ever reached,
        $this->assertIpDifferential(['dup', 'dup', 'dup', 'dup'], 'all-dup');
    }

    public function test_ip_all_reject_no_accepts(): void
    {
        // Given a run of REJECTED lines with no accept ever reached (every
        // reject re-zeros the same gap marker's dup counter),
        $this->assertIpDifferential(['reject', 'reject', 'reject', 'reject'], 'all-reject');
    }

    public function test_ip_dup_run_at_start_middle_end(): void
    {
        // Given dup runs positioned before the first accept, between two
        // accepts, and after the last accept,
        $this->assertIpDifferential(
            ['dup', 'dup', 'accept', 'dup', 'dup', 'dup', 'accept', 'dup'],
            'dup-run-start-middle-end'
        );
    }

    public function test_ip_reject_run_at_start_middle_end(): void
    {
        // Given reject runs positioned before the first accept, between two
        // accepts, and after the last accept (each clearing the port and
        // zeroing the badge),
        $this->assertIpDifferential(
            ['reject', 'reject', 'accept', 'reject', 'reject', 'reject', 'accept', 'reject'],
            'reject-run-start-middle-end'
        );
    }

    public function test_ip_alternating_dup_and_reject(): void
    {
        // Given dup/reject strictly alternating with no accept -- exercises
        // the int-run <-> gap-marker conversion on every line (a dup after a
        // reject must extend the GAP's counter, not open a fresh int run),
        $this->assertIpDifferential(
            ['dup', 'reject', 'dup', 'reject', 'dup', 'reject', 'dup', 'reject'],
            'alternating-dup-reject'
        );
    }

    public function test_ip_alternating_dup_and_accept(): void
    {
        // Given dup/accept strictly alternating (every accept sees badge == 1,
        // port unchanged from the prior accept -- no reject ever fires),
        $this->assertIpDifferential(
            ['dup', 'accept', 'dup', 'accept', 'dup', 'accept'],
            'alternating-dup-accept'
        );
    }

    public function test_ip_alternating_reject_and_accept(): void
    {
        // Given reject/accept strictly alternating (every accept sees badge ==
        // 0 and port == '' -- the reject immediately before it always wins),
        $this->assertIpDifferential(
            ['reject', 'accept', 'reject', 'accept', 'reject', 'accept'],
            'alternating-reject-accept'
        );
    }

    public function test_ip_mixed_dup_then_reject_run_before_accept_gap_semantics(): void
    {
        // Given a run mixing dups BEFORE a reject and dups AFTER it, all
        // preceding one accept -- the defining "gap" scenario: the streamed
        // loop's net effect is exactly the POST-last-reject dup count (the
        // pre-reject dups must NOT survive into the accept's badge),
        $this->assertIpDifferential(
            ['dup', 'dup', 'dup', 'reject', 'dup', 'dup', 'accept'],
            'mixed-dup-then-reject-run'
        );
    }

    public function test_ip_multiple_gaps_between_multiple_accepts(): void
    {
        // Given several independent dup/reject gaps, each sandwiched between
        // two accepts (every gap must reset independently -- no bleed-through
        // from an earlier gap's state into a later one),
        $this->assertIpDifferential(
            [
                'accept',
                'dup', 'reject', 'dup', 'dup',
                'accept',
                'reject', 'dup',
                'accept',
                'dup', 'dup', 'reject', 'reject', 'dup',
                'accept',
            ],
            'multiple-gaps-between-accepts'
        );
    }

    public function test_ip_run_abutting_accept_both_sides(): void
    {
        // Given a mixed dup/reject run immediately preceded AND followed by an
        // accept,
        $this->assertIpDifferential(
            ['accept', 'dup', 'reject', 'dup', 'accept'],
            'run-abutting-accept-both-sides'
        );
    }

    public function test_ip_long_pseudo_random_sequences(): void
    {
        // Given several long (>= 200 element), deterministically-seeded
        // pseudo-random sequences (50% dup / 30% reject / 20% accept),
        foreach ([11, 22, 33, 44, 55] as $seed) {
            $kinds = self::deterministicSequence($seed, 250, [[50, 'dup'], [80, 'reject'], [100, 'accept']]);

            // Then the compressed replay matches the naive reference and the
            // buffer bound holds, regardless of the sequence's length or
            // random dup/reject/accept interleaving.
            $this->assertIpDifferential($kinds, "long-pseudo-random-seed-{$seed}");
        }
    }
}
