<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Pin the resolved-hostname stats cell builder (pfblockerng_alerts.php,
 * pfb_stat_hostname_cell) used by the IP Src/Dst-in Block Stats. The resolved
 * hostname is attacker-influenceable, so it must be HTML-encoded; a long value
 * is truncated for display with the full value kept in the title="" attribute.
 *
 * Feature: the stats hostname cell encodes then truncates SAFELY
 *   Background:
 *     Given a resolved hostname folded into a <span title="..."><small> cell
 *
 * Branch coverage (both sides of the >45 length gate, asserted):
 *   - short (<=45): encoded in full, no title attr, no "..." ellipsis.
 *   - long (>45): truncated cell + full value in the title attr.
 *
 * Regression (issue #1069): the value must be truncated RAW then encoded.
 * Encoding first then substr() can split a named entity ("&quot;" -> "&qu") or a
 * multibyte character -- both exercised below, and both fail on the old ordering.
 *
 * The function is loaded off-appliance via AlertsPageLoader (the page's top-level
 * render wiring never runs); no production file is modified to make it testable.
 */
#[CoversFunction('pfb_stat_hostname_cell')]
#[CoversFunction('pfb_hsc')]
final class AlertsStatHostnameCellTest extends TestCase
{
    public static function setUpBeforeClass(): void
    {
        require_once __DIR__ . '/AlertsPageLoader.php';
        pfb_test_load_alerts_page_functions();
    }

    public function test_short_hostile_hostname_is_encoded_in_full_without_truncation(): void
    {
        // Given a short (<45 char) hostname carrying HTML metacharacters,
        $resolved = 'a"<b>.evil.example';
        $this->assertLessThan(45, strlen($resolved));

        $cell = pfb_stat_hostname_cell($resolved);

        // Then it is HTML-encoded, with no truncation ellipsis and no title attr.
        $this->assertStringContainsString('&quot;', $cell, 'the double-quote must be encoded');
        $this->assertStringContainsString('&lt;b&gt;', $cell, 'the <b> markup must be encoded');
        $this->assertStringContainsString('.evil.example', $cell, 'the benign suffix must render verbatim');
        $this->assertStringNotContainsString('<b>', $cell, 'no raw <b> markup may reach the output');
        $this->assertStringNotContainsString('...', $cell, 'a short value must not be truncated');
        $this->assertStringNotContainsString('title=', $cell, 'a short value needs no title attribute');
    }

    public function test_long_hostname_truncation_does_not_split_a_named_entity(): void
    {
        // Given a >=45-char hostname whose 45th raw character is a double-quote,
        // so escape-then-truncate would cut "&quot;" mid-entity into a dangling "&".
        $resolved = str_repeat('a', 44) . '"' . 'z.evil.example';
        $this->assertGreaterThanOrEqual(45, strlen($resolved));

        $cell = pfb_stat_hostname_cell($resolved);

        // Then the truncated display text carries a COMPLETE entity at the
        // boundary (truncate-raw-then-encode), never a split fragment.
        $this->assertStringContainsString('&quot;<small>...</small>', $cell, 'the entity must survive truncation intact');
        $this->assertStringNotContainsString('&<small>', $cell, 'a truncation must not dangle a bare & (split entity)');
        // And the full untruncated value is preserved in the title attribute.
        $this->assertStringContainsString('title="' . str_repeat('a', 44) . '&quot;z.evil.example"', $cell,
            'the title attribute must carry the full escaped hostname');
    }

    public function test_long_hostname_truncation_does_not_split_a_multibyte_char(): void
    {
        // Given a >=45-char hostname whose 45th character is multibyte (é, 2 bytes),
        // a byte-based substr() would cut it mid-sequence and pfb_hsc() (strict
        // UTF-8) would then blank the whole truncated run. mb_substr keeps it whole.
        $resolved = str_repeat('a', 44) . 'é' . 'z.evil.example';
        $this->assertGreaterThanOrEqual(45, strlen($resolved));

        $cell = pfb_stat_hostname_cell($resolved);

        // Then the cell is valid UTF-8 -- a byte-based substr() would leave a
        // dangling lead byte (0xC3) at the cut, making the output invalid.
        $this->assertTrue(mb_check_encoding($cell, 'UTF-8'), 'a split multibyte char must not corrupt the cell encoding');
        $this->assertStringContainsString('<small>...</small>', $cell, 'the ellipsis must mark the truncation');
    }

    public function test_benign_long_hostname_truncates_cleanly(): void
    {
        // The no-metacharacters side: a long benign hostname truncates without
        // producing stray entities (encoding is a no-op on safe input).
        $resolved = str_repeat('host-', 12) . '.example';
        $this->assertGreaterThanOrEqual(45, strlen($resolved));

        $cell = pfb_stat_hostname_cell($resolved);

        $this->assertStringContainsString('<small>...</small>', $cell, 'a long value must be truncated');
        $this->assertStringContainsString('title="', $cell, 'a long value keeps the full value in a title attr');
        $this->assertStringNotContainsString('&lt;', $cell, 'benign input must not produce stray entities');
        $this->assertStringNotContainsString('&amp;', $cell, 'benign input has no & to encode');
    }

    public function test_hostname_truncation_boundary_keeps_exact_limit_without_ellipsis(): void
    {
        $resolved = [
            44 => str_repeat('a', 44),
            45 => str_repeat('b', 45),
            46 => str_repeat('c', 46),
        ];
        $actual = [];

        foreach ($resolved as $length => $hostname) {
            $this->assertSame($length, mb_strlen($hostname, 'UTF-8'));
            $cell = pfb_stat_hostname_cell($hostname);
            $actual[$length] = [
                'visible' => strip_tags($cell),
                'ellipsis' => str_contains($cell, '<small>...</small>'),
                'title' => str_contains($cell, 'title="' . $hostname . '"'),
            ];
        }

        $this->assertSame([
            44 => ['visible' => $resolved[44], 'ellipsis' => FALSE, 'title' => FALSE],
            45 => ['visible' => $resolved[45], 'ellipsis' => FALSE, 'title' => FALSE],
            46 => ['visible' => str_repeat('c', 45) . '...', 'ellipsis' => TRUE, 'title' => TRUE],
        ], $actual);
    }

    public function test_invalid_utf8_in_truncated_hostname_uses_replacement_character(): void
    {
        $resolved = str_repeat('a', 40) . "\xFF" . str_repeat('b', 10);
        $this->assertGreaterThanOrEqual(45, mb_strlen($resolved, 'UTF-8'));

        $cell = pfb_stat_hostname_cell($resolved);

        $this->assertStringContainsString(
            str_repeat('a', 40) . "\u{FFFD}" . str_repeat('b', 4) . '<small>...</small>',
            $cell,
            'the displayed cut must represent an invalid byte with U+FFFD'
        );
        $this->assertStringNotContainsString(
            str_repeat('a', 40) . '?' . str_repeat('b', 4) . '<small>...</small>',
            $cell,
            "the displayed cut must not fabricate '?' for an invalid byte"
        );
    }

    public function test_character_gate_hostname_renders_complete_value_without_ellipsis(): void
    {
        $resolved = 'CG11' . str_repeat('界', 14);
        while (strlen($resolved) < 45) {
            $resolved .= '界';
        }
        $this->assertGreaterThanOrEqual(45, strlen($resolved));
        $this->assertLessThan(45, mb_strlen($resolved, 'UTF-8'));

        $cell = pfb_stat_hostname_cell($resolved);
        $escaped = pfb_hsc($resolved);

        $this->assertStringContainsString("<small>{$escaped}</small>", $cell);
        $this->assertStringNotContainsString($escaped . '<small>...</small>', $cell);
        $this->assertStringNotContainsString('title="', $cell);
    }
}
