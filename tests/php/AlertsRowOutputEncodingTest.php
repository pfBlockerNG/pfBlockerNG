<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Pin the HTML output-encoding contract of the Alerts/Reports DNSBL row builder
 * (pfblockerng_alerts.php). Every log-derived data token — the parsed log line
 * fields and the resolved/DHCP hostname — must be HTML-encoded where it enters a
 * <td> cell, so HTML metacharacters render as inert text and the only live markup
 * in a row is the static markup the builder itself emits (icons, <span>, <small>,
 * <br />, href).
 *
 * Feature: Alerts/Reports row fields are HTML-encoded before output
 *   Background:
 *     Given a DNSBL log line whose Domain / Source-IP-hostname carry HTML
 *           metacharacters ('"', '<', '>', '&')
 *     And the same builder fed an ordinary benign domain
 *
 * Branch coverage (both input classes, asserted before AND after):
 *   - has-metacharacters: the emitted row contains the ENTITY-encoded form
 *     (e.g. '&lt;img', '&quot;', '&amp;') and NEVER the raw '<img'/'<script'
 *     markup or a bare attribute-breaking '"' inside a data token.
 *   - no-metacharacters: a benign domain renders verbatim in the row (proving
 *     the encoding is a no-op on safe input — not an always-mangle path).
 *
 * The function under test is loaded off-appliance exactly like the wizard
 * functions in tests/php/bootstrap.php: the page source is read, its top-of-file
 * require_once() lines are stripped, and only the function definitions (from the
 * first `function ` keyword onward) are eval'd — so the page's top-level render
 * wiring, which needs the live pfSense runtime, never runs. No production file is
 * modified to make it testable.
 */
#[CoversFunction('convert_dnsbl_log')]
#[CoversFunction('dnsbl_whitelist_type')]
#[CoversFunction('dnsbl_log_details')]
#[CoversFunction('pfb_hsc')]
final class AlertsRowOutputEncodingTest extends TestCase
{
    /** Saved globals the builder reads, restored in tearDown. */
    private array $savedGlobals = [];

    public static function setUpBeforeClass(): void
    {
        // See AlertsPageLoader.php for the off-appliance load mechanics (shared with
        // WhitelistTrashIconTest / AlertsIpConvertPrefetchParityTest).
        require_once __DIR__ . '/AlertsPageLoader.php';
        pfb_test_load_alerts_page_functions();
    }

    protected function setUp(): void
    {
        // Seed every global the DNSBL builder + its helpers read. The values are
        // chosen so the python-mode path is taken: that avoided the DB call the
        // now-removed pfb_dnsbl_parse() made and, with an empty $dnsbl_int, skips ip_in_subnet(); an
        // empty whitelist customlist skips array_get_path(). What remains is the
        // pure field-folding + print path we are pinning.
        foreach ([
            'pfb', 'local_hosts', 'dnsbl_int', 'filterfieldsarray', 'clists',
            'dnsbl_unlock', 'dup', 'counter', 'pfbentries', 'skipcount',
            'dnsblfilterlimit', 'dnsblfilterlimitentries',
        ] as $g) {
            $this->savedGlobals[$g] = $GLOBALS[$g] ?? null;
        }

        $GLOBALS['pfb'] = ['filterlogentries' => false];
        $GLOBALS['local_hosts'] = [];
        $GLOBALS['dnsbl_int'] = [];
        $GLOBALS['filterfieldsarray'] = [];
        $GLOBALS['clists'] = ['dnsbl' => ['options' => []], 'dnsblwhitelist' => ['data' => []]];
        $GLOBALS['dnsbl_unlock'] = [];
        $GLOBALS['dup'] = ['DNSBL' => 0];
        $GLOBALS['counter'] = ['DNSBL' => 0, 'Unified' => 0];
        $GLOBALS['pfbentries'] = 1000;
        $GLOBALS['skipcount'] = 0;
        $GLOBALS['dnsblfilterlimit'] = false;
        $GLOBALS['dnsblfilterlimitentries'] = 100;
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
     * Build a python-mode dnsbl.log $fields row for $domain blocked by group
     * $group / feed $feed from source IP $src_ip. Field layout per the
     * convert_dnsbl_log() reference comment.
     */
    private function dnsblFields(string $domain, string $src_ip, string $group, string $feed): array
    {
        return [
            0 => 'DNSBL-python', // prefix (not DNSBL-HTTPS)
            1 => '2026-01-01 00:00:00',
            2 => $domain,        // Domain name
            3 => $src_ip,        // Source IP
            4 => '',             // DNSBL Type
            5 => 'Python A',     // Mode (contains 'Python' -> python path, not TLD)
            6 => $group,         // Group Name
            7 => $domain,        // Evaluated Domain
            8 => $feed,          // Feed Name
            9 => 0,              // Duplicate count
            10 => 'A',           // Query Type
        ];
    }

    private function renderDnsblRow(array $fields): string
    {
        ob_start();
        // Reports tab (non-Unified) avoids config_get_path(); we only care about
        // how the data tokens are encoded, which is mode-independent.
        convert_dnsbl_log('Reports', $fields);
        return (string) ob_get_clean();
    }

    public function test_metacharacters_in_domain_are_entity_encoded_not_raw_markup(): void
    {
        // Given a blocked-domain token carrying an HTML-injection payload and a
        // double-quote that would break out of a title="" attribute,
        $payloadDomain = '"><img src=x onerror=alert(1)>evil&co.com';
        $fields = $this->dnsblFields($payloadDomain, '10.0.0.5', 'BadGroup', 'BadFeed');

        // (before) the payload contains live markup that, unencoded, would inject.
        $this->assertStringContainsString('<img', $payloadDomain);

        // When the row is rendered,
        $html = $this->renderDnsblRow($fields);

        // Then the payload appears only in its entity-encoded form, never raw.
        $this->assertStringContainsString('&lt;img', $html, 'the <img payload must be HTML-encoded');
        $this->assertStringContainsString('&amp;', $html, '& must be encoded to &amp;');
        $this->assertStringNotContainsString('<img', $html, 'no raw <img tag may reach the output');
        $this->assertStringNotContainsString('onerror=alert(1)>', $html, 'no live onerror handler may reach the output');
        // The raw, attribute-breaking double-quote from the data token must be
        // encoded; the only literal quotes left belong to the static markup the
        // builder emits (class="...", id="...", title="...").
        $this->assertStringContainsString('&quot;', $html, 'a data-token double-quote must be encoded to &quot;');
    }

    public function test_metacharacters_in_resolved_hostname_are_entity_encoded(): void
    {
        // The resolved/DHCP hostname is a second untrusted source folded into the
        // SRC-IP cell's <span title="..."> markup.
        $src_ip = '10.0.0.9';
        $GLOBALS['local_hosts'] = [$src_ip => '<script>steal()</script>'];
        $fields = $this->dnsblFields('benign.example.test', $src_ip, 'Grp', 'Feed');

        $html = $this->renderDnsblRow($fields);

        $this->assertStringContainsString('&lt;script&gt;', $html, 'a malicious hostname must be HTML-encoded');
        $this->assertStringNotContainsString('<script>steal', $html, 'no raw <script> from a hostname may reach the output');
    }

    public function test_benign_domain_renders_verbatim(): void
    {
        // The no-metacharacters side of the branch: an ordinary domain must pass
        // through unchanged (encoding is a no-op on safe input), so green proves
        // the encoding is selective, not an always-mangle path.
        $domain = 'ordinary-domain.example.com';
        $fields = $this->dnsblFields($domain, '10.0.0.7', 'CleanGroup', 'CleanFeed');

        $html = $this->renderDnsblRow($fields);

        $this->assertStringContainsString($domain, $html, 'a benign domain must render verbatim');
        $this->assertStringContainsString('CleanFeed', $html, 'a benign feed name must render verbatim');
        $this->assertStringContainsString('CleanGroup', $html, 'a benign group name must render verbatim');
        // And it must not have been mangled into entities.
        $this->assertStringNotContainsString('&lt;', $html, 'benign input must not produce stray entities');
        $this->assertStringNotContainsString('&amp;', $html, 'benign input has no & to encode');
    }

    public function test_reports_dnsbl_domain_and_cname_keep_wide_truncation_widths(): void
    {
        $domain = 'WIDE-DNSBL02-' . str_repeat('a', 55) . '-tail';
        $cname  = 'WIDE-DNSBL03-' . str_repeat('b', 47) . '-tail';
        $this->assertGreaterThan(60, strlen($domain));
        $this->assertGreaterThan(52, strlen($cname));
        $fields    = $this->dnsblFields($domain, '10.0.0.8', 'WideGroup', 'WideFeed');
        $fields[5] = 'DNSBL_CNAME';
        $fields[7] = $cname;

        $html = $this->renderDnsblRow($fields);

        $this->assertStringContainsString(
            'Domain: ' . substr($domain, 0, 59) . '<small>...</small>',
            $html,
            'Reports DNSBL domains must retain the existing 59-character display width'
        );
        $this->assertStringContainsString(
            'CNAME: ' . substr($cname, 0, 51) . '<small>...</small>',
            $html,
            'Reports DNSBL CNAMEs must retain the existing 51-character display width'
        );
        $this->assertStringNotContainsString(
            'Domain: ' . substr($domain, 0, 39) . '<small>...</small>',
            $html,
            'Reports DNSBL domains must not use the Unified 39-character display width'
        );
        $this->assertStringNotContainsString(
            'CNAME: ' . substr($cname, 0, 31) . '<small>...</small>',
            $html,
            'Reports DNSBL CNAMEs must not use the Unified 31-character display width'
        );
    }

    public function test_invalid_utf8_byte_in_domain_renders_substituted_not_blanked(): void
    {
        // issue #1814: a single invalid-UTF-8 byte (0xFF is never valid in any UTF-8
        // sequence) embedded in an otherwise benign domain, well under the truncation
        // threshold (60 chars, see the truncation test below) -- exercises the direct
        // pfb_hsc($f2) branch. htmlspecialchars(ENT_QUOTES) alone returns '' on ANY
        // invalid byte (wiping the WHOLE string, not just the offending byte); ENT_SUBSTITUTE
        // keeps the valid surrounding text and substitutes only the bad byte with U+FFFD.
        $domain = "evil\xFFdomain.example";
        $fields = $this->dnsblFields($domain, '10.0.0.11', 'InvalidUtf8Group', 'InvalidUtf8Feed');

        $html = $this->renderDnsblRow($fields);

        $this->assertStringContainsString('evil', $html, 'the domain text before the invalid byte must survive, not blank the whole cell');
        $this->assertStringContainsString('domain.example', $html, 'the domain text after the invalid byte must survive, not blank the whole cell');
        $this->assertStringContainsString("\u{FFFD}", $html, 'the invalid byte must render substituted (U+FFFD), never silently dropped');
        $this->assertTrue(mb_check_encoding($html, 'UTF-8'), 'the rendered row must be valid UTF-8');
    }

    public function test_truncated_multibyte_char_in_domain_survives_whole_after_mb_substr_conversion(): void
    {
        // issue #1815: a >=60-char domain whose 59th raw BYTE is the lead byte of a
        // 2-byte UTF-8 sequence ("\xC3\xA9" = e-acute), straddling the blocked-domain
        // ($f2) truncation boundary in convert_dnsbl_log(). This call site was
        // byte substr() -- explicitly OUT OF SCOPE when this test was first written
        // (issue #1814 follow-up) -- and pfb_hsc()'s ENT_SUBSTITUTE made the resulting
        // dangling lead byte render safely (U+FFFD) instead of blanking the cell.
        // #1815 IS that follow-up: the site now calls pfb_truncate() (a character-based
        // mb_substr() wrapper), which keeps the character whole instead of ever leaving
        // a dangling lead byte, so no substitution is needed here anymore.
        $domain = str_repeat('a', 58) . "\xC3\xA9" . 'trailing-domain-suffix.example';
        $this->assertGreaterThanOrEqual(60, strlen($domain));

        $fields = $this->dnsblFields($domain, '10.0.0.12', 'TruncGroup', 'TruncFeed');

        $html = $this->renderDnsblRow($fields);

        $this->assertStringContainsString(str_repeat('a', 58), $html, 'the domain text before the truncation point must survive');
        $this->assertStringContainsString('é', $html, 'the whole multibyte character must survive the cut intact');
        $this->assertStringNotContainsString("\u{FFFD}", $html, 'mb_substr must keep the character whole -- U+FFFD must not appear');
        $this->assertStringContainsString('<small>...</small>', $html, 'the truncation ellipsis must still render');
        $this->assertTrue(mb_check_encoding($html, 'UTF-8'), 'the rendered row must be valid UTF-8');
    }

    public function test_single_quote_in_domain_is_entity_encoded(): void
    {
        // The remaining ENT_QUOTES metacharacter not yet directly pinned by a test in
        // this file (< / > / " / & are covered above): a single quote must still encode
        // to &#039; -- unchanged by the ENT_SUBSTITUTE addition.
        $domain = "o'brien.evil.example";
        $fields = $this->dnsblFields($domain, '10.0.0.13', 'QuoteGroup', 'QuoteFeed');

        $html = $this->renderDnsblRow($fields);

        $this->assertStringContainsString('&#039;', $html, "a data-token single-quote must be encoded to &#039;");
        $this->assertStringNotContainsString("o'brien", $html, 'no raw single-quote from a domain may reach the output unescaped');
    }

    public function test_valid_multibyte_domain_renders_unchanged_apart_from_escaping(): void
    {
        // Valid multibyte characters (a German umlaut, then CJK) must render unchanged
        // apart from HTML-escaping -- ENT_SUBSTITUTE only substitutes INVALID byte
        // sequences; it must never touch well-formed multibyte characters.
        $domain = 'b' . "\u{00FC}" . 'cher.' . "\u{4E2D}\u{6587}" . '.example'; // "bücher.中文.example"
        $fields = $this->dnsblFields($domain, '10.0.0.14', 'MultibyteGroup', 'MultibyteFeed');

        $html = $this->renderDnsblRow($fields);

        $this->assertStringContainsString($domain, $html, 'a valid multibyte domain must render verbatim (no HTML metachars to escape)');
        $this->assertStringNotContainsString("\u{FFFD}", $html, 'valid multibyte characters must never be substituted');
        $this->assertTrue(mb_check_encoding($html, 'UTF-8'), 'the rendered row must be valid UTF-8');
    }
}
