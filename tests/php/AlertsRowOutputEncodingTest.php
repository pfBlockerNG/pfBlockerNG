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
        // Load the alerts-page row-builder functions off-appliance: read the
        // source, drop the top-of-file require_once() lines (the bootstrap has
        // already loaded the real pfblockerng.inc + shims), and eval only the
        // function definitions, skipping the page-render wiring. Mirrors the
        // wizard-function load in bootstrap.php.
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
        // The row-builder functions form one contiguous block; after them the
        // page resumes top-level render wiring (the first such statement is the
        // `$pgtitle = array(...)` line, which precedes include_once('head.inc')
        // and display_top_tabs()). Eval only [first `function ` .. that line) so
        // we define the builders without executing any page-render code.
        $start = strpos($src, "\nfunction ");
        $end = strpos($src, "\n\$pgtitle = ");
        if ($start === false || $end === false || $end <= $start) {
            throw new RuntimeException('could not locate the row-builder function block in pfblockerng_alerts.php');
        }
        eval("\n" . substr($src, $start + 1, $end - $start - 1));
    }

    protected function setUp(): void
    {
        // Seed every global the DNSBL builder + its helpers read. The values are
        // chosen so the python-mode path is taken: that skips pfb_dnsbl_parse()
        // (a DB call) and, with an empty $dnsbl_int, skips ip_in_subnet(); an
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
}
