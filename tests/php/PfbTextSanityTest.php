<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for pfb_text_sanity() — ADR-49 Phase 1.
 *
 * pfb_text_sanity(string $sample): ?string is a PURE content-sanity scanner over
 * the first chunk (up to 8 KiB, a read cap never a floor) of a downloaded text
 * feed. It returns NULL when the sample looks like plausible blocklist text, or
 * one of three reason tokens otherwise. Verdict order (first hit wins):
 *   1. 'nul_bytes'         — any \x00 byte anywhere in the sample.
 *   2. 'html_error_page'   — opens with <!doctype html>/<html> AND carries no
 *                            blocklist-shaped line in its first 20 lines.
 *   3. 'below_min_content' — zero non-blank, non-comment lines (floor = 1).
 * All matching is BYTE-LEVEL (no `/u` modifier) — every pattern is pure ASCII,
 * so a chunk-truncated multibyte tail can never flip a verdict.
 */
#[CoversFunction('pfb_text_sanity')]
final class PfbTextSanityTest extends TestCase
{
	// -- Real blocklist samples -> NULL ------------------------------------------------

	public function test_plain_ipv4_cidr_list_is_sane(): void
	{
		$sample = "1.2.3.4\n5.6.7.0/24\n2001:db8::1\n";
		$this->assertNull(pfb_text_sanity($sample));
	}

	public function test_hosts_style_ip_domain_list_is_sane(): void
	{
		$sample = "0.0.0.0 ads.example.org\n0.0.0.0 tracker.example.net\n";
		$this->assertNull(pfb_text_sanity($sample));
	}

	public function test_abp_wrapped_domain_list_is_sane(): void
	{
		$sample = "||ads.example.org^\n||tracker.example.net^\n";
		$this->assertNull(pfb_text_sanity($sample));
	}

	public function test_single_legitimate_data_line_satisfies_the_floor(): void
	{
		// Floor = 1: one non-blank, non-comment line is a COMPLETE sample, not a
		// truncated/too-small one.
		$this->assertNull(pfb_text_sanity("0.0.0.0 x.example\n"));
	}

	public function test_tiny_few_byte_feed_is_not_size_penalised(): void
	{
		// A short body (well under the 8 KiB read cap) is a complete sample, never
		// penalised for its size — no "too small" heuristic exists.
		$this->assertNull(pfb_text_sanity("1.2.3.4\n"));
	}

	public function test_comment_header_then_data_is_sane(): void
	{
		// Comment lines never count toward the floor, but the trailing data line
		// satisfies it on its own.
		$sample = "# license\n# generated 2026-01-01\n0.0.0.0 x.example\n";
		$this->assertNull(pfb_text_sanity($sample));
	}

	// -- 'nul_bytes' --------------------------------------------------------------------

	public function test_embedded_nul_byte_is_flagged(): void
	{
		$this->assertSame('nul_bytes', pfb_text_sanity("1.2.3.4\n\x00garbage"));
	}

	public function test_nul_byte_wins_over_otherwise_valid_blocklist_text(): void
	{
		// Proves NUL is checked FIRST: an otherwise-perfect blocklist body still
		// flags nul_bytes the moment one NUL byte is present.
		$sample = "0.0.0.0 ads.example.org\n0.0.0.0 tracker.example.net\n\x00\n0.0.0.0 more.example\n";
		$this->assertSame('nul_bytes', pfb_text_sanity($sample));
	}

	// -- 'html_error_page' ---------------------------------------------------------------

	public function test_html_error_page_with_no_blocklist_line_is_flagged(): void
	{
		$sample = "<!doctype html>\n<html><body><h1>404 Not Found</h1></body></html>\n";
		$this->assertSame('html_error_page', pfb_text_sanity($sample));
	}

	public function test_html_tag_lowercase_is_flagged(): void
	{
		$sample = "<html><body>Forbidden</body></html>\n";
		$this->assertSame('html_error_page', pfb_text_sanity($sample));
	}

	public function test_html_tag_uppercase_is_flagged(): void
	{
		$sample = "<HTML><BODY>FORBIDDEN</BODY></HTML>\n";
		$this->assertSame('html_error_page', pfb_text_sanity($sample));
	}

	public function test_html_tag_mixed_case_is_flagged(): void
	{
		$sample = "<HtMl><body>captcha required</body></html>\n";
		$this->assertSame('html_error_page', pfb_text_sanity($sample));
	}

	public function test_html_tag_with_leading_whitespace_and_newlines_is_flagged(): void
	{
		// Leading whitespace/newlines before the tag are tolerated (left-trim).
		$sample = "\n\n   \t<html><body>error</body></html>\n";
		$this->assertSame('html_error_page', pfb_text_sanity($sample));
	}

	public function test_html_body_with_a_blocklist_line_is_not_flagged(): void
	{
		// The false-positive guard: an HTML-ish feed that DOES carry a
		// blocklist-shaped line within its first 20 lines must NOT be flagged.
		$sample = "<html><body>\n0.0.0.0 ads.example.org\n</body></html>\n";
		$this->assertNull(pfb_text_sanity($sample));
	}

	// -- 'below_min_content' --------------------------------------------------------------

	public function test_empty_string_is_below_min_content(): void
	{
		$this->assertSame('below_min_content', pfb_text_sanity(''));
	}

	public function test_whitespace_only_is_below_min_content(): void
	{
		$this->assertSame('below_min_content', pfb_text_sanity("   \n\t\n  \n"));
	}

	public function test_comment_only_body_is_below_min_content(): void
	{
		// '#' and '!' comment lines never count toward the floor; zero data lines
		// means the floor of 1 is never met.
		$this->assertSame('below_min_content', pfb_text_sanity("# a\n! b\n"));
	}

	// -- Verdict order proof (nul_bytes -> html_error_page -> below_min_content) ---------

	public function test_nul_bearing_html_error_page_flags_nul_first(): void
	{
		$sample = "<!doctype html>\n\x00\n<html><body>error</body></html>\n";
		$this->assertSame('nul_bytes', pfb_text_sanity($sample));
	}

	public function test_all_comment_html_less_body_flags_below_min(): void
	{
		// No NUL, no HTML opening tag -> falls through to the content floor.
		$this->assertSame('below_min_content', pfb_text_sanity("# nothing here\n! still nothing\n"));
	}

	// -- Byte-level (no /u) truncation cases ----------------------------------------------
	//
	// Each makes the truncated/multibyte tail the SOLE floor candidate (a comment
	// header precedes it), so NULL genuinely depends on the scanner reaching and
	// correctly handling that tail -- not short-circuiting on an earlier data line.
	// That is what makes them fail on a byte-level regression rather than pass
	// vacuously on any implementation of the floor loop.

	public function test_truncated_mid_token_line_is_the_sole_floor_candidate(): void
	{
		// 8180 bytes of comments, then a data line cut mid-token by the 8 KiB read
		// cap. The truncated "0.0.0.0 fill" is the ONLY non-comment line, so NULL
		// proves the floor loop counted the truncated tail as content; a mis-split
		// of it would flip the verdict to below_min_content.
		$header = str_repeat("# c\n", 2045);                              // 8180 bytes, all comments
		$sample = substr($header . "0.0.0.0 filler.example.org\n", 0, 8192);
		$lines  = explode("\n", $sample);
		// Guard the construction: the deciding line really is the mid-token cut, not
		// a line dropped past the cap -- else the test would silently retest comments.
		$this->assertSame('0.0.0.0 fill', end($lines), 'setup drift: final line must be the mid-token cut');
		$this->assertNull(pfb_text_sanity($sample), 'a truncated sole data line still meets the content floor');
	}

	public function test_dangling_partial_multibyte_tail_stays_byte_level(): void
	{
		// A split multibyte UTF-8 char (lead byte 0xC3, no continuation) ends the
		// SOLE data line. A /u regression on the preg_split would make PCRE reject
		// the invalid-UTF-8 subject -> FALSE -> zero lines -> below_min_content, so
		// NULL proves the split stayed byte-level AND the tailed line was reached.
		$sample = str_repeat("# c\n", 2045) . "0.0.0.0 x.example\xC3";
		$this->assertNull(pfb_text_sanity($sample), 'a dangling multibyte tail must not flip the verdict');
	}

	public function test_html_opening_with_multibyte_tailed_blocklist_line_stays_byte_level(): void
	{
		// The html branch runs preg_match($blocklist_shaped) per line. An html-opening
		// body whose only blocklist-shaped line ends in a dangling multibyte byte must
		// still match byte-level and yield NULL -- NOT html_error_page. A /u regression
		// on $blocklist_shaped would make preg_match reject the invalid-UTF-8 subject,
		// find no blocklist line, and wrongly return html_error_page (test flips red).
		$sample = "<html>\n0.0.0.0 real.example\xC3\n";
		$this->assertNull(pfb_text_sanity($sample), 'byte-level blocklist match must survive a multibyte tail');
	}
}
