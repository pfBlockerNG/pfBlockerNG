<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfbng_text_area_decode() — the Custom_List/whitelist textarea decoder: base64
 * in, CRLF-split, '#'-comment handling, lower-casing, optional IDN->punycode.
 *
 * $mode: FALSE => newline-joined string; TRUE => array.
 * $type (mode only): TRUE => per-line [value(, '#comment')]; FALSE => bare value.
 * $idn:  TRUE  => convert non-ASCII hostnames to punycode (idn_to_ascii).
 */
#[CoversFunction('pfbng_text_area_decode')]
final class TextAreaDecodeTest extends TestCase
{
    /** Encode like a browser textarea: lines joined by CRLF, then base64. */
    private static function enc(string ...$lines): string
    {
        return base64_encode(implode("\r\n", $lines));
    }

    public function testStringModeLowercasesJoinsAndStripsComments(): void
    {
        $in = self::enc('EXAMPLE.COM', 'foo.com', '# whole-line comment', 'bar.com # inline');
        // Whole-line comment dropped; inline comment trimmed off; all lower-cased.
        $this->assertSame("example.com\nfoo.com\nbar.com\n", pfbng_text_area_decode($in));
    }

    public function testStringModeSkipsEmptyLines(): void
    {
        $in = self::enc('a.com', '', 'b.com');
        $this->assertSame("a.com\nb.com\n", pfbng_text_area_decode($in));
    }

    public function testArrayModeBareValues(): void
    {
        $in = self::enc('Foo.com', '# c', 'bar.com # x');
        // mode=TRUE, type=FALSE => array of bare, comment-stripped, lower values.
        $this->assertSame(['foo.com', 'bar.com'], pfbng_text_area_decode($in, true, false));
    }

    public function testArrayModeTypedNonCommentWrapsInArray(): void
    {
        $in = self::enc('Foo.com');
        // mode=TRUE, type=TRUE => each non-comment line becomes [value].
        $this->assertSame([['foo.com']], pfbng_text_area_decode($in, true, true));
    }

    public function testArrayModeTypedCommentSplit(): void
    {
        $in = self::enc('bar.com # note');
        // Comment line splits into [value, '#comment'] via pfb_strtolower: the
        // value is trimmed+lowered, the '#'-bearing token kept (trimmed) verbatim.
        $this->assertSame([['bar.com', '# note']], pfbng_text_area_decode($in, true, true));
    }

    public function testIdnConversionToPunycode(): void
    {
        // The IDN branch is gated on !ctype_print(), which is locale-sensitive.
        // pfSense's PHP CLI runs under the C locale (high bytes non-printable),
        // so pin that to make the conversion deterministic on any host.
        $prev = setlocale(LC_CTYPE, '0');
        setlocale(LC_CTYPE, 'C');
        try {
            $in = self::enc('bücher.de');
            $this->assertSame("xn--bcher-kva.de\n", pfbng_text_area_decode($in, false, true, true));
        } finally {
            setlocale(LC_CTYPE, $prev);
        }
    }

    public function testEmptyInputReturnsNull(): void
    {
        // base64('') => '' => explode gives [''] => nothing appended => $custom
        // never initialised in string mode => implicit null return.
        $this->assertNull(pfbng_text_area_decode(''));
    }
}
