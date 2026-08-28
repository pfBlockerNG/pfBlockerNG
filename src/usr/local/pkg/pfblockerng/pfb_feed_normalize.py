"""Detect a downloaded feed file's encoding and convert it to UTF-8 (issue #1797).

Usage:
  /usr/local/pkg/pfblockerng/pfb_python.sh \
    /usr/local/pkg/pfblockerng/pfb_feed_normalize.py <src> <dst>

Runs only for files that already FAILED the iconv UTF-8 validity gate in
pfb_feed_normalize_generate(); the caller never hands it valid UTF-8.
Detection reads the WHOLE file via charset_normalizer.from_path() (a bounded
prefix mis-detects a long-ASCII-header file as ascii and loses every high
byte); conversion streams chunk-wise with errors='replace' so memory stays
bounded on multi-megabyte feeds.

stdout on success: "<detected-encoding> <replacement-count>\n", exit 0.
A nonzero replacement count means bytes the detected codec could not decode
were replaced with U+FFFD -- the caller logs it as a wrong-detection signal
(pre-existing U+FFFD in the input counts too; the signal stays a signal).
Any failure: message on stderr, exit 1, dst content undefined.
"""

from __future__ import annotations

import codecs
import sys


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: pfb_feed_normalize.py <src> <dst>", file=sys.stderr)
        return 1
    src, dst = argv[1], argv[2]

    try:
        from charset_normalizer import from_path
    except ImportError:
        print("charset_normalizer is not installed", file=sys.stderr)
        return 1

    try:
        best = from_path(src).best()
    except OSError as exc:
        print(f"detection failed: {exc}", file=sys.stderr)
        return 1
    if best is None:
        print("no encoding match", file=sys.stderr)
        return 1

    encoding = best.encoding
    replaced = 0
    try:
        decoder = codecs.getincrementaldecoder(encoding)("replace")
        with open(src, "rb") as fin, open(dst, "wb") as fout:
            while True:
                chunk = fin.read(1 << 20)
                text = decoder.decode(chunk, final=not chunk)
                if text:
                    replaced += text.count("\ufffd")
                    fout.write(text.encode("utf-8"))
                if not chunk:
                    break
    except (LookupError, OSError, ValueError) as exc:
        print(f"conversion failed: {exc}", file=sys.stderr)
        return 1

    print(f"{encoding} {replaced}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
