package geoip

import (
	"bytes"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// The PHP semantics pfblockerng_uc_countries() relies on, for the strings fgetcsv() gives it. A column the row does not
// have is PHP's null, which every one of these reads as "".

// empty is PHP's empty() on a string: "" and "0".
func empty(s string) bool { return s == "" || s == "0" }

// numericString is PHP 8's numeric string: optional leading and trailing white space around a decimal number.
var numericString = regexp.MustCompile(`^[ \t\n\r\v\f]*[+-]?([0-9]+(\.[0-9]*)?|\.[0-9]+)([eE][+-]?[0-9]+)?[ \t\n\r\v\f]*$`)

var integerString = regexp.MustCompile(`^[ \t\n\r\v\f]*[+-]?[0-9]+[ \t\n\r\v\f]*$`)

// number is a numeric string's value: an int when PHP holds it as one, else a float; overflow is the sign of an integer
// spelling past int64 (PHP's oflow).
func number(s string) (i int64, f float64, isInt bool, overflow int) {
	t := strings.Trim(s, " \t\n\r\v\f")
	if n, err := strconv.ParseInt(t, 10, 64); err == nil {
		return n, float64(n), true, 0
	}
	f, _ = strconv.ParseFloat(t, 64)
	if integerString.MatchString(s) {
		overflow = 1
		if strings.HasPrefix(t, "-") {
			overflow = -1
		}
	}
	return 0, f, false, overflow
}

// equal is PHP 8's == between two strings (zendi_smart_str_equals): numerically when both are numeric strings, else
// byte for byte. An integer spelling past int64 never equals an int, and two past it on the same side that meet as
// floats are compared as text.
func equal(a, b string) bool {
	if !numericString.MatchString(a) || !numericString.MatchString(b) {
		return a == b
	}
	ai, af, aInt, aOver := number(a)
	bi, bf, bInt, bOver := number(b)
	switch {
	case aInt && bInt:
		return ai == bi
	case aInt && bOver != 0, bInt && aOver != 0:
		return false
	case aOver != 0 && aOver == bOver && af == bf, !aInt && !bInt && af == bf && math.IsInf(af, 0):
		return a == b
	}
	return af == bf
}

// isOne is PHP 8's $s == 1.
func isOne(s string) bool {
	if !numericString.MatchString(s) {
		return false
	}
	_, f, _, _ := number(s)
	return f == 1
}

// word is pfb_filter($s, PFB_FILTER_WORD) answering a non-empty value: letters, digits and underscores only.
func word(s string) bool {
	if empty(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

// trim is PHP's trim() with its default characters.
func trim(s string) string { return strings.Trim(s, " \t\n\r\x00\x0b") }

// countLines is pfb_count_lines() on content: its line feeds, plus one for a last line without one.
func countLines(b []byte) int {
	n := bytes.Count(b, []byte{'\n'})
	if len(b) > 0 && b[len(b)-1] != '\n' {
		n++
	}
	return n
}

// natCompare is PHP's strnatcmp_ex() (ext/standard/strnatcmp.c), case-sensitive: the comparison ksort(SORT_NATURAL)
// sorts the countries with.
func natCompare(a, b string) int {
	if len(a) == 0 || len(b) == 0 {
		switch {
		case len(a) == len(b):
			return 0
		case len(a) > len(b):
			return 1
		}
		return -1
	}
	at := func(s string, i int) byte { // a C string reads its terminating NUL past the end
		if i < len(s) {
			return s[i]
		}
		return 0
	}
	digit := func(c byte) bool { return c >= '0' && c <= '9' }
	space := func(c byte) bool { return c == ' ' || c >= '\t' && c <= '\r' }
	ap, bp := 0, 0
	leading := true
	for {
		ca, cb := at(a, ap), at(b, bp)
		for leading && ca == '0' && ap+1 < len(a) && digit(a[ap+1]) {
			ap++
			ca = a[ap]
		}
		for leading && cb == '0' && bp+1 < len(b) && digit(b[bp+1]) {
			bp++
			cb = b[bp]
		}
		leading = false
		for space(ca) {
			ap++
			ca = at(a, ap)
		}
		for space(cb) {
			bp++
			cb = at(b, bp)
		}
		if digit(ca) && digit(cb) {
			var result int
			if ca == '0' || cb == '0' {
				result = compareLeft(a, &ap, b, &bp)
			} else {
				result = compareRight(a, &ap, b, &bp)
			}
			switch {
			case result != 0:
				return result
			case ap == len(a) && bp == len(b):
				return 0
			case ap == len(a):
				return -1
			case bp == len(b):
				return 1
			}
			ca, cb = a[ap], b[bp]
		}
		if ca < cb {
			return -1
		} else if ca > cb {
			return 1
		}
		ap++
		bp++
		switch {
		case ap >= len(a) && bp >= len(b):
			return 0
		case ap >= len(a):
			return -1
		case bp >= len(b):
			return 1
		}
	}
}

func runEnds(s string, i int) bool { return i >= len(s) || s[i] < '0' || s[i] > '9' }

// compareRight compares two runs of digits as integers: the longer run wins, else the first difference.
func compareRight(a string, ap *int, b string, bp *int) int {
	bias := 0
	for ; ; *ap, *bp = *ap+1, *bp+1 {
		aEnd, bEnd := runEnds(a, *ap), runEnds(b, *bp)
		switch {
		case aEnd && bEnd:
			return bias
		case aEnd:
			return -1
		case bEnd:
			return 1
		case bias == 0 && a[*ap] < b[*bp]:
			bias = -1
		case bias == 0 && a[*ap] > b[*bp]:
			bias = 1
		}
	}
}

// compareLeft compares two runs of digits as fractions: the first difference wins.
func compareLeft(a string, ap *int, b string, bp *int) int {
	for ; ; *ap, *bp = *ap+1, *bp+1 {
		aEnd, bEnd := runEnds(a, *ap), runEnds(b, *bp)
		switch {
		case aEnd && bEnd:
			return 0
		case aEnd:
			return -1
		case bEnd:
			return 1
		case a[*ap] < b[*bp]:
			return -1
		case a[*ap] > b[*bp]:
			return 1
		}
	}
}
