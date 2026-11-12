package feedparse

import "strings"

// str_getcsv($line, ',', '"', '"'): PHP's php_fgetcsv() on one string under the C locale (every byte one character).
// A line that is only a line ending has no fields; PHP returns [NULL], which csvExtract reads as one empty field.
func phpStrGetCSV(buf string) []string {
	const delim, encl, esc byte = ',', '"', '"'
	at := func(i int) byte {
		if i < len(buf) {
			return buf[i]
		}
		return 0 // the string's terminating NUL
	}
	isSpace := func(c byte) bool { return c == ' ' || (c >= 0x09 && c <= 0x0D) }
	// php_fgetcsv_lookup_trailing_spaces(): the text without one final \n, \r\n or \r.
	trimEnd := func(s string) int {
		switch {
		case strings.HasSuffix(s, "\r\n"):
			return len(s) - 2
		case strings.HasSuffix(s, "\n"), strings.HasSuffix(s, "\r"):
			return len(s) - 1
		}
		return len(s)
	}
	sub := func(a, b int) string { // C reads up to the NUL; clamp instead of panicking
		a, b = min(max(a, 0), len(buf)), min(max(b, 0), len(buf))
		if a > b {
			return ""
		}
		return buf[a:b]
	}
	limit := trimEnd(buf)
	lineEnd := limit
	lineEndLen := len(buf) - limit
	inc := func(bptr int) int {
		if bptr < limit {
			return 1
		}
		return 0
	}

	var values []string
	first := true
	bptr := 0
	for {
		var temp []byte
		incLen := inc(bptr)
		if incLen == 1 {
			t := bptr
			for at(t) != delim && isSpace(at(t)) {
				t++
			}
			if at(t) == encl && t < limit {
				bptr = t
			}
		}
		if first && bptr == lineEnd {
			return []string{""}
		}
		first = false

		var field string
		if incLen != 0 && at(bptr) == encl {
			state := 0
			bptr++
			hunk := bptr
		scan:
			for {
				if incLen == 0 {
					switch state {
					case 2:
						temp = append(temp, sub(hunk, bptr-1)...)
						hunk = bptr
						break scan
					case 1:
						temp = append(temp, sub(hunk, bptr)...)
						hunk = bptr
						fallthrough
					default:
						if hunk != lineEnd {
							temp = append(temp, sub(hunk, bptr)...)
							hunk = bptr
						}
						temp = append(temp, sub(lineEnd, lineEnd+lineEndLen)...)
						if bptr > limit { // an unterminated enclosure
							if hunk == bptr {
								hunk--
							}
							bptr--
						}
						break scan
					}
				}
				switch state {
				case 1: // escaped
					bptr++
					state = 0
				case 2: // an embedded enclosure?
					if at(bptr) != encl {
						temp = append(temp, sub(hunk, bptr-1)...)
						hunk = bptr
						break scan
					}
					temp = append(temp, sub(hunk, bptr)...)
					bptr++
					hunk = bptr
					state = 0
				default:
					if at(bptr) == encl {
						state = 2
					} else if at(bptr) == esc {
						state = 1
					}
					bptr++
				}
				incLen = inc(bptr)
			}
			for incLen != 0 && at(bptr) != delim {
				bptr += incLen
				incLen = inc(bptr)
			}
			temp = append(temp, sub(hunk, bptr)...)
			bptr += incLen
			field = string(temp)
		} else {
			hunk := bptr
			for incLen != 0 && at(bptr) != delim {
				bptr += incLen
				incLen = inc(bptr)
			}
			temp = append(temp, sub(hunk, bptr)...)
			field = string(temp[:trimEnd(string(temp))])
			if at(bptr) == delim {
				bptr++
			}
		}
		values = append(values, field)
		if incLen <= 0 {
			return values
		}
	}
}

// pfb_dnsbl_hash_line_classify(): the side effects of a '#' line.
type hashClass struct {
	stop, revFormat, csvParser bool
	csvType                    string // "" when the line names none
}

func hashLineClassify(line string) hashClass {
	if strings.Contains(line, "Append critical updates below") {
		return hashClass{stop: true}
	}
	h := hashClass{revFormat: strings.Contains(line, "The Spamhaus Project Ltd")}
	if line == "#family,type,url,status,first_seen,first_active,last_active,last_update" {
		h.csvType, h.csvParser = "h3x", true
	}
	return h
}

// csvExtract is pfb_dnsbl_csv_extract(): the upstream-CSV classify/extract switch. line is the (possibly replaced)
// line; the bool says the caller drops the line. A Ponomocup IP column is collected into out.
func (p *DNSBLParser) csvExtract(line string, csvline []string, out *DNSBLLine) (string, bool) {
	if !p.csvParser {
		return line, false
	}
	found := false
	n := len(csvline)
	switch p.csvType {
	case "pt":
		if n == 8 {
			line = strings.ReplaceAll(csvline[1], " ", "")
			found = true
		}
	case "bbc":
		if n == 4 {
			line, found = csvline[0], true
		}
	case "h3x":
		if n == 8 {
			line = csvline[2]
			if strings.Contains(line, "btc://") {
				return line, true
			}
			found = true
		}
	case "otx":
		if n == 3 {
			switch csvline[0] {
			case "domain", "hostname", "URL":
				line, found = csvline[1], true
			default:
				return line, true
			}
		}
	case "pon":
		if n == 9 {
			line, found = csvline[2], true
			if p.cfg.DNSBLIP {
				p.collectFeedIP(csvline[0], line, out)
			}
		}
	case "et":
		if n == 3 {
			line, found = csvline[0], true
		}
	default:
		fourth := ""
		if n > 3 {
			fourth = csvline[3]
		}
		switch {
		case strings.Contains(line, "phish_id,url,phish_detail_url"):
			p.csvType = "pt"
			return line, true
		case strings.Contains(fourth, "osint.bambenekconsulting.com"):
			p.csvType = "bbc"
			line, found = csvline[0], true
		case line == "Indicator type,Indicator,Description":
			p.csvType = "otx"
			return line, true
		case strings.Contains(csvline[0], "timestamp"):
			p.csvType = "pon"
			return line, true
		case line == "domain, category, score":
			p.csvType = "et"
			return line, true
		default:
			p.csvParser, p.runOnce = false, false
		}
	}
	if !found || phpEmpty(p.csvType) {
		p.fail(out, "")
		return line, true
	}
	return line, false
}
