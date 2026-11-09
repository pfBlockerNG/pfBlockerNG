// The ipaddress module's parsing of an address text (Python 3.11 Lib/ipaddress.py), error text included.
package pysem

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// IPAddress is the packed value of ipaddress.ip_address(text): 4 bytes for an IPv4 address, else 16 for an IPv6 one.
func IPAddress(text string) ([]byte, error) {
	if ip, err := IPv4Address(text); err == nil {
		return binary.BigEndian.AppendUint32(nil, ip), nil
	}
	if ip, err := IPv6Address(text); err == nil {
		return ip, nil
	}
	return nil, fmt.Errorf("%s does not appear to be an IPv4 or IPv6 address", Repr(text))
}

// IPv4Address is the value of ipaddress.IPv4Address(address).
func IPv4Address(address string) (uint32, error) {
	if strings.Contains(address, "/") {
		return 0, fmt.Errorf("Unexpected '/' in %s", Repr(address))
	}
	if address == "" {
		return 0, errors.New("Address cannot be empty")
	}
	octets := strings.Split(address, ".")
	if len(octets) != 4 {
		return 0, fmt.Errorf("Expected 4 octets in %s", Repr(address))
	}
	var value uint32
	for _, octet := range octets {
		number, err := parseOctet(octet)
		if err != nil {
			return 0, fmt.Errorf("%s in %s", err, Repr(address))
		}
		value = value<<8 | uint32(number)
	}
	return value, nil
}

func parseOctet(octet string) (int, error) {
	if octet == "" {
		return 0, errors.New("Empty octet not permitted")
	}
	if !IsASCIIDigits(octet) {
		return 0, fmt.Errorf("Only decimal digits permitted in %s", Repr(octet))
	}
	if len(octet) > 3 {
		return 0, fmt.Errorf("At most 3 characters permitted in %s", Repr(octet))
	}
	if octet != "0" && octet[0] == '0' {
		return 0, fmt.Errorf("Leading zeros are not permitted in %s", Repr(octet))
	}
	number := 0
	for i := range len(octet) {
		number = number*10 + int(octet[i]-'0')
	}
	if number > 255 {
		return 0, fmt.Errorf("Octet %d (> 255) not permitted", number)
	}
	return number, nil
}

const _HEXTET_COUNT = 8

// IPv6Address is the packed form of ipaddress.IPv6Address(address); a %scope id is validated and dropped.
func IPv6Address(address string) ([]byte, error) {
	if strings.Contains(address, "/") {
		return nil, fmt.Errorf("Unexpected '/' in %s", Repr(address))
	}
	ipStr, scopeID, hasScope := strings.Cut(address, "%")
	if hasScope && (scopeID == "" || strings.Contains(scopeID, "%")) {
		return nil, fmt.Errorf("Invalid IPv6 address: \"%s\"", Repr(address))
	}

	if ipStr == "" {
		return nil, errors.New("Address cannot be empty")
	}
	if chars := []rune(ipStr); len(chars) > 45 {
		shorten := ipStr
		if len(chars) > 100 {
			shorten = fmt.Sprintf("%s(%d chars elided)%s", string(chars[:45]), len(chars)-90, string(chars[len(chars)-45:]))
		}
		return nil, fmt.Errorf("At most 45 characters expected in %s", Repr(shorten))
	}

	// more parts than the max are split off to keep the right error message for too many parts combined with '::'
	maxParts := _HEXTET_COUNT + 1
	parts := strings.SplitN(ipStr, ":", maxParts+1)

	// An IPv6 address needs at least 2 colons (3 parts).
	const minParts = 3
	if len(parts) < minParts {
		return nil, fmt.Errorf("At least %d parts expected in %s", minParts, Repr(ipStr))
	}

	// If the address has an IPv4-style suffix, convert it to hexadecimal.
	if strings.Contains(parts[len(parts)-1], ".") {
		ipv4Int, err := IPv4Address(parts[len(parts)-1])
		if err != nil {
			return nil, fmt.Errorf("%s in %s", err, Repr(ipStr))
		}
		parts = append(parts[:len(parts)-1], fmt.Sprintf("%x", (ipv4Int>>16)&0xFFFF), fmt.Sprintf("%x", ipv4Int&0xFFFF))
	}

	// An IPv6 address can't have more than 8 colons (9 parts). The extra colon comes from using the "::" notation
	// for a single leading or trailing zero part.
	if len(parts) > maxParts {
		return nil, fmt.Errorf("At most %d colons permitted in %s", maxParts-1, Repr(ipStr))
	}

	// Disregarding the endpoints, find '::' with nothing in between: a run of zeroes has been skipped.
	skipIndex := -1
	for i := 1; i < len(parts)-1; i++ {
		if parts[i] == "" {
			if skipIndex != -1 {
				return nil, fmt.Errorf("At most one '::' permitted in %s", Repr(ipStr))
			}
			skipIndex = i
		}
	}

	// partsHi parts are copied from before the '::', partsLo from after it.
	var partsHi, partsLo, partsSkipped int
	if skipIndex != -1 {
		partsHi = skipIndex
		partsLo = len(parts) - skipIndex - 1
		if parts[0] == "" {
			partsHi--
			if partsHi != 0 {
				return nil, fmt.Errorf("Leading ':' only permitted as part of '::' in %s", Repr(ipStr))
			}
		}
		if parts[len(parts)-1] == "" {
			partsLo--
			if partsLo != 0 {
				return nil, fmt.Errorf("Trailing ':' only permitted as part of '::' in %s", Repr(ipStr))
			}
		}
		partsSkipped = _HEXTET_COUNT - (partsHi + partsLo)
		if partsSkipped < 1 {
			return nil, fmt.Errorf("Expected at most %d other parts with '::' in %s", _HEXTET_COUNT-1, Repr(ipStr))
		}
	} else {
		// The endpoints could still be empty, but parseHextet will check for that.
		if len(parts) != _HEXTET_COUNT {
			return nil, fmt.Errorf("Exactly %d parts expected without '::' in %s", _HEXTET_COUNT, Repr(ipStr))
		}
		if parts[0] == "" {
			return nil, fmt.Errorf("Leading ':' only permitted as part of '::' in %s", Repr(ipStr))
		}
		if parts[len(parts)-1] == "" {
			return nil, fmt.Errorf("Trailing ':' only permitted as part of '::' in %s", Repr(ipStr))
		}
		partsHi = len(parts)
	}

	packed := make([]byte, 0, 16)
	for _, part := range parts[:partsHi] {
		hextet, err := parseHextet(part)
		if err != nil {
			return nil, fmt.Errorf("%s in %s", err, Repr(ipStr))
		}
		packed = binary.BigEndian.AppendUint16(packed, hextet)
	}
	packed = append(packed, make([]byte, 2*partsSkipped)...)
	for _, part := range parts[len(parts)-partsLo:] {
		hextet, err := parseHextet(part)
		if err != nil {
			return nil, fmt.Errorf("%s in %s", err, Repr(ipStr))
		}
		packed = binary.BigEndian.AppendUint16(packed, hextet)
	}
	return packed, nil
}

func parseHextet(hextet string) (uint16, error) {
	var value uint16
	for i := range len(hextet) {
		c := hextet[i]
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
			return 0, fmt.Errorf("Only hex digits permitted in %s", Repr(hextet))
		}
	}
	if len(hextet) > 4 {
		return 0, fmt.Errorf("At most 4 characters permitted in %s", Repr(hextet))
	}
	if hextet == "" {
		return 0, errors.New("invalid literal for int() with base 16: ''")
	}
	for i := range len(hextet) {
		c := hextet[i]
		switch {
		case c <= '9':
			c -= '0'
		case c <= 'F':
			c = c - 'A' + 10
		default:
			c = c - 'a' + 10
		}
		value = value<<4 | uint16(c)
	}
	return value, nil
}
