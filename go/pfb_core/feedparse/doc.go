// Package feedparse is Core's feed content stage (issue #3906, map #3813): it turns the bytes of a downloaded feed into
// the IP entries or DNSBL rows today's PHP and Python produce, line for line. The parity corpus in testdata/ pins every
// result; the PHP runners under tests/php replay the same corpus against the old path until the cutover removes it.
package feedparse
