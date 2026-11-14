package main

import (
	"flag"
	"reflect"
	"testing"
)

func TestFeedPhaseDirectoriesAreExplicitFlags(t *testing.T) {
	fl := flag.NewFlagSet("test", flag.ContinueOnError)
	got := addFeedFlags(fl)
	err := fl.Parse([]string{
		"--feed-orig-dir", "/var/db/pfblockerng/original/.",
		"--dnsbl-orig-dir", "/var/db/pfblockerng/dnsblorig",
		"--feed-db-dir", "/var/db/pfblockerng",
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"OrigDir":      "/var/db/pfblockerng/original",
		"DNSBLOrigDir": "/var/db/pfblockerng/dnsblorig",
		"DBDir":        "/var/db/pfblockerng",
	} {
		value := reflect.ValueOf(got).Elem().FieldByName(name)
		if !value.IsValid() || value.Kind() != reflect.String || value.String() != want {
			t.Errorf("feedFlags.%s = %v, want %q", name, value, want)
		}
	}
}
