package main

import (
	"flag"
	"reflect"
	"testing"
)

func TestBlacklistDatabaseDirectoryIsAnExplicitFeedFlag(t *testing.T) {
	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	got := addFeedFlags(flags)
	if err := flags.Parse([]string{"--feed-blacklist-dir", "/var/db/pfblockerng/."}); err != nil {
		t.Fatalf("parse blacklist directory flag: %v", err)
	}
	value := reflect.ValueOf(got).Elem().FieldByName("BlacklistDir")
	if !value.IsValid() || value.Kind() != reflect.String || value.String() != "/var/db/pfblockerng" {
		t.Fatalf("feedFlags.BlacklistDir = %v, want cleaned absolute database directory", value)
	}
}
