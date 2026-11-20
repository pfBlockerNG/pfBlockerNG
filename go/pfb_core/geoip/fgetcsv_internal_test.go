package geoip

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
)

// The CSV reader against fgetcsv($handle, null, ",", "\"", "\\") on the same bytes (testdata/fgetcsv.json, written by
// today's PHP; tests/php/GeoipConversionCorpusTest.php holds it to PHP). PHP's [null] for a blank line is an empty
// record here: every reader of a row reads a missing field and a null one alike.
func TestTheCSVReaderIsFgetcsv(t *testing.T) {
	raw, err := os.ReadFile("testdata/fgetcsv.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		In      string      `json:"in"`
		Records [][]*string `json:"records"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("empty table")
	}
	decode := func(s string) string {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	for _, c := range cases {
		in := decode(c.In)
		want := [][]string{}
		for _, rec := range c.Records {
			fields := []string{}
			if !(len(rec) == 1 && rec[0] == nil) {
				for _, f := range rec {
					fields = append(fields, decode(*f))
				}
			}
			want = append(want, fields)
		}
		got := [][]string{}
		r := newCSVReader(strings.NewReader(in))
		for {
			rec, err := r.Read()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("%q: %v", in, err)
			}
			got = append(got, rec)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%q:\n got %q\nwant %q", in, got, want)
		}
	}
}
