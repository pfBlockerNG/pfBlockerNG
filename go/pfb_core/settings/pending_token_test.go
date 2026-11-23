package settings

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The platform's pending token (issue #4031, docs/specs/go-updater-pipeline.md §8.6): the adapter's read answers it beside the
// settings, the Update hands it back in the apply request, and the Outpost settles exactly that token. Core carries its JSON
// value as the adapter wrote it and never looks inside.

// tokenReply is a read reply whose platform member is the raw JSON platform ("" leaves the member out).
func tokenReply(t *testing.T, revision uint64, platform string) string {
	t.Helper()
	reply := strings.TrimSuffix(readReply(t, revision, nil), "}")
	if platform != "" {
		reply += `,"platform":` + platform
	}
	return reply + "}"
}

func TestTheStoreCarriesThePendingTokenOfTheLastReadAsTheAdapterWroteIt(t *testing.T) {
	f := newFakeAdapter(t, tokenReply(t, 7, `{"pendingToken":"0123456789abcdef"}`))
	st := loadFake(t, f, 0)
	if got := string(st.PendingToken()); got != `"0123456789abcdef"` {
		t.Fatalf("after Load PendingToken = %s, want the adapter's JSON string", got)
	}

	f.reply(tokenReply(t, 7, `{"pendingToken":"fedcba9876543210"}`))
	if _, err := st.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := string(st.PendingToken()); got != `"fedcba9876543210"` {
		t.Errorf("after Reload PendingToken = %s, want the token of the read that just ran", got)
	}
}

func TestAReplyWithoutATokenCarriesNone(t *testing.T) {
	for name, tc := range map[string]struct{ platform, want string }{
		"no platform member":     {"", ""},
		"an empty platform":      {`{}`, ""},
		"a null token":           {`{"pendingToken":null}`, "null"},
		"a null platform":        {`null`, ""},
		"an empty string":        {`{"pendingToken":""}`, `""`},
		"a number, uninspected":  {`{"pendingToken":12345678901234567890}`, `12345678901234567890`},
		"an object, uninspected": {`{"pendingToken":{"a":[1,"x"]}}`, `{"a":[1,"x"]}`},
	} {
		t.Run(name, func(t *testing.T) {
			st := loadFake(t, newFakeAdapter(t, tokenReply(t, 3, tc.platform)), 0)
			if got := string(st.PendingToken()); got != tc.want {
				t.Errorf("PendingToken = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAHostileTokenIsCarriedByteForByte(t *testing.T) {
	for name, token := range map[string]string{
		"one mebibyte":               `"` + strings.Repeat("a", 1<<20) + `"`,
		"escaped control characters": `"a\u0001b\nc\td\"e\\f\u007f\u0000"`,
		"escaped non-ASCII":          `"tökén 😀"`,
	} {
		t.Run(name, func(t *testing.T) {
			st := loadFake(t, newFakeAdapter(t, tokenReply(t, 3, `{"pendingToken":`+token+`}`)), 0)
			got := string(st.PendingToken())
			if len(got) != len(token) || got != token {
				t.Errorf("PendingToken has %d bytes, want the %d the adapter wrote, unchanged", len(got), len(token))
			}
		})
	}
}

func TestAPlatformMemberCoreDoesNotKnowRefusesTheRead(t *testing.T) {
	_, err := Load(&AdapterBackend{Path: newFakeAdapter(t, tokenReply(t, 3, `{"pendingToken":"t","other":1}`)).path}, Production())
	if isBackendError(err) == nil {
		t.Fatalf("Load = %v, want a *BackendError: the reply is strict", err)
	}
}

func TestTheCallerCannotChangeTheStoresToken(t *testing.T) {
	st := loadFake(t, newFakeAdapter(t, tokenReply(t, 3, `{"pendingToken":"abcdef"}`)), 0)
	got := st.PendingToken()
	got[1] = 'X'
	if again := string(st.PendingToken()); again != `"abcdef"` {
		t.Errorf("PendingToken = %s after a caller wrote into its copy, want the token unchanged", again)
	}
}

func TestTheFileBackendHasNoPendingToken(t *testing.T) {
	st, err := Open(t.TempDir(), Production())
	if err != nil {
		t.Fatal(err)
	}
	if got := st.PendingToken(); got != nil {
		t.Errorf("PendingToken = %s, want none: a standalone Core has no platform", got)
	}
}

// Core carries the token and nothing else: only the backend seam, the store, the Core Updater's snapshot and the request
// writer that hands it to the apply (issue #4038) name it, and none of them hands it to a formatter, a logger, a decoder
// or a comparison.
func TestNoCoreCodeInterpretsThePendingToken(t *testing.T) {
	holders := map[string]bool{"settings/adapter.go": true, "settings/backend.go": true, "settings/store.go": true,
		"update/loop.go": true, "update/stages.go": true, "update/apply/request.go": true}
	seen := 0
	err := filepath.WalkDir("..", func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel := filepath.ToSlash(strings.TrimPrefix(path, "../"))
		for n, line := range strings.Split(string(src), "\n") {
			code, _, _ := strings.Cut(line, "//")
			if !strings.Contains(strings.ToLower(code), "pendingtoken") {
				continue
			}
			seen++
			if !holders[rel] {
				t.Errorf("%s:%d names the pending token: only the settings backend seam, the store and the request writer carry it", rel, n+1)
			}
			for _, use := range []string{"fmt.", "log.", "slog.", "strconv.", "Unmarshal", "string(", "==", "!=", "bytes.", "strings."} {
				if strings.Contains(code, use) {
					t.Errorf("%s:%d uses %q on the pending token: Core does not interpret it\n\t%s", rel, n+1, use, strings.TrimSpace(line))
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen == 0 {
		t.Error("no production line names the pending token: the scan found nothing to judge")
	}
}

// WHEN the adapter's read answers platform.pendingApply THEN the store carries it until the next read, false when the member
// is absent; a value that is no JSON bool fails the read (issue #4038).
func TestTheStoreCarriesPendingApplyOfTheLastRead(t *testing.T) {
	f := newFakeAdapter(t, tokenReply(t, 7, `{"pendingToken":"0123456789abcdef","pendingApply":true}`))
	st := loadFake(t, f, 0)
	if !st.PendingApply() {
		t.Fatal("after Load PendingApply = false, want the adapter's true")
	}
	f.reply(tokenReply(t, 7, `{"pendingToken":null,"pendingApply":false}`))
	if _, err := st.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st.PendingApply() {
		t.Error("after Reload PendingApply = true, want the false of the read that just ran")
	}
	for name, platform := range map[string]string{"no platform member": "", "no pendingApply": `{"pendingToken":null}`} {
		if loadFake(t, newFakeAdapter(t, tokenReply(t, 3, platform)), 0).PendingApply() {
			t.Errorf("%s: PendingApply = true, want false", name)
		}
	}
	if _, err := (&AdapterBackend{Path: newFakeAdapter(t, tokenReply(t, 3, `{"pendingApply":"yes"}`)).path}).Read(context.Background()); err == nil {
		t.Error(`a read answering pendingApply "yes" succeeded`)
	}
}
