//go:build linux || freebsd

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/hooks"
)

// hookEnv runs one recording hook at when with c and returns the PFB_* lifecycle entries it saw.
func hookEnv(t *testing.T, when string, c hooks.Context) map[string]string {
	t.Helper()
	dir := t.TempDir()
	record, script := filepath.Join(dir, "record"), "hook_"+when+"_r.sh"
	body := "#!/bin/sh\nprintf '%s\\n' \"$PFB_POST_INSTALL\" \"$PFB_PRE_UNINSTALL\" \"$PFB_PKG_OP\" > '" + record + "'\n"
	if err := os.WriteFile(filepath.Join(dir, script), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute) // only salvages a hung run
	defer cancel()
	hooks.Runner{Dir: dir}.Run(ctx, when, []hooks.Hook{{When: when, Script: script, Enabled: true}}, c)
	got, err := os.ReadFile(record)
	if err != nil {
		t.Fatalf("the hook did not run: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(string(got), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("the hook recorded %q", got)
	}
	return map[string]string{"PFB_POST_INSTALL": lines[0], "PFB_PRE_UNINSTALL": lines[1], "PFB_PKG_OP": lines[2]}
}

// WHEN StartUpdate carries lifecycle install and a pkgOp THEN the worker's request carries both, and the hooks of that
// Update, given a Context built from that request, see PFB_POST_INSTALL=1 and that PFB_PKG_OP. WHEN it carries neither
// (or an empty pkgOp) THEN the request has neither, both lifecycle flags are 0 and PFB_PKG_OP is empty.
func TestStartUpdateCarriesTheLifecycleAndThePkgOpToTheUpdatesHooks(t *testing.T) {
	for _, tc := range []struct {
		trigger, params, request string
		post, op                 string
	}{
		{"manual", ``, `{"version":1,"trigger":"manual","scope":"both","force":"none"}`, "0", ""},
		{"manual", `,"pkgOp":""`, `{"version":1,"trigger":"manual","scope":"both","force":"none"}`, "0", ""},
		{"manual", `,"lifecycle":"install"`,
			`{"version":1,"trigger":"manual","scope":"both","force":"none","lifecycle":"install"}`, "1", ""},
		{"manual", `,"lifecycle":"install","pkgOp":"install"`,
			`{"version":1,"trigger":"manual","scope":"both","force":"none","lifecycle":"install","pkgOp":"install"}`, "1",
			"install"},
		{"manual", `,"lifecycle":"install","pkgOp":"upgrade"`,
			`{"version":1,"trigger":"manual","scope":"both","force":"none","lifecycle":"install","pkgOp":"upgrade"}`, "1",
			"upgrade"},
		{"manual", `,"lifecycle":"install","pkgOp":"reinstall"`,
			`{"version":1,"trigger":"manual","scope":"both","force":"none","lifecycle":"install","pkgOp":"reinstall"}`, "1",
			"reinstall"},
		{"manual", `,"pkgOp":"delete"`,
			`{"version":1,"trigger":"manual","scope":"both","force":"none","pkgOp":"delete"}`, "0", "delete"},
		{"apply", `,"lifecycle":"install","pkgOp":"upgrade"`,
			`{"version":1,"trigger":"apply","scope":"both","force":"none","lifecycle":"install","pkgOp":"upgrade"}`, "1",
			"upgrade"},
		{"retry", `,"lifecycle":"install","pkgOp":"install"`, "", "1", "install"}, // the Extras due vary with the clock
	} {
		t.Run(tc.trigger+tc.params, func(t *testing.T) {
			c, f := startUpdateCore(t)
			if tc.trigger == "retry" {
				c.initialize()
			}
			f.release()
			wantJSON(t, c.post("StartUpdate", fmt.Sprintf(`{"requestId":"p","trigger":%q%s}`, tc.trigger, tc.params)),
				http.StatusOK, `{}`)
			c.waitFinished(tc.trigger)
			if tc.request != "" {
				sameJSON(t, f.request(), tc.request)
			}

			var req struct {
				Lifecycle string `json:"lifecycle"`
				PkgOp     string `json:"pkgOp"`
			}
			if err := json.Unmarshal([]byte(f.request()), &req); err != nil {
				t.Fatal(err)
			}
			want := map[string]string{"PFB_POST_INSTALL": tc.post, "PFB_PRE_UNINSTALL": "0", "PFB_PKG_OP": tc.op}
			for _, when := range []string{"pre", "post"} {
				got := hookEnv(t, when, hooks.Context{Lifecycle: req.Lifecycle, PkgOp: req.PkgOp})
				if fmt.Sprint(got) != fmt.Sprint(want) {
					t.Errorf("%s hook of the Update saw %v, want %v", when, got, want)
				}
			}
		})
	}
}

// WHEN StartUpdate carries a lifecycle or a pkgOp outside the vocabulary THEN it answers invalid_argument naming the
// field and admits nothing.
func TestStartUpdateRefusesALifecycleOrPkgOpOutsideTheVocabulary(t *testing.T) {
	c, f := startUpdateCore(t)
	for i, tc := range []struct{ params, field string }{
		{`"lifecycle":"uninstall"`, "lifecycle"}, // the uninstall runs its hooks through the one-shot, never an Update
		{`"lifecycle":""`, "lifecycle"},
		{`"lifecycle":"INSTALL"`, "lifecycle"},
		{`"lifecycle":1`, "lifecycle"},
		{`"pkgOp":"remove"`, "pkgOp"},
		{`"pkgOp":"Install"`, "pkgOp"},
		{`"pkgOp":" install"`, "pkgOp"},
		{`"pkgOp":true`, "pkgOp"},
	} {
		body := fmt.Sprintf(`{"requestId":"bad%d","trigger":"manual",%s}`, i, tc.params)
		wantError(t, c.post("StartUpdate", body), http.StatusBadRequest, codeInvalidArgument, tc.field)
	}
	if n := f.runs(); n != 0 {
		t.Errorf("the program ran %d times for requests that were refused, want 0", n)
	}
	wantJSON(t, c.post("GetUpdate", `{}`), http.StatusOK, `{"running":false,"update":null,"log":"","next":"0"}`)
}
