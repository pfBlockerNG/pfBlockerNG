//go:build linux || freebsd

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

// WHEN StartUpdate carries lifecycle install and a pkgOp THEN the worker's request carries both, which the Update's
// hooks get as PFB_POST_INSTALL and PFB_PKG_OP (the runner's mapping is pinned by tests/hooks/fixtures/runner). WHEN it
// carries neither (or an empty pkgOp) THEN the request has neither.
func TestStartUpdateCarriesTheLifecycleAndThePkgOpToTheUpdatesHooks(t *testing.T) {
	for _, tc := range []struct {
		trigger, params, request string
		lifecycle, op            string
	}{
		{"manual", ``, `{"version":1,"trigger":"manual","scope":"both","force":"none"}`, "", ""},
		{"manual", `,"pkgOp":""`, `{"version":1,"trigger":"manual","scope":"both","force":"none"}`, "", ""},
		{"manual", `,"lifecycle":"install"`,
			`{"version":1,"trigger":"manual","scope":"both","force":"none","lifecycle":"install"}`, "install", ""},
		{"manual", `,"lifecycle":"install","pkgOp":"install"`,
			`{"version":1,"trigger":"manual","scope":"both","force":"none","lifecycle":"install","pkgOp":"install"}`,
			"install", "install"},
		{"manual", `,"lifecycle":"install","pkgOp":"upgrade"`,
			`{"version":1,"trigger":"manual","scope":"both","force":"none","lifecycle":"install","pkgOp":"upgrade"}`,
			"install", "upgrade"},
		{"manual", `,"lifecycle":"install","pkgOp":"reinstall"`,
			`{"version":1,"trigger":"manual","scope":"both","force":"none","lifecycle":"install","pkgOp":"reinstall"}`,
			"install", "reinstall"},
		{"manual", `,"pkgOp":"delete"`,
			`{"version":1,"trigger":"manual","scope":"both","force":"none","pkgOp":"delete"}`, "", "delete"},
		{"apply", `,"lifecycle":"install","pkgOp":"upgrade"`,
			`{"version":1,"trigger":"apply","scope":"both","force":"none","lifecycle":"install","pkgOp":"upgrade"}`,
			"install", "upgrade"},
		{"retry", `,"lifecycle":"install","pkgOp":"install"`, "", "install", "install"}, // the Extras due vary with the clock
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
			if req.Lifecycle != tc.lifecycle || req.PkgOp != tc.op {
				t.Errorf("the worker's request has lifecycle %q and pkgOp %q, want %q and %q", req.Lifecycle, req.PkgOp,
					tc.lifecycle, tc.op)
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
