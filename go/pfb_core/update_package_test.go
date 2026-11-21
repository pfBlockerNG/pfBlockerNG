//go:build linux || freebsd

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

// WHEN StartUpdate carries a lifecycle and a pkgOp THEN the worker's request carries both, which the Update's hooks get
// as PFB_POST_INSTALL and PFB_PKG_OP (the runner's mapping is pinned by tests/hooks/fixtures/runner); an empty pkgOp is
// none. tests/core/fixtures/update_request_v1.json pins every request Core writes for them.
func TestStartUpdateCarriesTheLifecycleAndThePkgOpToTheUpdatesHooks(t *testing.T) {
	for _, tc := range []struct{ trigger, params, request string }{
		{"manual", `,"pkgOp":""`, `{"version":1,"trigger":"manual","scope":"both","force":"none"}`},
		{"manual", `,"lifecycle":"install","pkgOp":"upgrade"`,
			`{"version":1,"trigger":"manual","scope":"both","force":"none","lifecycle":"install","pkgOp":"upgrade"}`},
		{"apply", `,"lifecycle":"install","pkgOp":"upgrade"`,
			`{"version":1,"trigger":"apply","scope":"both","force":"none","lifecycle":"install","pkgOp":"upgrade"}`},
		{"retry", `,"lifecycle":"install","pkgOp":"install"`, ""}, // the Extras due vary with the clock
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
				return
			}
			var req struct {
				Lifecycle string `json:"lifecycle"`
				PkgOp     string `json:"pkgOp"`
			}
			if err := json.Unmarshal([]byte(f.request()), &req); err != nil {
				t.Fatal(err)
			}
			if req.Lifecycle != "install" || req.PkgOp != "install" {
				t.Errorf("the worker's request has lifecycle %q and pkgOp %q, want install and install", req.Lifecycle,
					req.PkgOp)
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
