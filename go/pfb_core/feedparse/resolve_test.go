package feedparse

import (
	"os"
	"path/filepath"
	"testing"
)

// ResolveListScript holds a list script to pfb_resolve_list_script()'s containment: a base name found in one of the
// folders, in order, whose real path stays directly in that folder's real path and is a regular file.
func TestResolveListScriptMatchesOutpostContainmentCases(t *testing.T) {
	root := t.TempDir()
	primary, legacy, outside := filepath.Join(root, "list_scripts"), filepath.Join(root, "legacy"), filepath.Join(root, "outside")
	for _, dir := range []string{primary, legacy, outside} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	makeFile := func(dir, name string, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	nonexec := makeFile(primary, "ip_pre_noexec.sh", 0o644)
	legacyFile := makeFile(legacy, "ip_pre_legacy.sh", 0o755)
	outsideFile := makeFile(outside, "escape.sh", 0o755)
	makeFile(legacy, "victim.sh", 0o755)
	if err := os.Symlink(outsideFile, filepath.Join(primary, "ip_pre_escape.sh")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(legacy, filepath.Join(primary, "ip_pre_todir.sh")); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, input string
		dirs        []string
		want        string
	}{
		{name: "non-executable regular file", input: "ip_pre_noexec.sh", dirs: []string{primary, legacy}, want: nonexec},
		{name: "legacy fallback", input: "ip_pre_legacy.sh", dirs: []string{primary, legacy}, want: legacyFile},
		{name: "escaping symlink", input: "ip_pre_escape.sh", dirs: []string{primary, legacy}},
		{name: "symlink to a directory", input: "ip_pre_todir.sh", dirs: []string{primary, legacy}},
		{name: "traversal basename", input: "../legacy/victim.sh", dirs: []string{primary}},
		{name: "subpath basename", input: "subdir/ip_pre_subpath.sh", dirs: []string{primary, legacy}},
		{name: "empty name", input: "", dirs: []string{primary, legacy}},
		{name: "unset name", input: "0", dirs: []string{primary, legacy}},
		{name: "root name", input: string(filepath.Separator), dirs: []string{primary, legacy}},
		{name: "unset folder", input: "ip_pre_legacy.sh", dirs: []string{"", legacy}, want: legacyFile},
	} {
		got, ok := ResolveListScript(tc.input, tc.dirs)
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("ResolveListScript(%s: %q) = %q, %v; want %q", tc.name, tc.input, got, ok, tc.want)
		}
	}
}
