package feedfetch

import (
	"os"
	"path/filepath"
	"testing"
)

// The share holds the country folder: cc, a link to its generation .cc.<pid>.<hex>, with the publication lock .cc.lock
// beside it (#4140). A MaxMind archive's member named for any of them must never take that name in the share (#4142,
// cutover row 3 of #4038), whatever stands there today: a member file or folder called cc on a share without a country
// folder yet would become the entry link cc -> .<archive>/cc, where the GeoIP conversion publishes its link.
func TestAShareMemberNamedForTheCountryFolderRefusesThePublication(t *testing.T) {
	for _, tc := range []struct {
		name   string
		member string
		folder bool
	}{
		{"a file named cc", "cc", false},
		{"a folder named cc", "cc", true},
		{"the publication lock", ".cc.lock", false},
		{"a generation of the country folder", ".cc.123.0a1b2c3d", true},
		{"a link of a generation", ".cc.123.0a1b2c3d.link", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			share := t.TempDir()
			if !mergeIntoDir(share, "GeoLite2-Country-CSV.zip", writeEntries(map[string]string{"LICENSE.txt": "v1"})) {
				t.Fatal("the first publication failed")
			}
			ok := mergeIntoDir(share, "GeoLite2-Country-CSV.zip", func(dir string) error {
				if err := writeEntries(map[string]string{"LICENSE.txt": "v2"})(dir); err != nil {
					return err
				}
				if tc.folder {
					return os.MkdirAll(filepath.Join(dir, tc.member, "inner"), 0o755)
				}
				return os.WriteFile(filepath.Join(dir, tc.member), []byte("forged\n"), 0o644)
			})
			if ok {
				t.Errorf("a member named %q was published into the share", tc.member)
			}
			if _, err := os.Lstat(filepath.Join(share, tc.member)); !os.IsNotExist(err) {
				t.Errorf("%s stands in the share after a refused publication (err %v)", tc.member, err)
			}
			assertEntry(t, share, "LICENSE.txt", "v1") // the previous generation stays in service
		})
	}
}
