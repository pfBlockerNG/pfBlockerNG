package dnsbl

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
)

// SetUnlocks republishes dnsbl/manifest with domains as its unlock rows, and its other rows and its metadata as they are
// (issue #4264): the Alerts page's temporary unlocks, which Core holds and pfB-DNS takes through its poll. The next DNSBL
// build publishes no unlock row, which re-locks them. A store that holds no manifest has nothing to unlock in: nothing is
// written, and ok is false. The same domains again advance no generation. The caller is the store's one writer (it holds
// the Update gate).
func SetUnlocks(store *resources.Store, domains []string) (generation uint64, ok bool, err error) {
	cur, err := store.Current(ManifestID)
	if errors.Is(err, resources.ErrNotFound) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	f, _, err := store.Body(ManifestID, cur.Generation, resources.PartMembers, 0)
	if err != nil {
		return 0, false, err
	}
	defer f.Close()
	var rows []string
	lines := bufio.NewScanner(f)
	lines.Buffer(nil, resources.MaxMemberLength+1)
	for lines.Scan() {
		var row struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(lines.Bytes(), &row); err != nil {
			return 0, false, fmt.Errorf("%s %d: %w", ManifestID, cur.Generation, err)
		}
		if row.Kind != "unlock" {
			rows = append(rows, lines.Text())
		}
	}
	if err := lines.Err(); err != nil {
		return 0, false, err
	}
	for _, d := range domains {
		rows = append(rows, jsonLine(domainRow{"unlock", d}))
	}
	var meta map[string]any
	if err := json.Unmarshal(cur.Metadata, &meta); err != nil {
		return 0, false, fmt.Errorf("%s %d metadata: %w", ManifestID, cur.Generation, err)
	}
	if generation, err = store.Publish(ManifestID, rows, meta); err != nil {
		return 0, false, err
	}
	return generation, true, nil
}
