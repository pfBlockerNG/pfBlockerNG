package dnsbl

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
)

// Unlock is one temporary unlock: the domain, and its type, the label the Alerts page shows and sends back on Lock (#3977:
// Core's set is the page's source of truth). pfB-DNS reads the domain alone.
type Unlock struct {
	Domain string `json:"domain"`
	Type   string `json:"type"`
}

type unlockRow struct {
	Kind   string `json:"kind"`
	Domain string `json:"domain"`
	Type   string `json:"type,omitempty"`
}

// Unlocks are the unlock rows of the current dnsbl/manifest, in row order: the temporary unlocks Core holds. A store that
// holds no manifest holds none.
func Unlocks(store *resources.Store) ([]Unlock, error) {
	_, rows, err := currentManifest(store)
	if errors.Is(err, resources.ErrNotFound) {
		return []Unlock{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []Unlock{}
	for _, line := range rows {
		var r unlockRow
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, err
		}
		if r.Kind == "unlock" {
			out = append(out, Unlock{Domain: r.Domain, Type: r.Type})
		}
	}
	return out, nil
}

// SetUnlocks republishes dnsbl/manifest with unlocks as its unlock rows, and its other rows and its metadata as they are
// (issue #4264): the Alerts page's temporary unlocks, which Core holds and pfB-DNS takes through its poll. The next DNSBL
// build publishes no unlock row, which re-locks them. A store that holds no manifest has nothing to unlock in: nothing is
// written, and ok is false. The same unlocks again advance no generation. The caller is the store's one writer (it holds
// the Update gate).
func SetUnlocks(store *resources.Store, unlocks []Unlock) (generation uint64, ok bool, err error) {
	cur, all, err := currentManifest(store)
	if errors.Is(err, resources.ErrNotFound) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	var rows []string
	for _, line := range all {
		var row struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			return 0, false, fmt.Errorf("%s %d: %w", ManifestID, cur.Generation, err)
		}
		if row.Kind != "unlock" {
			rows = append(rows, line)
		}
	}
	for _, u := range unlocks {
		rows = append(rows, jsonLine(unlockRow{"unlock", u.Domain, u.Type}))
	}
	var raw map[string]json.RawMessage // kept verbatim: the same rows advance no generation
	if err := json.Unmarshal(cur.Metadata, &raw); err != nil {
		return 0, false, fmt.Errorf("%s %d metadata: %w", ManifestID, cur.Generation, err)
	}
	meta := make(map[string]any, len(raw))
	for k, v := range raw {
		meta[k] = v
	}
	if generation, err = store.Publish(ManifestID, rows, meta); err != nil {
		return 0, false, err
	}
	return generation, true, nil
}

// currentManifest is the current dnsbl/manifest and its rows; resources.ErrNotFound when the store holds none.
func currentManifest(store *resources.Store) (resources.Reply, []string, error) {
	cur, err := store.Current(ManifestID)
	if err != nil {
		return cur, nil, err
	}
	f, _, err := store.Body(ManifestID, cur.Generation, resources.PartMembers, 0)
	if err != nil {
		return cur, nil, err
	}
	defer f.Close()
	var rows []string
	lines := bufio.NewScanner(f)
	lines.Buffer(nil, resources.MaxMemberLength+1)
	for lines.Scan() {
		rows = append(rows, lines.Text())
	}
	return cur, rows, lines.Err()
}
