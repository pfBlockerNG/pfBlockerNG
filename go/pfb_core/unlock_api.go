package main

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sync"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/dnsbl"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/feedparse"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update"
)

// maxUnlocks bounds the set of temporary unlocks Core holds, which each request carries whole; a page holding more is refused
// on every click until a Lock or an Update brings it under.
const maxUnlocks = 4096

// unlockMu makes SetTemporaryUnlocks requests one at a time: two clicks at once are no Update to refuse, and without Updates it
// is the store's one writer.
var unlockMu sync.Mutex

// unlockMethods are SetTemporaryUnlocks and GetTemporaryUnlocks (issue #4264; owner, 2026-11-24): Core holds the Alerts page's
// temporary unlocks. Each Lock and Unlock sends the whole set of unlocked domains with their types, and Core republishes dnsbl/manifest with them as its unlock rows,
// without a whole Update; pfB-DNS takes them through its poll, and the next DNSBL build re-locks them. Root only: the page
// runs as root, and an unlock lifts a block.
func unlockMethods(store *resources.Store, gate *update.Gate) map[string]method {
	return map[string]method{
		"SetTemporaryUnlocks": {mutating: true, call: func(_ context.Context, params []byte) (any, error) {
			var p struct {
				RequestID string          `json:"requestId"`
				Unlocks   *[]dnsbl.Unlock `json:"unlocks"`
			}
			if err := decodeParams(params, &p); err != nil {
				return nil, err
			}
			if p.Unlocks == nil {
				return nil, newError(codeInvalidArgument, "the request names no unlocks; nothing was changed",
					fieldError{Field: "unlocks", Message: "required: the whole set of unlocked domains, empty to lock them all"})
			}
			if len(*p.Unlocks) > maxUnlocks {
				return nil, newError(codeInvalidArgument, "the request names too many unlocks; nothing was changed",
					fieldError{Field: "unlocks", Message: fmt.Sprintf("at most %d", maxUnlocks)})
			}
			var bad []fieldError
			for i, u := range *p.Unlocks {
				if !feedparse.DomainOK(u.Domain) {
					bad = append(bad, fieldError{Field: fmt.Sprintf("unlocks[%d].domain", i), Message: "is not a domain"})
				}
				if !unlockType.MatchString(u.Type) {
					bad = append(bad, fieldError{Field: fmt.Sprintf("unlocks[%d].type", i), Message: "is not a word of at most 64 characters"})
				}
			}
			if bad != nil {
				return nil, newError(codeInvalidArgument, "a domain is not valid; nothing was changed", bad...)
			}
			if store == nil {
				return nil, newError(codeUnavailable, "Core holds no temporary unlocks without its resource store (start it with --resource-dir)")
			}
			set := func() error {
				_, _, err := dnsbl.SetUnlocks(store, *p.Unlocks)
				return err
			}
			unlockMu.Lock()
			defer unlockMu.Unlock()
			// the Updater is the store's other writer: with no Updates, nothing else writes it
			var err error
			if gate == nil {
				err = set()
			} else {
				err = gate.Hold(set)
			}
			switch {
			case errors.Is(err, update.ErrRunning):
				return nil, newError(codeConflict, "an Update is running, and its end re-locks every temporary unlock; ask again after it")
			case err != nil:
				return nil, newError(codeUnavailable, err.Error())
			}
			return struct{}{}, nil
		}},
		// #3977 (owner, 2026-11-27): Core's set is the Alerts page's source of truth, read back with each type.
		"GetTemporaryUnlocks": {call: func(_ context.Context, params []byte) (any, error) {
			if err := decodeParams(params, &struct{}{}); err != nil {
				return nil, err
			}
			if store == nil {
				return nil, newError(codeUnavailable, "Core holds no temporary unlocks without its resource store (start it with --resource-dir)")
			}
			unlocks, err := dnsbl.Unlocks(store)
			if err != nil {
				return nil, newError(codeUnavailable, err.Error())
			}
			return struct {
				Unlocks []dnsbl.Unlock `json:"unlocks"`
			}{unlocks}, nil
		}},
	}
}

// unlockType is the Alerts page's DNSBL type, a word as pfb_filter()'s PFB_FILTER_WORD takes it.
var unlockType = regexp.MustCompile(`^\w{1,64}$`)
