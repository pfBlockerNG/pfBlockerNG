package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
)

// maxResourcesPerCall bounds one GetResources call (docs/misc/core-api-protocol.md, "Resources").
const maxResourcesPerCall = 16

// resourceItem is one resource's answer: a kind with its keys, or an error. A key foreign to the kind stays nil or empty and
// is omitted; omitzero keeps a non-nil empty slice, so add, remove and members of an empty set are still sent as [].
type resourceItem struct {
	Kind       string          `json:"kind,omitempty"`
	Generation string          `json:"generation,omitempty"`
	From       string          `json:"from,omitempty"`
	Add        []string        `json:"add,omitzero"`
	Remove     []string        `json:"remove,omitzero"`
	Members    []string        `json:"members,omitzero"`
	Digest     string          `json:"digest,omitempty"`
	Entries    *int            `json:"entries,omitempty"`
	Metadata   json.RawMessage `json:"metadata,omitzero"`
	Error      *apiError       `json:"error,omitempty"`
}

type resourceCursor struct {
	Generation *string `json:"generation"`
	Digest     *string `json:"digest"`
}

// resourceMethods is GetResources over store, read-only. Without a store (no --resource-dir) it answers unavailable.
func resourceMethods(store *resources.Store) map[string]method {
	return map[string]method{"GetResources": {call: func(_ context.Context, params []byte) (any, error) {
		if store == nil {
			return nil, newError(codeUnavailable, "Core runs no resource store: start it with --resource-dir")
		}
		var p struct {
			Resources map[string]*resourceCursor `json:"resources"`
		}
		if err := decodeParams(params, &p); err != nil {
			var ae *apiError
			if errors.As(err, &ae) {
				for i := range ae.FieldErrors {
					f := &ae.FieldErrors[i].Field // the decoder writes "/" as "~1" and "~" as "~0"
					*f = strings.ReplaceAll(strings.ReplaceAll(*f, "~1", "/"), "~0", "~")
				}
			}
			return nil, err
		}
		ids := slices.Sorted(maps.Keys(p.Resources))
		if len(ids) > maxResourcesPerCall {
			return nil, newError(codeInvalidArgument, "too many resources; nothing was read",
				fieldError{Field: "resources", Message: fmt.Sprintf("at most %d resources per call", maxResourcesPerCall)})
		}
		cursors, bad := map[string]*resources.Cursor{}, []fieldError(nil)
		for _, id := range ids {
			c, errs := parseResourceCursor(id, p.Resources[id])
			cursors[id], bad = c, append(bad, errs...)
		}
		if bad != nil {
			return nil, newError(codeInvalidArgument, "the resource request is not valid; nothing was read", bad...)
		}
		items := make(map[string]resourceItem, len(ids))
		for _, id := range ids {
			r, err := store.Get(id, cursors[id])
			switch {
			case errors.Is(err, resources.ErrNotFound):
				items[id] = resourceItem{Error: newError(codeNotFound, "the store has no such resource")}
			case errors.Is(err, resources.ErrUnavailable):
				items[id] = resourceItem{Error: newError(codeUnavailable, "the store cannot serve this resource now")}
			case err != nil:
				return nil, err
			default:
				items[id] = resourceItemOf(r)
			}
		}
		return map[string]any{"resources": items}, nil
	}}}
}

func resourceItemOf(r resources.Reply) resourceItem {
	it := resourceItem{Kind: r.Kind, Generation: strconv.FormatUint(r.Generation, 10)}
	if r.Kind == resources.KindUnchanged {
		return it
	}
	it.Digest, it.Entries, it.Metadata = r.Digest, &r.Entries, r.Metadata
	if r.Kind == resources.KindDelta {
		it.From, it.Add, it.Remove = strconv.FormatUint(r.From, 10), r.Add, r.Remove
	} else {
		it.Members = r.Members
	}
	return it
}

// parseResourceCursor is id's cursor (nil: none) or the field errors of the id or the cursor. A null field is absent. A field
// name carries the id as given: it passed resources.ValidID, a bad id never reaches a field name.
func parseResourceCursor(id string, c *resourceCursor) (*resources.Cursor, []fieldError) {
	field := "resources." + id + "."
	switch {
	case !resources.ValidID(id):
		return nil, []fieldError{{Field: "resources", Message: fmt.Sprintf("%q is not a resource id", id)}}
	case c == nil:
		return nil, []fieldError{{Field: "resources", Message: fmt.Sprintf("the cursor of %q must be a JSON object", id)}}
	case c.Generation == nil && c.Digest == nil:
		return nil, nil
	case c.Generation == nil:
		return nil, []fieldError{{Field: field + "generation", Message: "required with digest"}}
	case c.Digest == nil:
		return nil, []fieldError{{Field: field + "digest", Message: "required with generation"}}
	}
	var bad []fieldError
	g, err := strconv.ParseUint(*c.Generation, 10, 64)
	if err != nil {
		bad = append(bad, fieldError{Field: field + "generation", Message: "must be a string of decimal digits that fits 64 bits"})
	}
	if d := *c.Digest; len(d) != 32 || strings.Trim(d, "0123456789abcdef") != "" {
		bad = append(bad, fieldError{Field: field + "digest", Message: "must be 32 lower-case hexadecimal characters"})
	}
	if bad != nil {
		return nil, bad
	}
	return &resources.Cursor{Generation: g, Digest: *c.Digest}, nil
}
