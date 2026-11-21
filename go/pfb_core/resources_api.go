package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
)

// maxResourcesPerCall bounds one GetResources call (docs/misc/core-api-protocol.md, "Resources").
const maxResourcesPerCall = 16

// resourceItem is one resource's answer: a kind with its keys, or an error. A key foreign to the kind stays nil or empty and
// is omitted. It carries no members: GetResourceBody streams them.
type resourceItem struct {
	Kind          string          `json:"kind,omitempty"`
	Generation    string          `json:"generation,omitempty"`
	From          string          `json:"from,omitempty"`
	AddEntries    *int            `json:"addEntries,omitempty"`
	RemoveEntries *int            `json:"removeEntries,omitempty"`
	Digest        string          `json:"digest,omitempty"`
	Entries       *int            `json:"entries,omitempty"`
	Metadata      json.RawMessage `json:"metadata,omitzero"`
	Error         *apiError       `json:"error,omitempty"`
}

// bodyStream is a reply that is not JSON: a store file already checked against the index, sent as plain text and closed
// once written.
type bodyStream struct {
	f    *os.File
	size int64
}

type resourceCursor struct {
	Generation *string `json:"generation"`
	Digest     *string `json:"digest"`
}

// resourceMethods is GetResources and GetResourceBody over store, read-only. Without a store (no --resource-dir) they answer
// unavailable. A further local client (pfb-dns) reads only the dnsbl/* resources: to it no other resource exists.
func resourceMethods(store *resources.Store) map[string]method {
	return map[string]method{"GetResourceBody": {client: true, call: func(ctx context.Context, params []byte) (any, error) {
		if store == nil {
			return nil, newError(codeUnavailable, "Core runs no resource store: start it with --resource-dir")
		}
		return resourceBody(store, params, fromClient(ctx))
	}}, "GetResources": {client: true, call: func(ctx context.Context, params []byte) (any, error) {
		if store == nil {
			return nil, newError(codeUnavailable, "Core runs no resource store: start it with --resource-dir")
		}
		var p struct {
			Resources map[string]*resourceCursor `json:"resources"`
		}
		if err := decodeResourceParams(params, &p); err != nil {
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
			if fromClient(ctx) && !strings.HasPrefix(id, dnsblPrefix) {
				items[id] = resourceItem{Error: newError(codeNotFound, "the store has no such resource")}
				continue
			}
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

// decodeResourceParams is decodeParams for parameters keyed by resource id: a field error names the id as given.
func decodeResourceParams(params []byte, v any) error {
	err := decodeParams(params, v)
	var ae *apiError
	if errors.As(err, &ae) {
		for i := range ae.FieldErrors {
			// A path from the decoder writes "/" as "~1" and "~" as "~0"; an unknown name is verbatim
			if f := &ae.FieldErrors[i]; f.Message != "unknown parameter" {
				f.Field = strings.ReplaceAll(strings.ReplaceAll(f.Field, "~1", "/"), "~0", "~")
			}
		}
	}
	return err
}

func resourceItemOf(r resources.Reply) resourceItem {
	it := resourceItem{Kind: r.Kind, Generation: strconv.FormatUint(r.Generation, 10)}
	if r.Kind == resources.KindUnchanged {
		return it
	}
	it.Digest, it.Entries, it.Metadata = r.Digest, &r.Entries, r.Metadata
	if r.Kind == resources.KindDelta {
		it.From, it.AddEntries, it.RemoveEntries = strconv.FormatUint(r.From, 10), &r.Adds, &r.Removes
	}
	return it
}

// resourceBody answers GetResourceBody: the part of one resource the store holds, streamed from its file. To a further
// local client (client) a resource outside dnsbl/* is one the store does not hold.
func resourceBody(store *resources.Store, params []byte, client bool) (any, error) {
	var p struct {
		ID         *string `json:"id"`
		Generation *string `json:"generation"`
		Part       *string `json:"part"`
		From       *string `json:"from"`
	}
	if err := decodeParams(params, &p); err != nil {
		return nil, err
	}
	var bad []fieldError
	number := func(name string, s *string) uint64 {
		g, err := strconv.ParseUint(*s, 10, 64)
		if err != nil {
			bad = append(bad, fieldError{Field: name, Message: "must be a string of decimal digits that fits 64 bits"})
		}
		return g
	}
	var g, from uint64
	switch {
	case p.ID == nil:
		bad = append(bad, fieldError{Field: "id", Message: "required"})
	case !resources.ValidID(*p.ID):
		bad = append(bad, fieldError{Field: "id", Message: fmt.Sprintf("%q is not a resource id", *p.ID)})
	}
	if p.Generation == nil {
		bad = append(bad, fieldError{Field: "generation", Message: "required"})
	} else {
		g = number("generation", p.Generation)
	}
	delta := false
	switch {
	case p.Part == nil:
		bad = append(bad, fieldError{Field: "part", Message: "required"})
	case *p.Part == resources.PartAdd || *p.Part == resources.PartRemove:
		delta = true
	case *p.Part != resources.PartMembers:
		bad = append(bad, fieldError{Field: "part", Message: `must be "members", "add" or "remove"`})
	}
	switch {
	case delta && p.From == nil:
		bad = append(bad, fieldError{Field: "from", Message: "required with add or remove"})
	case p.Part != nil && *p.Part == resources.PartMembers && p.From != nil:
		bad = append(bad, fieldError{Field: "from", Message: "only with add or remove"})
	case p.From != nil:
		from = number("from", p.From)
	}
	if bad != nil {
		return nil, newError(codeInvalidArgument, "the body request is not valid; nothing was read", bad...)
	}
	if client && !strings.HasPrefix(*p.ID, dnsblPrefix) {
		return nil, newError(codeNotFound, "the store holds no such body")
	}
	f, size, err := store.Body(*p.ID, g, *p.Part, from)
	switch {
	case errors.Is(err, resources.ErrNotFound):
		return nil, newError(codeNotFound, "the store holds no such body")
	case errors.Is(err, resources.ErrUnavailable):
		return nil, newError(codeUnavailable, "the store cannot serve this body now")
	case err != nil:
		return nil, err
	}
	return &bodyStream{f: f, size: size}, nil
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
