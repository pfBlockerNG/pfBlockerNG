package main

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/settings"
)

// settingsMethods are the six settings methods over st (docs/misc/core-api-protocol.md, "Settings").
func settingsMethods(st *settings.Store) map[string]method {
	return map[string]method{
		"GetSettingsSchema": {call: func(_ context.Context, params []byte) (any, error) {
			if err := decodeParams(params, &struct{}{}); err != nil {
				return nil, err
			}
			return st.Schema(), nil
		}},
		"GetSettings": {call: func(_ context.Context, params []byte) (any, error) {
			var p struct {
				ProjectionIDs []string `json:"projectionIds"`
			}
			if err := decodeParams(params, &p); err != nil {
				return nil, err
			}
			snap, err := st.Get(p.ProjectionIDs)
			return snap, settingsError(err, "")
		}},
		"InitializeSettings": {mutating: true, call: func(_ context.Context, params []byte) (any, error) {
			var p struct {
				RequestID string                                `json:"requestId"`
				Settings  map[string]map[string]json.RawMessage `json:"settings"`
			}
			if err := decodeParams(params, &p); err != nil {
				return nil, err
			}
			res, err := st.Initialize(p.Settings)
			return res, settingsError(err, "settings.")
		}},
		"SaveSettings": {mutating: true, call: func(_ context.Context, params []byte) (any, error) {
			var p struct {
				RequestID        string                                `json:"requestId"`
				ExpectedRevision *uint64                               `json:"expectedRevision"`
				Changes          map[string]map[string]json.RawMessage `json:"changes"`
			}
			if err := decodeParams(params, &p); err != nil {
				return nil, err
			}
			if p.ExpectedRevision == nil {
				return nil, newError(codeInvalidArgument, "SaveSettings needs the revision the changes were made against",
					fieldError{Field: "expectedRevision", Message: "required"})
			}
			res, err := st.Save(*p.ExpectedRevision, p.Changes)
			return res, settingsError(err, "changes.")
		}},
		"ValidateSettings": {call: func(_ context.Context, params []byte) (any, error) {
			var p struct {
				Changes map[string]map[string]json.RawMessage `json:"changes"`
			}
			if err := decodeParams(params, &p); err != nil {
				return nil, err
			}
			return struct{}{}, settingsError(st.Validate(p.Changes), "changes.")
		}},
		"SettingsChanged": {call: func(_ context.Context, params []byte) (any, error) {
			if err := decodeParams(params, &struct{}{}); err != nil {
				return nil, err
			}
			snap, err := st.Reload()
			return snap, settingsError(err, "")
		}},
	}
}

// settingsError maps the store's refusals onto the protocol's codes; prefix places a field error under its parameter.
func settingsError(err error, prefix string) error {
	var v *settings.ValidationError
	var c *settings.ConflictError
	var b *settings.BackendError
	switch {
	case errors.As(err, &v):
		fields := make([]fieldError, len(v.Fields))
		for i, f := range v.Fields {
			fields[i] = fieldError{Field: prefix + f.Field, Message: f.Message}
		}
		return newError(codeInvalidArgument, "the settings are not valid; nothing was changed", fields...)
	case errors.As(err, &c):
		var fields []fieldError
		if c.Field != "" {
			fields = append(fields, fieldError{Field: c.Field, Message: c.Message})
		}
		return newError(codeConflict, c.Message, fields...)
	case errors.As(err, &b):
		return newError(codeUnavailable, "the settings backend failed: "+b.Error())
	}
	return err
}
