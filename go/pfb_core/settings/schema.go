// Package settings is Core's native settings store (issue #3842; map #3813): a schema of typed projections, and one
// persisted document holding the configuration revision and, per projection, its generation and values.
// docs/misc/core-api-protocol.md documents the API methods over it.
package settings

// Type is a field's native JSON type.
type Type string

const (
	TypeBool   Type = "bool"
	TypeInt    Type = "int"
	TypeEnum   Type = "enum"
	TypeString Type = "string"
)

// Field is one setting. A secret is write-only: a read shows only whether it is set. Requires names a bool field of the
// same projection: while that one is false, this bool is held false.
type Field struct {
	Name     string   `json:"name"`
	Type     Type     `json:"type"`
	Default  any      `json:"default"`
	Enum     []string `json:"enum,omitempty"`
	Min      *int64   `json:"min,omitempty"`
	Max      *int64   `json:"max,omitempty"`
	Secret   bool     `json:"secret,omitempty"`
	Requires string   `json:"requires,omitempty"`
}

// Projection is a group of fields read and versioned together, published as the resource settings/<ID>.
type Projection struct {
	ID     string  `json:"id"`
	Fields []Field `json:"fields"`
}

// Schema is what GetSettingsSchema answers.
type Schema struct {
	Version     int          `json:"schemaVersion"`
	Projections []Projection `json:"projections"`
}

// Production is Core's schema. dns: the DNSBL resolver settings pfb-dns reads from pfb_unbound.ini today, each with
// the default and range today's PHP gives (tests/core/fixtures/settings_dns_parity.json).
func Production() Schema {
	policy := []string{"ignore", "apex", "honor"}
	return Schema{Version: 1, Projections: []Projection{{ID: "dns", Fields: []Field{
		{Name: "replyLogging", Type: TypeBool, Default: true},
		{Name: "hstsNullBlocking", Type: TypeBool, Default: true},
		{Name: "tldWildcard", Type: TypeBool, Default: false},
		{Name: "pslIncludePrivate", Type: TypeBool, Default: true},
		{Name: "pslAllowPrivate", Type: TypeBool, Default: false},
		{Name: "pslFeedPrivatePolicy", Type: TypeEnum, Default: "honor", Enum: policy},
		{Name: "pslFeedIcannPolicy", Type: TypeEnum, Default: "honor", Enum: policy},
		{Name: "idnMode", Type: TypeEnum, Default: "off", Enum: []string{"off", "confusable", "on"}},
		{Name: "idnBlockMalicious", Type: TypeBool, Default: true},
		{Name: "idnEscalateSuspicious", Type: TypeBool, Default: false},
		{Name: "decisionCacheMax", Type: TypeInt, Default: int64(10000), Min: new(int64(0)), Max: new(int64(5000000))}, // 0: unlimited
		{Name: "logViaWebserver", Type: TypeBool, Default: false},
		{Name: "cnameValidation", Type: TypeBool, Default: false},
		{Name: "control", Type: TypeBool, Default: false},
		{Name: "controlLegacy", Type: TypeBool, Default: false, Requires: "control"},
		{Name: "regexCap", Type: TypeBool, Default: false},
		{Name: "metricsClientIp", Type: TypeBool, Default: false},
	}}}}
}
