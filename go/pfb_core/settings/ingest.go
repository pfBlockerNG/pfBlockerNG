package settings

// ingestProjection is settings/ingest (issue #3975): stub, the fields as data without their rules.
func ingestProjection() Projection {
	return Projection{ID: "ingest", ReadOnly: true, Fields: []Field{
		{Name: "suppression", Type: TypeBool, Default: true},
		{Name: "suppressionCidrV4", Type: TypeInt, Default: int64(0)},
		{Name: "suppressionCidrV6", Type: TypeInt, Default: int64(0)},
		{Name: "dnsblIp", Type: TypeBool, Default: false},
		{Name: "dnsblLenient", Type: TypeBool, Default: false},
		{Name: "feedHostFilter", Type: TypeBool, Default: true},
		{Name: "feedHostAllowlist", Type: TypeList, Default: []any{}, Key: "cidr", Items: []Field{{Name: "cidr", Type: TypeString, Default: ""}}},
		{Name: "selfAddresses", Type: TypeList, Default: []any{}, Key: "address", Items: []Field{{Name: "address", Type: TypeString, Default: ""}}},
		{Name: "proxyUrl", Type: TypeString, Default: ""},
		{Name: "proxyUser", Type: TypeString, Default: ""},
		{Name: "proxyPassword", Type: TypeString, Default: "", Secret: true},
	}}
}
