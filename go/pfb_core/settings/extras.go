package settings

// extrasProjection is settings/extras (issue #4031): what the Extras stage of an Update reads of the package settings, the
// MaxMind account, key, locale and CSV switch, the IPinfo token, the TOP1M provider and its token. The key and the two tokens
// are secrets. tests/core/fixtures/settings_extras_parity.json is the parity fixture.
func extrasProjection() Projection {
	const (
		word  = `^[A-Za-z0-9_]*$`
		token = `^[^\p{C}]*$` // it goes into a URL or an HTTP header
	)
	zero := []string{"0"} // the Outpost reads a stored 0 as none, so it stores none
	return Projection{ID: "extras", Fields: []Field{
		{Name: "maxmindAccount", Type: TypeString, Default: "", Pattern: word, Reserved: zero},
		{Name: "maxmindKey", Type: TypeString, Default: "", Pattern: word, Reserved: zero, Secret: true},
		{Name: "maxmindLocale", Type: TypeEnum, Default: "en", Enum: []string{"en", "fr", "pt-BR", "de", "ja", "zh-CN", "es"}},
		{Name: "maxmindCsvDisabled", Type: TypeBool, Default: false},
		{Name: "ipinfoToken", Type: TypeString, Default: "", Pattern: token, Reserved: zero, Secret: true},
		{Name: "top1mProvider", Type: TypeEnum, Default: "tranco", Enum: []string{"tranco", "cisco", "openpagerank", "majestic", "cloudflare"}},
		{Name: "top1mToken", Type: TypeString, Default: "", Pattern: token, Secret: true},
	}}
}
