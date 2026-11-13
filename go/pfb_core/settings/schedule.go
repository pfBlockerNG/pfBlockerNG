package settings

// scheduleProjection is settings/schedule (issue #3941): what Core's scheduler reads beside the feed projections to build its
// model (package schedule: ModelFromSettings). The default slot and the scheduled-updates switch of General, each group's
// override slot, and the Blacklist's updates. The Outpost leaves groups and providers to their pages: it answers only the ones
// config.xml holds, and a write names them, never creates one (docs/misc/core-api-protocol.md).
// tests/core/fixtures/settings_schedule_parity.json is the parity fixture.
func scheduleProjection() Projection {
	group := append([]Field{
		{Name: "id", Type: TypeString, Default: "", Pattern: `^(ipv4|ipv6|dnsbl)/[A-Za-z0-9_]+$`}, // <type>/<group name>
		{Name: "override", Type: TypeBool, Default: false},
	}, slotFields()...)
	provider := []Field{
		{Name: "id", Type: TypeString, Default: "", Pattern: `^[A-Za-z0-9_-]+$`, Reserved: []string{"0"}},
		{Name: "selected", Type: TypeBool, Default: false},
		{Name: "categories", Type: TypeString, Default: "", Pattern: `^[A-Za-z0-9_,.-]*$`}, // the provider's chosen categories, comma-separated
	}
	fields := append([]Field{{Name: "scheduledUpdates", Type: TypeBool, Default: true}}, slotFields()...)
	return Projection{ID: "schedule", Fields: append(fields,
		Field{Name: "groups", Type: TypeList, Default: []any{}, Key: "id", Items: group},
		Field{Name: "categoryUpdates", Type: TypeBool, Default: false},
		Field{Name: "categoryFrequency", Type: TypeEnum, Default: "Never", Enum: []string{"Never", "EveryDay", "Weekly"}},
		Field{Name: "categoryProviders", Type: TypeList, Default: []any{}, Key: "id", Items: provider})}
}

// slotFields is a schedule slot: Sunday 00:00 by default, on the quarter hour.
func slotFields() []Field {
	return []Field{
		{Name: "weekday", Type: TypeInt, Default: int64(7), Min: new(int64(1)), Max: new(int64(7))},
		{Name: "hour", Type: TypeInt, Default: int64(0), Min: new(int64(0)), Max: new(int64(23))},
		{Name: "minute", Type: TypeInt, Default: int64(0), Min: new(int64(0)), Max: new(int64(45)), Check: quarterHour},
	}
}

func quarterHour(v map[string]any) []FieldError {
	if v["minute"].(int64)%15 != 0 {
		return []FieldError{{Field: "minute", Message: "must be 0, 15, 30 or 45"}}
	}
	return nil
}
