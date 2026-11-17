package settings

// maintenanceProjection is settings/maintenance: what Core's timed lanes decide from, as the Outpost reads it from its
// configuration and the box. It is read-only: Core never changes any of it, so a change set that names it is refused.
// scheduledWorkDisabled is the platform's scheduled-work off switch being present. A counter cadence the Outpost cannot read
// as never, daily or weekly is never. tests/core/fixtures/settings_maintenance_parity.json is the parity fixture.
func maintenanceProjection() Projection {
	cadence := []string{"never", "daily", "weekly"}
	return Projection{ID: "maintenance", ReadOnly: true, Fields: []Field{
		{Name: "enabled", Type: TypeBool, Default: false},
		{Name: "scheduledWorkDisabled", Type: TypeBool, Default: false},
		{Name: "metricsExport", Type: TypeBool, Default: false},
		{Name: "clearIpCounters", Type: TypeEnum, Default: "never", Enum: cadence},
		{Name: "clearDnsblCounters", Type: TypeEnum, Default: "never", Enum: cadence},
	}}
}
