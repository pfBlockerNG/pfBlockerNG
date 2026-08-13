# Quarter-hour-anchored scheduling

This specification resolves the Wayfinder map
[Quarter-hour-anchored scheduling for update cadences](https://github.com/pfBlockerNG/pfBlockerNG/issues/1944)
and its decision tickets. Later amendments in
[Define quarter-hour anchor controls and migration](https://github.com/pfBlockerNG/pfBlockerNG/issues/2093)
supersede earlier global-weekday and jitter assumptions. The resolution in
[Decide whether to expose 15- and 30-minute per-feed schedules](https://github.com/pfBlockerNG/pfBlockerNG/issues/2094)
supersedes that ticket's earlier sub-hourly examples.

## Goal

Replace the legacy global feed interval and scattered schedule phase controls with one visible
quarter-hour Default Schedule, optional feed-group schedule overrides, and one derived feed wake
in the existing due-ledger cache.

The result preserves each feed group's configured cadence, runs calendar-scheduled Extras before
feeds at a shared slot, catches missed work up once, and migrates existing schedules through the
normal pfSense configuration save path without reintroducing a user-configurable tick or a second
scheduling model.

## Fixed constraints

- The scheduler clock is the literal `*/15` crontab tick. `pfb_tick_interval` remains retired;
  stored legacy values are inert. There is no per-minute tick, phased minute list, runtime jitter,
  hidden offset, or re-roll control.
- The canonical local-time schedule vocabulary is weekday `W`, hour `H`, and minute `M`.
  `W` uses ISO `1`–`7` (Monday–Sunday), `H` is `0`–`23`, and `M` is exactly `0`, `15`, `30`,
  or `45`.
- User-facing feed cadences remain hourly and above. Five-, ten-, fifteen-, twenty-, and
  thirty-minute feed cadences are not added.
- A feed group's cadence is authoritative. It is never intersected with a separate global
  cadence. Numeric `pfb_interval` values retire instead of becoming a new global rate limit.
- Feed schedule state lives in configuration. The disposable due-ledger cache contains one shared
  `cron` entry for the next scheduled feed wake; it never gains per-feed entries or a duplicate
  feed-schedule store.
- Durable per-feed execution history stores `last_successful_check` separately from
  `last_completed_occurrence`. Completion outcome is `success` or `retry-cap-reached`; failed
  attempts below the cap complete nothing. Durable per-Extra success facts and pending markers
  preserve the remaining work which must survive cache loss. These are runtime history, not
  another copy of schedule configuration.
- Existing manual update, Force Update/Reload, Hold, Never, disabled group, disabled row,
  package-disabled, feed-pass lock, cache-regeneration, and pending-apply contracts remain unless
  this specification explicitly changes them.
- SafeSearch and apply reconciliation retain their fixed zero-jitter 900-second ledger cadences.
  Log maintenance remains on each eligible idle tick.
- Registered General fields use `PfbConfig`; dynamic IPv4, IPv6, and DNSBL feed-group fields
  remain foreign section data. No direct registered-path access or second config gateway is
  introduced.
- The existing pfBlockerNG General-page write privilege remains the authorization boundary.
  No new privilege is introduced.
- All times are appliance-local wall-clock times. Existing local-clock behavior across timezone
  and daylight-saving changes is preserved; this effort adds no UTC conversion or timezone UI.

## Decisions

### Default Schedule and General controls

Add a **Scheduling** section to the General page after **General Settings** and before
**Log Settings**.

**Scheduled Feed Updates** is a checkbox labelled **Enable**, backed by registered
`gen/pfb_scheduled_feed_updates`. It uses `PfbToggle`, stores canonical `on` or an empty string,
and defaults On. Its help text is:

> Run enabled feed groups on their configured schedules. This does not affect manual updates,
> Extras refreshes, or pending applies.

Turning scheduled feed updates Off suppresses future scheduled feed checks only. The Default
Schedule and apply-window controls remain editable so an administrator can stage settings before
reenabling scheduled updates.

**Default Schedule** is one control group backed by these registered fields:

| Field | Stored values | Display |
| --- | --- | --- |
| `gen/pfb_schedule_weekday` | ISO `1`–`7` | Sunday first |
| `gen/pfb_schedule_hour` | `0`–`23` | zero-padded `00`–`23` |
| `gen/pfb_schedule_minute` | `0`, `15`, `30`, `45` | zero-padded |

Its help text is:

> Default local-time schedule for feed groups and calendar-scheduled Extras. Hourly schedules
> use the minute; daily schedules use the time; weekly schedules use all three.

Registry absence/corruption fallbacks are Sunday (`7`), hour `0`, and minute `0`. Fresh-install
seeding and upgrade migration persist real values before runtime reads them.

The Default Schedule applies to:

- a feed group without an enabled override;
- the daily GeoIP/MaxMind/TOP1M/ASN refresh (`dcc`); and
- the DNSBL Category refresh (`bl`), daily or weekly according to its existing cadence selector.

Calendar-scheduled Extras gain no override.

### Feed-group schedule overrides

IPv4, IPv6, and DNSBL feed groups gain **Override Default Schedule** directly below
**Update Frequency**. Enabling it exposes a **Schedule** row with Weekday, Hour, and Minute.
Client-side behavior disables Weekday unless cadence is Weekly; server-side validation remains
authoritative.

Each dynamic group record stores:

| Field | Canonical values |
| --- | --- |
| `schedule_override` | `on` or empty |
| `schedule_weekday` | ISO `1`–`7` |
| `schedule_hour` | `0`–`23` |
| `schedule_minute` | `0`, `15`, `30`, `45` |

The cadence selects the active components:

- Weekly uses `W,H,M`.
- Daily uses `H,M`.
- Every 2–12 hours uses `H,M`; occurrences are at hours congruent to `H` modulo the cadence.
- Every hour uses `M`; stored `H` is dormant.
- Never, a disabled group, or a group with no active rows schedules nothing, while its values
  remain stored.

Unchecking the override stores only `schedule_override=''` and preserves custom values. A cadence
change also preserves values that become dormant. With override Off, submitted custom values are
ignored and stored values remain unchanged. A group with no stored custom values renders current
General defaults in disabled controls.

With override On for Weekly, all three components are required and strictly validated. With
override On for another active cadence, hour and minute are required; a valid dormant weekday is
preserved, otherwise it seeds from the current General default.

DNSBL Category retains its existing Never/Daily/Weekly selector and uses the General default.
Extras and work without a current override gain none.

### Calendar occurrences and feed gates

For a reference time, the next occurrence is the first valid local calendar slot strictly after
that time:

- Every hour: next hour at `M`.
- Every `N` hours: next hour congruent to `H` modulo `N`, at `M`.
- Daily: next `(H,M)`.
- Weekly: next `(W,H,M)`.

At a `cron` wake, exact and idempotent per-feed gates select only groups with an occurrence due.
Mixed hourly/daily/weekly groups do not pull one another early. Multiple groups sharing a slot run
once each. Two consecutive ticks never run the same occurrence twice.

The shared `cron` cache entry stores the earliest future occurrence among enabled, scheduled
groups. The next tick recomputes that wake after a cadence, action, active-row state,
master-switch, or effective schedule change. A valid cache without a `cron` entry represents no
future scheduled-feed wake.

### Catch-up, pending work, and failure

If downtime crosses one or more occurrences, every affected feed group runs once on the next
eligible tick. Missed occurrences are never replayed. After that pass, the shared ledger advances
to the earliest future occurrence.

A busy feed pass leaves the active cache and durable state untouched and retries selection on the
next eligible tick. Existing pending state preserves one occurrence. Missing, malformed, or
configuration-stale cache state is regenerated before due work is selected; cache absence never
becomes a second scheduling policy.

Feed download/probe and downstream-processing failures retain their existing retry behavior. In
particular, an outcome which currently leaves a `.fail` marker continues to retry on later fixed
ticks, subject to the existing `skipfeed` daily threshold. Fresh installs default `skipfeed` to
`3`; options `0` (**No Limit**) through `6` remain available, and upgrades preserve configured
values, including `0`. A successful unchanged or conditional source check counts as successful
execution even though feed content was not modified, and completes that occurrence even if later
processing fails. Retry-cap exhaustion completes the occurrence with outcome
`retry-cap-reached`; failures below the cap do not complete it.

The scheduled-feed master switch does not discard pending applies. Changing the Automatic Apply
Window does not rephase feed cadence; pending work is reconsidered on the next fixed tick.

### Extras ordering and last-known-good data

`dcc` is due daily at the General `(H,M)`. Enabled `bl` is due daily at `(H,M)` or weekly at
`(W,H,M)` according to its existing Daily/Weekly setting. Independent Extras jittered hours are
removed.

When `dcc` or `bl` and feeds share a slot, all due Extras refreshes finish before feed processing,
so feeds consume the newest successful data. An Extras refresh failure keeps and consumes the
last-known-good data, never clears or partially replaces good data, and never blocks the feed pass.
It retries at its next scheduled occurrence, not the next fixed tick.

### Automatic Apply Window

Expose registered `gen/pfb_quiet_hours` after Default Schedule as **Automatic Apply Window**:

- checkbox: **Restrict automatic applies to a time window**;
- native Start and End time inputs with a 15-minute step; and
- form-only names `pfb_quiet_hours_enabled`, `pfb_quiet_hours_start`, and
  `pfb_quiet_hours_end`.

Only `gen/pfb_quiet_hours` persists, as canonical `HH:MM-HH:MM` or empty. With no stored window,
disabled controls show suggested values `00:00` and `06:00`. Unchecking forgets prior endpoints
and stores empty. Start is inclusive, End exclusive, midnight wrapping is valid, and equal
endpoints are invalid.

Its help text is:

> Changes detected outside this window remain pending and apply on the first eligible tick inside
> it.

The window restricts automatic applies, not scheduled feed checks or Extras refreshes.

### Validation, authorization, and cache publication

General schedule components are always required and strictly validated, even when scheduled feed
updates are Off. Missing checkboxes mean Off; literal `on` means On. Array-valued or other checkbox
tokens reject the whole save. Apply-window endpoints are required only while its checkbox is On.
Missing, array-valued, malformed, or out-of-set schedule input produces visible errors; interactive
saves never silently coerce it.

Registered fields use the existing delta-aware `PfbConfig::writeSection()` General-page
authorization boundary. Authorization denial is covered at that hermetic gateway/controller seam
and at pfSense's existing page privilege gate; no unreachable in-page denial seam is introduced.

After authorization and validation, save configuration through the normal pfSense path. Then
derive a candidate schedule cache in private temporary storage, reread and validate it there, and
discard it. The save path never replaces the active cache. If candidate generation or validation
fails, configuration remains saved and the General page visibly reports that schedule-cache
generation failed and the likely bug should be reported.

The cache may live in temporary storage. The first locked scheduling consumer after boot or
pfBlockerNG enablement, and every later tick or update that finds a missing, malformed, or
configuration-stale cache, regenerates it before scheduling decisions are made. Save and enable
paths only validate a private candidate; they never publish the active cache. This makes power loss
after configuration publication recoverable without a cross-file transaction or journal. The
scheduled process holds the schedule-dispatch lock and existing feed-pass lock while it regenerates
the active cache, reserves occurrences, runs Extras and feeds synchronously, writes marker and
outcome state, and publishes the final cache. No background scheduled worker or timed dispatch
lease can outlive those locks.

### Installation and upgrade migration

Use one idempotent migration/seed pass spanning General configuration and the IPv4, IPv6, and
DNSBL group sections, then publish it through the normal pfSense `write_config()` path. No
independent per-field flush is introduced.

Fresh installs persist Sunday and one uniformly selected `(H,M)` from the 28 quarter-hour slots
`00:00` through `06:45`, plus `skipfeed=3`. The values are normal visible settings and are never
recalculated.

On upgrade:

1. Legacy `pfb_interval='Disabled'` becomes Scheduled Feed Updates Off. Valid numeric values become
   On. Unknown or non-scalar values become On and emit a notice.
2. When both `pfb_dailystart` and `pfb_min` are valid, they seed General `(H,M)`. If either is
   missing or invalid, discard both and select one fresh uniform slot from `00:00` through `06:45`.
3. General `W` becomes Sunday.
4. Every currently Weekly group with valid legacy `dow` gets `schedule_override='on'` and
   `(dow,H,M)`, preserving its chosen weekday.
5. A valid `dow` on any other group becomes dormant `schedule_weekday`, with override Off.
6. Invalid or missing `dow` on a current Weekly group falls back to inherited Sunday and emits a
   notice. Invalid inactive `dow` is discarded.
7. Group hour/minute values seed from migrated General `(H,M)`.
8. Remove `pfb_interval`, `pfb_min`, `pfb_hour`, `pfb_dailystart`, and every legacy group `dow`
   from the configuration image published by that pass.
9. Preserve the existing `skipfeed` value, including `0`; an absent legacy value retains the
   former unlimited behavior.

Malformed-state notices name affected keys, never values. Migration never reseeds an already
migrated installation. Fresh groups inherit the Default Schedule (`schedule_override=''`).

## Acceptance criteria

1. Crontab contains one literal `*/15` pfBlockerNG tick and no user-configurable tick override;
   stale stored tick values cannot change runtime cadence.
2. Fresh-install seeding persists Sunday and one of the 28 allowed `(H,M)` slots; repeated runtime
   reads never reseed it. It also persists `skipfeed=3`, while upgrade coverage proves configured
   values and legacy absence remain unlimited.
3. One upgrade test covers General plus IPv4, IPv6, and DNSBL groups and proves every valid,
   invalid, missing, Weekly, non-Weekly, active, and inactive migration branch, including notices
   that name keys but not values.
4. Migration publishes once through the normal pfSense path, and rerunning a completed migration
   is a no-op.
5. Calendar tests cover every allowed minute, hour/day/week wrap, every existing hourly-through-
   weekly cadence, inherited and overridden phase, local-clock transition cases already supported
   by pfSense, and the strictly-after-reference rule.
6. Gate tests cover two consecutive ticks, multiple groups sharing a slot, mixed cadence groups,
   disabled/Never/Hold/empty groups, and IPv4/IPv6/DNSBL families. No group runs early or twice.
7. A frozen red-before/green-after test sets `cron.next_due` far in the past and proves each affected
   group runs exactly once, no missed slot is replayed, and the next wake is in the future.
8. Master-switch tests prove Off blocks scheduled feed checks only while manual runs, Extras,
   pending applies, and editable schedule controls retain their specified behavior.
9. Due Extras run before feeds at a shared slot. Injected `dcc` and `bl` failures preserve and feed
   last-known-good data and do not block the feed pass.
10. General save and stored-group runtime tests prove strict scalar/set validation, dormant-value
    preservation, unchanged override values while Off, delta-aware authorization, disposable
    candidate validation without active-cache replacement, and saved configuration plus a visible
    warning on candidate failure.
11. Automatic Apply Window tests prove empty, inclusive start, exclusive end, midnight wrap, equal-
    endpoint rejection, canonical storage, forgotten endpoints when unchecked, and pending apply at
    the first eligible tick.
12. `PfbConfig` registry, adapter, inventory, grandfathering, and registered-path sniff tests cover
    every new General field; dynamic group fields remain foreign and round-trip unchanged outside
    their explicit migration/save paths.
13. General and feed-group UI changes carry Tier-A render coverage and Tier-B browser coverage
    for control presence, placement, enable/disable behavior, validation errors, save/reload
    persistence, the existing privilege gate, and cache-failure warnings. Feed-group override
    controls are present for IPv4, IPv6, and DNSBL detailed editors. A failed disposable
    schedule-cache candidate leaves the saved configuration and active cache unchanged, reports
    a likely package bug, and directs operators to manual updates as a temporary workaround.
14. Focused live smoke proves fresh-install seed persistence, one genuine legacy migration,
    inherited and overridden hourly/daily/weekly dispatch, shared-slot Extras ordering,
    once-only downtime catch-up, cache regeneration, and pending apply-window behavior on selected
    CE and Plus legs.
15. Cache lifecycle tests cover valid, missing, malformed, configuration-stale, temporary-write
    failure, validation failure, rename failure, first-consumer regeneration after reboot or
    enablement, later tick/update regeneration, valid no-wake
    state, lock contention, and synchronous lock ownership through marker/outcome publication.
    Execution-history tests distinguish successful changed and unchanged checks, failures below
    the retry cap, retry-cap exhaustion, and downstream failure after source success.
16. `scripts/agent/run-gates.sh --diff origin/devel` and all focused PHP, smoke, and UI suites pass;
    every behavior change carries frozen test-first red-to-green evidence.

## Out of scope

- User-facing feed cadences below one hour, including 15 and 30 minutes.
- A per-minute or resident scheduler, arbitrary cron expressions, phased crontab minute lists, or
  an install-generated offset/re-roll UX.
- Per-feed due-ledger entries or any second persisted copy of feed schedule configuration. Durable
  successful-execution/completed-occurrence facts and pending markers are runtime history and are
  explicitly in scope.
- Schedule overrides for Extras, SafeSearch, apply reconciliation, log maintenance, or work that
  has no existing feed-group schedule.
- New privileges, timezone controls, UTC schedule storage, or changes to pfSense local-clock
  semantics.
- Replaying every occurrence missed during downtime.
- Implementing the scheduling behavior while authoring this specification.

## Open forks

None.
