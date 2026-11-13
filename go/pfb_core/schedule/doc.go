// Package schedule is the Go port of the scheduler's evaluation logic (issue #3938, map #3813). Core's scheduler package
// calls it, and main.go runs that package when Core starts with --update-cmd (#3941). The frozen corpus in testdata/ is
// replayed here for every section, and by PHP for the sections whose function remains there.
//
// Each function ports one of pfblockerng_extra.inc's (pfb_schedule_extra_plan, pfb_schedule_feed_plan, pfb_schedule_reserve,
// pfb_schedule_state_set_pending and pfb_schedule_state_record_outcome were removed by the cutover, #3941: Go is their only copy):
//
//	NextOccurrence  pfb_schedule_next_occurrence
//	Plan            pfb_schedule_plan (its $since and $next_occurrence arguments are always the defaults, so dropped)
//	ExtraPlan       pfb_schedule_extra_plan
//	FeedPlan        pfb_schedule_feed_plan (the tick's plan over the feeds, extracted from pfblockerng_tick())
//	CacheEntries    pfb_schedule_cache_refresh (the ledger entries it computes, not the file merge)
//	InApplyWindow   pfb_quiet_hours_in_window
//	ParseState      pfb_schedule_state_valid and pfb_schedule_state_read
//	SetPending      pfb_schedule_state_set_pending
//	Reserve         pfb_schedule_reserve (set_pending, then a newer planned occurrence replaces an older pending one)
//	RecordOutcome   pfb_schedule_state_record_outcome
//	RecordOutcomes  pfb_schedule_state_record_outcome for many ids, with one validation and copy of the state
//	RuntimeModel    pfb_schedule_runtime_model, pfb_schedule_runtime_hash_projection and pfb_group_action_valid
//	BlacklistExtra  the extra:bl derivation of pfb_schedule_runtime_config
//
// Instants are Unix seconds; a schedule is read in the *time.Location the caller passes.
package schedule
