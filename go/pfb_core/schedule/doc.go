// Package schedule is the Go port of the scheduler's evaluation logic (issue #3938, map #3813). It is parity only: nothing
// calls it yet and the PHP path stays authoritative; the frozen corpus in testdata/ proves both sides answer alike.
//
// Each function ports one of pfblockerng_extra.inc's:
//
//	NextOccurrence  pfb_schedule_next_occurrence
//	Plan            pfb_schedule_plan (its $since and $next_occurrence arguments are always the defaults, so dropped)
//	ExtraPlan       pfb_schedule_extra_plan
//	CacheEntries    pfb_schedule_cache_refresh (the ledger entries it computes, not the file merge)
//	InApplyWindow   pfb_quiet_hours_in_window
//	ParseState      pfb_schedule_state_valid and pfb_schedule_state_read
//	SetPending      pfb_schedule_state_set_pending
//	RecordOutcome   pfb_schedule_state_record_outcome
//	RuntimeModel    pfb_schedule_runtime_model, pfb_schedule_runtime_hash_projection and pfb_group_action_valid
//	BlacklistExtra  the extra:bl derivation of pfb_schedule_runtime_config
//
// Instants are Unix seconds; a schedule is read in the *time.Location the caller passes.
package schedule
