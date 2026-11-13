// Package scheduler is Core's quarter-hour scheduler (issue #3941, map #3813): the scheduling half of the PHP
// pfblockerng_tick(). Each quarter hour it evaluates what is due over the schedule package, reserves the occurrences,
// asks the singleton Update gate to run them and records the outcomes the Update reports. It also builds the request for an
// Update the Outpost or a user asked for, and answers the schedule view. Nothing in Core calls it yet.
//
// The Scheduler and the gate refer to each other, so they are wired in two steps: create the Scheduler, create the gate
// with s.Done as its done callback, then s.Bind(gate.Start). One mutex orders Tick, Start, Done and View; the gate calls
// Done before it admits the next Update, so a result is recorded before the next evaluation.
//
// The state is schedule.State kept in memory and in one file, {"schema":1,"items":{...}}, replaced atomically after every
// change. A file that is absent or unusable starts an empty state: the next evaluation recomputes what is due.
package scheduler
