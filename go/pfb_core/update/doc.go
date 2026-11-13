// Package update is Core's singleton Update (issue #3941, map #3813): a gate that admits one Update at a time (a TryLock held
// for the whole run; a second Start is refused, never queued) with its status and log readable meanwhile, and the executor
// that runs the Outpost's update program for it. Nothing survives a restart: a new process starts idle.
package update
