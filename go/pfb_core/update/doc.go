// Package update is Core's singleton Update (issue #3941, map #3813): the gate that lets one Update run at a time and
// keeps its progress in memory and in a log file, and the executor that runs the Outpost's update program for it.
//
// Admission is a nonblocking sync.Mutex.TryLock held for the whole run: a second Start is refused, never queued. The
// status and the log are read under a separate lock, so a View answers while a run holds the gate. Nothing is kept
// across a restart: a new process starts idle.
package update
