package process

// These pointers let external tests exercise Update through the shared owner's existing private seams.
var LeaderExited = &leaderExited
var Reap = &reap
