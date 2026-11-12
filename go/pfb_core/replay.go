package main

import (
	"context"
	"sync"
)

// replayEntries bounds the remembered mutating requests: the oldest is forgotten first. The memory is the process's own:
// a restarted Core remembers none, as documented.
const replayEntries = 4096

type replayEntry struct {
	digest  [32]byte // of the whole request body: the same requestId with another body is a conflict
	done    chan struct{}
	resp    response
	waiters int // duplicates waiting for the first execution (guarded by the cache's mutex)
}

// replayCache runs each (method, requestId) once and answers every repeat with the first response.
type replayCache struct {
	mu      sync.Mutex
	entries map[string]*replayEntry
	order   []string
	limit   int
}

func newReplayCache(limit int) *replayCache {
	return &replayCache{entries: make(map[string]*replayEntry), limit: limit}
}

func replayKey(method, id string) string { return method + "\x00" + id }

// do answers a mutating request: the first time run() executes and its response is kept; a repeat with the same body waits
// for that response (a repeat that arrives while the first still runs never runs it again) and gets the same bytes.
func (c *replayCache) do(ctx context.Context, method, id string, digest [32]byte, run func() response) response {
	key := replayKey(method, id)
	c.mu.Lock()
	if e, ok := c.entries[key]; ok {
		if e.digest != digest {
			c.mu.Unlock()
			return errorResponse(newError(codeConflict, "this requestId was already used for a different request",
				fieldError{Field: "requestId", Message: "already used with another body"}))
		}
		e.waiters++
		c.mu.Unlock()
		defer func() { c.mu.Lock(); e.waiters--; c.mu.Unlock() }()
		select {
		case <-e.done:
			return e.resp
		case <-ctx.Done():
			return errorResponse(newError(codeUnavailable, "the first request with this requestId is still running"))
		}
	}
	e := &replayEntry{digest: digest, done: make(chan struct{})}
	c.entries[key] = e
	c.order = append(c.order, key)
	// Forget the oldest finished entries above the limit; one still running is kept, or its repeat would run it again
	for i := 0; len(c.order) > c.limit && i < len(c.order); {
		key := c.order[i]
		select {
		case <-c.entries[key].done:
			delete(c.entries, key)
			c.order = append(c.order[:i], c.order[i+1:]...)
		default:
			i++
		}
	}
	c.mu.Unlock()
	e.resp = run()
	close(e.done)
	return e.resp
}

// waiting is how many repeats of (method, requestId) wait for its first execution now.
func (c *replayCache) waiting(method, id string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[replayKey(method, id)]; ok {
		return e.waiters
	}
	return 0
}
