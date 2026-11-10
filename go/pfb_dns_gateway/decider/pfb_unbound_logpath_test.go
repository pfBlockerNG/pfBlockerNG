// Which path a module's rows take, and what happens to them under concurrent queries: a running writer takes every row
// off the query path, and the duplicate mark of a row is decided once however many queries log at the same time.
package decider

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestARunningWriterTakesTheRowOffTheQueryPath(t *testing.T) {
	dir := t.TempDir()
	m, f := moduleWithLogs(t, dir)
	release := stuckWriter(t, m.logs, m.logPath(dnsblLogName))
	var answer []byte
	if !within(func() {
		answer = f.Resolve(qtypeWire(t, "lf1.example.", 1), "192.0.2.10", unboundAnswering192_0_2_77(t), "UDP", "", "")
	}) {
		t.Fatal("a query blocked on its log row while the writer was stuck")
	}
	if answer == nil {
		t.Fatal("the query got no answer")
	}
	if got, err := os.ReadFile(filepath.Join(dir, "dnsbl.log")); err == nil && len(bytes.TrimSpace(got)) > 0 {
		t.Fatalf("dnsbl.log = %q while the writer was stuck: the row was appended on the query path (the direct fallback is for a module with no writer)", got)
	}
	release()
	m.logs.flush()
	// "first" is what held the writer; the block row queued behind it
	if got := readLog(t, filepath.Join(dir, "dnsbl.log")); !strings.HasPrefix(got, "first\nDNSBL-python,") || strings.Count(got, "\n") != 2 {
		t.Errorf("dnsbl.log = %q, want the held row and then the one block row, written by the writer once it was free", got)
	}
}

func TestConcurrentBlocksMarkExactlyOneRowNewAndLoseNone(t *testing.T) {
	const rounds, queries = 1000, 32
	dir := t.TempDir()
	m, _ := moduleWithLogs(t, dir)
	block := &dnsblDecision{isFound: true, logType: "1", bType: "DNSBL", pType: "Python", feed: "F1", group: "G1", bEval: "lf1.example"}
	stopFlush, flushed := make(chan struct{}), make(chan struct{})
	go func() { // a flush racing the emitters, as a shutdown or a test barrier would
		defer close(flushed)
		for {
			select {
			case <-stopFlush:
				return
			default:
				m.logs.flush()
			}
		}
	}()
	for round := range rounds {
		// every round is one event, different from the previous round's: exactly one of its queries finds the last event
		// different and marks its row new
		client := fmt.Sprintf("10.%d.%d.1", round/250, round%250)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for range queries {
			wg.Add(1)
			go func() {
				defer wg.Done()
				qstate := newModuleQstate(queryInfo{"lf1.example.", RR_TYPE_A, RR_CLASS_IN}, "192.0.2.10", 0, 0, "UDP", "", "")
				<-start
				m.getDetailsDnsbl("dnsbl", nil, qstate, &logKwargs{pfbAddr: &client}, block, "")
			}()
		}
		close(start)
		wg.Wait()
		m.logs.flush() // a round never outruns the writer, so the 5000-row queue never drops
	}
	close(stopFlush)
	<-flushed
	m.stopLogging() // writes what is still queued
	rows := strings.Split(strings.TrimSuffix(readLog(t, filepath.Join(dir, "dnsbl.log")), "\n"), "\n")
	var fresh, duplicate int
	for _, row := range rows {
		switch {
		case strings.Contains(row, ",F1,+,A,"):
			fresh++
		case strings.Contains(row, ",F1,-,A,"):
			duplicate++
		default:
			t.Fatalf("unexpected row %q", row)
		}
	}
	if want := fmt.Sprintf("%d rows", rounds*queries); fmt.Sprintf("%d rows", len(rows)) != want {
		t.Errorf("%d rows written, want %s: none is dropped (the queue holds a round) or lost", len(rows), want)
	}
	if fresh != rounds || duplicate != rounds*(queries-1) {
		t.Errorf("%d new and %d duplicate rows, want %d and %d: of a round's identical events exactly the first is new", fresh, duplicate, rounds, rounds*(queries-1))
	}
}
