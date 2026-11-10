// The query watcher under #3820's lifecycle: deinit stops it, bounded as the other watchers are, and once the module is
// retired a request it reads or a reply it would write changes nothing on disk.
package decider

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func queryReplyExists(dir string) bool {
	_, err := os.Lstat(filepath.Join(dir, "pfb_py_query.reply"))
	return err == nil
}

// deinit stops the query watcher with the others (Python's deinit sets its stop Event and joins it): its goroutine and
// its tick source end, and the module no longer holds it.
func TestDeinitStopsTheQueryWatcher(t *testing.T) {
	m := modMust(t, t.TempDir())
	m.stopQueryWatcher()
	ended := make(chan struct{})
	m.queryTick = func() (<-chan time.Time, func()) { return make(chan time.Time), func() { close(ended) } }
	m.startQueryWatcher()
	m.deinit()
	chWait(t, "the query watcher to end after deinit", ended)
	if m.queryStop != nil {
		t.Errorf("the query watcher is still marked running after deinit")
	}
}

// A reply is not written once the module is closed, whoever asks for it.
func TestAClosedModuleWritesNoQueryReply(t *testing.T) {
	dir := t.TempDir()
	m := modMust(t, dir)
	m.deinit()
	m.queryWriteReply(queryMiss())
	if queryReplyExists(dir) {
		t.Errorf("a closed module wrote the query reply")
	}
}

// A request that is read after Close (the watcher was blocked reading the channel when Close gave up on it) is not
// answered or even evaluated, and Close does not wait for that read.
func TestAQueryRequestReadAfterCloseIsNotAnswered(t *testing.T) {
	dir := t.TempDir()
	m := modMust(t, dir)
	shortStopWait(t)
	m.stopQueryWatcher()
	channel := filepath.Join(dir, "pfb_py_query")
	if err := syscall.Mkfifo(channel, 0o660); err != nil { // the watcher's first read blocks: nobody writes the FIFO
		t.Fatal(err)
	}
	ended := make(chan struct{})
	m.queryTick = func() (<-chan time.Time, func()) { return make(chan time.Time), func() { close(ended) } }
	m.startQueryWatcher()
	var writer int
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		fd, err := syscall.Open(channel, syscall.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil { // a reader is waiting in its open: the watcher is in its read
			writer = fd
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the query watcher never blocked reading its channel")
		}
	}
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		m.deinit()
	}()
	chWait(t, "Close to give up on the blocked watcher", closed)

	if _, err := syscall.Write(writer, []byte(`{"id": "late", "domain": "listed.example.com"}`)); err != nil {
		t.Fatal(err)
	}
	syscall.Close(writer)
	chWait(t, "the query watcher to end", ended)
	if queryReplyExists(dir) {
		t.Errorf("a request read in a closed module was answered")
	}
	if _, memoized := m.decisionDB.get("listed.example.com"); memoized {
		t.Errorf("a request read in a closed module was evaluated: its decision is memoized")
	}
}
