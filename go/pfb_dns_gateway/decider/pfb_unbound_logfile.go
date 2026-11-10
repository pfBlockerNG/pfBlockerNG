// Go translation of the log files of pfb_unbound.py: pfb_setup_logging, pfb_log and _log_entry_direct. One writer
// goroutine per module appends each row to its file behind a bounded queue that drops on full, so a slow disk never
// holds a query; a file that was rotated or removed is reopened; a module with no writer appends synchronously.
package decider

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_dns_gateway/decider/pysem"
)

// logQueueMaxsize is PFB_LOG_QUEUE_MAXSIZE.
const logQueueMaxsize = 5000

// pfbLogDir is where the module's logs live (PFB_LOG_FILES); a variable so that tests never write the real ones.
var pfbLogDir = "/var/log/pfblockerng"

// logRetrySleep is _log_entry_direct's pause between attempts.
var logRetrySleep = time.Sleep

// logRecord is one row for the writer, or a barrier it closes once everything queued before it is written, or the stop.
type logRecord struct {
	path, line string
	barrier    chan struct{}
	stop       bool
}

// watchedFile is a log opened for append, with the file it was opened on: WatchedFileHandler's stream and (dev, ino).
type watchedFile struct {
	file *os.File
	info os.FileInfo
}

type logPipeline struct {
	queue      chan logRecord
	paths      map[string]struct{}
	done       chan struct{}
	stopMu     sync.Mutex // serializes stop; stopQueued is guarded by it
	stopQueued bool
	stopped    atomic.Bool
	drops      atomic.Int64
	// beforeWrite runs in the writer before each row is written; a test holds the writer there to fill the queue.
	beforeWrite func()

	// the writer's own: only its goroutine touches them
	files   map[string]*watchedFile
	failing map[string]bool
}

// newLogPipeline starts the writer for `paths`; a path opens on its first row (delay=True), not here.
func newLogPipeline(paths []string, maxsize int) *logPipeline {
	p := &logPipeline{
		queue:   make(chan logRecord, maxsize),
		paths:   make(map[string]struct{}, len(paths)),
		done:    make(chan struct{}),
		files:   map[string]*watchedFile{},
		failing: map[string]bool{},
	}
	for _, path := range paths {
		p.paths[path] = struct{}{}
	}
	go p.run()
	return p
}

func (p *logPipeline) handles(path string) bool {
	_, ok := p.paths[path]
	return ok
}

// emit queues a row, or drops it when the queue is full: it never blocks the DNS path.
func (p *logPipeline) emit(path, line string) {
	select {
	case p.queue <- logRecord{path: path, line: line}:
	default:
		p.drops.Add(1)
	}
}

// dropped is pfb["log_dropped"].
func (p *logPipeline) dropped() int64 { return p.drops.Load() }

// flush returns once every row emitted before it is written. It blocks while the queue is full, so it is for a test or
// a shutdown, never the DNS path.
func (p *logPipeline) flush() {
	if p.stopped.Load() {
		return
	}
	barrier := make(chan struct{})
	select {
	case p.queue <- logRecord{barrier: barrier}:
		select {
		case <-barrier:
		case <-p.done:
		}
	case <-p.done:
	}
}

// stop asks the writer to write what is queued and end (QueueListener.stop()), and waits for it. The request is queued
// without waiting, as Python does (put_nowait): on a full queue it is not queued, stop returns at once, and the writer
// keeps running and writing what is queued, as Python's listener thread does when deinit catches the queue.Full. A stop
// that did not queue can be tried again; once queued, a further stop only waits for the writer to end.
func (p *logPipeline) stop() {
	p.stopMu.Lock()
	defer p.stopMu.Unlock()
	if !p.stopQueued {
		select {
		case p.queue <- logRecord{stop: true}:
			p.stopQueued = true
			p.stopped.Store(true)
		default:
			return
		}
	}
	<-p.done
}

func (p *logPipeline) run() {
	defer close(p.done)
	for rec := range p.queue {
		switch {
		case rec.stop:
			for _, wf := range p.files {
				wf.file.Close()
			}
			return
		case rec.barrier != nil:
			close(rec.barrier)
		default:
			if p.beforeWrite != nil {
				p.beforeWrite()
			}
			p.write(rec.path, rec.line)
		}
	}
}

// write appends one row, reopening the file first if its path no longer names the file that was opened (WatchedFileHandler:
// the line-cap trim and the viewer clear rotate it). A failure is logged once, until a row is written again.
// shortcut: Python's logging handler reports every failed record (logging.handleError prints a "--- Logging error ---"
// traceback to stderr, the reason the same as here), so a run of failing rows is one line here and one traceback per row
// there. Only the stderr volume differs; the rows that fail and the rows written are the same.
func (p *logPipeline) write(path, line string) {
	err := p.append(path, line)
	if err == nil {
		delete(p.failing, path)
		return
	}
	if !p.failing[path] {
		p.failing[path] = true
		logErr(fmt.Sprintf("[pfBlockerNG]: Failed to write %s: %v", path, err))
	}
}

// rowEncodeError is the UnicodeEncodeError Python's UTF-8 codec raises on a row holding a lone surrogate, which only an
// observer report's name can put there; nil for a row it encodes. The first run of surrogates is the one named, by its
// position in characters.
func rowEncodeError(line string) error {
	start := -1
	var first rune
	pos := 0
	for rest := line; len(rest) > 0; pos++ {
		r, size := pysem.DecodeRune(rest)
		rest = rest[size:]
		surrogate := 0xD800 <= r && r <= 0xDFFF
		switch {
		case surrogate && start < 0:
			start, first = pos, r
		case surrogate:
		case start >= 0:
			return surrogateEncodeError(start, pos-1, first)
		}
	}
	if start >= 0 {
		return surrogateEncodeError(start, pos-1, first)
	}
	return nil
}

func surrogateEncodeError(start, end int, first rune) error {
	if start == end {
		return fmt.Errorf("'utf-8' codec can't encode character '\\u%04x' in position %d: surrogates not allowed", first, start)
	}
	return fmt.Errorf("'utf-8' codec can't encode characters in position %d-%d: surrogates not allowed", start, end)
}

func (p *logPipeline) append(path, line string) error {
	if err := rowEncodeError(line); err != nil {
		return err
	}
	if wf := p.files[path]; wf != nil {
		if current, err := os.Stat(path); err != nil || !os.SameFile(wf.info, current) {
			wf.file.Close()
			delete(p.files, path)
		}
	}
	wf := p.files[path]
	if wf == nil {
		file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o666)
		if err != nil {
			return err
		}
		info, err := file.Stat()
		if err != nil {
			file.Close()
			return err
		}
		wf = &watchedFile{file, info}
		p.files[path] = wf
	}
	if _, err := wf.file.WriteString(line + "\n"); err != nil {
		wf.file.Close()
		delete(p.files, path)
		return err
	}
	return nil
}

// logEntryDirect is _log_entry_direct: the synchronous append of a module with no writer, four attempts a quarter of a
// second apart; the last failure is reported.
// shortcut: Python writes the attempt-4 line to sys.stderr, which init_standard() points at a logger: it reaches
// py_error.log as "<asctime>|ERROR| [pfBlockerNG]: log_entry: 4: <reason>", the message stripped, and a message equal to
// the one before it is not logged again (three rows failing alike leave one line). Go writes "pfb_dns_proxy error:
// [pfBlockerNG]: log_entry: 4: <reason>" and a newline to the process stderr for every row that fails. The reason is
// Python's for a row that cannot be encoded; for an OS failure it is Go's text ("open …: no such file or directory"), where
// Python's is "[Errno 2] No such file or directory: '…'". Upgrade when the module's stderr is translated to py_error.log.
func logEntryDirect(line, log string) {
	for attempt := 1; attempt <= 4; attempt++ {
		file, err := os.OpenFile(log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o666)
		if err == nil {
			if err = rowEncodeError(line); err == nil {
				_, err = file.WriteString(line + "\n")
			}
			if closeErr := file.Close(); err == nil {
				err = closeErr
			}
		}
		if err == nil {
			return
		}
		if attempt == 4 {
			logErr(fmt.Sprintf("[pfBlockerNG]: log_entry: %d: %v", attempt, err))
		}
		logRetrySleep(250 * time.Millisecond)
	}
}

func (m *pfbUnbound) logPath(name string) string {
	dir := m.logDir
	if dir == "" {
		dir = pfbLogDir
	}
	return filepath.Join(dir, name)
}

// pfbLog is pfb_log: a row to an app log through the writer, else appended directly; a test's logSink takes it instead.
func (m *pfbUnbound) pfbLog(name, line string) {
	path := m.logPath(name)
	switch {
	case m.logSink != nil:
		m.logSink(name, line)
	case m.logs != nil && m.logs.handles(path):
		m.logs.emit(path, line)
	default:
		logEntryDirect(line, path)
	}
}

// pfbSetupLogging starts the writer for the two logs unless one runs (end of init_standard).
func (m *pfbUnbound) pfbSetupLogging() {
	if m.logs != nil {
		return
	}
	m.logDir = pfbLogDir
	m.logs = newLogPipeline([]string{m.logPath(dnsblLogName), m.logPath(dnsReplyLogName)}, logQueueMaxsize)
}

// stopLogging is deinit's stop of the writer, which writes what is queued; the module has no query in flight by then.
func (m *pfbUnbound) stopLogging() {
	if m.logs != nil {
		m.logs.stop()
		m.logs = nil
	}
}
