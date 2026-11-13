package settings

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

const (
	protocolVersion = 1
	maxReply        = 1 << 20          // the stdout a call accepts
	maxStderr       = 4 << 10          // the stderr tail kept for an error message
	waitDelay       = time.Second      // how long a grandchild holding the adapter's pipes may keep a call waiting
	readTimeout     = 10 * time.Second // under the API's 25 s method deadline
	writeTimeout    = 20 * time.Second
)

// AdapterBackend keeps the configuration in another program's store (on pfSense, config.xml, through a PHP adapter) and
// reaches it by running Path once per call: one JSON request on stdin, one JSON reply on stdout, exit status 0.
//
//	request {"version":1,"op":"read"} or {"version":1,"op":"write","expectedRevision":N,"settings":{<projection>:{<field>:<value>}}}
//	reply   {"version":1,"revision":N,"settings":{...}} for a read, {"version":1,"revision":N} for a write, or
//	        {"version":1,"error":{"code":"conflict"|"invalid_argument"|"unavailable","message":"...","fieldErrors":[{"field","message"}]}}
//
// Its settings always exist, so Read is always Initialized. Every failure is a *BackendError: a non-zero exit (with the
// adapter's stderr tail), a deadline, a reply that is not exactly one such object. ReadTimeout and WriteTimeout default to
// 10 s and 20 s; the deadline kills the adapter's whole process group.
type AdapterBackend struct {
	Path                      string
	ReadTimeout, WriteTimeout time.Duration
}

type request struct {
	Version          int                       `json:"version"`
	Op               string                    `json:"op"`
	ExpectedRevision *uint64                   `json:"expectedRevision,omitempty"`
	Settings         map[string]map[string]any `json:"settings,omitempty"`
}

type replyError struct {
	Code        string       `json:"code"`
	Message     string       `json:"message"`
	FieldErrors []FieldError `json:"fieldErrors"`
}

type reply struct {
	Version  int                                   `json:"version"`
	Revision uint64                                `json:"revision"`
	Settings map[string]map[string]json.RawMessage `json:"settings"`
	Error    *replyError                           `json:"error"`
}

func (a *AdapterBackend) Read() (Stored, error) {
	r, err := a.call(cmp.Or(a.ReadTimeout, readTimeout), request{Version: protocolVersion, Op: "read"})
	if err != nil {
		return Stored{}, err
	}
	if r.Settings == nil {
		return Stored{}, backendErr("the reply to a read holds no settings")
	}
	return Stored{Initialized: true, Revision: r.Revision, Projections: r.Settings}, nil
}

func (a *AdapterBackend) Write(expected uint64, values map[string]map[string]any) (uint64, error) {
	r, err := a.call(cmp.Or(a.WriteTimeout, writeTimeout),
		request{Version: protocolVersion, Op: "write", ExpectedRevision: &expected, Settings: values})
	if err != nil {
		return 0, err
	}
	return r.Revision, nil
}

func backendErr(format string, args ...any) *BackendError {
	return &BackendError{Err: fmt.Errorf(format, args...)}
}

// call runs the adapter with req and returns its reply: a whole one with a revision, or the error its refusal maps to.
func (a *AdapterBackend) call(timeout time.Duration, req request) (*reply, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, &BackendError{Err: err}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, errTail := &capped{limit: maxReply, stop: cancel}, &tail{limit: maxStderr}
	cmd := exec.CommandContext(ctx, a.Path)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = bytes.NewReader(body), out, errTail
	// One process group for the adapter and whatever it starts, so that the deadline leaves no child behind.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = waitDelay
	err = cmd.Run()
	switch {
	case out.over:
		return nil, backendErr("the reply is over 1 MiB")
	case err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded):
		return nil, backendErr("timed out after %s", timeout)
	case errors.Is(err, exec.ErrWaitDelay):
		// The adapter exited 0 and a child it left behind holds the pipes: the reply it wrote is whole.
	case err != nil:
		if msg := strings.TrimSpace(string(errTail.buf)); msg != "" {
			return nil, backendErr("%v: %s", err, msg)
		}
		return nil, &BackendError{Err: err}
	}
	return parseReply(out.buf)
}

// parseReply accepts exactly one JSON object of protocol version 1 and nothing after it.
func parseReply(out []byte) (*reply, error) {
	dec := json.NewDecoder(bytes.NewReader(out))
	dec.DisallowUnknownFields()
	var r reply
	if err := dec.Decode(&r); err != nil {
		return nil, backendErr("the reply is not one JSON object: %v", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, backendErr("the reply is not one JSON object: it has data after the first")
	}
	switch {
	case r.Version != protocolVersion:
		return nil, backendErr("the reply speaks version %d, not %d", r.Version, protocolVersion)
	case r.Error != nil:
		return nil, r.Error.refusal()
	case r.Revision == 0:
		return nil, backendErr("the reply has no revision")
	}
	return &r, nil
}

// refusal maps the adapter's error onto the store's: a conflict and an invalid request refuse the call, anything else is a failure.
func (e *replyError) refusal() error {
	switch e.Code {
	case "conflict":
		return &ConflictError{Field: "expectedRevision", Message: cmp.Or(e.Message, "the adapter holds the settings at another revision")}
	case "invalid_argument":
		fields := e.FieldErrors
		if len(fields) == 0 {
			fields = []FieldError{{Field: "settings", Message: e.Message}}
		}
		return &ValidationError{Fields: fields}
	}
	return backendErr("the adapter answered %s: %s", e.Code, e.Message)
}

// capped keeps the stdout written to it; past limit it stops the adapter instead of buffering more.
type capped struct {
	buf   []byte
	limit int
	over  bool
	stop  func()
}

func (c *capped) Write(p []byte) (int, error) {
	if len(c.buf)+len(p) <= c.limit {
		c.buf = append(c.buf, p...)
	} else if !c.over {
		c.over = true
		c.stop()
	}
	return len(p), nil
}

// tail keeps the last limit bytes written to it.
type tail struct {
	buf   []byte
	limit int
}

func (t *tail) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.limit {
		t.buf = append(t.buf[:0], t.buf[len(t.buf)-t.limit:]...)
	}
	return len(p), nil
}
