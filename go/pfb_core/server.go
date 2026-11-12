package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

// docs/misc/core-api-protocol.md is the contract this file serves: POST /v1/<Method>, one JSON object in and out, the
// error envelope and its HTTP statuses, requestId replay, the limits, and who may call.

const (
	apiVersion               = "v1"
	defaultMaxBody           = 1 << 20
	defaultReadHeaderTimeout = 5 * time.Second
	defaultReadTimeout       = 10 * time.Second
	defaultWriteTimeout      = 30 * time.Second
	defaultIdleTimeout       = 60 * time.Second
	defaultMethodTimeout     = 25 * time.Second // below the write timeout, so the reply still goes out
	maxRequestIDLength       = 128
)

// The error codes and their HTTP statuses: the closed set the protocol note documents.
const (
	codeInvalidArgument  = "invalid_argument"
	codeUnauthenticated  = "unauthenticated"
	codeNotFound         = "not_found"
	codeMethodNotAllowed = "method_not_allowed"
	codeConflict         = "conflict"
	codePayloadTooLarge  = "payload_too_large"
	codeInternal         = "internal"
	codeUnavailable      = "unavailable"
)

var statusOf = map[string]int{
	codeInvalidArgument:  http.StatusBadRequest,
	codeUnauthenticated:  http.StatusUnauthorized,
	codeNotFound:         http.StatusNotFound,
	codeMethodNotAllowed: http.StatusMethodNotAllowed,
	codeConflict:         http.StatusConflict,
	codePayloadTooLarge:  http.StatusRequestEntityTooLarge,
	codeInternal:         http.StatusInternalServerError,
	codeUnavailable:      http.StatusServiceUnavailable,
}

type fieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// apiError is what a method returns to answer with the error envelope; any other error is answered as internal.
type apiError struct {
	Code        string       `json:"code"`
	Message     string       `json:"message"`
	FieldErrors []fieldError `json:"fieldErrors,omitempty"`
}

func (e *apiError) Error() string { return e.Code + ": " + e.Message }

func newError(code, message string, fields ...fieldError) *apiError {
	return &apiError{Code: code, Message: message, FieldErrors: fields}
}

// method is one API method. params is the request body, a JSON object; mutating methods carry a requestId in it and
// run at most once per requestId (replay.go).
type method struct {
	mutating bool
	call     func(ctx context.Context, params []byte) (any, error)
}

func productionMethods() map[string]method {
	return map[string]method{
		"GetVersion": {call: func(_ context.Context, params []byte) (any, error) {
			if err := decodeParams(params, &struct{}{}); err != nil {
				return nil, err
			}
			return map[string]string{"service": "pfblockerng-core", "apiVersion": apiVersion, "status": "serving"}, nil
		}},
	}
}

// decodeParams reads params into v strictly: an unknown field or a value of the wrong type is a field error.
func decodeParams(params []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(params))
	dec.DisallowUnknownFields()
	err := dec.Decode(v)
	if err == nil {
		return nil
	}
	var typeErr *json.UnmarshalTypeError
	switch {
	case errors.As(err, &typeErr):
		return newError(codeInvalidArgument, "a parameter has the wrong type",
			fieldError{Field: typeErr.Field, Message: "must be a JSON " + typeErr.Type.Kind().String()})
	case strings.HasPrefix(err.Error(), `json: unknown field "`):
		name := strings.TrimSuffix(strings.TrimPrefix(err.Error(), `json: unknown field "`), `"`)
		return newError(codeInvalidArgument, "the request has a parameter this method does not take",
			fieldError{Field: name, Message: "unknown parameter"})
	}
	return newError(codeInvalidArgument, "the parameters cannot be read: "+err.Error())
}

type options struct {
	socket            string
	allowUID          uint32   // the privileged caller's uid (root): the kernel's credential of the connecting process
	clientUIDs        []uint32 // further local clients served (pfb-dns's user)
	socketGroup       int      // with groupSet: the group the socket's directory (0750) and the socket (0660) are opened to
	groupSet          bool
	maxBody           int64 // 0: defaultMaxBody
	readHeaderTimeout time.Duration
	methods           map[string]method
	logf              func(format string, args ...any)
}

type server struct {
	o      options
	ln     *net.UnixListener
	http   *http.Server
	replay *replayCache
}

type peerKey struct{}

type peer struct {
	uid uint32
	err error
}

// listen makes the socket's directory private (0700, the server's own), replaces a socket an earlier server left, and listens
// with the socket itself 0600: only the server's user can connect, and it is still checked by its kernel credential. With a
// socket group the directory is 0750 and the socket 0660, both of that group, so a further client's user in it can connect.
func listen(o options) (*server, error) {
	if o.maxBody == 0 {
		o.maxBody = defaultMaxBody
	}
	if o.readHeaderTimeout == 0 {
		o.readHeaderTimeout = defaultReadHeaderTimeout
	}
	dirMode, sockMode := os.FileMode(0o700), os.FileMode(0o600)
	if o.groupSet {
		dirMode, sockMode = 0o750, 0o660
	}
	if err := privateDir(filepath.Dir(o.socket), dirMode); err != nil {
		return nil, err
	}
	if o.groupSet {
		if err := os.Chown(filepath.Dir(o.socket), -1, o.socketGroup); err != nil {
			return nil, err
		}
	}
	if info, err := os.Lstat(o.socket); err == nil {
		if info.Mode()&fs.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", o.socket)
		}
		if err := os.Remove(o.socket); err != nil {
			return nil, fmt.Errorf("cannot replace the old socket: %w", err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: o.socket, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if o.groupSet {
		err = os.Chown(o.socket, -1, o.socketGroup)
	}
	if err == nil {
		err = os.Chmod(o.socket, sockMode)
	}
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("cannot set the socket's owner and mode: %w", err)
	}
	s := &server{o: o, ln: ln, replay: newReplayCache(replayEntries)}
	s.http = &http.Server{
		Handler:           http.HandlerFunc(s.handle),
		ReadHeaderTimeout: o.readHeaderTimeout,
		ReadTimeout:       defaultReadTimeout,
		WriteTimeout:      defaultWriteTimeout,
		IdleTimeout:       defaultIdleTimeout,
		MaxHeaderBytes:    16 << 10,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			uc, ok := c.(*net.UnixConn)
			if !ok {
				return context.WithValue(ctx, peerKey{}, peer{err: errors.New("not a Unix socket connection")})
			}
			uid, err := peerUID(uc)
			return context.WithValue(ctx, peerKey{}, peer{uid: uid, err: err})
		},
	}
	return s, nil
}

// privateDir creates dir with mode or checks the one there: a real directory of the server's user, set to mode if it differs.
func privateDir(dir string, mode os.FileMode) error {
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%s is not owned by the user running the server", dir)
	}
	if info.Mode().Perm() != mode {
		return os.Chmod(dir, mode)
	}
	return nil
}

// serve answers requests until shutdown; it returns nil then.
func (s *server) serve() error {
	if err := s.http.Serve(s.ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// shutdown stops taking connections, waits for the requests in flight (up to ctx, then closes them) and removes the socket.
func (s *server) shutdown(ctx context.Context) error {
	err := s.http.Shutdown(ctx)
	if err != nil {
		_ = s.http.Close()
	}
	if rmErr := os.Remove(s.o.socket); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) && err == nil {
		err = rmErr
	}
	return err
}

// response is one complete answer, kept as bytes so that a replay sends exactly what the first request got.
type response struct {
	status int
	body   []byte
}

func errorResponse(e *apiError) response {
	body, _ := json.Marshal(struct {
		Error *apiError `json:"error"`
	}{e})
	return response{status: statusOf[e.Code], body: body}
}

func (s *server) write(w http.ResponseWriter, r response) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(r.status)
	_, _ = w.Write(r.body) // shared by every replay: never appended to
	_, _ = w.Write([]byte{'\n'})
}

func (s *server) handle(w http.ResponseWriter, r *http.Request) {
	p, _ := r.Context().Value(peerKey{}).(peer)
	if p.err != nil || (p.uid != s.o.allowUID && !slices.Contains(s.o.clientUIDs, p.uid)) {
		if p.err != nil {
			s.o.logf("refused a caller whose credential cannot be read: %v", p.err)
		} else {
			s.o.logf("refused a caller of uid %d: it is neither the privileged uid %d nor a listed client", p.uid, s.o.allowUID)
		}
		s.write(w, errorResponse(newError(codeUnauthenticated, "the caller is not the local privileged process this API serves")))
		return
	}
	name, ok := strings.CutPrefix(r.URL.Path, "/"+apiVersion+"/")
	m, known := s.o.methods[name]
	if !ok || !known {
		s.write(w, errorResponse(newError(codeNotFound, "no such method: "+r.URL.Path)))
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		s.write(w, errorResponse(newError(codeMethodNotAllowed, "methods are called with POST")))
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.o.maxBody))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			s.write(w, errorResponse(newError(codePayloadTooLarge, fmt.Sprintf("the request body is larger than %d bytes", s.o.maxBody))))
			return
		}
		s.write(w, errorResponse(newError(codeInvalidArgument, "the request body cannot be read: "+err.Error())))
		return
	}
	if len(bytes.TrimSpace(body)) == 0 {
		body = []byte("{}")
	}
	if e := checkObject(body); e != nil {
		s.write(w, errorResponse(e))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), defaultMethodTimeout)
	defer cancel()
	if !m.mutating {
		s.write(w, s.call(ctx, name, m, body))
		return
	}
	id, e := requestID(body)
	if e != nil {
		s.write(w, errorResponse(e))
		return
	}
	s.write(w, s.replay.do(ctx, name, id, sha256.Sum256(body), func() response { return s.call(ctx, name, m, body) }))
}

// checkObject accepts exactly one JSON object and nothing after it.
func checkObject(body []byte) *apiError {
	dec := json.NewDecoder(bytes.NewReader(body))
	var obj map[string]json.RawMessage
	if err := dec.Decode(&obj); err != nil || obj == nil {
		reason := "null"
		if err != nil {
			reason = err.Error()
		}
		return newError(codeInvalidArgument, "the request body is not a JSON object: "+reason)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return newError(codeInvalidArgument, "the request body has data after its JSON object")
	}
	return nil
}

// requestID is the mutating request's requestId: 1 to 128 printable ASCII characters.
func requestID(body []byte) (string, *apiError) {
	var head struct {
		RequestID json.RawMessage `json:"requestId"`
	}
	_ = json.Unmarshal(body, &head) // checkObject already proved it an object
	bad := func(why string) (string, *apiError) {
		return "", newError(codeInvalidArgument, "a mutating method needs a valid requestId",
			fieldError{Field: "requestId", Message: why})
	}
	var id string
	if head.RequestID == nil {
		return bad("required")
	}
	if err := json.Unmarshal(head.RequestID, &id); err != nil {
		return bad("must be a JSON string")
	}
	if id == "" || len(id) > maxRequestIDLength {
		return bad(fmt.Sprintf("must be 1 to %d characters", maxRequestIDLength))
	}
	for _, c := range []byte(id) {
		if c < 0x21 || c > 0x7e {
			return bad("must be printable ASCII without spaces")
		}
	}
	return id, nil
}

// call runs the method and turns its outcome into the response; a panic is an internal error, never a dropped connection.
func (s *server) call(ctx context.Context, name string, m method, params []byte) (r response) {
	defer func() {
		if p := recover(); p != nil {
			s.o.logf("%s panicked: %v", name, p)
			r = errorResponse(newError(codeInternal, "the method failed"))
		}
	}()
	result, err := m.call(ctx, params)
	var e *apiError
	switch {
	case errors.As(err, &e):
		return errorResponse(e)
	case err != nil:
		s.o.logf("%s failed: %v", name, err)
		return errorResponse(newError(codeInternal, "the method failed"))
	}
	body, err := json.Marshal(result)
	if err != nil {
		s.o.logf("%s: cannot encode its result: %v", name, err)
		return errorResponse(newError(codeInternal, "the method failed"))
	}
	return response{status: http.StatusOK, body: body}
}
