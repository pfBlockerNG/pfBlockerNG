package feedfetch

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"time"
)

// maxReply bounds what one server reply may take: a reply without an end is cut off, not buffered.
const maxReply = 64 << 10

// libcurl's login for a URL that carries none.
const (
	anonymousUser     = "anonymous"
	anonymousPassword = "ftp@example.com"
)

// ftpTarget is what an ftp feed URL asks of the server, read as libcurl reads it: the login, the directories to change
// into, and the one file to retrieve. None of it holds a CR or LF, so none of it can end a command line.
type ftpTarget struct {
	user, pass string
	dirs       []string
	file       string
}

// ftpTargetOf refuses what this client does not do the way libcurl does, before any connection: a ;type= suffix other
// than ;type=i (an ASCII or listing transfer), a URL that names no file (libcurl lists the directory), and control bytes
// in the login or the path (an injected command; libcurl itself sends a feed's username as given).
func ftpTargetOf(req Request, r rawURL) (*ftpTarget, string) {
	raw := r.path
	if strings.Contains(strings.ToLower(raw), ";type=") {
		// libcurl reads the suffix off the path; "i" is the binary transfer this client makes anyway.
		cut, ok := strings.CutSuffix(raw, ";type=i")
		if !ok {
			cut, ok = strings.CutSuffix(raw, ";type=I")
		}
		if !ok || strings.Contains(strings.ToLower(cut), ";type=") {
			return nil, "feed ftp URL has a type suffix"
		}
		raw = cut
	}
	path, ok := ftpDecode(ftpDedot(raw))
	if !ok {
		return nil, "feed ftp path contains a control character"
	}
	// The login is the feed's own when it has one, else the URL's userinfo, else anonymous.
	const badLogin = "feed ftp credentials contain a control character"
	t := &ftpTarget{user: anonymousUser, pass: anonymousPassword}
	switch urlUser, urlPass, _ := strings.Cut(strings.TrimSuffix(r.userinfo, "@"), ":"); {
	case req.Username != "" || req.Password != "":
		if strings.ContainsAny(req.Username+req.Password, "\r\n") {
			return nil, badLogin
		}
		// CURLOPT_USERPWD "username:password" is cut at its first colon, one in the username included.
		t.user, t.pass, _ = strings.Cut(req.Username+":"+req.Password, ":")
	case r.userinfo != "": // "@" alone is an empty login, not none
		if t.user, ok = ftpDecode(urlUser); ok {
			t.pass, ok = ftpDecode(urlPass)
		}
		if !ok {
			return nil, badLogin
		}
	}

	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	t.file = parts[len(parts)-1]
	if t.file == "" {
		return nil, "feed ftp URL names no file"
	}
	for i, d := range parts[:len(parts)-1] {
		if d != "" {
			t.dirs = append(t.dirs, d)
		} else if i == 0 {
			t.dirs = append(t.dirs, "/") // libcurl: an empty first part is an absolute path
		}
	}
	return t, ""
}

var dotSpelling = strings.NewReplacer("%2e", ".", "%2E", ".")

// ftpDedot removes dot segments from a path, %2e spelling included, as libcurl's URL parser does before the path is
// split; a ".." that only appears once an encoded slash is decoded is left for the server to see.
func ftpDedot(path string) string {
	segs := strings.Split(path, "/")
	out := make([]string, 0, len(segs))
	for i, s := range segs {
		switch dotSpelling.Replace(s) {
		case ".":
		case "..":
			if len(out) > 1 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, s)
			continue
		}
		if i == len(segs)-1 {
			out = append(out, "") // a path ending in a dot segment ends in a slash
		}
	}
	return strings.Join(out, "/")
}

// ftpDecode percent-decodes as libcurl does (a % not followed by two hex digits stays) and refuses a control byte.
func ftpDecode(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' && i+2 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				c = byte(n)
				i += 2
			}
		}
		if c < 0x20 {
			return "", false
		}
		b.WriteByte(c)
	}
	return b.String(), true
}

// fetchFTP is pfb_download()'s cURL path for ftp:// without a proxy (through one it is an HTTP request: ftpViaProxy):
// the control connection is pinned to the vetted address, the data connection goes to that same address whatever the
// server names, and the transfer gets three attempts with the body reset between them.
func (f *Fetcher) fetchFTP(ctx context.Context, src *source, req Request, dst string) transfer {
	t, _ := f.fetchFTPMode(ctx, src, req, dst, nil)
	return t
}

func (f *Fetcher) fetchFTPProbe(ctx context.Context, src *source, req Request, dst string, baseline ftpMetadata) (transfer, bool) {
	return f.fetchFTPMode(ctx, src, req, dst, &baseline)
}

func (f *Fetcher) fetchFTPMode(ctx context.Context, src *source, req Request, dst string, baseline *ftpMetadata) (transfer, bool) {
	out, err := os.Create(dst)
	if err != nil {
		return transfer{reason: "download file could not be created"}, false
	}
	defer out.Close()

	var pin netip.Addr
	if !f.NoFilter {
		var reason string
		if pin, _, reason = f.vet(ctx, src.host); reason != "" {
			return transfer{reason: reason}, false
		}
	}
	host := src.host
	if pin.IsValid() {
		host = pin.String()
	}
	addr := net.JoinHostPort(host, strconv.Itoa(src.port))
	for attempt := 1; attempt <= attempts; attempt++ {
		if err := out.Truncate(0); err != nil {
			return transfer{reason: "download file could not be reset"}, false
		}
		out.Seek(0, io.SeekStart)
		t, err := ftpAttempt(ctx, req, src.ftp, addr, out, baseline)
		if err == nil {
			return t, t.unchanged
		}
		if errors.Is(err, errTooLarge) {
			return transfer{reason: "download_too_large"}, false
		}
		if attempt < attempts {
			select {
			case <-time.After(f.retryDelay()):
			case <-ctx.Done():
			}
		}
	}
	return transfer{reason: "curl_incomplete"}, false
}

// replyLimit lets a reply take at most maxReply bytes from the connection.
type replyLimit struct {
	net.Conn
	left int
}

func (l *replyLimit) Read(p []byte) (int, error) {
	if l.left <= 0 {
		return 0, errors.New("ftp reply too long")
	}
	n, err := l.Conn.Read(p[:min(len(p), l.left)])
	l.left -= n
	return n, err
}

// ftpAttempt logs in, reads MDTM and SIZE, and either returns a metadata match or retrieves the body. Ingest opens EPSV
// before TYPE/SIZE; Probe checks metadata first and opens EPSV only when it needs RETR. Each attempt has the request timeout.
func ftpAttempt(ctx context.Context, req Request, t *ftpTarget, addr string, out *os.File, baseline *ftpMetadata) (transfer, error) {
	ctx, cancel := context.WithTimeout(ctx, req.timeout())
	defer cancel()
	dialer := &net.Dialer{Timeout: connectTimeout}
	if req.BindAddr.IsValid() {
		dialer.LocalAddr = &net.TCPAddr{IP: req.BindAddr.AsSlice()}
	}
	dial := func(addr string) (net.Conn, error) {
		c, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			context.AfterFunc(ctx, func() { c.Close() })
		}
		return c, err
	}
	raw, err := dial(addr)
	if err != nil {
		return transfer{}, err
	}
	defer raw.Close()
	lim := &replyLimit{Conn: raw, left: maxReply}
	c := textproto.NewConn(lim)

	// cmd sends one command (none: the greeting is read) and returns its reply; fail makes an unexpected reply an error.
	cmd := func(format string, args ...any) (int, string, error) {
		lim.left = maxReply
		if format != "" {
			if err := c.PrintfLine(format, args...); err != nil {
				return 0, "", err
			}
		}
		return c.ReadResponse(0)
	}
	fail := func(code int, msg string, err error, ok bool) error {
		if err == nil && !ok {
			err = &textproto.Error{Code: code, Msg: msg}
		}
		return err
	}

	code, msg, err := cmd("")
	if err := fail(code, msg, err, code == 220); err != nil {
		return transfer{}, err
	}
	code, msg, err = cmd("USER %s", t.user)
	if err == nil && code == 331 {
		code, msg, err = cmd("PASS %s", t.pass)
	}
	if err := fail(code, msg, err, code/100 == 2); err != nil {
		return transfer{}, err
	}
	for _, d := range t.dirs {
		code, msg, err := cmd("CWD %s", d)
		if err := fail(code, msg, err, code/100 == 2); err != nil {
			return transfer{}, err
		}
	}

	var lastMod time.Time
	code, msg, err = cmd("MDTM %s", t.file)
	if err != nil {
		return transfer{}, err
	}
	if code == 213 && len(msg) >= 14 {
		// A reply that is no time is no timestamp; one at or before the epoch neither (PHP applies only filetime > 0).
		if when, perr := time.Parse("20060102150405", msg[:14]); perr == nil && when.Unix() > 0 {
			lastMod = when
		}
	}

	dataPort := 0
	if baseline == nil {
		dataPort, err = passive(cmd)
		if err != nil {
			return transfer{}, err
		}
	}
	code, msg, err = cmd("TYPE I")
	if err := fail(code, msg, err, code/100 == 2); err != nil {
		return transfer{}, err
	}
	code, msg, err = cmd("SIZE %s", t.file)
	if err != nil {
		return transfer{}, err
	}
	if err := fail(code, msg, err, code != 550); err != nil {
		return transfer{}, err
	}
	size, hasSize := int64(-1), false
	if n, perr := strconv.ParseInt(strings.TrimSpace(msg), 10, 64); code == 213 && perr == nil && n >= 0 {
		size, hasSize = n, true
	}
	if baseline != nil && baseline.hasTime && baseline.hasSize && !lastMod.IsZero() && hasSize &&
		lastMod.Equal(baseline.lastMod) && size == baseline.size {
		c.PrintfLine("QUIT")
		return transfer{status: 226, lastMod: lastMod, size: size, hasSize: true, unchanged: true}, nil
	}
	if baseline != nil {
		dataPort, err = passive(cmd)
		if err != nil {
			return transfer{}, err
		}
	}
	limit := req.maxBytes()
	if size > limit {
		return transfer{}, errTooLarge
	}

	// The data connection goes to the control connection's peer, the vetted address, never to one the reply names.
	data, err := dial(net.JoinHostPort(raw.RemoteAddr().(*net.TCPAddr).IP.String(), strconv.Itoa(dataPort)))
	if err != nil {
		return transfer{}, err
	}
	defer data.Close()
	code, msg, err = cmd("RETR %s", t.file)
	if err := fail(code, msg, err, code == 125 || code == 150); err != nil {
		return transfer{}, err
	}
	want := limit + 1 // libcurl stops at the SIZE it was told, and has no other bound than the ceiling
	if size > 0 {
		want = size
	}
	n, err := io.Copy(out, io.LimitReader(data, want))
	if size <= 0 && n > limit {
		return transfer{}, errTooLarge
	}
	if err == nil && size > 0 && n < size {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return transfer{}, err
	}
	data.Close()
	code, msg, err = cmd("")
	if err := fail(code, msg, err, code == 226 || code == 250); err != nil {
		return transfer{}, err
	}
	c.PrintfLine("QUIT")
	return transfer{status: code, lastMod: lastMod, size: size, hasSize: hasSize}, nil
}

// passive opens the data port the way libcurl does, EPSV first and PASV when that is refused or names port 0, and
// returns the port. The address a PASV reply names is not read: the caller dials the control connection's peer.
func passive(cmd func(string, ...any) (int, string, error)) (int, error) {
	code, msg, err := cmd("EPSV")
	if err != nil {
		return 0, err
	}
	if code == 229 {
		port, ok := epsvPort(msg)
		if !ok {
			return 0, &textproto.Error{Code: code, Msg: msg}
		}
		if port > 0 {
			return port, nil
		}
	}
	if code, msg, err = cmd("PASV"); err != nil {
		return 0, err
	}
	if port, ok := pasvPort(msg); code == 227 && ok {
		return port, nil
	}
	return 0, &textproto.Error{Code: code, Msg: msg}
}

// epsvPort reads "(|||port|)": the same delimiter three times, digits, the delimiter.
func epsvPort(msg string) (int, bool) {
	_, rest, ok := strings.Cut(msg, "(")
	if !ok || len(rest) < 5 || rest[1] != rest[0] || rest[2] != rest[0] {
		return 0, false
	}
	digits, _, ok := strings.Cut(rest[3:], rest[:1])
	port, err := strconv.Atoi(digits)
	return port, ok && err == nil && port < 1<<16 && allIn(digits, "0123456789")
}

// pasvPort reads the six comma-separated numbers of at most 255 a PASV reply names, from the first place they start
// (libcurl tries every digit in turn, one inside a number too), and returns the last two as the port.
func pasvPort(msg string) (int, bool) {
next:
	for i := range len(msg) {
		rest := msg[i:]
		var n [6]int
		for k := range n {
			if k > 0 {
				if rest == "" || rest[0] != ',' {
					continue next
				}
				rest = rest[1:]
			}
			j := 0
			for j < len(rest) && '0' <= rest[j] && rest[j] <= '9' {
				j++
			}
			v, err := strconv.Atoi(rest[:j])
			if err != nil || v > 255 {
				continue next
			}
			n[k], rest = v, rest[j:]
		}
		return n[4]<<8 | n[5], true
	}
	return 0, false
}
