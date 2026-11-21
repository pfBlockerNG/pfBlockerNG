package feedparse

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unicode"
	"unicode/utf8"
)

const (
	scriptAllowance = 1 << 20 // the transcript's share of one script's output (core-api-protocol.md "Update command")
	scriptNotice    = "\n[ pfBlockerNG ] Script output limit (1,048,576 bytes) reached; remaining output is in the main log.\n"
)

// PostScript is a list's post-script, as the two post-script call sites of sync_package_pfblockerng() run it
// (pfb_list_script_exec()): the vetted file only, as the program named (never through a shell, except that a file with no
// #! line is run by /bin/sh, as execvp() does), under the pre-script's strict policy: 300 seconds, TERM to its whole
// process group at the limit or when ctx ends, KILL 5 seconds later, and nothing of the group left when the run returns.
// Its output goes to a regular file, then sanitized to Log, all of it, and to Transcript, the first 1,048,576 bytes and one
// notice. Runner lines go to Log and Transcript, and those of a failure to Errors too; a nil writer discards.
type PostScript struct {
	Name                    string   // the list's script_post: a file name, looked up in Dirs as pfb_resolve_list_script() does
	Dirs                    []string // the list-script folders, in search order (--script-dir)
	Header                  string   // the feed's header, in the log lines
	Log, Errors, Transcript io.Writer
}

// PostScriptResult is what a post-script run leaves the caller.
type PostScriptResult struct {
	Skipped bool   // no post-script is set, or it is not a vetted file: nothing ran, and nothing failed
	Reason  string // "" when the script exited 0; else PreScriptStage, PreScriptExit or PreScriptTimeout: a script failure
	Status  int    // when Reason is PreScriptExit: as PreScriptResult.Status, or -1 when no output file could be made

	orig, restore string // RunIP's, for Restore
}

// RunDNSBL is the DNSBL post-script: orig is copied to staged, the script runs on staged with the argument dnsbl, and
// staged is then removed, whatever the script left there. Nothing reads its output.
func (p PostScript) RunDNSBL(ctx context.Context, orig, staged string) PostScriptResult {
	script, ok := p.vet()
	if !ok {
		return PostScriptResult{Skipped: true}
	}
	p.line(false, "\nExecuting post-script: %s\n", p.Name)
	if err := copyFile(orig, staged); err != nil {
		os.Remove(staged)
		p.line(true, "\n[ %s ] post-script '%s' could not stage its input; skipping\n", p.Header, p.Name)
		return PostScriptResult{Reason: PreScriptStage}
	}
	r := p.run(ctx, script, staged, "dnsbl")
	os.Remove(staged)
	return r
}

// RunIP is the IP post-script: orig is copied to restore, and the script runs on orig itself with vtype (_v4 or _v6). A
// failed script is undone at once, as Restore does. After a successful one orig holds its output, which the caller's
// empty-feed check reads; Restore then puts the download back.
func (p PostScript) RunIP(ctx context.Context, orig, restore, vtype string) PostScriptResult {
	script, ok := p.vet()
	if !ok {
		return PostScriptResult{Skipped: true}
	}
	p.line(false, "\nExecuting post-script: %s\n", p.Name)
	if err := copyFile(orig, restore); err != nil {
		os.Remove(restore)
		p.line(true, "\n[ %s ] post-script '%s' could not stage its restore point; skipping\n", p.Header, p.Name)
		return PostScriptResult{Reason: PreScriptStage}
	}
	r := p.run(ctx, script, orig, vtype)
	r.orig, r.restore = orig, restore
	if r.Reason != "" {
		r.Restore()
	}
	return r
}

// Restore renames RunIP's restore point back over the download; it does nothing for another result or once done. A restore
// point the script replaced with anything but a regular file is removed instead, so that no symlink or FIFO takes the
// download's place. A rename that fails (the script left a folder at orig) leaves both as they are.
func (r PostScriptResult) Restore() {
	if r.restore == "" {
		return
	}
	info, err := os.Lstat(r.restore)
	switch {
	case err != nil:
	case info.Mode().IsRegular():
		os.Rename(r.restore, r.orig)
	default:
		os.Remove(r.restore)
	}
}

// vet is pfb_resolve_list_script() on Name, run at every run: its base name, as a regular file whose real path sits directly
// in one of Dirs (a symlink may only point inside its folder); the in-folder path, which exec follows. A set name that fails
// is logged; "0" is no name, as PHP's empty() reads it.
func (p PostScript) vet() (string, bool) {
	if p.Name == "" || p.Name == "0" {
		return "", false
	}
	if name := filepath.Base(p.Name); name != "." && name != "/" {
		for _, dir := range p.Dirs {
			realDir, err := filepath.EvalSymlinks(dir)
			if err != nil {
				continue
			}
			path := filepath.Join(dir, name)
			real, err := filepath.EvalSymlinks(path)
			if err != nil || filepath.Dir(real) != realDir {
				continue
			}
			if info, err := os.Stat(real); err == nil && info.Mode().IsRegular() {
				return path, true
			}
		}
	}
	p.line(true, "\n[ %s ] post-script '%s' is not a file in the list-script folders; skipping\n", p.Header, p.Name)
	return "", false
}

// run runs the vetted script with args and logs its output and how it ended.
func (p PostScript) run(ctx context.Context, script string, args ...string) PostScriptResult {
	r := PostScriptResult{Reason: PreScriptExit, Status: -1}
	if capture, err := os.CreateTemp("", "pfb-script-output-"); err == nil {
		defer os.Remove(capture.Name())
		defer capture.Close()
		r.Reason, r.Status = runScript(ctx, capture, script, args)
		// shortcut: the output reaches the logs once the run has returned, not while the script runs; drain it on a tick
		// as it grows if a live transcript of long scripts is wanted.
		p.output(capture)
	}
	switch r.Reason {
	case PreScriptTimeout:
		p.line(true, "\n[ %s ] post-script '%s' TIMED OUT (killed); discarding its output\n", p.Header, p.Name)
	case PreScriptExit:
		p.line(true, "\n[ %s ] post-script '%s' exited non-zero [ %d ]; discarding its output\n", p.Header, p.Name, r.Status)
	}
	return r
}

// output sanitizes the capture file as pfb_script_output_sanitize_chunk() does, up to the size it has now: a process the
// script set loose with setsid() may still write to it. Printable ASCII, TAB and LF stay; other ASCII controls, DEL and
// each byte of malformed UTF-8 become \xNN; Unicode Cc and Cf become \u{HEX}; other characters stay.
func (p PostScript) output(capture *os.File) {
	info, err := capture.Stat()
	if err != nil {
		return
	}
	in := bufio.NewReaderSize(io.NewSectionReader(capture, 0, info.Size()), 64<<10)
	log, transcript := bufio.NewWriter(orDiscard(p.Log)), bufio.NewWriter(orDiscard(p.Transcript))
	defer log.Flush()
	defer transcript.Flush()
	left, noticed := scriptAllowance, false
	emit := func(text string, atomic bool) {
		log.WriteString(text)
		switch {
		case noticed:
		case len(text) <= left:
			transcript.WriteString(text)
			left -= len(text)
		default:
			if !atomic { // a run of printable ASCII is cut at the allowance
				transcript.WriteString(text[:left])
			}
			transcript.WriteString(scriptNotice)
			noticed = true
		}
	}
	for {
		b, _ := in.Peek(utf8.UTFMax)
		switch {
		case len(b) == 0:
			return
		case printable(b[0]):
			b, _ = in.Peek(in.Buffered())
			n := 1
			for n < len(b) && printable(b[n]) {
				n++
			}
			emit(string(b[:n]), false)
			in.Discard(n)
			continue
		case b[0] < utf8.RuneSelf:
			emit(fmt.Sprintf(`\x%02X`, b[0]), true)
			in.Discard(1)
			continue
		}
		ch, size := utf8.DecodeRune(b)
		switch {
		case ch == utf8.RuneError && size == 1:
			emit(fmt.Sprintf(`\x%02X`, b[0]), true)
		case unicode.In(ch, unicode.Cc, unicode.Cf):
			emit(fmt.Sprintf(`\u{%X}`, ch), true)
		default:
			emit(string(b[:size]), true)
		}
		in.Discard(size)
	}
}

func printable(b byte) bool { return b >= 0x20 && b <= 0x7e || b == '\t' || b == '\n' }

// line writes one runner line to Log and Transcript, and a failure's to Errors too.
func (p PostScript) line(failure bool, format string, args ...any) {
	text := fmt.Sprintf(format, args...)
	io.WriteString(orDiscard(p.Log), text)
	io.WriteString(orDiscard(p.Transcript), text)
	if failure {
		io.WriteString(orDiscard(p.Errors), text)
	}
}

func orDiscard(w io.Writer) io.Writer {
	if w == nil {
		return io.Discard
	}
	return w
}
