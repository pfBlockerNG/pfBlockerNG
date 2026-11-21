package feedparse

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/output"
)

// PostScript is a list's post-script, as the two post-script call sites of sync_package_pfblockerng() run it
// (pfb_list_script_exec()): the vetted file only, as the program named (never through a shell, except that a file with no
// #! line is run by /bin/sh, as execvp() does), under the pre-script's strict policy: 300 seconds, TERM to its whole
// process group at the limit or when ctx ends, KILL 5 seconds later, and nothing of the group left when the run returns.
// Its output goes to a regular file, sanitized while it runs to Log, all of it, and to Transcript, the first 1,048,576
// bytes and one notice; a sink that fails a write is one line in Errors (output.Capture). Runner lines go to Log and
// Transcript, and those of a failure to Errors too; a nil writer discards.
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

// run runs the vetted script with args, its output captured into the logs while it runs (output.Capture), and logs how it
// ended.
func (p PostScript) run(ctx context.Context, script string, args ...string) PostScriptResult {
	r := PostScriptResult{Reason: PreScriptExit, Status: -1}
	output.Capture("pfb-script-output-", output.Sinks{Log: p.Log, Transcript: p.Transcript, Errors: p.Errors},
		func(out *os.File) { r.Reason, r.Status = runScript(ctx, out, script, args) })
	switch r.Reason {
	case PreScriptTimeout:
		p.line(true, "\n[ %s ] post-script '%s' TIMED OUT (killed); discarding its output\n", p.Header, p.Name)
	case PreScriptExit:
		p.line(true, "\n[ %s ] post-script '%s' exited non-zero [ %d ]; discarding its output\n", p.Header, p.Name, r.Status)
	}
	return r
}

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
