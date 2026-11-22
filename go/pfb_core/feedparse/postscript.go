package feedparse

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/output"
)

// PostScript is a list's post-script, as the two post-script call sites of sync_package_pfblockerng() run it
// (pfb_list_script_exec()): the vetted file only, run and bounded as RunPreScript runs a pre-script. Its output goes to a
// regular file, sanitized while it runs to Log, all of it, and to Transcript, the first 1,048,576 bytes and one notice; a
// sink that fails a write is one line in Errors (output.Capture). Runner lines go to Log and Transcript, and those of a
// failure to Errors too; a nil writer discards.
type PostScript struct {
	Name                    string   // the list's script_post: a file name, looked up in Dirs as pfb_resolve_list_script() does
	Dirs                    []string // the list-script folders, in search order (--script-dir)
	Header                  string   // the feed's header, in the log lines
	Log, Errors, Transcript io.Writer
}

// PostScriptResult is what a post-script run leaves the caller.
type PostScriptResult struct {
	Skipped bool // no post-script is set, or it is not a vetted file: nothing ran, and nothing failed
	// Reason is "" when the script exited 0; else PreScriptStage, PreScriptExit or PreScriptTimeout, a script failure, or
	// PreScriptCancelled: the caller ended the run, and the script did not fail. A cancelled run leaves the feed as a failed
	// one does: RunDNSBL's staged copy is removed and the download untouched; RunIP has already renamed its restore point
	// back over the download, or removed a restore point that is no regular file, and a folder the script left at the
	// download keeps both where they are. Its line stays in Errors.
	Reason string
	Status int // when Reason is PreScriptExit: as PreScriptResult.Status, or -1 when no output file could be made

	restore *restorePoint // RunIP's, shared by every copy of the result, for Restore
}

// restorePoint is one RunIP run's restore point; done once it is back over the download or gone, so that no later Restore
// acts on what another run staged at that name.
type restorePoint struct {
	orig, path string
	done       bool
}

// RunDNSBL is the DNSBL post-script: orig is copied to staged, the script runs on staged with the argument dnsbl, and
// staged is then removed, whatever the script left there. Nothing reads its output. One run at a time per staged path,
// as for RunPreScript: the caller holds that exclusion.
func (p PostScript) RunDNSBL(ctx context.Context, orig, staged string) PostScriptResult {
	script, ok := p.vet()
	if !ok {
		return PostScriptResult{Skipped: true}
	}
	p.sinks().Line(false, "\nExecuting post-script: %s\n", p.Name)
	if err := copyFile(orig, staged); err != nil {
		os.Remove(staged)
		p.sinks().Line(true, "\n[ %s ] post-script '%s' could not stage its input; skipping\n", p.Header, p.Name)
		return PostScriptResult{Reason: PreScriptStage}
	}
	r := p.run(ctx, script, staged, "dnsbl")
	os.Remove(staged)
	return r
}

// RunIP is the IP post-script: orig is copied to restore, and the script runs on orig itself with vtype (_v4 or _v6). A
// failed script is undone at once, as Restore does. After a successful one orig holds its output, which the caller's
// empty-feed check reads; Restore then puts the download back. A regular file at the restore point that cannot be written
// is left as it was: one an earlier Restore could not rename back holds the only good copy. Anything else there (an empty
// folder a script left) is removed, as Restore does, so that it does not fail every later run. One run at a time per
// restore point, as for RunPreScript: the caller holds that exclusion.
func (p PostScript) RunIP(ctx context.Context, orig, restore, vtype string) PostScriptResult {
	script, ok := p.vet()
	if !ok {
		return PostScriptResult{Skipped: true}
	}
	p.sinks().Line(false, "\nExecuting post-script: %s\n", p.Name)
	if err := copyFile(orig, restore); err != nil {
		if info, err := os.Lstat(restore); err == nil && !info.Mode().IsRegular() {
			os.Remove(restore)
		}
		p.sinks().Line(true, "\n[ %s ] post-script '%s' could not stage its restore point; skipping\n", p.Header, p.Name)
		return PostScriptResult{Reason: PreScriptStage}
	}
	r := p.run(ctx, script, orig, vtype)
	r.restore = &restorePoint{orig: orig, path: restore}
	if r.Reason != "" {
		r.Restore()
	}
	return r
}

// Restore renames RunIP's restore point back over the download; it does nothing for another result, and nothing once the
// restore point is back or gone, on this result or any copy of it. A restore point the script replaced with anything but a
// regular file is removed instead, so that no symlink or FIFO takes the download's place. A rename that fails (the script
// left a folder at orig) leaves both as they are, and a later Restore tries again.
func (r PostScriptResult) Restore() {
	rp := r.restore
	if rp == nil || rp.done {
		return
	}
	info, err := os.Lstat(rp.path)
	switch {
	case err != nil:
		rp.done = errors.Is(err, fs.ErrNotExist)
	case info.Mode().IsRegular():
		rp.done = os.Rename(rp.path, rp.orig) == nil
	default:
		rp.done = os.Remove(rp.path) == nil
	}
}

// vet is ResolveListScript on Name and Dirs, run at every run; a set name that fails is logged.
func (p PostScript) vet() (string, bool) {
	if path, ok := ResolveListScript(p.Name, p.Dirs); ok || p.Name == "" || p.Name == "0" {
		return path, ok
	}
	p.sinks().Line(true, "\n[ %s ] post-script '%s' is not a file in the list-script folders; skipping\n", p.Header, p.Name)
	return "", false
}

// ResolveListScript is pfb_resolve_list_script(): name's base name, as a regular file whose real path sits directly in one of
// dirs, searched in order (a symlink may only point inside its folder). It returns the absolute in-folder path, which exec
// follows: a name without a slash would be looked up on PATH. "" and "0" are no name, as PHP's empty() reads them.
func ResolveListScript(name string, dirs []string) (string, bool) {
	if name == "" || name == "0" {
		return "", false
	}
	name = filepath.Base(name)
	for _, dir := range dirs {
		if dir == "" { // an unset folder, which Abs would make the working folder
			continue
		}
		base, err := filepath.Abs(dir)
		if err != nil {
			continue
		}
		realDir, err := filepath.EvalSymlinks(base)
		if err != nil {
			continue
		}
		path := filepath.Join(base, name)
		real, err := filepath.EvalSymlinks(path)
		if err != nil || filepath.Dir(real) != realDir {
			continue
		}
		if info, err := os.Stat(real); err == nil && info.Mode().IsRegular() {
			return path, true
		}
	}
	return "", false
}

func (p PostScript) run(ctx context.Context, script string, args ...string) PostScriptResult {
	r := PostScriptResult{Reason: PreScriptExit, Status: -1}
	output.Capture("pfb-script-output-", p.sinks(),
		func(out *os.File) { r.Reason, r.Status = runScript(ctx, out, script, args) })
	switch r.Reason {
	case PreScriptTimeout:
		p.sinks().Line(true, "\n[ %s ] post-script '%s' TIMED OUT (killed); discarding its output\n", p.Header, p.Name)
	case PreScriptCancelled:
		p.sinks().Line(true, "\n[ %s ] post-script '%s' was cancelled; discarding its output\n", p.Header, p.Name)
	case PreScriptExit:
		p.sinks().Line(true, "\n[ %s ] post-script '%s' exited non-zero [ %d ]; discarding its output\n", p.Header, p.Name,
			r.Status)
	}
	return r
}

func (p PostScript) sinks() output.Sinks {
	return output.Sinks{Log: p.Log, Transcript: p.Transcript, Errors: p.Errors}
}
