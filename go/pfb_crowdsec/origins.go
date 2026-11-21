package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Decision files (#4164): per origin, <decisions_dir>/<origin>.txt lists the values (an address or a prefix) whose origin
// that is, one per line and sorted, so pfBlockerNG's filterlog daemon can name the origin of the decision that dropped an
// address without a LAPI request. A value's origin is its lowest-numbered decision's, as in the status file.

const maxOriginName = 200

// originFileName maps an origin to a file name of A-Z a-z 0-9 _ : @ + - only: no dot, so no name holds ".txt:" (which ends
// the name in grep's output), no slash and no comma (which would split the log's CSV row). An origin that holds the key is
// "hidden", as in the status file; an empty one is "unknown".
func originFileName(origin, key string) string {
	if key != "" && strings.Contains(origin, key) {
		return "hidden"
	}
	if origin == "" {
		return "unknown"
	}
	b := []byte(origin)
	for i, c := range b {
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("_:@+-", c) >= 0) {
			b[i] = '_'
		}
	}
	return string(b[:min(len(b), maxOriginName)])
}

// writeDecisions brings the decision files to the current set: a file whose content changed is replaced atomically (a temp
// file in the folder, mode 0644, renamed over it); an origin with no values left loses its file. The first write also
// removes files an earlier run left.
func (d *daemon) writeDecisions() {
	dir := d.cfg.DecisionsDir
	files := map[string][]string{}
	for key, e := range d.bans.entries {
		name := originFileName(e.origin(), d.cfg.APIKey) + ".txt"
		files[name] = append(files[name], key)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		d.log.warnf("creating %s: %v", dir, err)
		return
	}
	if d.written == nil {
		d.written = map[string]string{}
		if old, err := filepath.Glob(filepath.Join(dir, "*.txt")); err == nil {
			for _, path := range old {
				d.written[filepath.Base(path)] = "\x00stale"
			}
		}
	}
	for name, keys := range files {
		slices.Sort(keys)
		content := strings.Join(keys, "\n") + "\n"
		if d.written[name] == content {
			continue
		}
		if err := writeFileAtomic(filepath.Join(dir, name), []byte(content)); err != nil {
			d.log.warnf("writing %s: %v", filepath.Join(dir, name), err)
			delete(d.written, name)
			continue
		}
		d.written[name] = content
	}
	for name := range d.written {
		if _, ok := files[name]; !ok {
			if err := os.Remove(filepath.Join(dir, name)); err != nil && !os.IsNotExist(err) {
				d.log.warnf("removing %s: %v", filepath.Join(dir, name), err)
				continue
			}
			delete(d.written, name)
		}
	}
}

// removeDecisions removes the decision files: a stopped bouncer bans nothing.
func (d *daemon) removeDecisions() {
	paths, _ := filepath.Glob(filepath.Join(d.cfg.DecisionsDir, "*.txt"))
	for _, path := range paths {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			d.log.warnf("removing %s: %v", path, err)
		}
	}
	d.written = nil
}
