package feedfetch

import "time"

// Seams for the black-box tests.

// Classify is classify.
func Classify(head []byte) string { return classify(head) }

// SetExtractMax sets the per-file ceiling of an extraction, which no corpus row can lower: PHP's is a constant.
func (f *Fetcher) SetExtractMax(n int64) { f.extractMax = n }

// EntryLink is entryLink: whether to, the text of the link at target/name, is a share entry link of this code.
func EntryLink(target, to, name string) bool { return entryLink(target, to, name) }

// SetRetime replaces the retime of an FTP probe's body; the returned func restores it.
func SetRetime(fn func(string, time.Time) error) (restore func()) {
	old := retimeFile
	retimeFile = fn
	return func() { retimeFile = old }
}
