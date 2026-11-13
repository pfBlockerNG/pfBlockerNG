package feedparse

// NormResult is pfb_feed_normalize()'s answer: the file to parse, whether its content changed since the last pass and
// whether it is a usable .norm.
type NormResult struct {
	Path                string
	Changed, Normalized bool
}

// NormalizeFile is the storage half of pfb_feed_normalize() for the feed name in dir: <name>.orig becomes <name>.norm, kept
// while <name>.norm.src.xxhash128 names the .orig it was built from.
func NormalizeFile(dir, name string) NormResult {
	return NormResult{}
}
