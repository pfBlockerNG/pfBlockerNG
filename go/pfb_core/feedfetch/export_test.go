package feedfetch

// Seams for the black-box tests.

// Classify is classify.
func Classify(head []byte) string { return classify(head, false) }

// SetExtractMax sets the per-file ceiling of an extraction, which no corpus row can lower: PHP's is a constant.
func (f *Fetcher) SetExtractMax(n int64) { f.extractMax = n }
