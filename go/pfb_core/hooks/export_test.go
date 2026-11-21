package hooks

import "github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/output"

// BeforeTickSize lets the external tests widen the gap between a drain tick and the size it reads up to.
var BeforeTickSize = &output.BeforeTickSize
