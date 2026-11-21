package hooks

import "github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/internal/output"

// BeforeTickSize lets the external tests widen the gap between a drain tick and the size it reads up to.
var BeforeTickSize = &output.BeforeTickSize

// CancelledWithin lets the external tests call the lag wait, and replace it to see whether a run enters it.
var CancelledWithin = &cancelledWithin
