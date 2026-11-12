//go:build !unix

package feedfetch

import "context"

func (f *Fetcher) fetchRsync(context.Context, *source, Request, string) transfer {
	return transfer{reason: "rsync needs a Unix host"}
}
