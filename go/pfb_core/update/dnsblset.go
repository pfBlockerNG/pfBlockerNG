package update

import (
	"context"
	"errors"

	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/dnsbl"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/resources"
	"github.com/pfBlockerNG/pfBlockerNG/go/pfb_core/update/apply"
)

// DNSBLSet is a stub: sub-slice 9g's RED commit.
type DNSBLSet struct {
	Store         *resources.Store
	FeedDir       string
	ListDir       string
	Top1m         string
	PSL           string
	SafeSearchDir string
	Resolve       dnsbl.Resolver
}

type DNSBLInput struct {
	Settings map[string]map[string]any
	Changed  map[string]bool
}

type DNSBLOut struct {
	DNSBL   *apply.DNSBL
	DNSBLIP []GeoSet
	Issues  []apply.Issue
}

func (s DNSBLSet) Build(ctx context.Context, in DNSBLInput) (DNSBLOut, error) {
	return DNSBLOut{}, errors.New("not implemented")
}
