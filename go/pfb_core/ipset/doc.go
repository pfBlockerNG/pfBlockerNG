// Package ipset is the Go port of the IP set algebra of pfblockerng.sh and the PHP helpers around it (issue #4033, map #3813,
// docs/specs/go-updater-pipeline.md). It turns parsed per-feed IP lists into the canonical set per logical set and
// family with today's results, member for member; the parity corpus in testdata/ pins every result. Nothing in Core calls it yet.
//
// Every function is pure: member lists enter as the raw text of a list (CRLF, a missing final newline, blanks and order
// matter) and leave as lines, the masterfile is a list of "alias member" rows, and the file layout, GeoIP and the placeholder
// are the caller's. Each function ports one verb or helper:
//
//	CIDRAggregate    the cidr_aggregate verb (exact union through iprange)
//	Preprocess       pfb_ip_preprocess_args and the per-feed verb it names (_255, _agg, _rep)
//	Recompute        the recompute verb (cross-feed dedup in member order, dMax, pMax)
//	PMax             the pmax verb (legacy pMax over the deny folder)
//	Suppress         the suppress verb (v4) and pfb_suppress_file_v6
//	Remove           the remove verb (a feed leaves)
//	Closing          the closing verb (placeholder refill and the masterfile sanity check)
//	Canonical        pfb_canonical_alias_set
//	Union            pfb_aggregate_member_list and the aggregate verb (the Uber union)
//	DNSBLIP          pfb_dnsbl_concat_files and the placeholder write around it
//	RecomputeMatrix  pfb_ip_recompute_matrix; ClosingPass is pfb_ip_closing_pass_active
//	Pipeline         the apply script's stage order over several passes, built on the functions above
//
// Union, subtraction and the minimal prefixes of a set go through go4.org/netipx (netset.go). The covered-row prune of Recompute
// does not: a row is pruned only under ONE earlier network at least as wide as itself, which a set union cannot answer.
package ipset
