// pfb_doq_probe (issue #3513) sends one DNS query over DoQ (RFC 9250) and prints the answer, for machines that have
// no DoQ client (the Debian test VM, a pfSense shell).
//
//	pfb_doq_probe -server HOST:PORT -name NAME [-type A|AAAA|...] [-ca FILE | -insecure] [-sni NAME] [-timeout 5s]
//
// Output: `rcode <NAME>` (NOERROR, NXDOMAIN, REFUSED, ...), then one `answer <name> <type> <rdata>` line per answer
// record. Exit 0 when a DNS response arrived, whatever its rcode; 2 on a command line that cannot be used; 1 when
// no response arrived (nothing is printed then, the reason goes to stderr).
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/net/dns/dnsmessage"
)

const usageLine = "usage: pfb_doq_probe -server HOST:PORT -name NAME [-type A|AAAA|...] [-ca FILE | -insecure] [-sni NAME] [-timeout 5s]"

var queryTypes = map[string]dnsmessage.Type{
	"A": dnsmessage.TypeA, "NS": dnsmessage.TypeNS, "CNAME": dnsmessage.TypeCNAME, "SOA": dnsmessage.TypeSOA,
	"PTR": dnsmessage.TypePTR, "MX": dnsmessage.TypeMX, "TXT": dnsmessage.TypeTXT, "AAAA": dnsmessage.TypeAAAA,
	"SRV": dnsmessage.TypeSRV, "ANY": dnsmessage.TypeALL,
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pfb_doq_probe", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	server := fs.String("server", "", "HOST:PORT of the DoQ server")
	name := fs.String("name", "", "name to ask for")
	qtype := fs.String("type", "A", "record type: a name (A, AAAA, CNAME, MX, TXT, ...) or a number")
	caFile := fs.String("ca", "", "PEM file with the CA certificates to trust (default: the system roots)")
	insecure := fs.Bool("insecure", false, "do not verify the server certificate")
	sni := fs.String("sni", "", "TLS server name (default: the host of -server)")
	timeout := fs.Duration("timeout", 5*time.Second, "limit for the whole exchange")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fs.SetOutput(stderr)
			fmt.Fprintln(stderr, usageLine)
			fs.PrintDefaults()
			return 0
		}
		return usage(stderr, err)
	}
	host, wire, err := parseArgs(fs, *server, *name, *qtype, *caFile != "", *insecure, *timeout)
	if err != nil {
		return usage(stderr, err)
	}
	lines, err := ask(*server, host, *sni, *caFile, *insecure, *timeout, wire)
	if err != nil {
		fmt.Fprintf(stderr, "pfb_doq_probe: %v\n", err)
		return 1
	}
	for _, l := range lines {
		fmt.Fprintln(stdout, l)
	}
	return 0
}

func usage(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "pfb_doq_probe: %v\n%s\n", err, usageLine)
	return 2
}

// parseArgs checks everything that needs no network and builds the query (Message ID 0, RD set: RFC 9250 4.2.1).
func parseArgs(fs *flag.FlagSet, server, name, qtype string, hasCA, insecure bool, timeout time.Duration) (host string, wire []byte, err error) {
	if fs.NArg() > 0 {
		return "", nil, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	host, port, splitErr := net.SplitHostPort(server)
	if p, perr := strconv.Atoi(port); splitErr != nil || host == "" || perr != nil || p < 1 || p > 65535 {
		return "", nil, fmt.Errorf("-server %q: want HOST:PORT", server)
	}
	if name == "" {
		return "", nil, errors.New("-name is required")
	}
	if hasCA && insecure {
		return "", nil, errors.New("-ca and -insecure exclude each other")
	}
	if timeout <= 0 {
		return "", nil, fmt.Errorf("-timeout %s must be positive", timeout)
	}
	typ, ok := queryTypes[strings.ToUpper(qtype)]
	if n, perr := strconv.ParseUint(qtype, 10, 16); !ok && perr == nil {
		typ, ok = dnsmessage.Type(n), true
	}
	if !ok {
		return "", nil, fmt.Errorf("-type %q: not a record type name or a number up to 65535", qtype)
	}
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return "", nil, fmt.Errorf("-name %q: %v", name, err)
	}
	query := dnsmessage.Message{
		Header:    dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: n, Type: typ, Class: dnsmessage.ClassINET}},
	}
	if wire, err = query.Pack(); err != nil {
		return "", nil, fmt.Errorf("-name %q: %v", name, err)
	}
	return host, wire, nil
}

// ask runs the exchange and renders the response as the lines to print.
func ask(server, host, sni, caFile string, insecure bool, timeout time.Duration, wire []byte) ([]string, error) {
	conf := &tls.Config{ServerName: host, NextProtos: []string{"doq"}, MinVersion: tls.VersionTLS13, InsecureSkipVerify: insecure} //nolint:gosec // -insecure is the user's explicit choice
	if sni != "" {
		conf.ServerName = sni
	}
	if caFile != "" {
		pemBytes, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		conf.RootCAs = x509.NewCertPool()
		if !conf.RootCAs.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("%s: no certificate in it", caFile)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	reply, err := exchange(ctx, server, conf, wire)
	if err != nil {
		return nil, err
	}
	return render(reply)
}

// exchange is one query on one stream of its own: the length-prefixed query and a FIN, then the response.
func exchange(ctx context.Context, server string, conf *tls.Config, wire []byte) ([]byte, error) {
	conn, err := quic.DialAddr(ctx, server, conf, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.CloseWithError(0, "") }()
	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = s.SetDeadline(deadline)
	}
	if _, err := s.Write(binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(wire)), uint16(len(wire)))); err != nil {
		return nil, err
	}
	if _, err := s.Write(wire); err != nil {
		return nil, err
	}
	if err := s.Close(); err != nil {
		return nil, err
	}
	var size [2]byte
	if _, err := io.ReadFull(s, size[:]); err != nil {
		return nil, fmt.Errorf("no response: %w", err)
	}
	reply := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(s, reply); err != nil {
		return nil, fmt.Errorf("response cut short: %w", err)
	}
	return reply, nil
}

var rcodeNames = map[dnsmessage.RCode]string{
	dnsmessage.RCodeSuccess: "NOERROR", dnsmessage.RCodeFormatError: "FORMERR", dnsmessage.RCodeServerFailure: "SERVFAIL",
	dnsmessage.RCodeNameError: "NXDOMAIN", dnsmessage.RCodeNotImplemented: "NOTIMP", dnsmessage.RCodeRefused: "REFUSED",
}

// render is `rcode X` and one `answer name type rdata` line per answer record; the whole response must parse.
func render(reply []byte) ([]string, error) {
	var p dnsmessage.Parser
	h, err := p.Start(reply)
	if err != nil {
		return nil, fmt.Errorf("the response is not a DNS message: %w", err)
	}
	rcode, ok := rcodeNames[h.RCode]
	if !ok {
		rcode = "RCODE" + strconv.Itoa(int(h.RCode))
	}
	lines := []string{"rcode " + rcode}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, fmt.Errorf("the response is not a DNS message: %w", err)
	}
	for {
		rh, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			return lines, nil
		}
		if err != nil {
			return nil, fmt.Errorf("the response is not a DNS message: %w", err)
		}
		rdata, err := rdataText(&p, rh.Type)
		if err != nil {
			return nil, fmt.Errorf("the response is not a DNS message: %w", err)
		}
		typ := strings.TrimPrefix(rh.Type.String(), "Type")
		lines = append(lines, fmt.Sprintf("answer %s %s %s", rh.Name, typ, rdata))
	}
}

func rdataText(p *dnsmessage.Parser, typ dnsmessage.Type) (string, error) {
	switch typ {
	case dnsmessage.TypeA:
		r, err := p.AResource()
		return netip.AddrFrom4(r.A).String(), err
	case dnsmessage.TypeAAAA:
		r, err := p.AAAAResource()
		return netip.AddrFrom16(r.AAAA).String(), err
	case dnsmessage.TypeCNAME:
		r, err := p.CNAMEResource()
		return r.CNAME.String(), err
	case dnsmessage.TypeNS:
		r, err := p.NSResource()
		return r.NS.String(), err
	case dnsmessage.TypePTR:
		r, err := p.PTRResource()
		return r.PTR.String(), err
	case dnsmessage.TypeMX:
		r, err := p.MXResource()
		return fmt.Sprintf("%d %s", r.Pref, r.MX), err
	case dnsmessage.TypeTXT:
		r, err := p.TXTResource()
		quoted := make([]string, len(r.TXT))
		for i, s := range r.TXT {
			quoted[i] = strconv.Quote(s)
		}
		return strings.Join(quoted, " "), err
	}
	r, err := p.UnknownResource() // RFC 3597 form
	return fmt.Sprintf(`\# %d %x`, len(r.Data), r.Data), err
}
