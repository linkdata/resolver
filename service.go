// Package resolver provides a minimal iterative DNS resolver with QNAME minimization
// using github.com/miekg/dns for wire format and transport.
package resolver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/linkdata/resolver/cache"
	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

//go:generate go run ./cmd/genhints roothints.gen.go

const maxChase = 16 // max CNAME/DNAME chase depth

type Service struct {
	proxy.ContextDialer
	Timeout     time.Duration
	DNSPort     uint16
	mu          sync.RWMutex // protects following
	useIPv4     bool
	useIPv6     bool
	useUDP      bool
	rootServers []netip.Addr
}

func (r *Service) DnsResolve(ctx context.Context, qname string, qtype uint16) (msg *dns.Msg, srv netip.Addr, err error) {
	return r.Resolve(ctx, qname, qtype, nil, DefaultCache)
}

var ErrCNAMEChainTooDeep = errors.New("resolver: cname/dname chain too deep")

var _ Resolver = &Service{}
var DefaultCache = cache.New()

// New returns a resolver seeded with IANA root servers.
func New() (r *Service) {
	var roots []netip.Addr
	roots = append(roots, Roots4...)
	roots = append(roots, Roots6...)
	return &Service{
		ContextDialer: &net.Dialer{},
		Timeout:       3 * time.Second,
		DNSPort:       53,
		useIPv4:       len(Roots4) > 0,
		useIPv6:       len(Roots6) > 0,
		useUDP:        true,
		rootServers:   roots,
	}
}

// Resolve performs iterative resolution with QNAME minimization for qname/qtype.
func (r *Service) Resolve(ctx context.Context, qname string, qtype uint16, logw io.Writer, cache Cacher) (msg *dns.Msg, origin netip.Addr, err error) {
	qry := query{
		Service:   r,
		ctx:       ctx,
		cache:     cache,
		writer:    logw,
		start:     time.Now(),
		addrCache: make(map[string][]netip.Addr),
	}
	qry.logf(0, "resolve start qname=%s qtype=%s", qname, dns.Type(qtype))
	msg, origin, err = qry.resolveWithDepth(dns.Fqdn(strings.ToLower(qname)), qtype, 0)
	return
}

func (r *Service) usable(protocol string, addr netip.Addr) (yes bool) {
	yes = strings.HasPrefix(protocol, "tcp") || r.usingUDP()
	yes = yes && (addr.Is4() || r.usingIPv6())
	return
}

func (r *Service) addrPort(addr netip.Addr) netip.AddrPort {
	return netip.AddrPortFrom(addr, r.DNSPort)
}

func (r *Service) deadline(ctx context.Context) time.Time {
	var deadline time.Time
	if ctx != nil {
		if d, ok := ctx.Deadline(); ok {
			deadline = d
		}
	}
	if r.Timeout > 0 {
		limit := time.Now().Add(r.Timeout)
		if deadline.IsZero() || limit.Before(deadline) {
			deadline = limit
		}
	}
	return deadline
}

func setEDNS(m *dns.Msg) {
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	opt.SetUDPSize(1232)
	m.Extra = append(m.Extra, opt)
}

func shuffle[T any](in []T) []T {
	out := append([]T(nil), in...)
	sort.Slice(out, func(i, j int) bool { return fmt.Sprint(out[i]) < fmt.Sprint(out[j]) })
	return out
}

func hasRRType(rrs []dns.RR, t uint16) bool {
	for _, rr := range rrs {
		if rr.Header().Rrtype == t {
			return true
		}
	}
	return false
}

func extractDelegationNS(m *dns.Msg, zone string) []string {
	var out []string
	for _, rr := range m.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			if strings.EqualFold(ns.Hdr.Name, zone) {
				out = append(out, strings.ToLower(ns.Ns))
			}
		}
	}
	return out
}

func delegationRecords(m *dns.Msg, zone string) (out []dns.RR) {
	if m != nil {
		for _, rr := range m.Ns {
			if ns, ok := rr.(*dns.NS); ok {
				if strings.EqualFold(ns.Hdr.Name, zone) {
					out = append(out, rr)
				}
			}
		}
	}
	return
}

func glueAddresses(m *dns.Msg) []netip.Addr {
	var addrs []netip.Addr
	for _, rr := range m.Extra {
		switch a := rr.(type) {
		case *dns.A:
			if addr := ipToAddr(a.A); addr.IsValid() {
				addrs = append(addrs, addr)
			}
		case *dns.AAAA:
			if addr := ipToAddr(a.AAAA); addr.IsValid() {
				addrs = append(addrs, addr)
			}
		}
	}
	return dedupAddrs(addrs)
}

func cnameChainRecords(rrs []dns.RR, owner string) []dns.RR {
	var out []dns.RR
	for _, rr := range rrs {
		if cname, ok := rr.(*dns.CNAME); ok {
			if strings.EqualFold(cname.Hdr.Name, owner) {
				out = append(out, rr)
			}
		}
	}
	return out
}

func dnameRecords(rrs []dns.RR, qname string) []dns.RR {
	var out []dns.RR
	for _, rr := range rrs {
		if d, ok := rr.(*dns.DNAME); ok {
			if strings.HasSuffix(strings.ToLower(qname), strings.ToLower(d.Hdr.Name)) {
				out = append(out, rr)
			}
		}
		if cname, ok := rr.(*dns.CNAME); ok {
			if strings.EqualFold(cname.Hdr.Name, qname) {
				out = append(out, rr)
			}
		}
	}
	return out
}

func dedupAddrs(addrs []netip.Addr) []netip.Addr {
	seen := map[netip.Addr]struct{}{}
	var out []netip.Addr
	for _, addr := range addrs {
		if _, ok := seen[addr]; !ok {
			seen[addr] = struct{}{}
			out = append(out, addr)
		}
	}
	return out
}

func prependRecords(msg *dns.Msg, resp *dns.Msg, qname string, gather func([]dns.RR, string) []dns.RR) {
	records := gather(resp.Answer, qname)
	if len(msg.Question) > 0 {
		msg.Question[0].Name = qname
	}
	if len(records) > 0 {
		msg.Answer = append(append([]dns.RR(nil), records...), msg.Answer...)
	}
	if len(resp.Ns) > 0 {
		msg.Ns = append([]dns.RR(nil), resp.Ns...)
	}
	if len(resp.Extra) > 0 {
		extras := append([]dns.RR(nil), resp.Extra...)
		msg.Extra = append(extras, msg.Extra...)
	}
}

func newResponseMsg(qname string, qtype uint16, rcode int, answer, authority, extra []dns.RR) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(qname, qtype)
	msg.Rcode = rcode
	if len(answer) > 0 {
		msg.Answer = append(msg.Answer, answer...)
	}
	if len(authority) > 0 {
		msg.Ns = append(msg.Ns, authority...)
	}
	if len(extra) > 0 {
		msg.Extra = append(msg.Extra, extra...)
	}
	return msg
}

func ipToAddr(ip net.IP) (addr netip.Addr) {
	if ip != nil {
		if v4 := ip.To4(); v4 != nil {
			addr = netip.AddrFrom4([4]byte(v4))
		} else if v6 := ip.To16(); v6 != nil {
			addr = netip.AddrFrom16([16]byte(v6))
		}
	}
	return
}

func formatProto(network string, addr netip.Addr) string {
	suffix := "6"
	if addr.Is4() {
		suffix = "4"
	}
	return network + suffix
}

func formatCounts(msg *dns.Msg) string {
	return fmt.Sprintf("%d+%d+%d A/N/E", len(msg.Answer), len(msg.Ns), len(msg.Extra))
}

// -------- CNAME/DNAME helpers ---------

func cnameTarget(resp *dns.Msg, owner string) (string, bool) {
	lo := strings.ToLower(owner)
	for _, rr := range resp.Answer {
		if c, ok := rr.(*dns.CNAME); ok && strings.EqualFold(c.Hdr.Name, lo) {
			return dns.Fqdn(strings.ToLower(c.Target)), true
		}
	}
	return "", false
}

// dnameSynthesize finds a DNAME and synthesizes the new qname per RFC 6672.
func dnameSynthesize(resp *dns.Msg, qname string) (string, bool) {
	q := strings.ToLower(qname)
	for _, rr := range resp.Answer {
		if d, ok := rr.(*dns.DNAME); ok {
			owner := strings.ToLower(d.Hdr.Name)
			if strings.HasSuffix(q, owner) {
				prefix := strings.TrimSuffix(q, owner)
				// Avoid double dots when concatenating
				prefix = strings.TrimSuffix(prefix, ".")
				tgt := dns.Fqdn(strings.Trim(prefix, ".") + "." + strings.ToLower(d.Target))
				return tgt, true
			}
		}
	}
	return "", false
}

// -------- Cache helpers ---------

func (r *Service) cacheStore(msg *dns.Msg, cache Cacher) (cached bool) {
	if cache != nil {
		if msg != nil && !msg.Zero && len(msg.Question) == 1 {
			cache.DnsSet(msg)
			cached = true
		}
	}
	return
}

func cloneIfCached(msg *dns.Msg) (clone *dns.Msg) {
	clone = msg
	if msg != nil {
		if msg.Zero {
			clone = msg.Copy()
			if clone != nil {
				clone.Zero = false
			}
		}
	}
	return
}

func cacheGet(name string, qtype uint16, cache Cacher) (msg *dns.Msg) {
	if cache != nil {
		msg = cache.DnsGet(name, qtype)
	}
	return
}

// -------- TODOs to reach production-grade ---------
// - Parallel/racing to multiple servers per step; jittered retries/backoff.
// - Full DNSSEC pipeline (DS lookups, validation, NSEC aggressive use).
// - ENT & wildcard corner cases under QMIN.
// - Smarter NS address resolution (bailiwick rules, cycle breaks).
// - Positive cache enhancements (serve-stale, prefetch, stale serve).
// - DoT/DoH transports; padding for privacy.
// - Upstream health checks and selection policies.
