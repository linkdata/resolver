// Package resolver provides a minimal iterative DNS resolver with QNAME minimization
// using github.com/miekg/dns for wire format and transport.
//
// Now includes:
//   - CNAME/DNAME chasing with loop protection.
//   - Fallback to non-QMIN when a parent returns REFUSED (or NOTIMP) during
//     a QNAME-minimized delegation step.
//
// ⚠️ This is still a learning-oriented skeleton. It simplifies DNSSEC, parallelism,
// retries, ENT/wildcard edges, etc.
//
// Usage:
//
//	r := resolver.New()
//	res, err := r.Resolve(context.Background(), "www.example.com.", dns.TypeA)
//	...
//
// Tested with Go ≥1.21.
package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

//go:generate go run ./cmd/genhints roothints.gen.go

// -------- Public API ---------

type Result struct {
	Answers    []dns.RR
	Authority  []dns.RR
	Additional []dns.RR
	Server     string
	RCODE      int // dns.Rcode
}

type Resolver struct {
	roots []string // "ip:port" of root servers
	proxy.ContextDialer
	Timeout     time.Duration
	maxChase    int // max CNAME/DNAME chase depth
	negMu       sync.RWMutex
	neg         map[negKey]negEntry
	addrMu      sync.RWMutex
	addrCache   map[string][]string
	mu          sync.RWMutex // protects following
	useIPv4     bool
	useIPv6     bool
	rootServers []netip.Addr
}

type negKey struct {
	name  string
	qtype uint16
}

type negEntry struct {
	expiry time.Time
	soa    *dns.SOA
}

// New returns a resolver seeded with IANA root servers.
func New() (r *Resolver) {
	roots := make([]string, 0, len(Roots4)+len(Roots6))
	rootAddrs := make([]netip.Addr, 0, len(Roots4)+len(Roots6))
	for _, addr := range Roots4 {
		roots = append(roots, net.JoinHostPort(addr.String(), "53"))
		rootAddrs = append(rootAddrs, addr)
	}
	for _, addr := range Roots6 {
		roots = append(roots, net.JoinHostPort(addr.String(), "53"))
		rootAddrs = append(rootAddrs, addr)
	}
	return &Resolver{
		roots:         roots,
		ContextDialer: &net.Dialer{},
		Timeout:       3 * time.Second,
		maxChase:      8,
		neg:           make(map[negKey]negEntry),
		addrCache:     make(map[string][]string),
		useIPv4:       len(Roots4) > 0,
		useIPv6:       len(Roots6) > 0,
		rootServers:   rootAddrs,
	}
}

// Resolve performs iterative resolution with QNAME minimization for qname/qtype.
func (r *Resolver) Resolve(ctx context.Context, qname string, qtype uint16) (*Result, error) {
	return r.resolveWithDepth(ctx, dns.Fqdn(strings.ToLower(qname)), qtype, 0)
}

// resolveWithDepth is Resolve plus a chase-depth counter to avoid infinite loops.
func (r *Resolver) resolveWithDepth(ctx context.Context, qname string, qtype uint16, depth int) (*Result, error) {
	if depth > r.maxChase {
		return nil, fmt.Errorf("cname/dname chain too deep (> %d)", r.maxChase)
	}
	if e := r.negGet(qname, qtype); e != nil {
		return &Result{RCODE: int(dns.RcodeNameError), Authority: []dns.RR{e.soa}}, nil
	}

	servers := append([]string(nil), r.roots...)
	labels := dns.SplitDomainName(qname)

	// Walk down: "." -> "com." -> "example.com."
	for i := len(labels) - 1; i >= 0; i-- {
		zone := dns.Fqdn(strings.Join(labels[i:], "."))

		nsSet, nextSrv, resp, err := r.queryForDelegation(ctx, zone, servers, qname)
		if err != nil {
			return nil, err
		}

		if zone == qname {
			targetServers := nextSrv
			if len(targetServers) == 0 {
				targetServers = servers
			}
			return r.queryFinal(ctx, qname, qtype, targetServers, servers, depth, resp)
		}

		if len(nsSet) == 0 {
			if resp != nil && resp.Rcode == dns.RcodeNameError {
				if zone == qname {
					return r.handleTerminal(zone, resp)
				}
				return r.queryFinal(ctx, qname, qtype, servers, servers, depth, resp)
			}
			continue
		}
		servers = nextSrv
	}
	return r.queryFinal(ctx, qname, qtype, servers, servers, depth, nil)
}

// -------- Core steps ---------

// queryForDelegation performs the QMIN step at `zone` against `parentServers`.
// If servers REFUSE/NOTIMP the minimized NS query, retry with non-QMIN (ask NS for the full qname).
// Returns: (nsOwnerNames, resolvedServerAddrs, lastResponse, error)
func (r *Resolver) queryForDelegation(ctx context.Context, zone string, parentServers []string, fullQname string) ([]string, []string, *dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(zone, dns.TypeNS)
	m.RecursionDesired = false
	setEDNS(m)

	var last *dns.Msg
	refusedSeen := false
	for _, svr := range shuffle(parentServers) {
		resp, err := r.exchange(ctx, m, svr)
		if err != nil {
			continue
		}
		last = resp

		if resp.Rcode == dns.RcodeRefused || resp.Rcode == dns.RcodeNotImplemented {
			refusedSeen = true
			continue
		}
		if resp.Rcode == dns.RcodeNameError { // NXDOMAIN at parent ⇒ bubble up
			if soa := extractSOA(resp); soa != nil {
				r.negPut(zone, dns.TypeNS, soa)
			}
			return nil, nil, resp, nil
		}

		nsOwners := extractDelegationNS(resp, zone)
		if len(nsOwners) == 0 {
			if resp != nil {
				if resp.Rcode == dns.RcodeNameError {
					if soa := extractSOA(resp); soa != nil {
						r.negPut(zone, dns.TypeNS, soa)
					}
					return nil, nil, resp, nil
				}
			}
			continue
		}
		addrs := glueAddresses(resp)
		if len(addrs) == 0 {
			addrs = r.resolveNSAddrs(ctx, nsOwners)
		}
		if len(addrs) > 0 {
			return nsOwners, addrs, resp, nil
		}
	}
	// Fallback to non-QMIN if we observed REFUSED/NOTIMP
	if refusedSeen {
		m2 := new(dns.Msg)
		m2.SetQuestion(fullQname, dns.TypeNS) // ask NS for the full name (non-minimized)
		m2.RecursionDesired = false
		setEDNS(m2)
		for _, svr := range shuffle(parentServers) {
			resp, err := r.exchange(ctx, m2, svr)
			if err != nil {
				continue
			}
			last = resp
			if resp.Rcode == dns.RcodeNameError {
				if soa := extractSOA(resp); soa != nil {
					r.negPut(fullQname, dns.TypeNS, soa)
				}
				return nil, nil, resp, nil
			}
			nsOwners := extractDelegationNS(resp, fullQname)
			if len(nsOwners) == 0 {
				continue
			}
			addrs := glueAddresses(resp)
			if len(addrs) == 0 {
				addrs = r.resolveNSAddrs(ctx, nsOwners)
			}
			if len(addrs) > 0 {
				return nsOwners, addrs, resp, nil
			}
		}
	}

	if last == nil {
		return nil, nil, nil, errors.New("no response from parent servers")
	}
	return nil, nil, last, nil
}

// queryFinal asks the authoritative (or closest) servers for the target qname/qtype.
// It also performs CNAME/DNAME chasing, with a loop bound controlled by depth.
func (r *Resolver) queryFinal(ctx context.Context, qname string, qtype uint16, authServers []string, fallbackParent []string, depth int, parentResp *dns.Msg) (*Result, error) {
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	m.RecursionDesired = false
	setEDNS(m)

	var last *dns.Msg
	for _, svr := range shuffle(authServers) {
		resp, err := r.exchange(ctx, m, svr)
		if err != nil {
			continue
		}
		last = resp

		switch resp.Rcode {
		case dns.RcodeSuccess:
			// If we got the desired RRset, return it directly.
			if hasRRType(resp.Answer, qtype) {
				return &Result{Answers: resp.Answer, Authority: resp.Ns, Additional: resp.Extra, Server: svr, RCODE: resp.Rcode}, nil
			}

			// CNAME chase: if owner has CNAME, follow it.
			if tgt, ok := cnameTarget(resp, qname); ok {
				var res *Result
				var chaseErr error
				res, chaseErr = r.resolveWithDepth(ctx, tgt, qtype, depth+1)
				if chaseErr == nil {
					res.Answers = append(cnameChainRecords(resp.Answer, qname), res.Answers...)
					if len(resp.Ns) > 0 {
						res.Authority = resp.Ns
					}
					if len(resp.Extra) > 0 {
						res.Additional = append(resp.Extra, res.Additional...)
					}
					return res, nil
				}
				return nil, chaseErr
			}

			// DNAME chase: synthesize target and follow.
			if tgt, ok := dnameSynthesize(resp, qname); ok {
				var res *Result
				var chaseErr error
				res, chaseErr = r.resolveWithDepth(ctx, tgt, qtype, depth+1)
				if chaseErr == nil {
					res.Answers = append(dnameRecords(resp.Answer, qname), res.Answers...)
					if len(resp.Ns) > 0 {
						res.Authority = resp.Ns
					}
					if len(resp.Extra) > 0 {
						res.Additional = append(resp.Extra, res.Additional...)
					}
					return res, nil
				}
				return nil, chaseErr
			}

			// NODATA? If SOA present, negative-cache and return.
			if soa := extractSOA(resp); soa != nil {
				r.negPut(qname, qtype, soa)
				return &Result{Answers: nil, Authority: []dns.RR{soa}, Additional: resp.Extra, Server: svr, RCODE: resp.Rcode}, nil
			}

			// Otherwise, try next server.
		case dns.RcodeNameError:
			if soa := extractSOA(resp); soa != nil {
				r.negPut(qname, qtype, soa)
			}
			return &Result{Answers: nil, Authority: resp.Ns, Additional: resp.Extra, Server: svr, RCODE: resp.Rcode}, nil
		}
	}

	if last == nil {
		if parentResp != nil && qtype == dns.TypeNS {
			if answers := delegationRecords(parentResp, qname); len(answers) > 0 {
				return &Result{Answers: answers, Authority: parentResp.Ns, Additional: parentResp.Extra, Server: "", RCODE: parentResp.Rcode}, nil
			}
		}
		return nil, errors.New("no response from authoritative servers")
	}
	return &Result{Answers: last.Answer, Authority: last.Ns, Additional: last.Extra, Server: "", RCODE: last.Rcode}, nil
}

func (r *Resolver) handleTerminal(zone string, resp *dns.Msg) (*Result, error) {
	if resp == nil {
		return nil, errors.New("terminal with no response")
	}
	if resp.Rcode == dns.RcodeSuccess {
		if soa := extractSOA(resp); soa != nil {
			r.negPut(zone, dns.TypeNS, soa)
			return &Result{RCODE: resp.Rcode, Authority: []dns.RR{soa}, Additional: resp.Extra}, nil
		}
	}
	if resp.Rcode == dns.RcodeNameError {
		if soa := extractSOA(resp); soa != nil {
			r.negPut(zone, dns.TypeNS, soa)
		}
		return &Result{RCODE: resp.Rcode, Authority: resp.Ns, Additional: resp.Extra}, nil
	}
	return &Result{RCODE: resp.Rcode, Authority: resp.Ns, Additional: resp.Extra}, nil
}

// -------- Transport & helpers ---------

func (r *Resolver) exchange(ctx context.Context, m *dns.Msg, server string) (*dns.Msg, error) {
	c := &dns.Client{Net: "udp", Timeout: r.Timeout, SingleInflight: true}
	resp, _, err := c.ExchangeContext(ctx, m, server)
	if err != nil {
		return nil, err
	}
	if resp.Truncated { // TC → retry with TCP
		cTCP := &dns.Client{Net: "tcp", Timeout: r.Timeout, SingleInflight: true}
		resp, _, err := cTCP.ExchangeContext(ctx, m, server)
		return resp, err
	}
	return resp, nil
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

func delegationRecords(m *dns.Msg, zone string) []dns.RR {
	var out []dns.RR
	if m == nil {
		return out
	}
	for _, rr := range m.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			if strings.EqualFold(ns.Hdr.Name, zone) {
				out = append(out, rr)
			}
		}
	}
	return out
}

func glueAddresses(m *dns.Msg) []string {
	var addrs []string
	for _, rr := range m.Extra {
		switch a := rr.(type) {
		case *dns.A:
			addrs = append(addrs, net.JoinHostPort(a.A.String(), "53"))
		case *dns.AAAA:
			addrs = append(addrs, net.JoinHostPort(a.AAAA.String(), "53"))
		}
	}
	return addrs
}

func extractSOA(m *dns.Msg) *dns.SOA {
	for _, rr := range append(append([]dns.RR{}, m.Ns...), m.Answer...) {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa
		}
	}
	return nil
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

// resolveNSAddrs minimally resolves NS owner names to addresses by asking the roots → ...
func (r *Resolver) resolveNSAddrs(ctx context.Context, nsOwners []string) []string {
	var addrs []string
	for _, host := range nsOwners {
		r.addrMu.RLock()
		cached, ok := r.addrCache[host]
		r.addrMu.RUnlock()
		if ok {
			addrs = append(addrs, cached...)
		} else {
			var resolved []string
			haveIPv4 := false
			if res, err := r.Resolve(ctx, host, dns.TypeA); err == nil {
				for _, rr := range res.Answers {
					if a, ok := rr.(*dns.A); ok {
						resolved = append(resolved, net.JoinHostPort(a.A.String(), "53"))
						haveIPv4 = true
					}
				}
			}
			if !haveIPv4 {
				if res, err := r.Resolve(ctx, host, dns.TypeAAAA); err == nil {
					for _, rr := range res.Answers {
						if a, ok := rr.(*dns.AAAA); ok {
							resolved = append(resolved, net.JoinHostPort(a.AAAA.String(), "53"))
						}
					}
				}
			}
			resolved = dedup(resolved)
			if len(resolved) > 0 {
				r.addrMu.Lock()
				r.addrCache[host] = resolved
				r.addrMu.Unlock()
				addrs = append(addrs, resolved...)
			}
		}
	}
	return dedup(addrs)
}

func dedup(ss []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range ss {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
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

// -------- Negative cache (minimal RFC 2308) ---------

func (r *Resolver) negPut(name string, qtype uint16, soa *dns.SOA) {
	if soa == nil {
		return
	}
	minTTL := time.Duration(soa.Minttl) * time.Second
	soaTTL := time.Duration(soa.Hdr.Ttl) * time.Second
	if soaTTL > 0 && soaTTL < minTTL {
		minTTL = soaTTL
	}
	if minTTL <= 0 {
		minTTL = 30 * time.Second
	}
	r.negMu.Lock()
	r.neg[negKey{strings.ToLower(name), qtype}] = negEntry{expiry: time.Now().Add(minTTL), soa: soa}
	r.negMu.Unlock()
}

func (r *Resolver) negGet(name string, qtype uint16) *negEntry {
	r.negMu.RLock()
	e, ok := r.neg[negKey{strings.ToLower(name), qtype}]
	r.negMu.RUnlock()
	if !ok {
		return nil
	}
	if time.Now().After(e.expiry) {
		r.negMu.Lock()
		delete(r.neg, negKey{strings.ToLower(name), qtype})
		r.negMu.Unlock()
		return nil
	}
	return &e
}

// -------- TODOs to reach production-grade ---------
// - Parallel/racing to multiple servers per step; jittered retries/backoff.
// - Full DNSSEC pipeline (DS lookups, validation, NSEC aggressive use).
// - ENT & wildcard corner cases under QMIN.
// - Smarter NS address resolution (bailiwick rules, cycle breaks).
// - Positive cache with TTL tracking; serve-stale/prefetch.
// - DoT/DoH transports; padding for privacy.
// - Upstream health checks and selection policies.
