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
//	msg, server, err := r.Resolve(context.Background(), "www.example.com.", dns.TypeA)
//	...
//
// Tested with Go ≥1.21.
package resolver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

//go:generate go run ./cmd/genhints roothints.gen.go

type Resolver struct {
	proxy.ContextDialer
	Timeout     time.Duration
	DNSPort     uint16
	maxChase    int // max CNAME/DNAME chase depth
	negMu       sync.RWMutex
	neg         map[negKey]negEntry
	addrMu      sync.RWMutex
	addrCache   map[string][]netip.Addr
	mu          sync.RWMutex // protects following
	useIPv4     bool
	useIPv6     bool
	useUDP      bool
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
	var roots []netip.Addr
	roots = append(roots, Roots4...)
	roots = append(roots, Roots6...)
	return &Resolver{
		ContextDialer: &net.Dialer{},
		Timeout:       3 * time.Second,
		DNSPort:       53,
		maxChase:      8,
		neg:           make(map[negKey]negEntry),
		addrCache:     make(map[string][]netip.Addr),
		useIPv4:       len(Roots4) > 0,
		useIPv6:       len(Roots6) > 0,
		useUDP:        true,
		rootServers:   roots,
	}
}

// Resolve performs iterative resolution with QNAME minimization for qname/qtype.
func (r *Resolver) Resolve(ctx context.Context, qname string, qtype uint16, logw io.Writer) (*dns.Msg, netip.Addr, error) {
	logf(logw, "resolve start qname=%s qtype=%s", qname, typeName(qtype))
	return r.resolveWithDepth(ctx, dns.Fqdn(strings.ToLower(qname)), qtype, 0, logw)
}

// resolveWithDepth is Resolve plus a chase-depth counter to avoid infinite loops.
func (r *Resolver) resolveWithDepth(ctx context.Context, qname string, qtype uint16, depth int, logw io.Writer) (*dns.Msg, netip.Addr, error) {
	logf(logw, "depth=%d qname=%s qtype=%s", depth, qname, typeName(qtype))
	if depth > r.maxChase {
		return nil, netip.Addr{}, fmt.Errorf("cname/dname chain too deep (> %d)", r.maxChase)
	}
	if e := r.negGet(qname, qtype); e != nil {
		logf(logw, "negcache hit qname=%s qtype=%s", qname, typeName(qtype))
		msg := newResponseMsg(qname, qtype, dns.RcodeNameError, nil, []dns.RR{e.soa}, nil)
		return msg, netip.Addr{}, nil
	}

	servers := append([]netip.Addr(nil), r.rootServers...)
	labels := dns.SplitDomainName(qname)

	// Walk down: "." -> "com." -> "example.com."
	for i := len(labels) - 1; i >= 0; i-- {
		zone := dns.Fqdn(strings.Join(labels[i:], "."))
		logf(logw, "delegation step zone=%s", zone)

		nsSet, nextSrv, resp, err := r.queryForDelegation(ctx, zone, servers, qname, logw)
		if err != nil {
			logf(logw, "delegation error zone=%s err=%v", zone, err)
			return nil, netip.Addr{}, err
		}

		if zone == qname {
			targetServers := nextSrv
			if len(targetServers) == 0 {
				targetServers = servers
			}
			logf(logw, "delegation terminal zone=%s servers=%d", zone, len(targetServers))
			return r.queryFinal(ctx, qname, qtype, targetServers, depth, resp, logw)
		}

		if len(nsSet) == 0 {
			if resp != nil && resp.Rcode == dns.RcodeNameError {
				if zone == qname {
					logf(logw, "delegation NXDOMAIN terminal zone=%s", zone)
					return r.handleTerminal(zone, resp, logw)
				}
				logf(logw, "delegation NXDOMAIN zone=%s continuing", zone)
				return r.queryFinal(ctx, qname, qtype, servers, depth, resp, logw)
			}
			logf(logw, "delegation no-ns zone=%s", zone)
			continue
		}
		servers = nextSrv
	}
	return r.queryFinal(ctx, qname, qtype, servers, depth, nil, logw)
}

// -------- Core steps ---------

// queryForDelegation performs the QMIN step at `zone` against `parentServers`.
// If servers REFUSE/NOTIMP the minimized NS query, retry with non-QMIN (ask NS for the full qname).
// Returns: (nsOwnerNames, resolvedServerAddrs, lastResponse, error)
func (r *Resolver) queryForDelegation(ctx context.Context, zone string, parentServers []netip.Addr, fullQname string, logw io.Writer) ([]string, []netip.Addr, *dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(zone, dns.TypeNS)
	m.RecursionDesired = false
	setEDNS(m)

	var last *dns.Msg
	refusedSeen := false
	for _, svr := range shuffle(parentServers) {
		serverStr := r.addrPort(svr).String()
		logf(logw, "delegation query zone=%s server=%s", zone, serverStr)
		resp, err := r.exchange(ctx, m, svr, logw)
		if err != nil {
			logf(logw, "delegation error zone=%s server=%s err=%v", zone, serverStr, err)
			continue
		}
		last = resp
		logf(logw, "delegation response zone=%s server=%s rcode=%s", zone, serverStr, dns.RcodeToString[resp.Rcode])

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
			addrs = r.resolveNSAddrs(ctx, nsOwners, logw)
		}
		if len(addrs) > 0 {
			return nsOwners, addrs, resp, nil
		}
	}
	// Fallback to non-QMIN if we observed REFUSED/NOTIMP
	if refusedSeen {
		logf(logw, "delegation fallback zone=%s", zone)
		m2 := new(dns.Msg)
		m2.SetQuestion(fullQname, dns.TypeNS) // ask NS for the full name (non-minimized)
		m2.RecursionDesired = false
		setEDNS(m2)
		for _, svr := range shuffle(parentServers) {
			serverStr := r.addrPort(svr).String()
			logf(logw, "delegation fallback query full=%s server=%s", fullQname, serverStr)
			resp, err := r.exchange(ctx, m2, svr, logw)
			if err != nil {
				logf(logw, "delegation fallback error full=%s server=%s err=%v", fullQname, serverStr, err)
				continue
			}
			last = resp
			logf(logw, "delegation fallback response full=%s server=%s rcode=%s", fullQname, serverStr, dns.RcodeToString[resp.Rcode])
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
				addrs = r.resolveNSAddrs(ctx, nsOwners, logw)
			}
			if len(addrs) > 0 {
				logf(logw, "delegation returning zone=%s addrs=%d", zone, len(addrs))
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
func (r *Resolver) queryFinal(ctx context.Context, qname string, qtype uint16, authServers []netip.Addr, depth int, parentResp *dns.Msg, logw io.Writer) (*dns.Msg, netip.Addr, error) {
	logf(logw, "final query qname=%s qtype=%s servers=%d", qname, typeName(qtype), len(authServers))
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	m.RecursionDesired = false
	setEDNS(m)

	var last *dns.Msg
	var lastServer netip.Addr
	for _, svr := range shuffle(authServers) {
		resp, err := r.exchange(ctx, m, svr, logw)
		if err != nil {
			logf(logw, "final query error qname=%s server=%s err=%v", qname, r.addrPort(svr), err)
			continue
		}
		last = resp
		lastServer = svr

		switch resp.Rcode {
		case dns.RcodeSuccess:
			logf(logw, "final query success partial qname=%s server=%s", qname, r.addrPort(svr))
			if hasRRType(resp.Answer, qtype) {
				logf(logw, "final query returning answer qname=%s server=%s", qname, r.addrPort(svr))
				return resp, svr, nil
			}

			if tgt, ok := cnameTarget(resp, qname); ok {
				logf(logw, "final query cname qname=%s target=%s", qname, tgt)
				msg, origin, err := r.resolveWithDepth(ctx, tgt, qtype, depth+1, logw)
				if err != nil {
					return nil, netip.Addr{}, err
				}
				prependRecords(msg, resp, qname, cnameChainRecords)
				return msg, origin, nil
			}

			if tgt, ok := dnameSynthesize(resp, qname); ok {
				logf(logw, "final query dname qname=%s target=%s", qname, tgt)
				msg, origin, err := r.resolveWithDepth(ctx, tgt, qtype, depth+1, logw)
				if err != nil {
					return nil, netip.Addr{}, err
				}
				prependRecords(msg, resp, qname, dnameRecords)
				return msg, origin, nil
			}

			if soa := extractSOA(resp); soa != nil {
				r.negPut(qname, qtype, soa)
				logf(logw, "final query NODATA cached soa qname=%s", qname)
				return resp, svr, nil
			}

		case dns.RcodeNameError:
			if soa := extractSOA(resp); soa != nil {
				r.negPut(qname, qtype, soa)
			}
			logf(logw, "final query NXDOMAIN qname=%s", qname)
			return resp, svr, nil
		}
	}

	if last == nil {
		if parentResp != nil && qtype == dns.TypeNS {
			if answers := delegationRecords(parentResp, qname); len(answers) > 0 {
				logf(logw, "final query parent delegation qname=%s count=%d", qname, len(answers))
				parent := parentResp.Copy()
				parent.Answer = append([]dns.RR(nil), answers...)
				return parent, netip.Addr{}, nil
			}
		}
		logf(logw, "final query no response qname=%s", qname)
		return nil, netip.Addr{}, errors.New("no response from authoritative servers")
	}
	logf(logw, "final query completed qname=%s server=%s rcode=%s", qname, r.addrPort(lastServer), dns.RcodeToString[last.Rcode])
	return last, lastServer, nil
}

func (r *Resolver) handleTerminal(zone string, resp *dns.Msg, logw io.Writer) (*dns.Msg, netip.Addr, error) {
	if resp == nil {
		return nil, netip.Addr{}, errors.New("terminal with no response")
	}
	if soa := extractSOA(resp); soa != nil {
		r.negPut(zone, dns.TypeNS, soa)
		logf(logw, "terminal cached soa zone=%s", zone)
	}
	return resp, netip.Addr{}, nil
}

// -------- Transport & helpers ---------

func (r *Resolver) exchange(ctx context.Context, m *dns.Msg, server netip.Addr, logw io.Writer) (resp *dns.Msg, err error) {
	serverStr := r.addrPort(server).String()
	if server.Is6() && !r.usingIPv6() {
		logf(logw, "exchange skip IPv6 server=%s", serverStr)
		return nil, net.ErrClosed
	}
	if r.usingUDP() {
		logf(logw, "exchange udp server=%s", serverStr)
		if resp, err = r.exchangeWithNetwork(ctx, "udp", m, server, logw); err != nil {
			if r.maybeDisableUdp(err) {
				err = nil
			}
			if err != nil {
				logf(logw, "exchange udp error server=%s err=%v", serverStr, err)
			}
		}
	}
	if err == nil && (resp == nil || resp.Truncated) {
		logf(logw, "exchange tcp server=%s trigger=%v", serverStr, resp != nil && resp.Truncated)
		resp, err = r.exchangeWithNetwork(ctx, "tcp", m, server, logw)
	}
	return
}

func (r *Resolver) exchangeWithNetwork(ctx context.Context, network string, m *dns.Msg, server netip.Addr, logw io.Writer) (resp *dns.Msg, err error) {
	var dnsConn *dns.Conn
	if dnsConn, err = r.dialDNSConn(ctx, network, server, logw); err == nil {
		defer dnsConn.Close()
		deadline := r.deadline(ctx)
		if !deadline.IsZero() {
			_ = dnsConn.SetDeadline(deadline)
		}
		if err = dnsConn.WriteMsg(m); err == nil {
			resp, err = dnsConn.ReadMsg()
		}
	}
	if err != nil {
		logf(logw, "exchange network=%s server=%s err=%v", network, r.addrPort(server), err)
	}
	return
}

func (r *Resolver) dialDNSConn(ctx context.Context, network string, server netip.Addr, logw io.Writer) (dnsConn *dns.Conn, err error) {
	var rawConn net.Conn
	addrPort := r.addrPort(server)
	if rawConn, err = r.DialContext(ctx, network, addrPort.String()); err == nil {
		dnsConn = &dns.Conn{Conn: rawConn}
		if strings.HasPrefix(network, "udp") {
			dnsConn.UDPSize = dns.DefaultMsgSize
		}
	} else if server.Is6() {
		r.maybeDisableIPv6(err)
	}
	if err != nil {
		logf(logw, "dial error network=%s server=%s err=%v", network, addrPort, err)
	}
	return
}

func (r *Resolver) port() uint16 {
	if r.DNSPort != 0 {
		return r.DNSPort
	}
	return 53
}

func (r *Resolver) addrPort(addr netip.Addr) netip.AddrPort {
	return netip.AddrPortFrom(addr, r.port())
}

func (r *Resolver) deadline(ctx context.Context) time.Time {
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

func glueAddresses(m *dns.Msg) []netip.Addr {
	var addrs []netip.Addr
	for _, rr := range m.Extra {
		switch a := rr.(type) {
		case *dns.A:
			if addr, ok := ipToAddr(a.A); ok {
				addrs = append(addrs, addr)
			}
		case *dns.AAAA:
			if addr, ok := ipToAddr(a.AAAA); ok {
				addrs = append(addrs, addr)
			}
		}
	}
	return dedupAddrs(addrs)
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
func (r *Resolver) resolveNSAddrs(ctx context.Context, nsOwners []string, logw io.Writer) []netip.Addr {
	var addrs []netip.Addr
	for _, host := range nsOwners {
		r.addrMu.RLock()
		cached, ok := r.addrCache[host]
		r.addrMu.RUnlock()
		if ok {
			logf(logw, "resolveNS cached host=%s addrs=%d", host, len(cached))
			addrs = append(addrs, cached...)
		} else {
			var resolved []netip.Addr
			haveIPv4 := false
			if msg, _, err := r.Resolve(ctx, host, dns.TypeA, logw); err == nil {
				for _, rr := range msg.Answer {
					if a, ok := rr.(*dns.A); ok {
						if addr, ok := ipToAddr(a.A); ok {
							resolved = append(resolved, addr)
							haveIPv4 = true
						}
					}
				}
			}
			if !haveIPv4 {
				if msg, _, err := r.Resolve(ctx, host, dns.TypeAAAA, logw); err == nil {
					for _, rr := range msg.Answer {
						if a, ok := rr.(*dns.AAAA); ok {
							if addr, ok := ipToAddr(a.AAAA); ok {
								resolved = append(resolved, addr)
							}
						}
					}
				}
			}
			resolved = dedupAddrs(resolved)
			if len(resolved) > 0 {
				r.addrMu.Lock()
				r.addrCache[host] = resolved
				r.addrMu.Unlock()
				logf(logw, "resolveNS resolved host=%s addrs=%d", host, len(resolved))
				addrs = append(addrs, resolved...)
			}
		}
	}
	logf(logw, "resolveNS total addrs=%d", len(addrs))
	return dedupAddrs(addrs)
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
	mergeResponse(msg, resp, gather(resp.Answer, qname))
}

func mergeResponse(msg *dns.Msg, resp *dns.Msg, records []dns.RR) {
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

func ipToAddr(ip net.IP) (netip.Addr, bool) {
	if ip == nil {
		return netip.Addr{}, false
	}
	if v4 := ip.To4(); v4 != nil {
		var arr [4]byte
		copy(arr[:], v4)
		return netip.AddrFrom4(arr), true
	}
	if v6 := ip.To16(); v6 != nil {
		var arr [16]byte
		copy(arr[:], v6)
		return netip.AddrFrom16(arr), true
	}
	return netip.Addr{}, false
}

func typeName(qtype uint16) string {
	if name, ok := dns.TypeToString[qtype]; ok {
		return name
	}
	return strconv.Itoa(int(qtype))
}

func logf(logw io.Writer, format string, args ...any) {
	if logw != nil {
		_, _ = fmt.Fprintf(logw, format+"\n", args...)
	}
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
