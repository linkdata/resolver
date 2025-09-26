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
	maxChase    int          // max CNAME/DNAME chase depth
	mu          sync.RWMutex // protects following
	useIPv4     bool
	useIPv6     bool
	useUDP      bool
	rootServers []netip.Addr
}

type query struct {
	resolver  *Resolver
	ctx       context.Context
	cache     Cacher
	log       logContext
	addrMu    sync.RWMutex
	addrCache map[string][]netip.Addr
}

type logContext struct {
	writer io.Writer
	start  time.Time
}

var ErrCNAMEChainTooDeep = errors.New("resolver: cname/dname chain too deep")

type errCNAMEChainTooDeep struct {
	limit int
}

func (e errCNAMEChainTooDeep) Error() string {
	return "resolver: cname/dname chain too deep (> " + strconv.Itoa(e.limit) + ")"
}

func (e errCNAMEChainTooDeep) Is(target error) bool {
	return target == ErrCNAMEChainTooDeep
}

func (e errCNAMEChainTooDeep) Unwrap() error {
	return ErrCNAMEChainTooDeep
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
		useIPv4:       len(Roots4) > 0,
		useIPv6:       len(Roots6) > 0,
		useUDP:        true,
		rootServers:   roots,
	}
}

// Resolve performs iterative resolution with QNAME minimization for qname/qtype.
func (r *Resolver) Resolve(ctx context.Context, qname string, qtype uint16, logw io.Writer, cache Cacher) (msg *dns.Msg, origin netip.Addr, err error) {
	qry := query{
		resolver:  r,
		ctx:       ctx,
		cache:     cache,
		log:       logContext{writer: logw, start: time.Now()},
		addrCache: make(map[string][]netip.Addr),
	}
	qry.logf(0, "resolve start qname=%s qtype=%s", qname, typeName(qtype))
	msg, origin, err = qry.resolveWithDepth(dns.Fqdn(strings.ToLower(qname)), qtype, 0)
	return
}

// resolveWithDepth is Resolve plus a chase-depth counter to avoid infinite loops.
func (q *query) resolveWithDepth(qname string, qtype uint16, depth int) (*dns.Msg, netip.Addr, error) {
	q.logf(depth, "resolve depth qname=%s qtype=%s", qname, typeName(qtype))
	if depth > q.resolver.maxChase {
		return nil, netip.Addr{}, errCNAMEChainTooDeep{limit: q.resolver.maxChase}
	}
	if cached := cacheGet(qname, qtype, q.cache); cached != nil {
		q.logf(depth, "cache hit qname=%s qtype=%s", qname, typeName(qtype))
		return cached, netip.Addr{}, nil
	}

	servers := append([]netip.Addr(nil), q.resolver.rootServers...)
	labels := dns.SplitDomainName(qname)

	// Walk down: "." -> "com." -> "example.com."
	for i := len(labels) - 1; i >= 0; i-- {
		zone := dns.Fqdn(strings.Join(labels[i:], "."))
		nsSet, nextSrv, resp, err := q.queryForDelegation(zone, servers, qname, depth)
		if err != nil {
			q.logf(depth, "delegation error zone=%s err=%v", zone, err)
			return nil, netip.Addr{}, err
		}

		if zone == qname {
			targetServers := nextSrv
			if len(targetServers) == 0 {
				targetServers = servers
			}
			return q.queryFinal(qname, qtype, targetServers, depth, resp)
		}

		if len(nsSet) == 0 {
			if resp != nil && resp.Rcode == dns.RcodeNameError {
				if zone == qname {
					return q.handleTerminal(zone, resp, depth)
				}
				q.logf(depth, "delegation NXDOMAIN zone=%s continuing", zone)
				return q.queryFinal(qname, qtype, servers, depth, resp)
			}
			q.logf(depth, "delegation empty ns zone=%s", zone)
			continue
		}
		servers = nextSrv
	}
	return q.queryFinal(qname, qtype, servers, depth, nil)
}

// -------- Core steps ---------

// queryForDelegation performs the QMIN step at `zone` against `parentServers`.
// If servers REFUSE/NOTIMP the minimized NS query, retry with non-QMIN (ask NS for the full qname).
// Returns: (nsOwnerNames, resolvedServerAddrs, lastResponse, error)
func (q *query) queryForDelegation(zone string, parentServers []netip.Addr, fullQname string, depth int) ([]string, []netip.Addr, *dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(zone, dns.TypeNS)
	m.RecursionDesired = false
	setEDNS(m)

	var last *dns.Msg
	refusedSeen := false
	for _, svr := range shuffle(parentServers) {
		serverStr := q.resolver.addrPort(svr).String()
		q.logf(depth+1, "delegation query zone=%s server=%s", zone, serverStr)
		resp, err := q.resolver.exchange(q, m, svr, depth+2)
		if err != nil {
			q.logf(depth+1, "delegation error zone=%s server=%s err=%v", zone, serverStr, err)
			continue
		}
		if resp == nil {
			continue
		}
		last = resp
		q.logf(depth+1, "delegation response zone=%s server=%s rcode=%s", zone, serverStr, dns.RcodeToString[resp.Rcode])

		if resp.Rcode == dns.RcodeRefused || resp.Rcode == dns.RcodeNotImplemented {
			refusedSeen = true
			continue
		}
		if resp.Rcode == dns.RcodeNameError { // NXDOMAIN at parent ⇒ bubble up
			if q.resolver.cacheStore(resp, q.cache) {
				q.logf(depth+1, "delegation cached response zone=%s", zone)
			}
			return nil, nil, resp, nil
		}

		nsOwners := extractDelegationNS(resp, zone)
		if len(nsOwners) == 0 {
			if resp.Rcode == dns.RcodeNameError {
				if q.resolver.cacheStore(resp, q.cache) {
					q.logf(depth+1, "delegation cached response zone=%s", zone)
				}
				return nil, nil, resp, nil
			}
			continue
		}
		addrs := glueAddresses(resp)
		if len(addrs) == 0 {
			addrs = q.resolveNSAddrs(nsOwners, depth+2)
		}
		if len(addrs) > 0 {
			return nsOwners, addrs, resp, nil
		}
	}
	// Fallback to non-QMIN if we observed REFUSED/NOTIMP
	if refusedSeen {
		q.logf(depth, "delegation fallback zone=%s", zone)
		m2 := new(dns.Msg)
		m2.SetQuestion(fullQname, dns.TypeNS) // ask NS for the full name (non-minimized)
		m2.RecursionDesired = false
		setEDNS(m2)
		for _, svr := range shuffle(parentServers) {
			serverStr := q.resolver.addrPort(svr).String()
			q.logf(depth+1, "delegation fallback query full=%s server=%s", fullQname, serverStr)
			resp, err := q.resolver.exchange(q, m2, svr, depth+2)
			if err != nil {
				q.logf(depth+1, "delegation fallback error full=%s server=%s err=%v", fullQname, serverStr, err)
				continue
			}
			if resp == nil {
				continue
			}
			last = resp
			q.logf(depth+1, "delegation fallback response full=%s server=%s rcode=%s", fullQname, serverStr, dns.RcodeToString[resp.Rcode])
			if resp.Rcode == dns.RcodeNameError {
				if q.resolver.cacheStore(resp, q.cache) {
					q.logf(depth+1, "delegation cached response zone=%s", fullQname)
				}
				return nil, nil, resp, nil
			}
			nsOwners := extractDelegationNS(resp, fullQname)
			if len(nsOwners) == 0 {
				continue
			}
			addrs := glueAddresses(resp)
			if len(addrs) == 0 {
				addrs = q.resolveNSAddrs(nsOwners, depth+2)
			}
			if len(addrs) > 0 {
				q.logf(depth+1, "delegation returning zone=%s addrs=%d", fullQname, len(addrs))
				return nsOwners, addrs, resp, nil
			}
		}
	}

	if last == nil {
		return nil, nil, nil, errors.New("no response from parent servers")
	}
	return nil, nil, last, nil
}

func (r *Resolver) usable(protocol string, addr netip.Addr) (yes bool) {
	yes = strings.HasPrefix(protocol, "tcp") || r.usingUDP()
	yes = yes && (addr.Is4() || r.usingIPv6())
	return
}

// queryFinal asks the authoritative (or closest) servers for the target qname/qtype.
// It also performs CNAME/DNAME chasing, with a loop bound controlled by depth.
func (q *query) queryFinal(qname string, qtype uint16, authServers []netip.Addr, depth int, parentResp *dns.Msg) (*dns.Msg, netip.Addr, error) {
	q.logf(depth, "final query qname=%s qtype=%s servers=%d", qname, typeName(qtype), len(authServers))
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	m.RecursionDesired = false
	setEDNS(m)

	var last *dns.Msg
	var lastServer netip.Addr
	for _, svr := range shuffle(authServers) {
		resp, err := q.resolver.exchange(q, m, svr, depth+1)
		if err != nil || resp == nil {
			continue
		}
		last = resp
		lastServer = svr

		switch resp.Rcode {
		case dns.RcodeSuccess:
			q.logf(depth+1, "final success partial qname=%s server=%s", qname, q.resolver.addrPort(svr))
			if hasRRType(resp.Answer, qtype) {
				q.logf(depth+1, "final returning answer qname=%s server=%s", qname, q.resolver.addrPort(svr))
				q.resolver.cacheStore(resp, q.cache)
				return resp, svr, nil
			}

			if tgt, ok := cnameTarget(resp, qname); ok {
				q.logf(depth+1, "final cname qname=%s target=%s", qname, tgt)
				msg, origin, err := q.resolveWithDepth(tgt, qtype, depth+1)
				if err != nil {
					return nil, netip.Addr{}, err
				}
				msg = cloneIfCached(msg)
				prependRecords(msg, resp, qname, cnameChainRecords)
				q.resolver.cacheStore(msg, q.cache)
				return msg, origin, nil
			}

			if tgt, ok := dnameSynthesize(resp, qname); ok {
				q.logf(depth+1, "final dname qname=%s target=%s", qname, tgt)
				msg, origin, err := q.resolveWithDepth(tgt, qtype, depth+1)
				if err != nil {
					return nil, netip.Addr{}, err
				}
				msg = cloneIfCached(msg)
				prependRecords(msg, resp, qname, dnameRecords)
				q.resolver.cacheStore(msg, q.cache)
				return msg, origin, nil
			}

			if q.resolver.cacheStore(resp, q.cache) {
				q.logf(depth+1, "final cached soa qname=%s", qname)
				return resp, svr, nil
			}

		case dns.RcodeNameError:
			q.resolver.cacheStore(resp, q.cache)
			q.logf(depth+1, "final NXDOMAIN qname=%s", qname)
			return resp, svr, nil
		}
	}

	if last == nil {
		if parentResp != nil && qtype == dns.TypeNS {
			if answers := delegationRecords(parentResp, qname); len(answers) > 0 {
				q.logf(depth+1, "final parent delegation qname=%s count=%d", qname, len(answers))
				parent := parentResp.Copy()
				parent.Answer = append([]dns.RR(nil), answers...)
				q.resolver.cacheStore(parent, q.cache)
				return parent, netip.Addr{}, nil
			}
		}
		q.logf(depth+1, "final no response qname=%s", qname)
		return nil, netip.Addr{}, errors.New("no response from authoritative servers")
	}
	q.logf(depth, "final completed qname=%s server=%s rcode=%s", qname, q.resolver.addrPort(lastServer), dns.RcodeToString[last.Rcode])
	q.resolver.cacheStore(last, q.cache)
	return last, lastServer, nil
}

func (q *query) handleTerminal(zone string, resp *dns.Msg, depth int) (*dns.Msg, netip.Addr, error) {
	if resp == nil {
		return nil, netip.Addr{}, errors.New("terminal with no response")
	}
	if q.resolver.cacheStore(resp, q.cache) {
		q.logf(depth, "terminal cached soa zone=%s", zone)
	}
	return resp, netip.Addr{}, nil
}

// -------- Transport & helpers ---------

func (r *Resolver) exchange(q *query, m *dns.Msg, server netip.Addr, depth int) (resp *dns.Msg, err error) {
	if resp, err = r.exchangeWithNetwork(q, "udp", m, server, depth+1); err != nil {
		if r.maybeDisableUdp(err) {
			err = nil
		}
	}
	if err == nil && (resp == nil || resp.Truncated) {
		resp, err = r.exchangeWithNetwork(q, "tcp", m, server, depth+1)
	}
	return
}

func (r *Resolver) exchangeWithNetwork(q *query, network string, m *dns.Msg, server netip.Addr, depth int) (resp *dns.Msg, err error) {
	if r.usable(network, server) {
		var dnsConn *dns.Conn
		if dnsConn, err = r.dialDNSConn(q, network, server, depth); err == nil {
			defer dnsConn.Close()
			deadline := r.deadline(q.ctx)
			if !deadline.IsZero() {
				_ = dnsConn.SetDeadline(deadline)
			}
			var question dns.Question
			if len(m.Question) > 0 {
				question = m.Question[0]
				q.logQuerySend(depth, network, server, question)
			}
			start := time.Now()
			if err = dnsConn.WriteMsg(m); err == nil {
				resp, err = dnsConn.ReadMsg()
				if err == nil && len(m.Question) > 0 {
					q.logQueryReceive(depth, network, server, question, resp, time.Since(start))
				}
			}
		}
	}
	return
}

func (r *Resolver) dialDNSConn(q *query, network string, server netip.Addr, depth int) (dnsConn *dns.Conn, err error) {
	var rawConn net.Conn
	addrPort := r.addrPort(server)
	if rawConn, err = r.DialContext(q.ctx, network, addrPort.String()); err == nil {
		dnsConn = &dns.Conn{Conn: rawConn}
		if strings.HasPrefix(network, "udp") {
			dnsConn.UDPSize = dns.DefaultMsgSize
		}
	} else if server.Is6() {
		r.maybeDisableIPv6(err)
	}
	if err != nil {
		q.logf(depth, "DIAL FAIL %s: @%s err=%v", formatProto(network, server), server.String(), err)
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
func (q *query) resolveNSAddrs(nsOwners []string, depth int) []netip.Addr {
	var addrs []netip.Addr
	for _, host := range nsOwners {
		q.addrMu.RLock()
		cached, ok := q.addrCache[host]
		q.addrMu.RUnlock()
		if ok {
			q.logf(depth, "resolveNS cached host=%s addrs=%d", host, len(cached))
			addrs = append(addrs, cached...)
		} else {
			var resolved []netip.Addr
			haveIPv4 := false
			if msg, _, err := q.resolveWithDepth(dns.Fqdn(strings.ToLower(host)), dns.TypeA, depth+1); err == nil {
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
				if msg, _, err := q.resolveWithDepth(dns.Fqdn(strings.ToLower(host)), dns.TypeAAAA, depth+1); err == nil {
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
				q.addrMu.Lock()
				q.addrCache[host] = resolved
				q.addrMu.Unlock()
				q.logf(depth, "resolveNS resolved host=%s addrs=%d", host, len(resolved))
				addrs = append(addrs, resolved...)
			}
		}
	}
	q.logf(depth, "resolveNS total addrs=%d", len(addrs))
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
	var haveQuestion bool
	if len(msg.Question) > 0 {
		msg.Question[0].Name = qname
		haveQuestion = true
	}
	if !haveQuestion {
		if resp != nil {
			if len(resp.Question) > 0 {
				question := resp.Question[0]
				question.Name = qname
				msg.Question = append(msg.Question, question)
			}
		}
	}
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

func (q *query) logf(depth int, format string, args ...any) {
	if q == nil {
		return
	}
	if q.log.writer == nil {
		return
	}
	elapsed := time.Since(q.log.start).Milliseconds()
	indent := strings.Repeat("  ", depth)
	_, _ = fmt.Fprintf(q.log.writer, "[%6dms] %s%s\n", elapsed, indent, fmt.Sprintf(format, args...))
}

func (q *query) logQuerySend(depth int, network string, addr netip.Addr, question dns.Question) {
	if q == nil {
		return
	}
	if q.log.writer == nil {
		return
	}
	q.logf(depth, "SENDING  %s: @%s %s %q", formatProto(network, addr), addr.String(), typeName(question.Qtype), question.Name)
}

func (q *query) logQueryReceive(depth int, network string, addr netip.Addr, question dns.Question, resp *dns.Msg, dur time.Duration) {
	if q == nil {
		return
	}
	if q.log.writer == nil || resp == nil {
		return
	}
	var flag string
	if resp.Authoritative {
		flag = " AUTH"
	}
	q.logf(depth, "RECEIVED %s: @%s %s %q => %s [%s] (%s, %d bytes%s)",
		formatProto(network, addr),
		addr.String(),
		typeName(question.Qtype),
		question.Name,
		dns.RcodeToString[resp.Rcode],
		formatCounts(resp),
		formatDuration(dur),
		resp.Len(),
		flag,
	)
}

func formatProto(network string, addr netip.Addr) string {
	proto := network
	if addr.Is4() {
		return proto + "4"
	}
	if addr.Is6() {
		return proto + "6"
	}
	return proto
}

func formatCounts(msg *dns.Msg) string {
	return fmt.Sprintf("%d+%d+%d A/N/E", len(msg.Answer), len(msg.Ns), len(msg.Extra))
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "0ms"
	}
	ms := d.Milliseconds()
	if ms == 0 {
		return "<1ms"
	}
	return fmt.Sprintf("%dms", ms)
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

func (r *Resolver) cacheStore(msg *dns.Msg, cache Cacher) (cached bool) {
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
