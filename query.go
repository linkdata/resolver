package resolver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type query struct {
	*Resolver
	ctx       context.Context
	cache     Cacher
	writer    io.Writer
	start     time.Time
	addrCache map[string][]netip.Addr
}

// resolveWithDepth is Resolve plus a chase-depth counter to avoid infinite loops.
func (q *query) resolveWithDepth(qname string, qtype uint16, depth int) (*dns.Msg, netip.Addr, error) {
	q.logf(depth, "resolve depth qname=%s qtype=%s", qname, dns.Type(qtype))
	if depth > maxChase {
		return nil, netip.Addr{}, ErrCNAMEChainTooDeep
	}
	if cached := cacheGet(qname, qtype, q.cache); cached != nil {
		q.logf(depth, "cache hit qname=%s qtype=%s", qname, dns.Type(qtype))
		return cached, netip.Addr{}, nil
	}

	servers := append([]netip.Addr(nil), q.rootServers...)
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
		serverStr := q.addrPort(svr).String()
		q.logf(depth+1, "delegation query zone=%s server=%s", zone, serverStr)
		resp, err := q.exchange(m, svr, depth+2)
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
			if q.cacheStore(resp, q.cache) {
				q.logf(depth+1, "delegation cached response zone=%s", zone)
			}
			return nil, nil, resp, nil
		}

		nsOwners := extractDelegationNS(resp, zone)
		if len(nsOwners) == 0 {
			if resp.Rcode == dns.RcodeNameError {
				if q.cacheStore(resp, q.cache) {
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
			serverStr := q.addrPort(svr).String()
			q.logf(depth+1, "delegation fallback query full=%s server=%s", fullQname, serverStr)
			resp, err := q.exchange(m2, svr, depth+2)
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
				if q.cacheStore(resp, q.cache) {
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

// queryFinal asks the authoritative (or closest) servers for the target qname/qtype.
// It also performs CNAME/DNAME chasing, with a loop bound controlled by depth.
func (q *query) queryFinal(qname string, qtype uint16, authServers []netip.Addr, depth int, parentResp *dns.Msg) (*dns.Msg, netip.Addr, error) {
	q.logf(depth, "final query qname=%s qtype=%s servers=%d", qname, dns.Type(qtype), len(authServers))
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	m.RecursionDesired = false
	setEDNS(m)

	var last *dns.Msg
	var lastServer netip.Addr
	for _, svr := range shuffle(authServers) {
		resp, err := q.exchange(m, svr, depth+1)
		if err != nil || resp == nil {
			continue
		}
		last = resp
		lastServer = svr

		switch resp.Rcode {
		case dns.RcodeSuccess:
			q.logf(depth+1, "final success partial qname=%s server=%s", qname, q.addrPort(svr))
			if hasRRType(resp.Answer, qtype) {
				q.logf(depth+1, "final returning answer qname=%s server=%s", qname, q.addrPort(svr))
				q.cacheStore(resp, q.cache)
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
				q.cacheStore(msg, q.cache)
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
				q.cacheStore(msg, q.cache)
				return msg, origin, nil
			}

			if q.cacheStore(resp, q.cache) {
				q.logf(depth+1, "final cached soa qname=%s", qname)
				return resp, svr, nil
			}

		case dns.RcodeNameError:
			q.cacheStore(resp, q.cache)
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
				q.cacheStore(parent, q.cache)
				return parent, netip.Addr{}, nil
			}
		}
		q.logf(depth+1, "final no response qname=%s", qname)
		return nil, netip.Addr{}, errors.New("no response from authoritative servers")
	}
	q.logf(depth, "final completed qname=%s server=%s rcode=%s", qname, q.addrPort(lastServer), dns.RcodeToString[last.Rcode])
	q.cacheStore(last, q.cache)
	return last, lastServer, nil
}

func (q *query) handleTerminal(zone string, resp *dns.Msg, depth int) (*dns.Msg, netip.Addr, error) {
	if resp == nil {
		return nil, netip.Addr{}, errors.New("terminal with no response")
	}
	if q.cacheStore(resp, q.cache) {
		q.logf(depth, "terminal cached soa zone=%s", zone)
	}
	return resp, netip.Addr{}, nil
}

// resolveNSAddrs minimally resolves NS owner names to addresses by asking the roots → ...
func (q *query) resolveNSAddrs(nsOwners []string, depth int) []netip.Addr {
	var addrs []netip.Addr
	for _, host := range nsOwners {
		cached, ok := q.addrCache[host]
		if ok {
			q.logf(depth, "resolveNS cached host=%s addrs=%d", host, len(cached))
			addrs = append(addrs, cached...)
		} else {
			var resolved []netip.Addr
			haveIPv4 := false
			if msg, _, err := q.resolveWithDepth(dns.Fqdn(strings.ToLower(host)), dns.TypeA, depth+1); err == nil {
				for _, rr := range msg.Answer {
					if a, ok := rr.(*dns.A); ok {
						if addr := ipToAddr(a.A); addr.IsValid() {
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
							if addr := ipToAddr(a.AAAA); addr.IsValid() {
								resolved = append(resolved, addr)
							}
						}
					}
				}
			}
			resolved = dedupAddrs(resolved)
			if len(resolved) > 0 {
				q.addrCache[host] = resolved
				q.logf(depth, "resolveNS resolved host=%s addrs=%d", host, len(resolved))
				addrs = append(addrs, resolved...)
			}
		}
	}
	q.logf(depth, "resolveNS total addrs=%d", len(addrs))
	return dedupAddrs(addrs)
}

func (q *query) logf(depth int, format string, args ...any) {
	if q.writer != nil {
		elapsed := time.Since(q.start).Milliseconds()
		indent := strings.Repeat("  ", depth)
		_, _ = fmt.Fprintf(q.writer, "[%6dms] %s%s\n", elapsed, indent, fmt.Sprintf(format, args...))
	}
}

func (q *query) logQuerySend(depth int, network string, addr netip.Addr, question dns.Question) {
	q.logf(depth, "SENDING  %s: @%s %s %q", formatProto(network, addr), addr.String(), dns.Type(question.Qtype), question.Name)
}

func (q *query) logQueryReceive(depth int, network string, addr netip.Addr, question dns.Question, resp *dns.Msg, dur time.Duration) {
	if resp != nil {
		var flag string
		if resp.Authoritative {
			flag = " AUTH"
		}
		q.logf(depth, "RECEIVED %s: @%s %s %q => %s [%s] (%v, %d bytes%s)",
			formatProto(network, addr),
			addr.String(),
			dns.Type(question.Qtype),
			question.Name,
			dns.RcodeToString[resp.Rcode],
			formatCounts(resp),
			dur.Round(time.Millisecond),
			resp.Len(),
			flag,
		)
	}
}
func (q *query) exchange(m *dns.Msg, server netip.Addr, depth int) (resp *dns.Msg, err error) {
	if resp, err = q.exchangeWithNetwork("udp", m, server, depth+1); err != nil {
		if q.maybeDisableUdp(err) {
			err = nil
		}
	}
	if err == nil && (resp == nil || resp.Truncated) {
		resp, err = q.exchangeWithNetwork("tcp", m, server, depth+1)
	}
	return
}

func (q *query) exchangeWithNetwork(network string, m *dns.Msg, server netip.Addr, depth int) (resp *dns.Msg, err error) {
	if q.usable(network, server) {
		var dnsConn *dns.Conn
		if dnsConn, err = q.dialDNSConn(network, server, depth); err == nil {
			defer dnsConn.Close()
			deadline := q.deadline(q.ctx)
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

func (q *query) dialDNSConn(network string, server netip.Addr, depth int) (dnsConn *dns.Conn, err error) {
	var rawConn net.Conn
	addrPort := q.addrPort(server)
	if rawConn, err = q.DialContext(q.ctx, network, addrPort.String()); err == nil {
		dnsConn = &dns.Conn{Conn: rawConn}
		if strings.HasPrefix(network, "udp") {
			dnsConn.UDPSize = dns.DefaultMsgSize
		}
	} else if server.Is6() {
		q.maybeDisableIPv6(err)
	}
	if err != nil {
		q.logf(depth, "DIAL FAIL %s: @%s err=%v", formatProto(network, server), server.String(), err)
	}
	return
}
