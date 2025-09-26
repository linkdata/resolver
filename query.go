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
	"time"

	"github.com/miekg/dns"
)

type query struct {
	*Service
	ctx     context.Context
	cache   Cacher
	writer  io.Writer
	start   time.Time
	depth   int
	queries int
}

const maxChase = 16     // max CNAME/DNAME chase depth
const maxQueries = 1024 // max queries to make for a single resolve

var ErrCNAMEChainTooDeep = errors.New("cname/dname chain too deep")
var ErrTooManyQueries = errors.New("to many queries, possible loop")

func (q *query) dive() (err error) {
	q.depth++
	if q.depth > maxChase {
		err = ErrCNAMEChainTooDeep
	}
	return
}

func (q *query) surface() {
	q.depth--
}

func (q *query) resolve(qname string, qtype uint16) (resp *dns.Msg, srv netip.Addr, err error) {
	if err = q.dive(); err == nil {
		defer q.surface()
		q.logf("RESOLVE %s %q\n", dns.Type(qtype), qname)
		if resp = cacheGet(qname, qtype, q.cache); resp == nil {
			servers := append([]netip.Addr(nil), q.rootServers...)
			labels := dns.SplitDomainName(qname)

			// Walk down: "." -> "com." -> "example.com."
			for i := len(labels) - 1; i >= 0; i-- {
				zone := dns.Fqdn(strings.Join(labels[i:], "."))
				nsSet, nextSrv, resp, err := q.queryForDelegation(zone, servers, qname)
				if err != nil {
					q.logf("delegation error zone=%s err=%v", zone, err)
					return nil, netip.Addr{}, err
				}

				if zone == qname {
					targetServers := nextSrv
					if len(targetServers) == 0 {
						targetServers = servers
					}
					return q.queryFinal(qname, qtype, targetServers, resp)
				}

				if len(nsSet) == 0 {
					if resp != nil && resp.Rcode == dns.RcodeNameError {
						if zone == qname {
							return q.handleTerminal(zone, resp)
						}
						q.logf("delegation NXDOMAIN zone=%s continuing", zone)
						return q.queryFinal(qname, qtype, servers, resp)
					}
					q.logf("delegation empty ns zone=%s", zone)
					continue
				}
				servers = nextSrv
			}
			return q.queryFinal(qname, qtype, servers, nil)
		}
	}
	return
}

// -------- Core steps ---------

// queryForDelegation performs the QMIN step at `zone` against `parentServers`.
// If servers REFUSE/NOTIMP the minimized NS query, retry with non-QMIN (ask NS for the full qname).
// Returns: (nsOwnerNames, resolvedServerAddrs, lastResponse, error)
func (q *query) queryForDelegation(zone string, parentServers []netip.Addr, fullQname string) (nsOwnerNames []string, resolvedServerAddrs []netip.Addr, last *dns.Msg, err error) {
	if err = q.dive(); err == nil {
		defer q.surface()
		m := new(dns.Msg)
		m.SetQuestion(zone, dns.TypeNS)
		m.RecursionDesired = false
		setEDNS(m)

		refusedSeen := false
		for _, svr := range shuffle(parentServers) {
			serverStr := q.addrPort(svr).String()
			q.logf("delegation query zone=%s server=%s", zone, serverStr)
			resp, err := q.exchange(m, svr)
			if err != nil {
				q.logf("delegation error zone=%s server=%s err=%v", zone, serverStr, err)
				continue
			}
			if resp == nil {
				continue
			}
			last = resp
			q.logf("delegation response zone=%s server=%s rcode=%s", zone, serverStr, dns.RcodeToString[resp.Rcode])

			if resp.Rcode == dns.RcodeRefused || resp.Rcode == dns.RcodeNotImplemented {
				refusedSeen = true
				continue
			}
			if resp.Rcode == dns.RcodeNameError { // NXDOMAIN at parent ⇒ bubble up
				if q.cacheStore(resp, q.cache) {
					q.logf("delegation cached response zone=%s", zone)
				}
				return nil, nil, resp, nil
			}

			nsOwners := extractDelegationNS(resp, zone)
			if len(nsOwners) == 0 {
				if resp.Rcode == dns.RcodeNameError {
					if q.cacheStore(resp, q.cache) {
						q.logf("delegation cached response zone=%s", zone)
					}
					return nil, nil, resp, nil
				}
				continue
			}
			addrs := glueAddresses(resp)
			if len(addrs) == 0 {
				addrs = q.resolveNSAddrs(nsOwners)
			}
			if len(addrs) > 0 {
				return nsOwners, addrs, resp, nil
			}
		}
		// Fallback to non-QMIN if we observed REFUSED/NOTIMP
		if refusedSeen {
			q.logf("delegation fallback zone=%s", zone)
			m2 := new(dns.Msg)
			m2.SetQuestion(fullQname, dns.TypeNS) // ask NS for the full name (non-minimized)
			m2.RecursionDesired = false
			setEDNS(m2)
			for _, svr := range shuffle(parentServers) {
				serverStr := q.addrPort(svr).String()
				q.logf("delegation fallback query full=%s server=%s", fullQname, serverStr)
				resp, err := q.exchange(m2, svr)
				if err != nil {
					q.logf("delegation fallback error full=%s server=%s err=%v", fullQname, serverStr, err)
					continue
				}
				if resp == nil {
					continue
				}
				last = resp
				q.logf("delegation fallback response full=%s server=%s rcode=%s", fullQname, serverStr, dns.RcodeToString[resp.Rcode])
				if resp.Rcode == dns.RcodeNameError {
					if q.cacheStore(resp, q.cache) {
						q.logf("delegation cached response zone=%s", fullQname)
					}
					return nil, nil, resp, nil
				}
				nsOwners := extractDelegationNS(resp, fullQname)
				if len(nsOwners) == 0 {
					continue
				}
				addrs := glueAddresses(resp)
				if len(addrs) == 0 {
					addrs = q.resolveNSAddrs(nsOwners)
				}
				if len(addrs) > 0 {
					q.logf("delegation returning zone=%s addrs=%d", fullQname, len(addrs))
					return nsOwners, addrs, resp, nil
				}
			}
		}
	}

	if last == nil {
		return nil, nil, nil, errors.New("no response from parent servers")
	}

	return
}

// queryFinal asks the authoritative (or closest) servers for the target qname/qtype.
// It also performs CNAME/DNAME chasing, with a loop bound controlled by depth.
func (q *query) queryFinal(qname string, qtype uint16, authServers []netip.Addr, parentResp *dns.Msg) (*dns.Msg, netip.Addr, error) {
	q.logf("final query qname=%s qtype=%s servers=%d", qname, dns.Type(qtype), len(authServers))
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	m.RecursionDesired = false
	setEDNS(m)

	var last *dns.Msg
	var lastServer netip.Addr
	for _, svr := range shuffle(authServers) {
		resp, err := q.exchange(m, svr)
		if err != nil || resp == nil {
			continue
		}
		last = resp
		lastServer = svr

		switch resp.Rcode {
		case dns.RcodeSuccess:
			q.logf("final success partial qname=%s server=%s", qname, q.addrPort(svr))
			if hasRRType(resp.Answer, qtype) {
				q.logf("final returning answer qname=%s server=%s", qname, q.addrPort(svr))
				q.cacheStore(resp, q.cache)
				return resp, svr, nil
			}

			if tgt, ok := cnameTarget(resp, qname); ok {
				q.logf("final cname qname=%s target=%s", qname, tgt)
				msg, origin, err := q.resolve(tgt, qtype)
				if err != nil {
					return nil, netip.Addr{}, err
				}
				msg = cloneIfCached(msg)
				prependRecords(msg, resp, qname, cnameChainRecords)
				q.cacheStore(msg, q.cache)
				return msg, origin, nil
			}

			if tgt, ok := dnameSynthesize(resp, qname); ok {
				q.logf("final dname qname=%s target=%s", qname, tgt)
				msg, origin, err := q.resolve(tgt, qtype)
				if err != nil {
					return nil, netip.Addr{}, err
				}
				msg = cloneIfCached(msg)
				prependRecords(msg, resp, qname, dnameRecords)
				q.cacheStore(msg, q.cache)
				return msg, origin, nil
			}

			if q.cacheStore(resp, q.cache) {
				q.logf("final cached soa qname=%s", qname)
				return resp, svr, nil
			}

		case dns.RcodeNameError:
			q.cacheStore(resp, q.cache)
			q.logf("final NXDOMAIN qname=%s", qname)
			return resp, svr, nil
		}
	}

	if last == nil {
		if parentResp != nil && qtype == dns.TypeNS {
			if answers := delegationRecords(parentResp, qname); len(answers) > 0 {
				q.logf("final parent delegation qname=%s count=%d", qname, len(answers))
				parent := parentResp.Copy()
				parent.Answer = append([]dns.RR(nil), answers...)
				q.cacheStore(parent, q.cache)
				return parent, netip.Addr{}, nil
			}
		}
		q.logf("final no response qname=%s", qname)
		return nil, netip.Addr{}, errors.New("no response from authoritative servers")
	}
	q.logf("final completed qname=%s server=%s rcode=%s", qname, q.addrPort(lastServer), dns.RcodeToString[last.Rcode])
	q.cacheStore(last, q.cache)
	return last, lastServer, nil
}

func (q *query) handleTerminal(zone string, resp *dns.Msg) (*dns.Msg, netip.Addr, error) {
	if resp == nil {
		return nil, netip.Addr{}, errors.New("terminal with no response")
	}
	if q.cacheStore(resp, q.cache) {
		q.logf("terminal cached soa zone=%s", zone)
	}
	return resp, netip.Addr{}, nil
}

// resolveNSAddrs minimally resolves NS owner names to addresses by asking the roots → ...
func (q *query) resolveNSAddrs(nsOwners []string) []netip.Addr {
	var addrs []netip.Addr
	for _, host := range nsOwners {
		var resolved []netip.Addr
		haveIPv4 := false
		if msg, _, err := q.resolve(dns.Fqdn(strings.ToLower(host)), dns.TypeA); err == nil {
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
			if msg, _, err := q.resolve(dns.Fqdn(strings.ToLower(host)), dns.TypeAAAA); err == nil {
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
			q.logf("resolveNS resolved host=%s addrs=%d", host, len(resolved))
			addrs = append(addrs, resolved...)
		}
	}
	q.logf("resolveNS total addrs=%d", len(addrs))
	return dedupAddrs(addrs)
}

func (q *query) logf(format string, args ...any) {
	if q.writer != nil {
		_, _ = fmt.Fprintf(q.writer, "\n[%6dms]%*s", time.Since(q.start).Milliseconds(), 1+q.depth*2, "")
		_, _ = fmt.Fprintf(q.writer, format, args...)
	}
}

func (q *query) logQuerySend(network string, addr netip.Addr, question dns.Question) {
	q.logf("SENDING  %s: @%s %s %q", formatProto(network, addr), addr.String(), dns.Type(question.Qtype), question.Name)
}

func (q *query) logQueryReceive(network string, addr netip.Addr, question dns.Question, resp *dns.Msg, dur time.Duration) {
	if resp != nil {
		var flag string
		if resp.Authoritative {
			flag = " AUTH"
		}
		q.logf("RECEIVED %s: @%s %s %q => %s [%s] (%v, %d bytes%s)",
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
func (q *query) exchange(m *dns.Msg, server netip.Addr) (resp *dns.Msg, err error) {
	if err = q.dive(); err == nil {
		defer q.surface()
		q.queries++
		if q.queries > maxQueries {
			return nil, ErrTooManyQueries
		}
		if q.cache != nil {
			if resp = q.cache.DnsGet(m.Question[0].Name, m.Question[0].Qtype); resp != nil {
				return
			}
		}
		if resp, err = q.exchangeWithNetwork("udp", m, server); err != nil {
			err = q.maybeDisableUdp(err)
		}
		if err == nil && (resp == nil || resp.Truncated) {
			resp, err = q.exchangeWithNetwork("tcp", m, server)
		}
		if resp != nil && q.cache != nil {
			q.cache.DnsSet(resp)
		}
	}
	return
}

func (q *query) exchangeWithNetwork(network string, m *dns.Msg, server netip.Addr) (resp *dns.Msg, err error) {
	if q.usable(network, server) {
		var dnsConn *dns.Conn
		if dnsConn, err = q.dialDNSConn(network, server); err == nil {
			defer dnsConn.Close()
			deadline := q.deadline(q.ctx)
			if !deadline.IsZero() {
				_ = dnsConn.SetDeadline(deadline)
			}
			var question dns.Question
			if len(m.Question) > 0 {
				question = m.Question[0]
				q.logQuerySend(network, server, question)
			}
			start := time.Now()
			if err = dnsConn.WriteMsg(m); err == nil {
				resp, err = dnsConn.ReadMsg()
				if err == nil && len(m.Question) > 0 {
					q.logQueryReceive(network, server, question, resp, time.Since(start))
				}
			}
		}
	}
	return
}

func (q *query) dialDNSConn(network string, server netip.Addr) (dnsConn *dns.Conn, err error) {
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
		q.logf("DIAL FAIL %s: @%s err=%v", formatProto(network, server), server.String(), err)
	}
	return
}

func shuffle(in []netip.Addr) []netip.Addr {
	sort.Slice(in, func(i, j int) bool { return in[i].Compare(in[j]) < 0 })
	return in
}
