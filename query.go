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
	ctx    context.Context
	cache  Cacher
	writer io.Writer
	start  time.Time
	depth  int
	steps  int
}

const maxDepth = 16   // max recursion depth
const maxSteps = 1024 // max steps to take for a query

var ErrDepthExceeded = errors.New("recursion depth limit exceeded")
var ErrTooManySteps = errors.New("to many steps, possible loop")

func (q *query) dive(format string, args ...any) (err error) {
	err = ErrDepthExceeded
	if q.steps < maxSteps {
		q.steps++
		err = ErrDepthExceeded
		if q.depth < maxDepth {
			err = nil
			if format != "" {
				q.logf(format, args...)
			}
			q.depth++
		}
	}
	return
}

func (q *query) surface() {
	q.depth--
}

func (q *query) resolve(qname string, qtype uint16) (resp *dns.Msg, srv netip.Addr, err error) {
	qname = dns.CanonicalName(qname)
	if err = q.dive("RESOLVE QUERY %s %q\n", dns.Type(qtype), qname); err == nil {
		defer func() {
			q.logf("RESOLVE ANSWER %s %q => ", dns.Type(qtype), qname)
			q.logResponse(time.Time{}, resp, err)
			q.surface()
		}()
		if resp = cacheGet(qname, qtype, q.cache); resp == nil {

			servers := append([]netip.Addr(nil), q.rootServers...)
			labels := dns.SplitDomainName(qname)

			// Walk down: "." -> "com." -> "example.com."
			for i := len(labels) - 1; i >= 0; i-- {
				zone := dns.Fqdn(strings.Join(labels[i:], "."))
				var nsSet []string
				var nextSrv []netip.Addr

				if nsSet, nextSrv, resp, err = q.queryForDelegation(zone, servers, qname); err != nil {
					q.logf("DELEGATION ERROR %q: %v\n", zone, err)
					return
				}
				rcode := dns.RcodeServerFailure
				if resp != nil {
					rcode = resp.Rcode
				}

				if zone == qname {
					if len(nextSrv) > 0 {
						servers = nextSrv
					}
					break
				}

				if len(nsSet) == 0 {
					if rcode == dns.RcodeNameError {
						if zone == qname {
							return q.handleTerminal(zone, resp)
						}
						return q.queryFinal(qname, qtype, servers, resp)
					}
					continue
				}

				servers = nextSrv
			}

			return q.queryFinal(qname, qtype, servers, resp)
		}
	}
	return
}

// -------- Core steps ---------

// queryForDelegation performs the QMIN step at `zone` against `parentServers`.
// If servers REFUSE/NOTIMP the minimized NS query, retry with non-QMIN (ask NS for the full qname).
// Returns: (nsOwnerNames, resolvedServerAddrs, lastResponse, error)
func (q *query) queryForDelegation(zone string, parentServers []netip.Addr, fullQname string) (nsOwners []string, resolvedServerAddrs []netip.Addr, last *dns.Msg, err error) {
	if err = q.dive("DELEGATION QUERY %q from %d servers\n", zone, len(parentServers)); err == nil {
		rcode := -1
		defer func() {
			q.logf("DELEGATION ANSWER %q: %s with %d records\n", zone, dns.RcodeToString[rcode], len(nsOwners))
			q.surface()
		}()

		m := new(dns.Msg)
		m.SetQuestion(zone, dns.TypeNS)
		m.RecursionDesired = false
		setEDNS(m)

		refusedSeen := false
		for _, svr := range shuffle(parentServers) {
			resp, err := q.exchange(m, svr)
			if err != nil {
				q.logf("DELEGATION ERROR @%s NS %q: %v\n", svr, zone, err)
				continue
			}
			if resp == nil {
				continue
			}
			rcode = resp.Rcode
			last = resp

			if rcode == dns.RcodeRefused || rcode == dns.RcodeNotImplemented {
				refusedSeen = true
				continue
			}
			if rcode == dns.RcodeNameError { // NXDOMAIN at parent ⇒ bubble up
				return nil, nil, resp, nil
			}

			nsOwners = extractDelegationNS(resp, zone)
			if len(nsOwners) == 0 {
				if resp.Rcode == dns.RcodeNameError {
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
			q.logf("DELEGATION non-QMIN %q\n", zone)
			m2 := new(dns.Msg)
			m2.SetQuestion(fullQname, dns.TypeNS) // ask NS for the full name (non-minimized)
			m2.RecursionDesired = false
			setEDNS(m2)
			for _, svr := range shuffle(parentServers) {
				q.logf("DELEGATION non-QMIN QUERY @%s NS %q", svr, fullQname)
				resp, err := q.exchange(m2, svr)
				if err != nil {
					q.logf("DELEGATION non-QMIN ERROR @%s NS %q: %v\n", svr, fullQname, err)
					continue
				}
				if resp == nil {
					continue
				}
				last = resp
				q.logf("DELEGATION non-QMIN ANSWER @%s NS %q: %s\n", svr, fullQname, dns.RcodeToString[resp.Rcode])
				if resp.Rcode == dns.RcodeNameError {
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
					q.logf("DELEGATION non-QMIN RESULT NS %q: %d addrs\n", fullQname, len(addrs))
					return nsOwners, addrs, resp, nil
				}
			}
		}

		if last == nil {
			err = errors.New("no response from parent servers")
		}
	}

	return
}

// queryFinal asks the authoritative (or closest) servers for the target qname/qtype.
// It also performs CNAME/DNAME chasing, with a loop bound controlled by depth.
func (q *query) queryFinal(qname string, qtype uint16, authServers []netip.Addr, parentResp *dns.Msg) (last *dns.Msg, lastServer netip.Addr, err error) {
	if err = q.dive("FINAL QUERY %s %q from %d servers\n", dns.Type(qtype), qname, len(authServers)); err == nil {
		defer func() {
			q.logf("FINAL ANSWER @%s %s %q with %d records\n", lastServer, dns.Type(qtype), qname, len(last.Answer))
			q.surface()
		}()
		m := new(dns.Msg)
		m.SetQuestion(qname, qtype)
		m.RecursionDesired = false
		setEDNS(m)

		for _, svr := range shuffle(authServers) {
			var resp *dns.Msg
			resp, err = q.exchange(m, svr)
			if err != nil || resp == nil {
				continue
			}
			last = resp
			lastServer = svr

			switch resp.Rcode {
			case dns.RcodeSuccess:
				if hasRRType(resp.Answer, qtype) {
					return
				}

				if tgt, ok := cnameTarget(resp, qname); ok {
					q.logf("FINAL CNAME @%s %s %q => %q\n", svr, dns.Type(qtype), qname, tgt)
					var msg *dns.Msg
					var origin netip.Addr
					msg, origin, err = q.resolve(tgt, qtype)
					if err == nil {
						msg = cloneIfCached(msg)
						prependRecords(msg, resp, qname, cnameChainRecords)
					}
					last = msg
					lastServer = origin
					return
				}

				if tgt, ok := dnameSynthesize(resp, qname); ok {
					q.logf("FINAL DNAME @%s %s %q => %q\n", svr, dns.Type(qtype), qname, tgt)
					msg, origin, err := q.resolve(tgt, qtype)
					if err != nil {
						return nil, netip.Addr{}, err
					}
					msg = cloneIfCached(msg)
					prependRecords(msg, resp, qname, dnameRecords)
					return msg, origin, nil
				}

				q.logf("FINAL soa qname=%s\n", qname)
				return resp, svr, nil

			case dns.RcodeNameError:
				q.logf("FINAL NXDOMAIN qname=%s\n", qname)
				return resp, svr, nil
			}
		}

		if last == nil {
			if parentResp != nil && qtype == dns.TypeNS {
				if answers := delegationRecords(parentResp, qname); len(answers) > 0 {
					q.logf("FINAL parent delegation qname=%s count=%d\n", qname, len(answers))
					parent := parentResp.Copy()
					parent.Answer = append([]dns.RR(nil), answers...)
					return parent, netip.Addr{}, nil
				}
			}
			q.logf("FINAL no response qname=%s\n", qname)
			return nil, netip.Addr{}, errors.New("no response from authoritative servers")
		}
		q.logf("FINAL result @%s %s %q: %s\n", lastServer, dns.Type(qtype), qname, dns.RcodeToString[last.Rcode])
		return last, lastServer, nil
	}
	return
}

func (q *query) handleTerminal(_ string, resp *dns.Msg) (*dns.Msg, netip.Addr, error) {
	if resp == nil {
		return nil, netip.Addr{}, errors.New("terminal with no response")
	}
	return resp, netip.Addr{}, nil
}

// resolveNSAddrs minimally resolves NS owner names to addresses by asking the roots
func (q *query) resolveNSAddrs(nsOwners []string) (addrs []netip.Addr) {
	resolved := map[netip.Addr]struct{}{}
	for _, host := range nsOwners {
		if msg, _, err := q.resolve(dns.CanonicalName(host), dns.TypeA); err == nil {
			for _, rr := range msg.Answer {
				if a, ok := rr.(*dns.A); ok {
					if addr := ipToAddr(a.A); addr.IsValid() {
						resolved[addr] = struct{}{}
					}
				}
			}
		}
		if len(resolved) == 0 && q.usingIPv6() {
			if msg, _, err := q.resolve(dns.CanonicalName(host), dns.TypeAAAA); err == nil {
				for _, rr := range msg.Answer {
					if a, ok := rr.(*dns.AAAA); ok {
						if addr := ipToAddr(a.AAAA); addr.IsValid() {
							resolved[addr] = struct{}{}
						}
					}
				}
			}
		}
	}
	for addr := range resolved {
		addrs = append(addrs, addr)
	}
	return
}

func (q *query) logf(format string, args ...any) {
	if q.writer != nil {
		_, _ = fmt.Fprintf(q.writer, "[%-5d %2d] %*s", time.Since(q.start).Milliseconds(), q.depth, q.depth, "")
		_, _ = fmt.Fprintf(q.writer, format, args...)
	}
}

func (q *query) exchange(m *dns.Msg, server netip.Addr) (resp *dns.Msg, err error) {
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
	return
}

func (q *query) logResponse(start time.Time, resp *dns.Msg, err error) {
	if q.writer != nil {
		if resp != nil {
			var flag string
			if resp.Authoritative {
				flag = " AUTH"
			}
			var elapsed string
			if !start.IsZero() {
				elapsed = fmt.Sprintf("%s, ", time.Since(start).Round(time.Millisecond))
			}
			fmt.Fprintf(q.writer, "%s [%s] (%s%d bytes%s)\n",
				dns.RcodeToString[resp.Rcode],
				formatCounts(resp),
				elapsed,
				resp.Len(),
				flag,
			)
		} else {
			fmt.Fprintf(q.writer, "%v\n", err)
		}
	}
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
			question := m.Question[0]
			var start time.Time
			if q.writer != nil {
				q.logf("SENDING %s: @%s %s %q => ", formatProto(network, server), server, dns.Type(question.Qtype), question.Name)
				start = time.Now()
			}
			if err = dnsConn.WriteMsg(m); err == nil {
				resp, err = dnsConn.ReadMsg()
			}
			q.logResponse(start, resp, err)
		}
	}
	return
}

func (q *query) dialDNSConn(network string, server netip.Addr) (dnsConn *dns.Conn, err error) {
	var rawConn net.Conn
	if rawConn, err = q.DialContext(q.ctx, network, netip.AddrPortFrom(server, q.DNSPort).String()); err == nil {
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
