package resolver

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func Test_A_console_aws_amazon_com(t *testing.T) {
	t.Parallel()
	/*
		This domain tests that CNAME chains are followed.
	*/
	r := New()
	r.OrderRoots(t.Context(), time.Millisecond*100)
	qname := dns.Fqdn("console.aws.amazon.com")
	qtype := dns.TypeA
	msg, _, err := r.Resolve(t.Context(), qname, qtype, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if x := msg.Rcode; x != dns.RcodeSuccess {
		t.Error(dns.RcodeToString[x])
	}
	if x := msg.Question[0].Name; x != qname {
		t.Error(x)
	}
	if x := msg.Question[0].Qtype; x != qtype {
		t.Error(x)
	}
	travelled := make(map[string]struct{})
	var chainLength int
	var haveA bool
	var searching bool
	searching = true
	for searching {
		var foundCNAME bool
		for _, rr := range msg.Answer {
			var cname *dns.CNAME
			var ok bool
			if cname, ok = rr.(*dns.CNAME); ok {
				if strings.EqualFold(cname.Hdr.Name, qname) {
					var ownerKey string
					var haveLoop bool
					ownerKey = strings.ToLower(qname)
					if _, haveLoop = travelled[ownerKey]; haveLoop {
						t.Fatalf("cname loop detected at %s", qname)
					}
					travelled[ownerKey] = struct{}{}
					qname = strings.ToLower(dns.Fqdn(cname.Target))
					foundCNAME = true
				}
			}
		}
		if foundCNAME {
			chainLength++
			if chainLength > len(msg.Answer) {
				t.Fatalf("cname chain exceeded answers for %s", qname)
			}
		} else {
			for _, rr := range msg.Answer {
				var arecord *dns.A
				var ok bool
				if arecord, ok = rr.(*dns.A); ok {
					if strings.EqualFold(arecord.Hdr.Name, qname) {
						haveA = true
					}
				}
			}
			searching = false
		}
	}
	if chainLength < 1 {
		t.Fatalf("expected cname chain for %s", qname)
	}
	if !haveA {
		t.Fatalf("missing A record terminating chain at %s", qname)
	}
}

func Test_TXT_qnamemintest_internet_nl(t *testing.T) {
	t.Parallel()
	/*
		This domain tests that QNAME minimization works.
	*/
	r := New()
	r.OrderRoots(t.Context(), time.Millisecond*100)
	qname := dns.Fqdn("qnamemintest.internet.nl")
	qtype := dns.TypeTXT
	ctx, cancel := context.WithTimeout(t.Context(), time.Second*5)
	defer cancel()
	msg, _, err := r.Resolve(ctx, qname, qtype, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if x := msg.Rcode; x != dns.RcodeSuccess {
		t.Error(dns.RcodeToString[x])
	}
	if x := msg.Question[0].Name; x != qname {
		t.Error(x)
	}
	if x := msg.Question[0].Qtype; x != qtype {
		t.Error(x)
	}
	if x := len(msg.Answer); x < 1 {
		t.Fatal(x)
	}
	found := false
	for _, rr := range msg.Answer {
		if rr, ok := rr.(*dns.TXT); ok {
			for _, txt := range rr.Txt {
				found = found || strings.HasPrefix(txt, "HOORAY")
			}
		}
	}
	if !found {
		t.Error("expected a TXT record starting with HOORAY")
		t.Log(msg.Answer)
	}
}

func Test_NS_bankgirot_nu(t *testing.T) {
	t.Parallel()
	/*
	   This domain has delegation servers that do not respond.
	   We expect the final queries to time out, but since we
	   have a NS answer (the delegation servers) for the query
	   we want a response with those:

	   bankgirot.nu.	86400	IN	NS	sem1.eun.net.
	   bankgirot.nu.	86400	IN	NS	sem2.eun.net.
	   bankgirot.nu.	86400	IN	NS	sem3.eun.net.
	*/

	r := New()
	r.OrderRoots(t.Context(), time.Millisecond*100)
	r.Timeout = time.Second
	qname := dns.Fqdn("bankgirot.nu")
	qtype := dns.TypeNS
	ctx, cancel := context.WithTimeout(t.Context(), time.Second*5)
	defer cancel()
	msg, _, err := r.Resolve(ctx, qname, qtype, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Rcode == dns.RcodeNameError {
		t.Skip(qname, "no longer exists")
	}
	if x := msg.Rcode; x != dns.RcodeSuccess {
		t.Error(dns.RcodeToString[x])
	}
	if x := msg.Question[0].Name; x != qname {
		t.Error(x)
	}
	if x := msg.Question[0].Qtype; x != qtype {
		t.Error(x)
	}
	if x := len(msg.Answer); x < 1 {
		t.Fatal(x)
	}
	expect := map[string]struct{}{
		"sem1.eun.net.": {},
		"sem2.eun.net.": {},
		"sem3.eun.net.": {},
	}
	for _, rr := range msg.Answer {
		ns, ok := rr.(*dns.NS)
		if !ok {
			t.Fatalf("unexpected rr type %T", rr)
		}
		if !strings.EqualFold(ns.Hdr.Name, qname) {
			t.Fatalf("unexpected owner %s", ns.Hdr.Name)
		}
		k := strings.ToLower(dns.Fqdn(ns.Ns))
		delete(expect, k)
	}
	if len(expect) > 0 {
		t.Fatalf("missing expected ns records: %v", expect)
	}
}

func TestResolverCacheStoreAndGet(t *testing.T) {
	t.Parallel()
	r := New()
	qname := dns.Fqdn("cache.example.com")
	qtype := dns.TypeA
	answer := &dns.A{
		Hdr: dns.RR_Header{
			Name:   qname,
			Rrtype: qtype,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.IPv4(192, 0, 2, 42),
	}
	msg := newResponseMsg(qname, qtype, dns.RcodeSuccess, []dns.RR{answer}, nil, nil)
	if !r.cacheStore(msg, nil) {
		t.Fatal("expected message to be cached")
	}
	cached := r.cacheGet(qname, qtype, nil)
	if cached == nil {
		t.Fatalf("expected cached response for %s %s", qname, typeName(qtype))
	}
	if !cached.Zero {
		t.Fatal("cached response must have Zero bit set")
	}
	originalQuestion := cached.Question[0].Name
	cached.Question[0].Name = "mutated.example.com."
	cachedAgain := r.cacheGet(qname, qtype, nil)
	if cachedAgain == nil {
		t.Fatal("expected cached response on second lookup")
	}
	if cachedAgain.Question[0].Name != originalQuestion {
		t.Fatalf("cache returned mutated question got=%s want=%s", cachedAgain.Question[0].Name, originalQuestion)
	}
}

func TestResolverCacheSkipsZeroResponses(t *testing.T) {
	t.Parallel()
	r := New()
	qname := dns.Fqdn("skip-cache.example.com")
	qtype := dns.TypeA
	msg := newResponseMsg(qname, qtype, dns.RcodeSuccess, nil, nil, nil)
	msg.Zero = true
	if r.cacheStore(msg, nil) {
		t.Fatal("unexpectedly cached zero response")
	}
	if cached := r.cacheGet(qname, qtype, nil); cached != nil {
		t.Fatalf("expected no cache entry, got %v", cached)
	}
}

func TestResolverResolveUsesProvidedCache(t *testing.T) {
	t.Parallel()
	r := New()
	r.SetCache(panicCacher{})
	qname := dns.Fqdn("cached.example.com")
	qtype := dns.TypeA
	answer := &dns.A{
		Hdr: dns.RR_Header{
			Name:   qname,
			Rrtype: qtype,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.IPv4(192, 0, 2, 25),
	}
	cachedMsg := newResponseMsg(qname, qtype, dns.RcodeSuccess, []dns.RR{answer}, nil, nil)
	cachedMsg.Zero = true
	override := &recordingCacher{msg: cachedMsg}
	originalQuestion := override.msg.Question[0].Name
	msg, _, err := r.Resolve(t.Context(), qname, qtype, nil, override)
	if err != nil {
		t.Fatal(err)
	}
	if msg == nil {
		t.Fatal("expected message from cache override")
	}
	if !msg.Zero {
		t.Fatal("expected cached result to keep zero bit set")
	}
	if x := override.getCount; x != 1 {
		t.Fatalf("override cache get count got=%d want=1", x)
	}
	if x := override.setCount; x != 0 {
		t.Fatalf("override cache set count got=%d want=0", x)
	}
	msg.Question[0].Name = "mutated.example.com."
	if override.msg.Question[0].Name != originalQuestion {
		t.Fatalf("override cache msg mutated got=%s want=%s", override.msg.Question[0].Name, originalQuestion)
	}
}

type panicCacher struct{}

func (panicCacher) DnsSet(*dns.Msg) {
	panic("unexpected default cache DnsSet")
}

func (panicCacher) DnsGet(string, uint16) *dns.Msg {
	panic("unexpected default cache DnsGet")
}

type recordingCacher struct {
	msg      *dns.Msg
	getCount int
	setCount int
}

func (c *recordingCacher) DnsSet(msg *dns.Msg) {
	c.setCount++
	c.msg = msg
}

func (c *recordingCacher) DnsGet(string, uint16) *dns.Msg {
	c.getCount++
	return c.msg
}
