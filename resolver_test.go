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
	msg, _, err := r.Resolve(t.Context(), qname, qtype, nil)
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
	msg, _, err := r.Resolve(ctx, qname, qtype, nil)
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
	msg, _, err := r.Resolve(ctx, qname, qtype, nil)
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

func TestNegPutUsesMessageMinTTL(t *testing.T) {
	t.Parallel()
	const (
		expectedTTLSeconds = 2
		tolerance          = 50 * time.Millisecond
	)
	r := New()
	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    600,
		},
		Ns:     "ns1.example.com.",
		Mbox:   "hostmaster.example.com.",
		Serial: 1,
		Minttl: 400,
	}
	msg := new(dns.Msg)
	msg.Ns = append(msg.Ns, soa)
	msg.Extra = append(msg.Extra, &dns.A{
		Hdr: dns.RR_Header{
			Name:   "ns1.example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    expectedTTLSeconds,
		},
		A: net.IPv4(192, 0, 2, 1),
	})
	r.negPut("example.com.", dns.TypeA, msg)
	entry := r.negGet("example.com.", dns.TypeA)
	if entry == nil {
		t.Fatal("expected negative cache entry")
	}
	ttl := time.Until(entry.expiry)
	expected := time.Duration(expectedTTLSeconds) * time.Second
	if ttl > expected || ttl < expected-tolerance {
		t.Fatalf("unexpected ttl got=%s want=%s±%s", ttl, expected, tolerance)
	}
}

func TestNegPutUsesSoaMinimumTTL(t *testing.T) {
	t.Parallel()
	const (
		expectedTTLSeconds = 12
		tolerance          = 50 * time.Millisecond
	)
	r := New()
	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   "example.org.",
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    expectedTTLSeconds,
		},
		Ns:     "ns1.example.org.",
		Mbox:   "hostmaster.example.org.",
		Serial: 1,
		Minttl: 40,
	}
	msg := new(dns.Msg)
	msg.Ns = append(msg.Ns, soa)
	r.negPut("example.org.", dns.TypeAAAA, msg)
	entry := r.negGet("example.org.", dns.TypeAAAA)
	if entry == nil {
		t.Fatal("expected negative cache entry")
	}
	ttl := time.Until(entry.expiry)
	expected := time.Duration(expectedTTLSeconds) * time.Second
	if ttl > expected || ttl < expected-tolerance {
		t.Fatalf("unexpected ttl got=%s want=%s±%s", ttl, expected, tolerance)
	}
}
