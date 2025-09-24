package resolver

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func Test_A_console_aws_amazon_com(t *testing.T) {
	/*
		This domain tests that CNAME chains are followed.
	*/
	r := New()
	qname := dns.Fqdn("console.aws.amazon.com")
	result, err := r.Resolve(t.Context(), qname, dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if x := result.RCODE; x != dns.RcodeSuccess {
		t.Error(dns.RcodeToString[x])
	}
	travelled := make(map[string]struct{})
	var chainLength int
	var haveA bool
	var searching bool
	searching = true
	for searching {
		var foundCNAME bool
		for _, rr := range result.Answers {
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
			if chainLength > len(result.Answers) {
				t.Fatalf("cname chain exceeded answers for %s", qname)
			}
		} else {
			for _, rr := range result.Answers {
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
	/*
		This domain tests that QNAME minimization works.
	*/
	r := New()
	qname := dns.Fqdn("qnamemintest.internet.nl")
	ctx, cancel := context.WithTimeout(t.Context(), time.Second*5)
	defer cancel()
	result, err := r.Resolve(ctx, qname, dns.TypeTXT)
	if err != nil {
		t.Fatal(err)
	}
	if x := result.RCODE; x != dns.RcodeSuccess {
		t.Error(dns.RcodeToString[x])
	}
	if x := len(result.Answers); x < 1 {
		t.Fatal(x)
	}
	found := false
	for _, rr := range result.Answers {
		if rr, ok := rr.(*dns.TXT); ok {
			for _, txt := range rr.Txt {
				found = found || strings.HasPrefix(txt, "HOORAY")
			}
		}
	}
	if !found {
		t.Error("expected a TXT record starting with HOORAY")
		t.Log(result.Answers)
	}
}

func Test_NS_bankgirot_nu(t *testing.T) {
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
	r.Timeout = time.Second
	qname := dns.Fqdn("bankgirot.nu")
	ctx, cancel := context.WithTimeout(t.Context(), time.Second*5)
	defer cancel()
	result, err := r.Resolve(ctx, qname, dns.TypeNS)
	if err != nil {
		t.Fatal(err)
	}
	if result.RCODE == dns.RcodeNameError {
		t.Skip(qname, "no longer exists")
	}
	if x := result.RCODE; x != dns.RcodeSuccess {
		t.Error(dns.RcodeToString[x])
	}
	if x := len(result.Answers); x < 1 {
		t.Fatal(x)
	}
	expect := map[string]struct{}{
		"sem1.eun.net.": {},
		"sem2.eun.net.": {},
		"sem3.eun.net.": {},
	}
	for _, rr := range result.Answers {
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
