package resolver

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func Test_A_console_aws_amazon_com(t *testing.T) {
	r := New()
	result, err := r.Resolve(t.Context(), "console.aws.amazon.com.", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if x := result.RCODE; x != dns.RcodeSuccess {
		t.Error(dns.RcodeToString[x])
	}
	var chainOwner string
	chainOwner = dns.Fqdn("console.aws.amazon.com")
	var travelled map[string]struct{}
	travelled = make(map[string]struct{})
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
				if strings.EqualFold(cname.Hdr.Name, chainOwner) {
					var ownerKey string
					var haveLoop bool
					ownerKey = strings.ToLower(chainOwner)
					if _, haveLoop = travelled[ownerKey]; haveLoop {
						t.Fatalf("cname loop detected at %s", chainOwner)
					}
					travelled[ownerKey] = struct{}{}
					chainOwner = strings.ToLower(dns.Fqdn(cname.Target))
					foundCNAME = true
				}
			}
		}
		if foundCNAME {
			chainLength++
			if chainLength > len(result.Answers) {
				t.Fatalf("cname chain exceeded answers for %s", chainOwner)
			}
		} else {
			for _, rr := range result.Answers {
				var arecord *dns.A
				var ok bool
				if arecord, ok = rr.(*dns.A); ok {
					if strings.EqualFold(arecord.Hdr.Name, chainOwner) {
						haveA = true
					}
				}
			}
			searching = false
		}
	}
	if chainLength < 1 {
		t.Fatalf("expected cname chain for %s", chainOwner)
	}
	if !haveA {
		t.Fatalf("missing A record terminating chain at %s", chainOwner)
	}
	/*
		Expect the ANSWER section of the result to be like this. Actual names and IP's may differ,
		but the chain of CNAMEs must be intact and it must contain at least one A record.

		console.aws.amazon.com.	7191	IN	CNAME	console.cname-proxy.amazon.com.
		console.cname-proxy.amazon.com.	51 IN	CNAME	lbr.us.console.amazonaws.com.
		lbr.us.console.amazonaws.com. 51 IN	CNAME	eu-north-1.console.aws.amazon.com.
		eu-north-1.console.aws.amazon.com. 7191	IN CNAME eu-north-1.console.cname-proxy.amazon.com.
		eu-north-1.console.cname-proxy.amazon.com. 51 IN CNAME gr.aga.console-geo.eu-north-1.amazonaws.com.
		gr.aga.console-geo.eu-north-1.amazonaws.com. 51	IN CNAME aba8735d2c3d241de.awsglobalaccelerator.com.
		aba8735d2c3d241de.awsglobalaccelerator.com. 291	IN A 166.117.166.206
		aba8735d2c3d241de.awsglobalaccelerator.com. 291	IN A 166.117.98.246
	*/
}

func Test_TXT_qnamemintest_internet_nl(t *testing.T) {
	r := New()
	result, err := r.Resolve(t.Context(), "qnamemintest.internet.nl.", dns.TypeTXT)
	if err != nil {
		t.Fatal(err)
	}
	if x := result.RCODE; x != dns.RcodeSuccess {
		t.Error(dns.RcodeToString[x])
	}
	if x := len(result.Answers); x < 1 {
		t.Error(x)
	}

	/*
		The result must have a TXT record that starts with "HOORAY".
	*/
}
