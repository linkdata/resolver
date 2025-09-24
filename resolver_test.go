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
