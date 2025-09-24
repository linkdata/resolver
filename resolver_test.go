package resolver

import (
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
	if x := len(result.Answers); x < 1 {
		t.Error(x)
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
		t.Error(x)
	}
}
