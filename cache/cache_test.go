package cache

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestCachePositiveUsesMessageMinTTL(t *testing.T) {
	t.Parallel()
	const (
		expectedTTLSeconds = 2
		tolerance          = 75 * time.Millisecond
	)
	cache := New()
	cache.MinTTL = 0
	cache.MaxTTL = time.Hour
	qname := dns.Fqdn("example-positive-ttl.com")
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeA)
	msg.Rcode = dns.RcodeSuccess
	msg.Extra = append(msg.Extra, &dns.A{
		Hdr: dns.RR_Header{
			Name:   qname,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    expectedTTLSeconds,
		},
		A: net.IPv4(192, 0, 2, 5),
	})
	cache.DnsSet(msg)
	cq := cache.cq[dns.TypeA]
	cq.mu.RLock()
	entry, ok := cq.cache[qname]
	cq.mu.RUnlock()
	if !ok {
		t.Fatalf("expected cache entry for %s", qname)
	}
	ttl := time.Until(entry.expires)
	expected := time.Duration(expectedTTLSeconds) * time.Second
	if ttl > expected+tolerance || ttl < expected-tolerance {
		t.Fatalf("unexpected ttl got=%s want=%s±%s", ttl, expected, tolerance)
	}
}

func TestCacheNegativeUsesNXTTL(t *testing.T) {
	t.Parallel()
	const (
		expectedTTLSeconds = 12
		tolerance          = 75 * time.Millisecond
	)
	cache := New()
	cache.MinTTL = 0
	cache.NXTTL = time.Duration(expectedTTLSeconds) * time.Second
	qname := dns.Fqdn("example-negative-ttl.org")
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeAAAA)
	msg.Rcode = dns.RcodeNameError
	msg.Ns = append(msg.Ns, &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   qname,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Ns:     "ns1.example-negative-ttl.org.",
		Mbox:   "hostmaster.example-negative-ttl.org.",
		Serial: 1,
		Minttl: 900,
	})
	cache.DnsSet(msg)
	cq := cache.cq[dns.TypeAAAA]
	cq.mu.RLock()
	entry, ok := cq.cache[qname]
	cq.mu.RUnlock()
	if !ok {
		t.Fatalf("expected cache entry for %s", qname)
	}
	ttl := time.Until(entry.expires)
	expected := cache.NXTTL
	if ttl > expected+tolerance || ttl < expected-tolerance {
		t.Fatalf("unexpected ttl got=%s want=%s±%s", ttl, expected, tolerance)
	}
}
