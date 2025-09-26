package cache

import (
	"context"
	"math"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const DefaultMinTTL = 10 * time.Second // ten seconds
const DefaultMaxTTL = 6 * time.Hour    // six hours
const DefaultNXTTL = time.Hour         // one hour
const MaxQtype = 260

type Cache struct {
	MinTTL time.Duration // always cache responses for at least this long
	MaxTTL time.Duration // never cache responses for longer than this (excepting successful NS responses)
	NXTTL  time.Duration // cache NXDOMAIN responses for this long
	count  atomic.Uint64
	hits   atomic.Uint64
	cq     []*cacheQtype
}

func NewCache() *Cache {
	cq := make([]*cacheQtype, MaxQtype+1)
	for i := range cq {
		cq[i] = newCacheQtype()
	}
	return &Cache{
		MinTTL: DefaultMinTTL,
		MaxTTL: DefaultMaxTTL,
		NXTTL:  DefaultNXTTL,
		cq:     cq,
	}
}

// HitRatio returns the hit ratio as a percentage.
func (cache *Cache) HitRatio() (n float64) {
	if cache != nil {
		if count := cache.count.Load(); count > 0 {
			n = float64(cache.hits.Load()*100) / float64(count)
		}
	}
	return
}

// Entries returns the number of entries in the cache.
func (cache *Cache) Entries() (n int) {
	if cache != nil {
		for _, cq := range cache.cq {
			n += cq.entries()
		}
	}
	return
}

func (cache *Cache) DnsSet(msg *dns.Msg) {
	if cache != nil && msg != nil && !msg.Zero && len(msg.Question) == 1 {
		if qtype := msg.Question[0].Qtype; qtype <= MaxQtype {
			msg = msg.Copy()
			msg.Zero = true
			ttl := cache.NXTTL
			if msg.Rcode != dns.RcodeNameError {
				ttl = max(cache.MinTTL, time.Duration(minDNSMsgTTL(msg))*time.Second)
				if qtype != dns.TypeNS || msg.Rcode != dns.RcodeSuccess {
					ttl = min(cache.MaxTTL, ttl)
				}
			}
			cache.cq[qtype].set(msg, ttl)
		}
	}
}

func (cache *Cache) DnsGet(qname string, qtype uint16) (msg *dns.Msg) {
	if cache != nil {
		cache.count.Add(1)
		if qtype <= MaxQtype {
			if msg = cache.cq[qtype].get(qname); msg != nil {
				cache.hits.Add(1)
			}
		}
	}
	return
}

func (cache *Cache) DnsResolve(ctx context.Context, qname string, qtype uint16) (msg *dns.Msg, srv netip.Addr, err error) {
	msg = cache.DnsGet(qname, qtype)
	return
}

func (cache *Cache) Clear() {
	if cache != nil {
		for _, cq := range cache.cq {
			cq.clear()
		}
	}
}

func (cache *Cache) Clean() {
	if cache != nil {
		now := time.Now()
		for _, cq := range cache.cq {
			cq.clean(now)
		}
	}
}

func minDNSMsgTTL(msg *dns.Msg) (minTTL int) {
	minTTL = math.MaxInt
	if msg != nil {
		for _, rr := range msg.Answer {
			if rr != nil {
				minTTL = min(minTTL, int(rr.Header().Ttl))
			}
		}
		for _, rr := range msg.Ns {
			if rr != nil {
				minTTL = min(minTTL, int(rr.Header().Ttl))
			}
		}
		for _, rr := range msg.Extra {
			if rr != nil {
				if rr.Header().Rrtype != dns.TypeOPT {
					minTTL = min(minTTL, int(rr.Header().Ttl))
				}
			}
		}
	}
	if minTTL == math.MaxInt {
		minTTL = -1
	}
	return
}
