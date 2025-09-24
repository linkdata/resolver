package resolver

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

type rootRtt struct {
	addr netip.Addr
	rtt  time.Duration
}

func timeRoot(ctx context.Context, r *Resolver, wg *sync.WaitGroup, rt *rootRtt) {
	defer wg.Done()
	const numProbes = 3
	network := "tcp4"
	if rt.addr.Is6() {
		network = "tcp6"
	}
	rt.rtt = time.Hour
	var rtt time.Duration
	for i := 0; i < numProbes; i++ {
		now := time.Now()
		conn, err := r.DialContext(ctx, network, netip.AddrPortFrom(rt.addr, r.DNSPort).String())
		if err != nil {
			return
		}
		rtt += time.Since(now)
		_ = conn.Close()
	}
	rt.rtt = rtt / numProbes
}
