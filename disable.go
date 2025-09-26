package resolver

import (
	"errors"
	"net"
	"strings"
	"syscall"
)

func (r *Service) usingUDP() (yes bool) {
	r.mu.RLock()
	yes = r.useUDP
	r.mu.RUnlock()
	return
}

func (r *Service) usingIPv6() (yes bool) {
	r.mu.RLock()
	yes = r.useIPv6
	r.mu.RUnlock()
	return
}

func (r *Service) maybeDisableIPv6(err error) {
	if err != nil {
		errstr := err.Error()
		if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) ||
			strings.Contains(errstr, "network is unreachable") || strings.Contains(errstr, "no route to host") {
			r.mu.Lock()
			defer r.mu.Unlock()
			if r.useIPv6 {
				r.useIPv6 = false
				var idx int
				for i := range r.rootServers {
					if r.rootServers[i].Is4() {
						r.rootServers[idx] = r.rootServers[i]
						idx++
					}
				}
				r.rootServers = r.rootServers[:idx]
			}
		}
	}
}

func (r *Service) maybeDisableUdp(err error) (newerr error) {
	newerr = err
	var ne net.Error
	if errors.As(err, &ne) && !ne.Timeout() {
		errstr := err.Error()
		if errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EPROTONOSUPPORT) || strings.Contains(errstr, "network not implemented") {
			r.mu.Lock()
			defer r.mu.Unlock()
			newerr = nil
			r.useUDP = false
		}
	}
	return
}
