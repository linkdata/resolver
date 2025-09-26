package main

import (
	"context"
	"fmt"
	"os"

	"github.com/linkdata/resolver"
	"github.com/linkdata/resolver/cache"
	"github.com/miekg/dns"
)

func Resolve(ctx context.Context, r *resolver.Service, name string, qtype uint16) error {
	cache := cache.New()
	msg, server, err := r.Resolve(ctx, name, qtype, os.Stderr, cache)
	if err == nil {
		fmt.Println(msg)
		fmt.Println(";; SERVER:", server.String())
		fmt.Println(";; CACHE:", cache.Entries(), "entries,", cache.HitRatio(), "hit ratio")
	}
	return err
}

func main() {
	r := resolver.New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fmt.Println(Resolve(ctx, r, "console.aws.amazon.com.", dns.TypeA))
}
