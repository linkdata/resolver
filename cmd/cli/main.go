package main

import (
	"context"
	"fmt"
	"os"

	"github.com/linkdata/resolver"
	"github.com/miekg/dns"
)

func Resolve(ctx context.Context, r *resolver.Resolver, name string, qtype uint16) error {
	msg, server, err := r.Resolve(ctx, name, qtype, os.Stderr)
	if err == nil {
		fmt.Println(msg)
		fmt.Println(";; SERVER:", server.String())
	}
	return err
}

func main() {
	r := resolver.New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fmt.Println(Resolve(ctx, r, "console.aws.amazon.com.", dns.TypeA))
}
