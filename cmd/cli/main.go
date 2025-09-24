package main

import (
	"context"
	"fmt"

	"github.com/linkdata/resolver"
	"github.com/miekg/dns"
)

func Resolve(ctx context.Context, r *resolver.Resolver, name string, qtype uint16) error {
	msg, server, err := r.Resolve(ctx, name, qtype, nil)
	if err != nil {
		return err
	}
	fmt.Printf("RCODE=%s", dns.RcodeToString[msg.Rcode])
	if server.IsValid() {
		fmt.Printf(" from %s", server)
	}
	fmt.Println()
	for _, rr := range msg.Answer {
		fmt.Println(rr)
	}
	for _, rr := range msg.Ns {
		fmt.Println("AUTH:", rr)
	}
	for _, rr := range msg.Extra {
		fmt.Println("EXTRA:", rr)
	}
	return nil
}

func main() {
	r := resolver.New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fmt.Println(Resolve(ctx, r, "console.aws.amazon.com.", dns.TypeA))
	fmt.Println(Resolve(ctx, r, "qnamemintest.internet.nl.", dns.TypeTXT))
}
