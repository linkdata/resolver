package main

import (
	"context"
	"fmt"

	"github.com/linkdata/resolver"
	"github.com/miekg/dns"
)

func Resolve(ctx context.Context, r *resolver.Resolver, name string, qtype uint16) error {
	res, err := r.Resolve(ctx, name, qtype)
	if err != nil {
		return err
	}
	fmt.Printf("RCODE=%s from %s", dns.RcodeToString[res.RCODE], res.Server)
	for _, rr := range res.Answers {
		fmt.Println(rr)
	}
	for _, rr := range res.Authority {
		fmt.Println("AUTH:", rr)
	}
	for _, rr := range res.Additional {
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
