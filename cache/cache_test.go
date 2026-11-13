package cache

import (
	"net/netip"
	"testing"
	"time"

	"github.com/Other-Now/nano-dns/dnswire"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTest(n int) (*Cache, *clock) {
	ck := &clock{t: time.Unix(1_700_000_000, 0)}
	c := New(n)
	c.Now = ck.now
	return c, ck
}

func TestPositiveTTLAgesAndExpires(t *testing.T) {
	c, ck := newTest(1000)
	a := dnswire.NewA("www.example.com.", 300, netip.MustParseAddr("192.0.2.1"))
	b := dnswire.NewA("www.example.com.", 120, netip.MustParseAddr("192.0.2.2"))
	c.SetPositive("www.example.com.", dnswire.TypeA, []dnswire.RR{a, b}, nil)

	ck.t = ck.t.Add(100 * time.Second)
	r, ok := c.Get("www.example.com.", dnswire.TypeA)
	if !ok {
		t.Fatal("miss")
	}
	// the RRset lives for the minimum TTL (120); both records age together
	if r.Answer[0].TTL != 20 || r.Answer[1].TTL != 20 {
		t.Fatalf("ttls %d %d, want 20 20", r.Answer[0].TTL, r.Answer[1].TTL)
	}
	ck.t = ck.t.Add(21 * time.Second)
	if _, ok := c.Get("www.example.com.", dnswire.TypeA); ok {
		t.Fatal("expired entry served")
	}
}

func TestNegativeCachingRFC2308(t *testing.T) {
	c, ck := newTest(1000)
	soa := dnswire.NewSOA("example.com.", 3600, "ns.example.com.", "h.example.com.", 1, 60)
	if !c.SetNegative("nope.example.com.", dnswire.TypeA, dnswire.RcodeNXDomain, []dnswire.RR{soa}) {
		t.Fatal("not cached")
	}
	// NXDOMAIN applies to every type at the name
	r, ok := c.Get("nope.example.com.", dnswire.TypeAAAA)
	if !ok || r.Rcode != dnswire.RcodeNXDomain {
		t.Fatalf("NXDOMAIN not served for another type: %v %v", ok, r.Rcode)
	}
	// lifetime is min(SOA TTL 3600, MINIMUM 60) = 60
	ck.t = ck.t.Add(61 * time.Second)
	if _, ok := c.Get("nope.example.com.", dnswire.TypeA); ok {
		t.Fatal("negative entry outlived SOA minimum")
	}
	// NODATA is per type
	c.SetNegative("www.example.com.", dnswire.TypeAAAA, dnswire.RcodeSuccess, []dnswire.RR{soa})
	if _, ok := c.Get("www.example.com.", dnswire.TypeA); ok {
		t.Fatal("NODATA for AAAA leaked to A")
	}
	// no SOA, no caching
	if c.SetNegative("x.example.com.", dnswire.TypeA, dnswire.RcodeNXDomain, nil) {
		t.Fatal("cached a negative answer without SOA")
	}
}

func TestBoundedSize(t *testing.T) {
	c, _ := newTest(shards * 4)
	for i := 0; i < 10_000; i++ {
		name := "h" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)) + string(rune('a'+(i/676)%26)) + ".example."
		c.SetPositive(name, dnswire.TypeA, []dnswire.RR{dnswire.NewA(name, 300, netip.MustParseAddr("192.0.2.1"))}, nil)
	}
	if n := c.Len(); n > shards*4 {
		t.Fatalf("cache grew to %d entries, bound %d", n, shards*4)
	}
}
