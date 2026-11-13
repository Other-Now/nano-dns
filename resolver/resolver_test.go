package resolver

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/Other-Now/nano-dns/authsim"
	"github.com/Other-Now/nano-dns/cache"
	"github.com/Other-Now/nano-dns/dnswire"
)

// FreePort finds a UDP+TCP port free on 127.0.1.1.
func freePort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 1, 1)})
	if err != nil {
		t.Skipf("cannot bind 127.0.1.1 (needs a 127/8 loopback): %v", err)
	}
	p := c.LocalAddr().(*net.UDPAddr).Port
	c.Close()
	return p
}

func newSim(t *testing.T, qmin bool) (*authsim.Sim, *Resolver) {
	t.Helper()
	port := freePort(t)
	sim, err := authsim.Start(authsim.Config{Port: port, PopularHosts: 10, VictimHosts: 10})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sim.Close)
	r := New(Config{Roots: sim.RootHints, UpstreamPort: uint16(port), QMin: qmin, Cache: cache.New(10000), Timeout: 500 * time.Millisecond})
	return sim, r
}

func resolve(t *testing.T, r *Resolver, name string, qt uint16) Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := r.Resolve(ctx, name, qt)
	if err != nil {
		t.Fatalf("resolve %s: %v", name, err)
	}
	return res
}

func addrs(res Result) []string {
	var out []string
	for _, rr := range res.Answer {
		if a, ok := rr.Addr(); ok {
			out = append(out, a.String())
		}
	}
	return out
}

func TestReferralsAndCache(t *testing.T) {
	sim, r := newSim(t, false)
	res := resolve(t, r, "www.victim.com", dnswire.TypeA)
	if got := addrs(res); len(got) != 1 || got[0] != "198.51.100.10" {
		t.Fatalf("got %v", got)
	}
	// root -> com -> victim = 3 upstream queries
	if n := r.Stats().Upstream.Load(); n != 3 {
		t.Fatalf("upstream %d, want 3", n)
	}
	// second name in the same zone starts at the cached victim.com cut
	resolve(t, r, "api.victim.com", dnswire.TypeA)
	if n := r.Stats().Upstream.Load(); n != 4 {
		t.Fatalf("upstream %d, want 4 (delegation not reused)", n)
	}
	// and an exact repeat is a pure cache hit
	before := sim.TotalQueries()
	resolve(t, r, "www.victim.com", dnswire.TypeA)
	if sim.TotalQueries() != before {
		t.Fatal("repeat query went upstream")
	}
}

func TestNoGlueAndCrossZoneCNAME(t *testing.T) {
	_, r := newSim(t, false)
	// www.shop.com: NS ns.hosting.net has no glue in com., and the answer is a
	// CNAME into cdn.net.
	res := resolve(t, r, "www.shop.com", dnswire.TypeA)
	if len(res.Answer) != 2 || res.Answer[0].Type != dnswire.TypeCNAME {
		t.Fatalf("answer %v", res.Answer)
	}
	if got := addrs(res); len(got) != 1 || got[0] != "203.0.113.80" {
		t.Fatalf("got %v", got)
	}
}

func TestNegativeAnswers(t *testing.T) {
	sim, r := newSim(t, false)
	res := resolve(t, r, "nope.victim.com", dnswire.TypeA)
	if res.Rcode != dnswire.RcodeNXDomain {
		t.Fatalf("rcode %s", dnswire.RcodeString(res.Rcode))
	}
	before := sim.TotalQueries()
	// NXDOMAIN is cached for every type (RFC 2308)
	if res := resolve(t, r, "nope.victim.com", dnswire.TypeAAAA); res.Rcode != dnswire.RcodeNXDomain {
		t.Fatal("cached NXDOMAIN not applied to AAAA")
	}
	if sim.TotalQueries() != before {
		t.Fatal("negative answer not cached")
	}
	// NODATA: name exists, type does not
	res = resolve(t, r, "www.victim.com", dnswire.TypeAAAA)
	if res.Rcode != dnswire.RcodeSuccess || len(res.Answer) != 0 || len(res.Authority) != 1 {
		t.Fatalf("NODATA wrong: %+v", res)
	}
}

func TestTruncationFallsBackToTCP(t *testing.T) {
	_, r := newSim(t, false)
	res := resolve(t, r, "bigtxt.victim.com", dnswire.TypeTXT)
	if len(res.Answer) != 1 || len(res.Answer[0].Data) < 3000 {
		t.Fatalf("big TXT not received: %v", res.Answer)
	}
	if r.Stats().UpstreamTCP.Load() != 1 {
		t.Fatalf("tcp retries %d", r.Stats().UpstreamTCP.Load())
	}
}

func TestQNameMinimisation(t *testing.T) {
	sim, r := newSim(t, true)
	var mu sync.Mutex
	seen := map[netip.AddrPort][]string{}
	r.cfg.OnUpstream = func(s netip.AddrPort, name string, _ uint16) {
		mu.Lock()
		seen[s] = append(seen[s], name)
		mu.Unlock()
	}
	res := resolve(t, r, "a.b.c.deep.victim.com", dnswire.TypeA)
	if got := addrs(res); len(got) != 1 {
		t.Fatalf("got %v", got)
	}
	if q := seen[sim.Root.Addr]; len(q) != 1 || q[0] != "com." {
		t.Fatalf("root saw %v, want only com.", q)
	}
	if q := seen[sim.TLD.Addr]; len(q) != 1 || q[0] != "victim.com." {
		t.Fatalf("TLD saw %v, want only victim.com.", q)
	}
	// the victim server is walked label by label down to the full name
	if q := seen[sim.Victim.Addr]; len(q) != 4 {
		t.Fatalf("victim saw %v", q)
	}
}

func TestSpoofedReplyIgnored(t *testing.T) {
	// A server that first sends a reply with the wrong ID, then the right one.
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 1500)
		n, from, err := pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		var q dnswire.Msg
		q.Unpack(buf[:n])
		forged := dnswire.Msg{ID: q.ID + 1, Response: true, Question: q.Question,
			Answer: []dnswire.RR{dnswire.NewA(q.Question[0].Name, 300, netip.MustParseAddr("6.6.6.6"))}}
		b, _ := forged.Pack()
		pc.WriteToUDPAddrPort(b, from)
		real := dnswire.Msg{ID: q.ID, Response: true, Authoritative: true, Question: q.Question,
			Answer: []dnswire.RR{dnswire.NewA(q.Question[0].Name, 300, netip.MustParseAddr("192.0.2.1"))}}
		b, _ = real.Pack()
		pc.WriteToUDPAddrPort(b, from)
	}()
	server := pc.LocalAddr().(*net.UDPAddr).AddrPort()
	r := New(Config{Roots: []netip.AddrPort{server}, Cache: cache.New(100)})
	res, err := r.Resolve(context.Background(), "example.", dnswire.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if got := addrs(res); len(got) != 1 || got[0] != "192.0.2.1" {
		t.Fatalf("accepted forged answer: %v", got)
	}
	if r.Stats().Mismatched.Load() != 1 {
		t.Fatalf("mismatched %d", r.Stats().Mismatched.Load())
	}
}

func TestOutOfBailiwickAnswerDropped(t *testing.T) {
	// A server for "example." that also "answers" for bank.com: the extra
	// record must not reach the cache.
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			var q dnswire.Msg
			q.Unpack(buf[:n])
			resp := dnswire.Msg{ID: q.ID, Response: true, Authoritative: true, Question: q.Question, Answer: []dnswire.RR{
				dnswire.NewName("www.example.", dnswire.TypeCNAME, 300, "www.bank.com."),
				dnswire.NewA("www.bank.com.", 300, netip.MustParseAddr("6.6.6.6")),
			}}
			b, _ := resp.Pack()
			pc.WriteToUDPAddrPort(b, from)
		}
	}()
	server := pc.LocalAddr().(*net.UDPAddr).AddrPort()
	c := cache.New(100)
	// Make this server the delegated server for "example." (the root is in
	// bailiwick for everything, so it must not be the root).
	c.SetPositive("example.", dnswire.TypeNS, []dnswire.RR{dnswire.NewName("example.", dnswire.TypeNS, 300, "ns.example.")}, nil)
	c.SetPositive("ns.example.", dnswire.TypeA, []dnswire.RR{dnswire.NewA("ns.example.", 300, server.Addr())}, nil)
	unreachable := netip.MustParseAddrPort("127.0.0.1:9")
	r := New(Config{Roots: []netip.AddrPort{unreachable}, UpstreamPort: server.Port(), Cache: c, Timeout: 200 * time.Millisecond, Tries: 1})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	r.Resolve(ctx, "www.example.", dnswire.TypeA) // the chase of www.bank.com fails; that's fine
	if _, ok := c.Get("www.bank.com.", dnswire.TypeA); ok {
		t.Fatal("out-of-bailiwick record was cached (cache poisoning)")
	}
	if r.Stats().BailiwickDropped.Load() == 0 {
		t.Fatal("drop not counted")
	}
}
