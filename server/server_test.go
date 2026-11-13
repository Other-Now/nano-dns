package server

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/Other-Now/nano-dns/authsim"
	"github.com/Other-Now/nano-dns/cache"
	"github.com/Other-Now/nano-dns/dnswire"
	"github.com/Other-Now/nano-dns/guard"
	"github.com/Other-Now/nano-dns/policy"
	"github.com/Other-Now/nano-dns/resolver"
)

func freePort(t *testing.T, ip net.IP) int {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip})
	if err != nil {
		t.Skipf("cannot bind %v: %v", ip, err)
	}
	p := c.LocalAddr().(*net.UDPAddr).Port
	c.Close()
	return p
}

type env struct {
	sim  *authsim.Sim
	res  *resolver.Resolver
	srv  *Server
	addr string
}

func setup(t *testing.T, mod func(*Config), simCfg authsim.Config) *env {
	t.Helper()
	simCfg.Port = freePort(t, net.IPv4(127, 0, 1, 1))
	sim, err := authsim.Start(simCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sim.Close)
	res := resolver.New(resolver.Config{Roots: sim.RootHints, UpstreamPort: uint16(simCfg.Port), Cache: cache.New(10000), Timeout: 300 * time.Millisecond})
	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t, net.IPv4(127, 0, 0, 1)))
	cfg := Config{Listen: addr, Resolver: res, QueryTimeout: 2 * time.Second}
	if mod != nil {
		mod(&cfg)
	}
	srv := New(cfg)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	return &env{sim, res, srv, addr}
}

// query sends from a chosen local address (to act as different subscribers).
func query(t *testing.T, from, server, name string, qt uint16) *dnswire.Msg {
	t.Helper()
	m, err := queryErr(from, server, name, qt, 2*time.Second)
	if err != nil {
		t.Fatalf("query %s: %v", name, err)
	}
	return m
}

func queryErr(from, server, name string, qt uint16, timeout time.Duration) (*dnswire.Msg, error) {
	la := &net.UDPAddr{IP: net.ParseIP(from)}
	ra, _ := net.ResolveUDPAddr("udp", server)
	c, err := net.DialUDP("udp", la, ra)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	q := dnswire.Msg{ID: 4242, RecursionDesired: true, Question: []dnswire.Question{{Name: name, Type: qt, Class: dnswire.ClassINET}}}
	b, _ := q.Pack()
	c.SetDeadline(time.Now().Add(timeout))
	c.Write(b)
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	var m dnswire.Msg
	return &m, m.Unpack(buf[:n])
}

func TestResolveThroughServer(t *testing.T) {
	e := setup(t, nil, authsim.Config{})
	m := query(t, "127.0.0.1", e.addr, "www.shop.com.", dnswire.TypeA)
	if m.Rcode != dnswire.RcodeSuccess || len(m.Answer) != 2 || !m.RecursionAvailable {
		t.Fatalf("bad response %+v", m)
	}
	if m := query(t, "127.0.0.1", e.addr, "nope.victim.com.", dnswire.TypeA); m.Rcode != dnswire.RcodeNXDomain {
		t.Fatalf("rcode %v", m.Rcode)
	}
	if m := query(t, "127.0.0.1", e.addr, "victim.com.", dnswire.TypeANY); m.Rcode != dnswire.RcodeRefused {
		t.Fatal("ANY not refused")
	}
}

func TestPolicyPerSubscriberAndCNAMETarget(t *testing.T) {
	threats := policy.NewList("threats")
	threats.Add("shop.cdn.net", policy.Rule{Action: policy.NXDomain}) // the CNAME target, not the query name
	threats.Add("*.evil.com", policy.Rule{Action: policy.NXDomain})
	adult := policy.NewList("adult")
	adult.Add("www.victim.com", policy.Rule{Action: policy.Redirect, Addr: netip.MustParseAddr("10.0.0.53")})
	def := &policy.Profile{Name: "default", Lists: []*policy.List{threats}}
	fam := &policy.Profile{Name: "family", Lists: []*policy.List{threats, adult}}
	eng := policy.NewEngine(def)
	eng.AddSubscriber(netip.MustParsePrefix("127.0.0.7/32"), fam)
	e := setup(t, func(c *Config) { c.Policy = eng }, authsim.Config{})

	if m := query(t, "127.0.0.1", e.addr, "x.evil.com.", dnswire.TypeA); m.Rcode != dnswire.RcodeNXDomain {
		t.Fatal("listed name not blocked")
	}
	if e.sim.TotalQueries() != 0 {
		t.Fatal("a blocked query went upstream")
	}
	// www.shop.com is clean but aliases to a listed name
	if m := query(t, "127.0.0.1", e.addr, "www.shop.com.", dnswire.TypeA); m.Rcode != dnswire.RcodeNXDomain {
		t.Fatal("CNAME target not checked")
	}
	// default subscriber resolves www.victim.com; family gets the walled garden
	m := query(t, "127.0.0.1", e.addr, "www.victim.com.", dnswire.TypeA)
	if a, _ := m.Answer[0].Addr(); a.String() != "198.51.100.10" {
		t.Fatalf("default got %v", a)
	}
	m = query(t, "127.0.0.7", e.addr, "www.victim.com.", dnswire.TypeA)
	if a, _ := m.Answer[0].Addr(); a.String() != "10.0.0.53" {
		t.Fatalf("family got %v", a)
	}
}

func TestWaterTortureMitigation(t *testing.T) {
	tt := guard.NewTorture(5*time.Second, 20, time.Minute)
	e := setup(t, func(c *Config) { c.Torture = tt }, authsim.Config{VictimHosts: 5, VictimTTL: 1})
	// a legitimate name resolves before the attack
	query(t, "127.0.0.1", e.addr, "host1.victim.com.", dnswire.TypeA)
	for i := 0; i < 40; i++ {
		query(t, "127.0.0.1", e.addr, fmt.Sprintf("rnd%d-x.victim.com.", i), dnswire.TypeA)
	}
	before := e.sim.Victim.Queries.Load()
	for i := 0; i < 50; i++ {
		if m := query(t, "127.0.0.1", e.addr, fmt.Sprintf("late%d-y.victim.com.", i), dnswire.TypeA); m.Rcode != dnswire.RcodeServFail {
			t.Fatalf("random name not mitigated: %s", dnswire.RcodeString(m.Rcode))
		}
	}
	if d := e.sim.Victim.Queries.Load() - before; d != 0 {
		t.Fatalf("%d attack queries reached the victim during mitigation", d)
	}
	// a known-good name still resolves once its cache entry (TTL 1 s) is gone:
	// it is allowed upstream during mitigation
	time.Sleep(1100 * time.Millisecond)
	before = e.sim.Victim.Queries.Load()
	if m := query(t, "127.0.0.1", e.addr, "host1.victim.com.", dnswire.TypeA); m.Rcode != dnswire.RcodeSuccess {
		t.Fatal("known-good name blocked")
	}
	if e.sim.Victim.Queries.Load() == before {
		t.Fatal("known-good name was not re-resolved upstream (test proves nothing)")
	}
	if m := query(t, "127.0.0.1", e.addr, "www.shop.com.", dnswire.TypeA); m.Rcode != dnswire.RcodeSuccess {
		t.Fatal("unrelated domain affected")
	}
}

func TestRRL(t *testing.T) {
	e := setup(t, func(c *Config) { c.RRL = guard.NewRRL(5, 5, 2) }, authsim.Config{})
	got, tc := 0, 0
	for i := 0; i < 25; i++ {
		m, err := queryErr("127.0.0.1", e.addr, "www.victim.com.", dnswire.TypeA, 200*time.Millisecond)
		if err != nil {
			continue // dropped
		}
		got++
		if m.Truncated {
			tc++
		}
	}
	// ~5 burst (+ a few refilled), then half the limited ones slip as TC=1
	if got >= 25 || tc == 0 {
		t.Fatalf("answered %d (tc %d) of 25: RRL not limiting", got, tc)
	}
}

func TestCoalescing(t *testing.T) {
	e := setup(t, nil, authsim.Config{Delay: 20 * time.Millisecond})
	query(t, "127.0.0.1", e.addr, "www.victim.com.", dnswire.TypeA) // warm the delegation
	before := e.sim.Victim.Queries.Load()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			query(t, "127.0.0.1", e.addr, "api.victim.com.", dnswire.TypeA)
		}()
	}
	wg.Wait()
	if d := e.sim.Victim.Queries.Load() - before; d != 1 {
		t.Fatalf("20 concurrent misses sent %d upstream queries, want 1", d)
	}
}
