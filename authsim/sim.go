package authsim

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/Other-Now/nano-dns/dnswire"
)

// Config shapes the simulated internet.
type Config struct {
	Port int // every simulated server listens on this port
	// PopularHosts names host0..hostN-1.popular.com (TTL 300): the workload for
	// cache experiments.
	PopularHosts int
	// VictimHosts names host0..hostN-1.victim.com. VictimTTL is their TTL; keep
	// it short so legitimate clients have to go upstream during an attack.
	VictimHosts int
	VictimTTL   uint32
	// VictimCapacity caps victim.com's authoritative server (queries/s).
	VictimCapacity int
	// Delay is the simulated RTT added by every server.
	Delay time.Duration
}

// Sim is the running hierarchy.
//
//	127.0.1.1  root            .           delegates com., net.
//	127.0.1.2  TLD             com. net.   delegates victim.com (glue),
//	                                       popular.com / shop.com (no glue: NS in hosting.net)
//	127.0.1.3  victim          victim.com.
//	127.0.1.4  hosting         popular.com. shop.com. cdn.net. hosting.net.
type Sim struct {
	Root, TLD, Victim, Hosting *Server
	RootHints                  []netip.AddrPort
}

func addr(last byte, port int) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 1, last}), uint16(port))
}

func a(name, ip string, ttl uint32) dnswire.RR {
	return dnswire.NewA(name, ttl, netip.MustParseAddr(ip))
}

func ns(zone, target string) dnswire.RR {
	return dnswire.NewName(zone, dnswire.TypeNS, 86400, target)
}

// Start builds the zones and starts all four servers.
func Start(cfg Config) (*Sim, error) {
	if cfg.VictimTTL == 0 {
		cfg.VictimTTL = 300
	}
	root := NewZone(".", 86400).
		Add(ns(".", "a.root.sim."), a("a.root.sim.", "127.0.1.1", 86400)).
		Add(ns("com.", "a.gtld.net."), ns("net.", "a.gtld.net.")).
		Glue(a("a.gtld.net.", "127.0.1.2", 86400))

	com := NewZone("com.", 900).
		Add(ns("com.", "a.gtld.net.")).
		Add(ns("victim.com.", "ns1.victim.com.")).
		Glue(a("ns1.victim.com.", "127.0.1.3", 86400)).
		// no glue: the resolver has to look up ns.hosting.net itself
		Add(ns("popular.com.", "ns.hosting.net."), ns("shop.com.", "ns.hosting.net."))
	net := NewZone("net.", 900).
		Add(ns("net.", "a.gtld.net."), a("a.gtld.net.", "127.0.1.2", 86400)).
		Add(ns("hosting.net.", "ns.hosting.net."), ns("cdn.net.", "ns.hosting.net.")).
		Glue(a("ns.hosting.net.", "127.0.1.4", 86400))

	victim := NewZone("victim.com.", 60).
		Add(ns("victim.com.", "ns1.victim.com."), a("ns1.victim.com.", "127.0.1.3", 86400)).
		Add(a("www.victim.com.", "198.51.100.10", cfg.VictimTTL),
			a("api.victim.com.", "198.51.100.11", cfg.VictimTTL),
			a("a.b.c.deep.victim.com.", "198.51.100.12", cfg.VictimTTL),
			dnswire.NewTXT("bigtxt.victim.com.", 300, strings.Repeat("v=big ", 600)))
	for i := 0; i < cfg.VictimHosts; i++ {
		victim.Add(a(fmt.Sprintf("host%d.victim.com.", i), fmt.Sprintf("198.51.%d.%d", 101+i/250, 1+i%250), cfg.VictimTTL))
	}

	popular := NewZone("popular.com.", 300).Add(ns("popular.com.", "ns.hosting.net."))
	for i := 0; i < cfg.PopularHosts; i++ {
		popular.Add(a(fmt.Sprintf("host%d.popular.com.", i), fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), 300))
	}
	shop := NewZone("shop.com.", 300).
		Add(ns("shop.com.", "ns.hosting.net.")).
		Add(dnswire.NewName("www.shop.com.", dnswire.TypeCNAME, 300, "shop.cdn.net."))
	cdn := NewZone("cdn.net.", 300).
		Add(ns("cdn.net.", "ns.hosting.net."), a("shop.cdn.net.", "203.0.113.80", 60))
	hosting := NewZone("hosting.net.", 300).
		Add(ns("hosting.net.", "ns.hosting.net."), a("ns.hosting.net.", "127.0.1.4", 86400))

	s := &Sim{
		Root:    &Server{Addr: addr(1, cfg.Port), Zones: []*Zone{root}, Delay: cfg.Delay},
		TLD:     &Server{Addr: addr(2, cfg.Port), Zones: []*Zone{com, net}, Delay: cfg.Delay},
		Victim:  &Server{Addr: addr(3, cfg.Port), Zones: []*Zone{victim}, Delay: cfg.Delay, Capacity: cfg.VictimCapacity},
		Hosting: &Server{Addr: addr(4, cfg.Port), Zones: []*Zone{popular, shop, cdn, hosting}, Delay: cfg.Delay},
	}
	s.RootHints = []netip.AddrPort{s.Root.Addr}
	for _, srv := range s.all() {
		if err := srv.Start(); err != nil {
			s.Close()
			return nil, fmt.Errorf("authsim %v: %w", srv.Addr, err)
		}
	}
	return s, nil
}

func (s *Sim) all() []*Server { return []*Server{s.Root, s.TLD, s.Victim, s.Hosting} }

// Close stops every server that was started.
func (s *Sim) Close() {
	for _, srv := range s.all() {
		if srv.udp != nil {
			srv.Close()
		}
	}
}

// TotalQueries sums the queries all simulated servers received.
func (s *Sim) TotalQueries() int64 {
	var n int64
	for _, srv := range s.all() {
		n += srv.Queries.Load()
	}
	return n
}
