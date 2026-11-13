// Command nanodns is a carrier-style recursive resolver with threat blocking.
//
//	nanodns serve     run the resolver
//	nanodns authsim   run the simulated root/TLD/zone servers (for testing)
//	nanodns query     send one query (a tiny dig)
//	nanodns bench     load-generate against a server
//	nanodns exp       run a benchmark experiment, write results/<name>.json
//	nanodns difftest  compare answers with a public resolver on real domains
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/Other-Now/nano-dns/authsim"
	"github.com/Other-Now/nano-dns/cache"
	"github.com/Other-Now/nano-dns/dnswire"
	"github.com/Other-Now/nano-dns/guard"
	"github.com/Other-Now/nano-dns/loadgen"
	"github.com/Other-Now/nano-dns/policy"
	"github.com/Other-Now/nano-dns/resolver"
	"github.com/Other-Now/nano-dns/server"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// IPv4 addresses of the 13 root servers (IANA named.root).
var rootHints = []string{
	"198.41.0.4", "170.247.170.2", "192.33.4.12", "199.7.91.13", "192.203.230.10",
	"192.5.5.241", "192.112.36.4", "198.97.190.53", "192.36.148.17", "192.58.128.30",
	"193.0.14.129", "199.7.83.42", "202.12.27.33",
}

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "serve":
		serve(args)
	case "authsim":
		runAuthsim(args)
	case "query":
		query(args)
	case "bench":
		bench(args)
	case "exp":
		exp(args)
	case "difftest":
		difftest(args)
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: nanodns serve|authsim|query|bench|exp|difftest [flags]")
	os.Exit(2)
}

type resolverFlags struct {
	simPort  *int
	qmin     *bool
	cacheMax *int
	timeout  *time.Duration
}

func addResolverFlags(fs *flag.FlagSet) resolverFlags {
	return resolverFlags{
		simPort:  fs.Int("sim-port", 0, "use the simulated hierarchy on 127.0.1.1:<port> instead of the real roots"),
		qmin:     fs.Bool("qmin", false, "QNAME minimisation (RFC 9156)"),
		cacheMax: fs.Int("cache", 1_000_000, "max cache entries"),
		timeout:  fs.Duration("upstream-timeout", 800*time.Millisecond, "per upstream attempt"),
	}
}

func (f resolverFlags) build() (*resolver.Resolver, *cache.Cache) {
	c := cache.New(*f.cacheMax)
	cfg := resolver.Config{QMin: *f.qmin, Cache: c, Timeout: *f.timeout}
	if *f.simPort > 0 {
		cfg.Roots = []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.1.1"), uint16(*f.simPort))}
		cfg.UpstreamPort = uint16(*f.simPort)
	} else {
		for _, h := range rootHints {
			cfg.Roots = append(cfg.Roots, netip.AddrPortFrom(netip.MustParseAddr(h), 53))
		}
	}
	return resolver.New(cfg), c
}

func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:5354", "UDP/TCP listen address")
	sockets := fs.Int("sockets", 1, "UDP sockets with SO_REUSEPORT (Linux)")
	readers := fs.Int("readers", 1, "reader goroutines per socket")
	metricsAddr := fs.String("metrics", "127.0.0.1:9153", "Prometheus /metrics address (empty: off)")
	policyFile := fs.String("policy", "", "JSON policy file (lists, profiles, subscribers)")
	rrlRate := fs.Float64("rrl-rate", 0, "responses/s per client /24 (0: RRL off)")
	rrlBurst := fs.Float64("rrl-burst", 0, "RRL burst (default = rate)")
	rrlSlip := fs.Int("rrl-slip", 2, "send every Nth limited response as TC=1")
	tThresh := fs.Int("torture-threshold", 0, "failed upstream lookups per domain per window to start mitigation (0: off)")
	tWindow := fs.Duration("torture-window", 2*time.Second, "water-torture counting window")
	tHold := fs.Duration("torture-hold", time.Minute, "how long mitigation lasts")
	rf := addResolverFlags(fs)
	fs.Parse(args)

	res, c := rf.build()
	reg := prometheus.NewRegistry()
	cfg := server.Config{Listen: *listen, Sockets: *sockets, Readers: *readers, Resolver: res, Metrics: server.NewMetrics(reg)}
	if *policyFile != "" {
		t0 := time.Now()
		eng, err := policy.Load(*policyFile)
		if err != nil {
			log.Fatal(err)
		}
		for _, l := range eng.Lists {
			log.Printf("policy list %v", l)
		}
		log.Printf("policy loaded in %v", time.Since(t0).Round(time.Millisecond))
		cfg.Policy = eng
	}
	if *rrlRate > 0 {
		b := *rrlBurst
		if b == 0 {
			b = *rrlRate
		}
		cfg.RRL = guard.NewRRL(*rrlRate, b, *rrlSlip)
	}
	if *tThresh > 0 {
		cfg.Torture = guard.NewTorture(*tWindow, *tThresh, *tHold)
	}
	registerResolverMetrics(reg, res, c, cfg.Torture)

	srv := server.New(cfg)
	if err := srv.Start(); err != nil {
		log.Fatal(err)
	}
	if *metricsAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
		go func() { log.Fatal(http.ListenAndServe(*metricsAddr, mux)) }()
	}
	log.Printf("nanodns serving on %s (sockets=%d readers=%d qmin=%v sim-port=%d rrl=%v torture=%v)",
		*listen, *sockets, *readers, *rf.qmin, *rf.simPort, cfg.RRL != nil, cfg.Torture != nil)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
	srv.Close()
}

func registerResolverMetrics(reg *prometheus.Registry, r *resolver.Resolver, c *cache.Cache, t *guard.Torture) {
	st := r.Stats()
	cf := func(name, help string, f func() float64) {
		reg.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{Name: name, Help: help}, f))
	}
	cf("nanodns_upstream_queries_total", "Queries sent to authoritative servers.", func() float64 { return float64(st.Upstream.Load()) })
	cf("nanodns_upstream_tcp_total", "TCP retries after truncation.", func() float64 { return float64(st.UpstreamTCP.Load()) })
	cf("nanodns_upstream_timeouts_total", "Upstream attempts that timed out.", func() float64 { return float64(st.Timeouts.Load()) })
	cf("nanodns_upstream_mismatched_total", "Replies ignored for wrong ID/question.", func() float64 { return float64(st.Mismatched.Load()) })
	cf("nanodns_bailiwick_dropped_total", "Records dropped as out of bailiwick.", func() float64 { return float64(st.BailiwickDropped.Load()) })
	reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "nanodns_cache_entries", Help: "Cache entries."},
		func() float64 { return float64(c.Len()) }))
	if t != nil {
		reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "nanodns_torture_mitigated_domains", Help: "Domains under water-torture mitigation."},
			func() float64 { return float64(len(t.Mitigated(time.Now()))) }))
	}
}

func runAuthsim(args []string) {
	fs := flag.NewFlagSet("authsim", flag.ExitOnError)
	port := fs.Int("port", 5300, "port for all simulated servers")
	popular := fs.Int("popular", 10000, "hostN.popular.com names")
	victimHosts := fs.Int("victim-hosts", 1000, "hostN.victim.com names")
	victimTTL := fs.Uint("victim-ttl", 300, "TTL of victim.com hosts")
	capacity := fs.Int("victim-capacity", 0, "victim.com server queries/s (0: unlimited)")
	delay := fs.Duration("delay", 0, "simulated RTT per server")
	fs.Parse(args)
	sim, err := authsim.Start(authsim.Config{Port: *port, PopularHosts: *popular, VictimHosts: *victimHosts,
		VictimTTL: uint32(*victimTTL), VictimCapacity: *capacity, Delay: *delay})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("authsim: root 127.0.1.1:%d, TLD .2, victim.com .3, hosting .4", *port)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	tick := time.NewTicker(5 * time.Second)
	for {
		select {
		case <-sig:
			sim.Close()
			return
		case <-tick.C:
			log.Printf("queries root=%d tld=%d victim=%d (dropped %d) hosting=%d",
				sim.Root.Queries.Load(), sim.TLD.Queries.Load(), sim.Victim.Queries.Load(), sim.Victim.Dropped.Load(), sim.Hosting.Queries.Load())
		}
	}
}

func query(args []string) {
	fs := flag.NewFlagSet("query", flag.ExitOnError)
	srv := fs.String("server", "127.0.0.1:5354", "server")
	src := fs.String("source", "", "local address to send from (act as another subscriber)")
	fs.Parse(args)
	if fs.NArg() < 1 {
		log.Fatal("usage: nanodns query [-server addr] name [type]")
	}
	qt := dnswire.TypeA
	if fs.NArg() > 1 {
		t, ok := dnswire.ParseType(fs.Arg(1))
		if !ok {
			log.Fatalf("unknown type %s", fs.Arg(1))
		}
		qt = t
	}
	t0 := time.Now()
	m, err := loadgen.QueryFrom(*src, *srv, fs.Arg(0), qt, 5*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf(";; %s  aa=%v tc=%v ra=%v  %v\n", dnswire.RcodeString(m.Rcode), m.Authoritative, m.Truncated, m.RecursionAvailable, time.Since(t0).Round(time.Microsecond))
	for _, sec := range []struct {
		n   string
		rrs []dnswire.RR
	}{{"ANSWER", m.Answer}, {"AUTHORITY", m.Authority}} {
		if len(sec.rrs) > 0 {
			fmt.Printf(";; %s\n", sec.n)
			for _, rr := range sec.rrs {
				fmt.Println(rr)
			}
		}
	}
}

func bench(args []string) {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	srv := fs.String("server", "127.0.0.1:5354", "server")
	conc := fs.Int("c", 32, "closed-loop concurrency")
	rate := fs.Int("rate", 0, "open-loop rate (queries/s); 0 = closed loop")
	dur := fs.Duration("d", 10*time.Second, "duration")
	names := fs.String("names", "host%d.popular.com", "name pattern with %d")
	n := fs.Int("n", 1000, "number of distinct names (uniform)")
	random := fs.String("random-under", "", "random subdomains under this domain (attack traffic)")
	fs.Parse(args)
	gen := func(r *rand.Rand) (string, uint16) {
		if *random != "" {
			return fmt.Sprintf("%x.%s", r.Uint64(), *random), dnswire.TypeA
		}
		return fmt.Sprintf(*names, r.IntN(*n)), dnswire.TypeA
	}
	rep, err := loadgen.Run(context.Background(), loadgen.Config{Server: *srv, Gen: gen, Concurrency: *conc, Rate: *rate, Duration: *dur})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(rep)
}

func trimDot(s string) string { return strings.TrimSuffix(s, ".") }
