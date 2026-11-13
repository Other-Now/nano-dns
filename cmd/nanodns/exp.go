package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Other-Now/nano-dns/authsim"
	"github.com/Other-Now/nano-dns/cache"
	"github.com/Other-Now/nano-dns/dnswire"
	"github.com/Other-Now/nano-dns/loadgen"
	"github.com/Other-Now/nano-dns/policy"
	"github.com/Other-Now/nano-dns/resolver"
)

const (
	simPort     = 5300
	expListen   = "127.0.0.1:5354"
	expMetrics  = "127.0.0.1:9154"
	expFeedsDir = "feeds"
)

var (
	outDir  string
	expDur  time.Duration
	expConc int
)

func exp(args []string) {
	fs := flag.NewFlagSet("exp", flag.ExitOnError)
	fs.StringVar(&outDir, "out", "results", "results directory")
	fs.DurationVar(&expDur, "d", 10*time.Second, "duration of each load phase")
	fs.IntVar(&expConc, "c", 32, "closed-loop concurrency")
	fs.Parse(args)
	if fs.NArg() < 1 {
		log.Fatal("usage: nanodns exp [-d 10s] [-c 32] throughput|cache|torture|rrl|qmin|blocklist|all")
	}
	os.MkdirAll(outDir, 0o755)
	run := map[string]func() any{
		"throughput": expThroughput, "cache": expCache, "torture": expTorture,
		"rrl": expRRL, "qmin": expQmin, "blocklist": expBlocklist,
	}
	names := []string{fs.Arg(0)}
	if fs.Arg(0) == "all" {
		names = []string{"qmin", "blocklist", "throughput", "cache", "rrl", "torture"}
	}
	for _, n := range names {
		f, ok := run[n]
		if !ok {
			log.Fatalf("unknown experiment %q", n)
		}
		log.Printf("=== exp %s", n)
		res := f()
		b, _ := json.MarshalIndent(map[string]any{
			"experiment": n, "when": time.Now().UTC().Format(time.RFC3339),
			"host": hostInfo(), "result": res,
		}, "", "  ")
		path := filepath.Join(outDir, n+".json")
		if err := os.WriteFile(path, b, 0o644); err != nil {
			log.Fatal(err)
		}
		log.Printf("wrote %s", path)
	}
}

func hostInfo() map[string]any {
	return map[string]any{"goos": runtime.GOOS, "cpus": runtime.NumCPU(), "go": runtime.Version()}
}

// --- child resolver process -------------------------------------------------

type child struct {
	cmd *exec.Cmd
}

func startServe(extra ...string) *child {
	self, _ := os.Executable()
	args := append([]string{"serve", "-listen", expListen, "-metrics", expMetrics, "-sim-port", strconv.Itoa(simPort)}, extra...)
	cmd := exec.Command(self, args...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}
	deadline := time.Now().Add(60 * time.Second) // policy loading can take a while
	for time.Now().Before(deadline) {
		if _, err := scrape(); err == nil {
			return &child{cmd}
		}
		time.Sleep(100 * time.Millisecond)
	}
	cmd.Process.Kill()
	log.Fatal("resolver child did not come up")
	return nil
}

func (c *child) stop() {
	c.cmd.Process.Signal(os.Interrupt)
	done := make(chan struct{})
	go func() { c.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		c.cmd.Process.Kill()
		<-done
	}
}

// scrape reads the child's Prometheus metrics into series -> value.
func scrape() (map[string]float64, error) {
	resp, err := http.Get("http://" + expMetrics + "/metrics")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out := map[string]float64{}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		i := strings.LastIndexByte(line, ' ')
		if v, err := strconv.ParseFloat(line[i+1:], 64); err == nil {
			out[line[:i]] = v
		}
	}
	return out, nil
}

func outcome(m map[string]float64, o string) float64 {
	return m[`nanodns_queries_total{outcome="`+o+`"}`]
}

func delta(a, b map[string]float64) map[string]float64 {
	out := map[string]float64{}
	for k, v := range b {
		if d := v - a[k]; d != 0 && !strings.Contains(k, "_bucket") {
			out[k] = d
		}
	}
	return out
}

func startSim(cfg authsim.Config) *authsim.Sim {
	cfg.Port = simPort
	sim, err := authsim.Start(cfg)
	if err != nil {
		log.Fatal(err)
	}
	return sim
}

func uniform(pattern string, n int) loadgen.Gen {
	return func(r *rand.Rand) (string, uint16) { return fmt.Sprintf(pattern, r.IntN(n)), dnswire.TypeA }
}

func warm(names []string) {
	var wg sync.WaitGroup
	ch := make(chan string)
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := range ch {
				loadgen.Query(expListen, n, dnswire.TypeA, 3*time.Second)
			}
		}()
	}
	for _, n := range names {
		ch <- n
	}
	close(ch)
	wg.Wait()
}

func names(pattern string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf(pattern, i)
	}
	return out
}

func run(cfg loadgen.Config) loadgen.Report {
	cfg.Server = expListen
	rep, err := loadgen.Run(context.Background(), cfg)
	if err != nil {
		log.Fatal(err)
	}
	return rep
}

// --- throughput -------------------------------------------------------------

type phase struct {
	Name    string             `json:"name"`
	Args    []string           `json:"args,omitempty"`
	Load    loadgen.Report     `json:"load"`
	Metrics map[string]float64 `json:"metrics,omitempty"`
}

func expThroughput() any {
	sim := startSim(authsim.Config{PopularHosts: 200_000})
	defer sim.Close()
	policyFile, rules := bigPolicy()
	sweep := []int{32, 128, 256}
	variants := []struct {
		name  string
		args  []string
		miss  bool
		concs []int
	}{
		{"hit/1sock-1reader", []string{"-sockets", "1", "-readers", "1"}, false, sweep},
		{"hit/1sock-4readers", []string{"-sockets", "1", "-readers", "4"}, false, sweep},
		{"hit/4sock-reuseport", []string{"-sockets", "4", "-readers", "1"}, false, sweep},
		{fmt.Sprintf("hit/4sock-reuseport+policy-%dk-rules", rules/1000), []string{"-sockets", "4", "-readers", "1", "-policy", policyFile}, false, []int{128}},
		{"miss/4sock-reuseport", []string{"-sockets", "4", "-readers", "1"}, true, []int{128}},
	}
	var out []phase
	for _, v := range variants {
		c := startServe(v.args...)
		var gen loadgen.Gen
		if v.miss {
			// every query a new name: full iteration to the simulated
			// authoritative server (no RTT added) on each one
			var next atomic.Int64
			gen = func(*rand.Rand) (string, uint16) {
				return fmt.Sprintf("host%d.popular.com", next.Add(1)%200_000), dnswire.TypeA
			}
			warm([]string{"host0.popular.com"}) // learn the delegation
		} else {
			gen = uniform("host%d.popular.com", 1000)
			warm(names("host%d.popular.com", 1000))
		}
		for _, conc := range v.concs {
			m0, _ := scrape()
			rep := run(loadgen.Config{Gen: gen, Concurrency: conc, Duration: expDur})
			m1, _ := scrape()
			name := fmt.Sprintf("%s c=%d", v.name, conc)
			log.Printf("%-48s %v", name, rep)
			out = append(out, phase{name, v.args, rep, delta(m0, m1)})
		}
		c.stop()
	}
	return map[string]any{"note": "load generator runs on the same 4 vCPUs", "phases": out}
}

// --- cache ------------------------------------------------------------------

func expCache() any {
	const n = 100_000
	sim := startSim(authsim.Config{PopularHosts: n})
	defer sim.Close()
	type row struct {
		CacheSize    int     `json:"cache_size"`
		HitRatio     float64 `json:"hit_ratio"`
		UpstreamPerQ float64 `json:"upstream_per_query"`
		Load         loadgen.Report
	}
	var zipfs sync.Map
	gen := func(r *rand.Rand) (string, uint16) {
		z, ok := zipfs.Load(r)
		if !ok {
			z = rand.NewZipf(r, 1.1, 1, n-1)
			zipfs.Store(r, z)
		}
		return fmt.Sprintf("host%d.popular.com", z.(*rand.Zipf).Uint64()), dnswire.TypeA
	}
	var out []row
	for _, size := range []int{1_000, 10_000, 100_000, 1_000_000} {
		c := startServe("-sockets", "4", "-cache", strconv.Itoa(size))
		m0, _ := scrape()
		rep := run(loadgen.Config{Gen: gen, Concurrency: expConc, Duration: expDur})
		m1, _ := scrape()
		c.stop()
		d := delta(m0, m1)
		hits := outcome(d, "cache_hit")
		total := hits + outcome(d, "resolved") + outcome(d, "coalesced") + outcome(d, "servfail")
		r := row{CacheSize: size, Load: rep}
		if total > 0 {
			r.HitRatio = hits / total
			r.UpstreamPerQ = d["nanodns_upstream_queries_total"] / total
		}
		log.Printf("cache %8d: hit %.3f upstream/q %.3f %v", size, r.HitRatio, r.UpstreamPerQ, rep)
		out = append(out, r)
	}
	return map[string]any{"workload": "Zipf s=1.1 over 100k names, TTL 300 s", "rows": out}
}

// --- water torture ----------------------------------------------------------

func expTorture() any {
	const (
		victimHosts = 500
		capacity    = 2000
		attackRate  = 10_000
	)
	type res struct {
		Phase             string             `json:"phase"`
		LegitVictim       loadgen.Report     `json:"legit_victim"`
		LegitPopular      loadgen.Report     `json:"legit_popular"`
		Attack            *loadgen.Report    `json:"attack,omitempty"`
		VictimQPS         float64            `json:"victim_server_qps"`
		VictimDroppedFrac float64            `json:"victim_server_dropped_frac"`
		Metrics           map[string]float64 `json:"metrics"`
	}
	phases := []struct {
		name          string
		attack, mitig bool
	}{
		{"baseline (no attack)", false, true},
		{"attack, no mitigation", true, false},
		{"attack, mitigation on", true, true},
	}
	var out []res
	for _, p := range phases {
		sim := startSim(authsim.Config{PopularHosts: 1000, VictimHosts: victimHosts, VictimTTL: 2,
			VictimCapacity: capacity, Delay: time.Millisecond})
		args := []string{"-sockets", "4"}
		if p.mitig {
			args = append(args, "-torture-threshold", "200", "-torture-window", "2s", "-torture-hold", "60s")
		}
		c := startServe(args...)
		warm(append(names("host%d.victim.com", victimHosts), names("host%d.popular.com", 1000)...))
		m0, _ := scrape()
		q0, d0 := sim.Victim.Queries.Load(), sim.Victim.Dropped.Load()
		var wg sync.WaitGroup
		var atk loadgen.Report
		if p.attack {
			wg.Add(1)
			go func() {
				defer wg.Done()
				atk = run(loadgen.Config{Rate: attackRate, Duration: expDur, Gen: func(r *rand.Rand) (string, uint16) {
					return fmt.Sprintf("%x.victim.com", r.Uint64()), dnswire.TypeA
				}})
			}()
		}
		var lv, lp loadgen.Report
		wg.Add(2)
		go func() {
			defer wg.Done()
			lv = run(loadgen.Config{Gen: uniform("host%d.victim.com", victimHosts), Concurrency: 4, Duration: expDur})
		}()
		go func() {
			defer wg.Done()
			lp = run(loadgen.Config{Gen: uniform("host%d.popular.com", 1000), Concurrency: 4, Duration: expDur})
		}()
		wg.Wait()
		m1, _ := scrape()
		c.stop()
		vq, vd := sim.Victim.Queries.Load()-q0, sim.Victim.Dropped.Load()-d0
		sim.Close()
		r := res{Phase: p.name, LegitVictim: lv, LegitPopular: lp, VictimQPS: float64(vq) / expDur.Seconds(), Metrics: delta(m0, m1)}
		if vq > 0 {
			r.VictimDroppedFrac = float64(vd) / float64(vq)
		}
		if p.attack {
			r.Attack = &atk
		}
		log.Printf("%-24s legit-victim success %.3f p50 %.0fus p99 %.0fus | legit-popular success %.3f | victim server %.0f q/s, %.0f%% dropped",
			p.name, lv.Success(), lv.P50us, lv.P99us, lp.Success(), r.VictimQPS, 100*r.VictimDroppedFrac)
		out = append(out, r)
		time.Sleep(time.Second)
	}
	return map[string]any{
		"setup":  fmt.Sprintf("victim.com authoritative capacity %d q/s, 1 ms RTT, host TTL 2 s; attacker %d q/s random subdomains; legit 4+4 closed-loop clients", capacity, attackRate),
		"phases": out,
	}
}

// --- RRL --------------------------------------------------------------------

func expRRL() any {
	sim := startSim(authsim.Config{})
	defer sim.Close()
	var out []phase
	for _, v := range []struct {
		name string
		args []string
	}{
		{"rrl off", nil},
		{"rrl 100/s per /24, slip 2", []string{"-rrl-rate", "100", "-rrl-slip", "2"}},
	} {
		c := startServe(append([]string{"-sockets", "4"}, v.args...)...)
		warm([]string{"www.victim.com"})
		m0, _ := scrape()
		// one /24 (the spoofed victim) receiving a flood of answers
		rep := run(loadgen.Config{Rate: 20_000, Duration: expDur, Gen: func(*rand.Rand) (string, uint16) {
			return "www.victim.com", dnswire.TypeA
		}})
		m1, _ := scrape()
		c.stop()
		log.Printf("%-28s %v", v.name, rep)
		out = append(out, phase{v.name, v.args, rep, delta(m0, m1)})
	}
	return out
}

// --- QNAME minimisation -----------------------------------------------------

func expQmin() any {
	sim := startSim(authsim.Config{PopularHosts: 200, VictimHosts: 200})
	defer sim.Close()
	qs := append(names("host%d.popular.com.", 200), names("host%d.victim.com.", 200)...)
	qs = append(qs, "a.b.c.deep.victim.com.", "www.shop.com.")
	type row struct {
		QMin            bool  `json:"qmin"`
		Names           int   `json:"names"`
		Failures        int   `json:"failures"`
		Upstream        int64 `json:"upstream_queries"`
		RootQueries     int64 `json:"root_queries"`
		RootSawFullName int64 `json:"root_saw_more_than_tld"`
		TLDQueries      int64 `json:"tld_queries"`
		TLDSawFullName  int64 `json:"tld_saw_more_than_domain"`
	}
	var out []row
	for _, qmin := range []bool{false, true} {
		r := row{QMin: qmin, Names: len(qs)}
		var mu sync.Mutex
		res := resolver.New(resolver.Config{Roots: sim.RootHints, UpstreamPort: simPort, QMin: qmin, Cache: cache.New(100_000),
			OnUpstream: func(s netip.AddrPort, name string, _ uint16) {
				mu.Lock()
				defer mu.Unlock()
				switch s {
				case sim.Root.Addr:
					r.RootQueries++
					if dnswire.CountLabels(name) > 1 {
						r.RootSawFullName++
					}
				case sim.TLD.Addr:
					r.TLDQueries++
					if dnswire.CountLabels(name) > 2 {
						r.TLDSawFullName++
					}
				}
			}})
		for _, n := range qs {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if rr, err := res.Resolve(ctx, n, dnswire.TypeA); err != nil || len(rr.Answer) == 0 {
				r.Failures++
			}
			cancel()
		}
		r.Upstream = res.Stats().Upstream.Load()
		log.Printf("qmin=%v %+v", qmin, r)
		out = append(out, r)
	}
	return out
}

// --- blocklist --------------------------------------------------------------

// bigPolicy writes a policy file whose single list holds the real feeds in
// feeds/ plus synthetic rules up to 1M. Returns the path and the rule count.
func bigPolicy() (string, int) {
	dir, _ := os.MkdirTemp("", "nanodns-policy")
	l, files := loadRealFeeds()
	f, _ := os.Create(filepath.Join(dir, "big.rpz"))
	w := bufio.NewWriter(f)
	n := 0
	for _, path := range files {
		b, _ := os.ReadFile(path)
		w.Write(b)
		w.WriteByte('\n')
	}
	n = l.Len()
	for i := 0; n < 1_000_000; i++ {
		fmt.Fprintf(w, "pad%d.invalid CNAME .\n", i)
		n++
	}
	w.Flush()
	f.Close()
	pf := filepath.Join(dir, "policy.json")
	os.WriteFile(pf, []byte(`{"lists":{"threats":{"file":"big.rpz","format":"rpz"}},"profiles":{"default":["threats"]},"default":"default"}`), 0o644)
	return pf, n
}

func loadRealFeeds() (*policy.List, []string) {
	l := policy.NewList("real")
	var files []string
	for _, name := range []string{"hagezi-tif-medium.rpz", "urlhaus-filter.rpz"} {
		p := filepath.Join(expFeedsDir, name)
		f, err := os.Open(p)
		if err != nil {
			log.Printf("feed %s missing (run scripts/fetch-feeds.sh)", p)
			continue
		}
		l.LoadRPZ(f)
		f.Close()
		files = append(files, p)
	}
	return l, files
}

func heapMB() float64 {
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return float64(ms.HeapAlloc) / (1 << 20)
}

func trancoTop(n int) []string {
	f, err := os.Open(filepath.Join(expFeedsDir, "top-1m.csv"))
	if err != nil {
		log.Printf("tranco list missing (run scripts/fetch-feeds.sh)")
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() && len(out) < n {
		if _, d, ok := strings.Cut(sc.Text(), ","); ok {
			out = append(out, dnswire.Canonical(strings.TrimSpace(d)))
		}
	}
	return out
}

func expBlocklist() any {
	h0 := heapMB()
	t0 := time.Now()
	l, files := loadRealFeeds()
	loadReal := time.Since(t0)
	hReal := heapMB() - h0
	realRules := l.Len()

	top := trancoTop(10_000)
	var hits []string
	for _, n := range top {
		if r, ok := l.Match(n); ok && r.Action != policy.Passthru {
			hits = append(hits, trimDot(n))
		}
	}
	// lookup cost: clean popular names, each also with a "www." and a
	// 4-label "static.cdn." prefix (more labels = more suffix probes)
	probe := make([]string, 0, 3*len(top))
	for _, n := range top {
		probe = append(probe, n, "www."+n, "static.cdn."+n)
	}
	lookupNs := func(l *policy.List) float64 {
		const reps = 20
		t := time.Now()
		for i := 0; i < reps; i++ {
			for _, n := range probe {
				l.Match(n)
			}
		}
		return float64(time.Since(t).Nanoseconds()) / float64(reps*len(probe))
	}
	realNs := lookupNs(l)

	for i := 0; l.Len() < 1_000_000; i++ {
		l.Add(fmt.Sprintf("pad%d.invalid", i), policy.Rule{Action: policy.NXDomain})
	}
	h1M := heapMB() - h0
	bigNs := lookupNs(l)
	res := map[string]any{
		"feeds":                    files,
		"real_rules":               realRules,
		"load_seconds":             loadReal.Seconds(),
		"heap_mb_real":             hReal,
		"lookup_ns_real":           realNs,
		"heap_mb_1m":               h1M,
		"lookup_ns_1m":             bigNs,
		"tranco_top":               len(top),
		"tranco_top_listed":        len(hits),
		"tranco_top_listed_sample": hits[:min(len(hits), 30)],
	}
	log.Printf("blocklist: %d real rules loaded in %v, %.0f MB; lookup %.0f ns (real) / %.0f ns (1M rules, %.0f MB); %d of top %d Tranco domains listed",
		realRules, loadReal.Round(time.Millisecond), hReal, realNs, bigNs, h1M, len(hits), len(top))
	return res
}
