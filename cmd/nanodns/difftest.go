package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Other-Now/nano-dns/dnswire"
	"github.com/Other-Now/nano-dns/loadgen"
)

// difftest resolves the Tranco top-N domains from the real root servers and
// compares the A records with a public resolver. Different addresses are not
// automatically a bug (CDNs answer by location and rotate), so a disjoint
// answer is checked against a second public resolver: if the two public
// resolvers also disagree, it is load balancing.
func difftest(args []string) {
	fs := flag.NewFlagSet("difftest", flag.ExitOnError)
	n := fs.Int("n", 500, "top-N Tranco domains")
	skip := fs.Int("skip", 0, "skip the first N domains")
	ref := fs.String("ref", "1.1.1.1:53", "reference resolver")
	ref2 := fs.String("ref2", "8.8.8.8:53", "second reference, consulted on disjoint answers")
	conc := fs.Int("c", 8, "concurrent lookups")
	out := fs.String("out", "results/difftest.json", "output file")
	www := fs.Bool("www", false, "query www.<domain> instead of the apex")
	rf := addResolverFlags(fs)
	fs.Parse(args)
	*rf.simPort = 0
	res, _ := rf.build()

	domains := trancoTop(*skip + *n)
	if len(domains) <= *skip {
		log.Fatal("no domains (feeds/top-1m.csv missing?)")
	}
	domains = domains[*skip:]
	if *www {
		for i := range domains {
			domains[i] = "www." + domains[i]
		}
	}

	type row struct {
		Domain   string   `json:"domain"`
		Class    string   `json:"class"`
		Ours     string   `json:"ours"`
		Ref      string   `json:"ref"`
		OursErr  string   `json:"ours_err,omitempty"`
		OursMs   float64  `json:"ours_ms"`
		OursAddr []string `json:"-"`
	}
	rows := make([]row, len(domains))
	var wg sync.WaitGroup
	ch := make(chan int)
	for w := 0; w < *conc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range ch {
				d := domains[i]
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				t0 := time.Now()
				o, oerr := res.Resolve(ctx, d, dnswire.TypeA)
				ms := float64(time.Since(t0).Microseconds()) / 1000
				cancel()
				r := row{Domain: trimDot(d), OursMs: ms}
				oa := addrSet(o.Answer)
				r.Ours = fmt.Sprintf("%s %v", dnswire.RcodeString(o.Rcode), keys(oa))
				if oerr != nil {
					r.OursErr = oerr.Error()
				}
				// the path loses a few % of UDP packets, so the reference gets
				// retries too (3 x 2 s), as a stub resolver would
				var rm *dnswire.Msg
				var rerr error
				for try := 0; try < 3; try++ {
					if rm, rerr = loadgen.Query(*ref, d, dnswire.TypeA, 2*time.Second); rerr == nil {
						break
					}
				}
				if rerr != nil {
					r.Class, r.Ref = "ref_failed", rerr.Error()
					rows[i] = r
					continue
				}
				ra := addrSet(rm.Answer)
				r.Ref = fmt.Sprintf("%s %v", dnswire.RcodeString(rm.Rcode), keys(ra))
				switch {
				case oerr != nil || o.Rcode == dnswire.RcodeServFail:
					if rm.Rcode == dnswire.RcodeServFail {
						r.Class = "both_servfail"
					} else {
						r.Class = "ours_failed"
					}
				case o.Rcode != rm.Rcode:
					r.Class = "rcode_diff"
				case equal(oa, ra):
					r.Class = "identical"
				case len(oa) == 0 || len(ra) == 0:
					r.Class = "one_empty"
				case overlap(oa, ra):
					r.Class = "overlap"
				default:
					// Ask both public resolvers a few more times: many sites
					// rotate single-address answers per query (x.com does).
					seen := map[string]bool{}
					for k := range ra {
						seen[k] = true
					}
					var r2 map[string]bool
					for i := 0; i < 3; i++ {
						for j, s := range []string{*ref, *ref2} {
							if m, err := loadgen.Query(s, d, dnswire.TypeA, 5*time.Second); err == nil {
								a := addrSet(m.Answer)
								for k := range a {
									seen[k] = true
								}
								if j == 1 && r2 == nil {
									r2 = a
								}
							}
						}
					}
					switch {
					case overlap(oa, seen):
						r.Class = "rotation" // our answer is one the public resolvers also give
					case r2 != nil && !overlap(r2, ra):
						r.Class = "disjoint_cdn" // the public resolvers disagree with each other too
					default:
						r.Class = "disjoint_ours_vs_ref"
					}
				}
				rows[i] = r
			}
		}()
	}
	for i := range domains {
		ch <- i
	}
	close(ch)
	wg.Wait()

	counts := map[string]int{}
	var lat []float64
	var bad []row
	for _, r := range rows {
		counts[r.Class]++
		lat = append(lat, r.OursMs)
		switch r.Class {
		case "identical", "overlap", "rotation", "disjoint_cdn", "both_servfail":
		default:
			bad = append(bad, r)
		}
	}
	sort.Float64s(lat)
	st := res.Stats()
	summary := map[string]any{
		"domains": len(domains), "skip": *skip, "www": *www, "ref": *ref, "qmin": *rf.qmin,
		"classes": counts, "to_investigate": bad,
		"cold_ms_p50": lat[len(lat)/2], "cold_ms_p90": lat[len(lat)*9/10],
		"upstream_queries": st.Upstream.Load(), "upstream_tcp": st.UpstreamTCP.Load(),
		"upstream_timeouts": st.Timeouts.Load(), "bailiwick_dropped": st.BailiwickDropped.Load(),
		"when": time.Now().UTC().Format(time.RFC3339),
	}
	os.MkdirAll(filepath.Dir(*out), 0o755)
	b, _ := json.MarshalIndent(summary, "", "  ")
	os.WriteFile(*out, b, 0o644)
	log.Printf("difftest %d domains: %v; cold p50 %.0f ms; %d to investigate -> %s", len(domains), counts, lat[len(lat)/2], len(bad), *out)
	for _, r := range bad {
		fmt.Printf("%-28s %-22s ours=%s %s | ref=%s\n", r.Domain, r.Class, r.Ours, r.OursErr, r.Ref)
	}
}

func addrSet(rrs []dnswire.RR) map[string]bool {
	m := map[string]bool{}
	for _, rr := range rrs {
		if a, ok := rr.Addr(); ok {
			m[a.String()] = true
		}
	}
	return m
}

func keys(m map[string]bool) string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return strings.Join(k, ",")
}

func equal(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func overlap(a, b map[string]bool) bool {
	for k := range a {
		if b[k] {
			return true
		}
	}
	return false
}
