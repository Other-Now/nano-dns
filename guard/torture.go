package guard

import (
	"strings"
	"sync"
	"time"

	"github.com/Other-Now/nano-dns/dnswire"
	"golang.org/x/net/publicsuffix"
)

// Torture detects random-subdomain attacks ("DNS water torture"): a botnet
// asks resolvers for <random>.victim.com. Every name is new, so the cache
// cannot help, every query goes to victim.com's servers, and they drown.
// Then the resolver drowns as well, waiting on timeouts.
//
// Signal: failed upstream resolutions (NXDOMAIN or SERVFAIL) per registrable
// domain per window. Over Threshold, the domain is put under mitigation for
// Hold. While mitigated, a cache miss for a name under it is answered
// SERVFAIL locally, without going upstream, unless the name resolved
// successfully before the attack (the "known-good" set). Legitimate traffic
// keeps flowing, and the attack traffic never leaves the resolver.
type Torture struct {
	Window    time.Duration
	Threshold int
	Hold      time.Duration
	MaxGood   int // known-good names remembered per domain

	mu    sync.Mutex
	zones map[string]*zoneState
}

type zoneState struct {
	winStart  time.Time
	failures  int
	until     time.Time // mitigation end
	triggered int       // how many times mitigation started
	good      map[string]struct{}
}

// NewTorture makes a detector.
func NewTorture(window time.Duration, threshold int, hold time.Duration) *Torture {
	return &Torture{Window: window, Threshold: threshold, Hold: hold, MaxGood: 10_000, zones: map[string]*zoneState{}}
}

// Base returns the registrable domain (eTLD+1) of a canonical name, using
// the public suffix list: "a.b.example.co.uk." -> "example.co.uk.".
func Base(name string) string {
	n := strings.TrimSuffix(name, ".")
	if b, err := publicsuffix.EffectiveTLDPlusOne(n); err == nil {
		return b + "."
	}
	return name
}

func (t *Torture) zone(base string, now time.Time) *zoneState {
	z, ok := t.zones[base]
	if !ok {
		if len(t.zones) > 100_000 {
			t.prune(now)
		}
		z = &zoneState{winStart: now, good: map[string]struct{}{}}
		t.zones[base] = z
	}
	if now.Sub(z.winStart) >= t.Window {
		z.winStart, z.failures = now, 0
	}
	return z
}

func (t *Torture) prune(now time.Time) {
	for k, z := range t.zones {
		if now.Sub(z.winStart) > 2*t.Window && now.After(z.until) {
			delete(t.zones, k)
		}
	}
}

// Observe records the outcome of an upstream resolution (not cache hits).
func (t *Torture) Observe(name string, rcode uint8, answered bool, now time.Time) {
	base := Base(name)
	t.mu.Lock()
	defer t.mu.Unlock()
	z := t.zone(base, now)
	switch {
	case rcode == dnswire.RcodeNXDomain || rcode == dnswire.RcodeServFail:
		z.failures++
		if z.failures >= t.Threshold {
			if !now.Before(z.until) {
				z.triggered++
			}
			z.until = now.Add(t.Hold)
		}
	case rcode == dnswire.RcodeSuccess && answered:
		if now.Before(z.until) {
			return // don't learn new "good" names during an attack
		}
		if len(z.good) < t.MaxGood {
			z.good[name] = struct{}{}
		}
	}
}

// Allow reports whether a cache miss for name may go upstream.
func (t *Torture) Allow(name string, now time.Time) bool {
	base := Base(name)
	t.mu.Lock()
	defer t.mu.Unlock()
	z, ok := t.zones[base]
	if !ok || !now.Before(z.until) {
		return true
	}
	_, good := z.good[name]
	return good
}

// Mitigated lists domains currently under mitigation.
func (t *Torture) Mitigated(now time.Time) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []string
	for k, z := range t.zones {
		if now.Before(z.until) {
			out = append(out, k)
		}
	}
	return out
}
