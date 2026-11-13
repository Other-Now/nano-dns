// Package guard holds the resolver's abuse defences: response rate limiting
// (RRL) per client netblock, and random-subdomain ("water torture")
// detection per registrable domain.
package guard

import (
	"hash/maphash"
	"net/netip"
	"sync"
	"time"
)

// Verdict is what RRL decided for one response.
type Verdict uint8

const (
	Allow Verdict = iota
	Slip          // send a tiny TC=1 reply so a real client retries over TCP
	Drop          // send nothing
)

// RRL limits responses per client netblock (/24 for IPv4, /56 for IPv6)
// with a token bucket. Over the limit, every Slip-th response is sent
// truncated and the rest are dropped. That is how BIND's RRL keeps a resolver
// from being used to flood a spoofed victim, while a genuine client whose
// address is being spoofed can still get answers over TCP.
type RRL struct {
	Rate  float64 // responses per second per netblock
	Burst float64
	Slip  int // 0: never slip, always drop

	seed   maphash.Seed
	shards [16]rrlShard
}

type rrlShard struct {
	mu sync.Mutex
	m  map[netip.Prefix]*bucket
}

type bucket struct {
	tokens  float64
	last    time.Time
	limited int
}

// NewRRL makes a limiter.
func NewRRL(rate, burst float64, slip int) *RRL {
	r := &RRL{Rate: rate, Burst: burst, Slip: slip, seed: maphash.MakeSeed()}
	for i := range r.shards {
		r.shards[i].m = map[netip.Prefix]*bucket{}
	}
	return r
}

func netblock(a netip.Addr) netip.Prefix {
	a = a.Unmap()
	bits := 24
	if a.Is6() {
		bits = 56
	}
	p, _ := a.Prefix(bits)
	return p
}

// Check charges one response to client's netblock.
func (r *RRL) Check(client netip.Addr, now time.Time) Verdict {
	key := netblock(client)
	b := key.Addr().As16()
	sh := &r.shards[maphash.Bytes(r.seed, b[:])%16]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	bk, ok := sh.m[key]
	if !ok {
		if len(sh.m) > 50_000 {
			sh.prune(now)
		}
		bk = &bucket{tokens: r.Burst, last: now}
		sh.m[key] = bk
	}
	bk.tokens = min(r.Burst, bk.tokens+now.Sub(bk.last).Seconds()*r.Rate)
	bk.last = now
	if bk.tokens >= 1 {
		bk.tokens--
		return Allow
	}
	bk.limited++
	if r.Slip > 0 && bk.limited%r.Slip == 0 {
		return Slip
	}
	return Drop
}

// prune drops buckets idle long enough to have refilled completely.
func (s *rrlShard) prune(now time.Time) {
	for k, b := range s.m {
		if now.Sub(b.last) > 10*time.Second {
			delete(s.m, k)
		}
	}
}
