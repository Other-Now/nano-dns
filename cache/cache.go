// Package cache is the resolver's record cache: positive answers, negative
// answers (RFC 2308) and delegation data all live here, keyed by
// (name, type).
//
// It is a sharded map with a size bound per shard. When a shard is full it
// evicts an expired entry if it finds one among a few it samples, otherwise a
// random one (Go map iteration order is random). Random eviction is simple
// and, under a skewed popularity distribution, close to LRU in hit ratio.
package cache

import (
	"hash/maphash"
	"sync"
	"time"

	"github.com/Other-Now/nano-dns/dnswire"
)

const shards = 64

// TypeNXDomain is the pseudo-type an NXDOMAIN is stored under: it applies to
// every type at that name (RFC 2308 section 5).
const TypeNXDomain uint16 = 0

type key struct {
	name  string
	qtype uint16
}

type entry struct {
	rcode     uint8
	answer    []dnswire.RR
	authority []dnswire.RR
	stored    time.Time
	expires   time.Time
}

type shard struct {
	mu sync.Mutex
	m  map[key]*entry
}

// Cache is safe for concurrent use.
type Cache struct {
	sh        [shards]shard
	seed      maphash.Seed
	perShard  int
	MaxTTL    time.Duration // cap on positive TTLs
	MaxNegTTL time.Duration // cap on negative TTLs (RFC 2308 suggests 1-3 h)
	Now       func() time.Time
}

// New makes a cache holding about maxEntries entries.
func New(maxEntries int) *Cache {
	c := &Cache{
		seed:      maphash.MakeSeed(),
		perShard:  max(1, maxEntries/shards),
		MaxTTL:    24 * time.Hour,
		MaxNegTTL: time.Hour,
		Now:       time.Now,
	}
	for i := range c.sh {
		c.sh[i].m = make(map[key]*entry)
	}
	return c
}

func (c *Cache) shard(name string) *shard {
	return &c.sh[maphash.String(c.seed, name)%shards]
}

// Result is what a lookup returns. TTLs are already decremented by the time
// the entry has spent in the cache.
type Result struct {
	Rcode     uint8
	Answer    []dnswire.RR
	Authority []dnswire.RR
}

// Get looks up (name, qtype). A cached NXDOMAIN for the name matches any type.
func (c *Cache) Get(name string, qtype uint16) (Result, bool) {
	if r, ok := c.get(name, qtype); ok {
		return r, true
	}
	return c.get(name, TypeNXDomain)
}

func (c *Cache) get(name string, qtype uint16) (Result, bool) {
	s := c.shard(name)
	now := c.Now()
	k := key{name, qtype}
	s.mu.Lock()
	e, ok := s.m[k]
	if ok && !now.Before(e.expires) {
		delete(s.m, k)
		ok = false
	}
	s.mu.Unlock()
	if !ok {
		return Result{}, false
	}
	// Entries are immutable once stored, so copying outside the lock is safe.
	elapsed := uint32(now.Sub(e.stored) / time.Second)
	return Result{Rcode: e.rcode, Answer: aged(e.answer, elapsed), Authority: aged(e.authority, elapsed)}, true
}

func aged(rrs []dnswire.RR, elapsed uint32) []dnswire.RR {
	if len(rrs) == 0 {
		return nil
	}
	out := make([]dnswire.RR, len(rrs))
	copy(out, rrs)
	for i := range out {
		if out[i].TTL > elapsed {
			out[i].TTL -= elapsed
		} else {
			out[i].TTL = 0
		}
	}
	return out
}

// SetPositive caches an answer. The entry lives for the smallest TTL in the
// answer, capped at MaxTTL. Zero-TTL answers are not cached.
func (c *Cache) SetPositive(name string, qtype uint16, answer, authority []dnswire.RR) {
	if len(answer) == 0 {
		return
	}
	ttl := answer[0].TTL
	for _, rr := range answer[1:] {
		ttl = min(ttl, rr.TTL)
	}
	d := min(time.Duration(ttl)*time.Second, c.MaxTTL)
	if d <= 0 {
		return
	}
	// Normalise the stored TTLs to the entry lifetime so ageing is consistent.
	ans := capTTL(answer, uint32(d/time.Second))
	c.put(key{name, qtype}, &entry{rcode: dnswire.RcodeSuccess, answer: ans, authority: authority}, d)
}

// SetNegative caches NXDOMAIN or NODATA. The lifetime comes from the SOA in
// the authority section: min(SOA TTL, SOA MINIMUM), capped at MaxNegTTL.
// Without an SOA there is no negative TTL, so nothing is cached (RFC 2308
// section 5). It reports whether it cached.
func (c *Cache) SetNegative(name string, qtype uint16, rcode uint8, authority []dnswire.RR) bool {
	var ttl uint32
	found := false
	for _, rr := range authority {
		if v, ok := rr.SOANegTTL(); ok {
			ttl, found = v, true
			break
		}
	}
	if !found {
		return false
	}
	d := min(time.Duration(ttl)*time.Second, c.MaxNegTTL)
	if d <= 0 {
		return false
	}
	if rcode == dnswire.RcodeNXDomain {
		qtype = TypeNXDomain
	}
	c.put(key{name, qtype}, &entry{rcode: rcode, authority: capTTL(authority, uint32(d/time.Second))}, d)
	return true
}

func capTTL(rrs []dnswire.RR, ttl uint32) []dnswire.RR {
	out := make([]dnswire.RR, len(rrs))
	copy(out, rrs)
	for i := range out {
		out[i].TTL = min(out[i].TTL, ttl)
	}
	return out
}

func (c *Cache) put(k key, e *entry, d time.Duration) {
	now := c.Now()
	e.stored, e.expires = now, now.Add(d)
	s := c.shard(k.name)
	s.mu.Lock()
	if _, exists := s.m[k]; !exists && len(s.m) >= c.perShard {
		c.evict(s, now)
	}
	s.m[k] = e
	s.mu.Unlock()
}

// evict removes one entry: the first expired one among up to 8 sampled,
// otherwise the first sampled (a random entry).
func (c *Cache) evict(s *shard, now time.Time) {
	var victim key
	n := 0
	for k, e := range s.m {
		if n == 0 {
			victim = k
		}
		if !now.Before(e.expires) {
			victim = k
			break
		}
		if n++; n >= 8 {
			break
		}
	}
	delete(s.m, victim)
}

// Len returns the number of entries, including expired ones not yet removed.
func (c *Cache) Len() int {
	n := 0
	for i := range c.sh {
		c.sh[i].mu.Lock()
		n += len(c.sh[i].m)
		c.sh[i].mu.Unlock()
	}
	return n
}
