// Package resolver is an iterative (recursive-from-the-roots) DNS resolver.
//
// For a name it starts at the closest zone cut it already knows (from the
// cache) or at the root, follows referrals down the tree, and chases CNAMEs
// across zones. Everything learnt is cached: answers, negative answers
// (RFC 2308), and delegations (NS + glue), so the next lookup under the same
// zone skips the root and TLD.
//
// Safety rules applied to every response:
//   - bailiwick: a server for zone Z is only believed about names under Z.
//     Answer records outside Z and out-of-bailiwick glue are dropped;
//   - a referral must point strictly below the zone we asked, and at or
//     above the name we asked about (no sideways or upward referrals).
//
// Optional QNAME minimisation (RFC 9156): each server is only told one label
// more than the zone it serves, so the root sees "com." and not the full name.
package resolver

import (
	"context"
	"errors"
	"math/rand/v2"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/Other-Now/nano-dns/cache"
	"github.com/Other-Now/nano-dns/dnswire"
)

// Config configures a Resolver.
type Config struct {
	Roots []netip.AddrPort
	// UpstreamPort is used for name-server addresses learnt from DNS data:
	// 53 on the internet, the simulator's port in tests.
	UpstreamPort uint16
	QMin         bool
	Timeout      time.Duration // per upstream attempt (default 800 ms)
	Tries        int           // servers tried per step (default 3)
	Cache        *cache.Cache
	// OnUpstream, if set, sees every query sent upstream.
	OnUpstream func(server netip.AddrPort, name string, qtype uint16)
}

// Stats are cumulative counters.
type Stats struct {
	Upstream         atomic.Int64 // queries sent upstream (UDP)
	UpstreamTCP      atomic.Int64 // TCP retries after TC=1
	Timeouts         atomic.Int64
	Mismatched       atomic.Int64 // replies with wrong ID/question (possible spoofing)
	Referrals        atomic.Int64
	BailiwickDropped atomic.Int64 // records dropped for being out of bailiwick
}

// Resolver is safe for concurrent use.
type Resolver struct {
	cfg   Config
	stats Stats
}

// Result is an answer: rcode plus answer and authority sections.
type Result = cache.Result

var (
	errNotCached = errors.New("resolver: not cached")
	errDepth     = errors.New("resolver: too much recursion (NS lookups)")
	errCNAME     = errors.New("resolver: CNAME chain too long")
	errSteps     = errors.New("resolver: too many referrals")
	errLame      = errors.New("resolver: lame or bogus response")
	errBogus     = errors.New("resolver: answer had no in-bailiwick data")
	errNoNS      = errors.New("resolver: no usable name-server address")
)

const (
	maxDepth = 6
	maxCNAME = 8
	maxSteps = 24
)

// New returns a resolver. cfg.Cache must be set.
func New(cfg Config) *Resolver {
	if cfg.Timeout == 0 {
		cfg.Timeout = 800 * time.Millisecond
	}
	if cfg.Tries == 0 {
		cfg.Tries = 3
	}
	if cfg.UpstreamPort == 0 {
		cfg.UpstreamPort = 53
	}
	return &Resolver{cfg: cfg}
}

// Stats returns the live counters.
func (r *Resolver) Stats() *Stats { return &r.stats }

// Lookup answers from the cache only, following cached CNAMEs.
func (r *Resolver) Lookup(name string, qtype uint16) (Result, bool) {
	res, err := r.chase(context.Background(), dnswire.Canonical(name), qtype, 0, true)
	return res, err == nil
}

// Resolve answers from the cache or by iterating from the closest known zone
// cut. On error the Result has Rcode SERVFAIL.
func (r *Resolver) Resolve(ctx context.Context, name string, qtype uint16) (Result, error) {
	res, err := r.chase(ctx, dnswire.Canonical(name), qtype, 0, false)
	if err != nil {
		return Result{Rcode: dnswire.RcodeServFail}, err
	}
	return res, nil
}

// chase resolves name and follows CNAMEs that leave the zone they came from.
func (r *Resolver) chase(ctx context.Context, name string, qtype uint16, depth int, cacheOnly bool) (Result, error) {
	var chain []dnswire.RR
	cur := name
	for hops := 0; hops <= maxCNAME; hops++ {
		res, ok := r.cachedOne(cur, qtype)
		if !ok {
			if cacheOnly {
				return Result{}, errNotCached
			}
			var err error
			if res, err = r.iterate(ctx, cur, qtype, depth); err != nil {
				return Result{}, err
			}
		}
		chain = append(chain, res.Answer...)
		if res.Rcode != dnswire.RcodeSuccess || qtype == dnswire.TypeCNAME {
			return Result{Rcode: res.Rcode, Answer: chain, Authority: res.Authority}, nil
		}
		next, dangling := danglingCNAME(res.Answer, cur, qtype)
		if !dangling {
			return Result{Rcode: dnswire.RcodeSuccess, Answer: chain, Authority: res.Authority}, nil
		}
		cur = next
	}
	return Result{}, errCNAME
}

func (r *Resolver) cachedOne(name string, qtype uint16) (Result, bool) {
	if res, ok := r.cfg.Cache.Get(name, qtype); ok {
		return res, true
	}
	if qtype != dnswire.TypeCNAME {
		if res, ok := r.cfg.Cache.Get(name, dnswire.TypeCNAME); ok && res.Rcode == dnswire.RcodeSuccess && len(res.Answer) > 0 {
			return res, true
		}
	}
	return Result{}, false
}

// danglingCNAME follows the CNAME chain from name inside ans. If the chain
// ends at a name that has no qtype data in ans, it returns that name.
func danglingCNAME(ans []dnswire.RR, name string, qtype uint16) (string, bool) {
	cur := name
	for hops := 0; hops <= maxCNAME; hops++ {
		next := ""
		for _, rr := range ans {
			if rr.Name != cur {
				continue
			}
			if rr.Type == qtype {
				return "", false
			}
			if rr.Type == dnswire.TypeCNAME {
				next, _ = rr.Target()
			}
		}
		if next == "" {
			return cur, cur != name
		}
		cur = next
	}
	return "", false
}

type kind int

const (
	kAnswer kind = iota
	kNXDomain
	kNoData
	kReferral
	kLame
)

// classify decides what a response to (qn, qt) from a server for zone means.
// For a referral it also returns the child zone.
func classify(resp *dnswire.Msg, qn string, qt uint16, zone string) (kind, string) {
	if resp.Rcode == dnswire.RcodeNXDomain {
		return kNXDomain, ""
	}
	for _, rr := range resp.Answer {
		if rr.Name == qn && (rr.Type == qt || rr.Type == dnswire.TypeCNAME) {
			return kAnswer, ""
		}
	}
	sawNS := false
	for _, rr := range resp.Authority {
		if rr.Type != dnswire.TypeNS {
			continue
		}
		sawNS = true
		if rr.Name != zone && dnswire.IsSubdomain(rr.Name, zone) && dnswire.IsSubdomain(qn, rr.Name) {
			return kReferral, rr.Name
		}
	}
	if sawNS && !resp.Authoritative {
		return kLame, "" // upward or sideways referral
	}
	return kNoData, ""
}

// iterate walks referrals from the closest known zone cut down to name.
func (r *Resolver) iterate(ctx context.Context, name string, qtype uint16, depth int) (Result, error) {
	if depth > maxDepth {
		return Result{}, errDepth
	}
	zone, servers := r.closest(name)
	qn := name
	if r.cfg.QMin && zone != name {
		qn = dnswire.ChildOf(name, zone)
	}
	for step := 0; step < maxSteps; step++ {
		qt := qtype
		if qn != name {
			qt = dnswire.TypeA // RFC 9156 2.3: A for the hidden steps
		}
		resp, err := r.exchangeAny(ctx, servers, qn, qt)
		if err != nil {
			return Result{}, err
		}
		k, child := classify(resp, qn, qt, zone)
		switch k {
		case kAnswer, kNoData:
			if qn != name { // QMIN: not a zone cut; reveal one more label
				qn = dnswire.ChildOf(name, qn)
				continue
			}
			if k == kNoData {
				auth := soaOnly(resp.Authority, zone)
				r.cfg.Cache.SetNegative(name, qtype, dnswire.RcodeSuccess, auth)
				return Result{Rcode: dnswire.RcodeSuccess, Authority: auth}, nil
			}
			ans := r.filterAnswer(resp, name, qtype, zone)
			if len(ans) == 0 {
				return Result{}, errBogus
			}
			r.cacheAnswer(name, qtype, ans)
			return Result{Rcode: dnswire.RcodeSuccess, Answer: ans}, nil

		case kNXDomain:
			if qn != name {
				// Some servers wrongly say NXDOMAIN for empty non-terminals;
				// RFC 9156 lets us fall back to the full name once.
				qn = name
				continue
			}
			auth := soaOnly(resp.Authority, zone)
			r.cfg.Cache.SetNegative(name, qtype, dnswire.RcodeNXDomain, auth)
			return Result{Rcode: dnswire.RcodeNXDomain, Authority: auth}, nil

		case kReferral:
			r.stats.Referrals.Add(1)
			nsrrs, glue := r.referralData(resp, child, zone)
			r.cfg.Cache.SetPositive(child, dnswire.TypeNS, nsrrs, nil)
			for owner, rrs := range glue {
				r.cfg.Cache.SetPositive(owner, dnswire.TypeA, rrs, nil)
			}
			if servers, err = r.serversFor(ctx, child, nsrrs, glue, depth); err != nil {
				return Result{}, err
			}
			zone = child
			if r.cfg.QMin && child != name {
				qn = dnswire.ChildOf(name, child)
			} else {
				qn = name
			}

		default:
			return Result{}, errLame
		}
	}
	return Result{}, errSteps
}

// closest returns the deepest cached zone cut above name that has at least
// one cached server address, or the root.
func (r *Resolver) closest(name string) (string, []netip.AddrPort) {
	for z := name; ; z = dnswire.Parent(z) {
		if res, ok := r.cfg.Cache.Get(z, dnswire.TypeNS); ok && res.Rcode == dnswire.RcodeSuccess {
			var addrs []netip.AddrPort
			for _, rr := range res.Answer {
				t, ok := rr.Target()
				if !ok {
					continue
				}
				if ar, ok := r.cfg.Cache.Get(t, dnswire.TypeA); ok {
					addrs = append(addrs, r.addrsOf(ar.Answer)...)
				}
			}
			if len(addrs) > 0 {
				return z, addrs
			}
		}
		if z == "." {
			return ".", r.cfg.Roots
		}
	}
}

func (r *Resolver) addrsOf(rrs []dnswire.RR) []netip.AddrPort {
	var out []netip.AddrPort
	for _, rr := range rrs {
		// IPv4 only: this lab has no IPv6 upstream connectivity.
		if a, ok := rr.Addr(); ok && a.Is4() {
			out = append(out, netip.AddrPortFrom(a, r.cfg.UpstreamPort))
		}
	}
	return out
}

// referralData extracts the NS set for child and the glue we are willing to
// believe: address records for those NS names that are inside the bailiwick
// of the zone whose server sent the referral.
func (r *Resolver) referralData(resp *dnswire.Msg, child, zone string) ([]dnswire.RR, map[string][]dnswire.RR) {
	var nsrrs []dnswire.RR
	targets := map[string]bool{}
	for _, rr := range resp.Authority {
		if rr.Type == dnswire.TypeNS && rr.Name == child {
			nsrrs = append(nsrrs, rr)
			if t, ok := rr.Target(); ok {
				targets[t] = true
			}
		}
	}
	glue := map[string][]dnswire.RR{}
	for _, rr := range resp.Additional {
		if rr.Type != dnswire.TypeA || !targets[rr.Name] {
			continue
		}
		if !dnswire.IsSubdomain(rr.Name, zone) {
			r.stats.BailiwickDropped.Add(1)
			continue
		}
		glue[rr.Name] = append(glue[rr.Name], rr)
	}
	return nsrrs, glue
}

// serversFor turns a delegation into addresses: glue first, otherwise
// resolve the NS names (each a full resolution, one level deeper).
func (r *Resolver) serversFor(ctx context.Context, child string, nsrrs []dnswire.RR, glue map[string][]dnswire.RR, depth int) ([]netip.AddrPort, error) {
	var addrs []netip.AddrPort
	for _, rrs := range glue {
		addrs = append(addrs, r.addrsOf(rrs)...)
	}
	if len(addrs) > 0 {
		return addrs, nil
	}
	var targets []string
	for _, rr := range nsrrs {
		if t, ok := rr.Target(); ok && !dnswire.IsSubdomain(t, child) {
			targets = append(targets, t) // in-child NS names need glue we don't have
		}
	}
	// Resolve two NS names (trying at most three), so the zone has more than
	// one server to fall back on.
	rand.Shuffle(len(targets), func(i, j int) { targets[i], targets[j] = targets[j], targets[i] })
	resolved := 0
	for i, t := range targets {
		if i >= 3 || resolved == 2 {
			break
		}
		res, err := r.chase(ctx, t, dnswire.TypeA, depth+1, false)
		if err != nil {
			continue
		}
		if a := r.addrsOf(res.Answer); len(a) > 0 {
			addrs = append(addrs, a...)
			resolved++
		}
	}
	if len(addrs) == 0 {
		return nil, errNoNS
	}
	return addrs, nil
}

// filterAnswer keeps the CNAME chain from name and the final qtype records,
// stopping where the chain leaves the zone of the server that answered.
func (r *Resolver) filterAnswer(resp *dnswire.Msg, name string, qtype uint16, zone string) []dnswire.RR {
	var out []dnswire.RR
	cur := name
	for hops := 0; hops <= maxCNAME && dnswire.IsSubdomain(cur, zone); hops++ {
		found := false
		next := ""
		for _, rr := range resp.Answer {
			if rr.Name != cur || rr.Class != dnswire.ClassINET {
				continue
			}
			if rr.Type == qtype {
				out = append(out, rr)
				found = true
			} else if rr.Type == dnswire.TypeCNAME && next == "" {
				out = append(out, rr)
				next, _ = rr.Target()
			}
		}
		if found || next == "" {
			break
		}
		cur = next
	}
	if d := len(resp.Answer) - len(out); d > 0 {
		r.stats.BailiwickDropped.Add(int64(d))
	}
	return out
}

// cacheAnswer stores the whole chain under the query, and each piece under
// its own owner so other queries can reuse it.
func (r *Resolver) cacheAnswer(name string, qtype uint16, ans []dnswire.RR) {
	r.cfg.Cache.SetPositive(name, qtype, ans, nil)
	byOwner := map[string][]dnswire.RR{}
	for _, rr := range ans {
		if rr.Name == name {
			continue
		}
		byOwner[rr.Name] = append(byOwner[rr.Name], rr)
	}
	for owner, rrs := range byOwner {
		r.cfg.Cache.SetPositive(owner, rrs[0].Type, rrs, nil)
	}
	for _, rr := range ans {
		if rr.Type == dnswire.TypeCNAME && rr.Name == name && qtype != dnswire.TypeCNAME {
			r.cfg.Cache.SetPositive(name, dnswire.TypeCNAME, []dnswire.RR{rr}, nil)
		}
	}
}

// soaOnly keeps the zone's SOA from an authority section (for negative
// caching) and drops anything else.
func soaOnly(auth []dnswire.RR, zone string) []dnswire.RR {
	for _, rr := range auth {
		if rr.Type == dnswire.TypeSOA && dnswire.IsSubdomain(rr.Name, zone) {
			return []dnswire.RR{rr}
		}
	}
	return nil
}
