// Package authsim is a tiny authoritative DNS server plus a simulated
// root -> TLD -> zone hierarchy on loopback addresses (127.0.1.x).
//
// It exists so the resolver can be tested and benchmarked end to end,
// including attack traffic, without sending a single packet to a real
// authoritative server.
package authsim

import (
	"github.com/Other-Now/nano-dns/dnswire"
)

// Zone is one authoritative zone held in memory.
type Zone struct {
	Origin  string
	soa     dnswire.RR
	records map[string][]dnswire.RR // owner -> all records at that owner
	exists  map[string]bool         // owners plus empty non-terminals
	cuts    map[string][]dnswire.RR // delegated child apex -> NS records
	glue    map[string][]dnswire.RR // address records for NS targets
}

// NewZone makes a zone whose negative answers carry an SOA with the given
// MINIMUM (the negative-caching TTL).
func NewZone(origin string, negTTL uint32) *Zone {
	z := &Zone{
		Origin:  origin,
		records: map[string][]dnswire.RR{},
		exists:  map[string]bool{},
		cuts:    map[string][]dnswire.RR{},
		glue:    map[string][]dnswire.RR{},
	}
	z.soa = dnswire.NewSOA(origin, 3600, "ns."+trimRoot(origin), "hostmaster."+trimRoot(origin), 1, negTTL)
	z.exists[origin] = true
	return z
}

func trimRoot(s string) string {
	if s == "." {
		return ""
	}
	return s
}

// Add adds a record. An NS record below the apex creates a delegation.
func (z *Zone) Add(rrs ...dnswire.RR) *Zone {
	for _, rr := range rrs {
		if rr.Type == dnswire.TypeNS && rr.Name != z.Origin {
			z.cuts[rr.Name] = append(z.cuts[rr.Name], rr)
			continue
		}
		z.records[rr.Name] = append(z.records[rr.Name], rr)
		for n := rr.Name; n != z.Origin && n != "."; n = dnswire.Parent(n) {
			z.exists[n] = true
		}
	}
	return z
}

// Glue adds an address record that is returned with referrals.
func (z *Zone) Glue(rr dnswire.RR) *Zone {
	z.glue[rr.Name] = append(z.glue[rr.Name], rr)
	return z
}

// Answer builds the authoritative response for q.
func (z *Zone) Answer(q dnswire.Question) *dnswire.Msg {
	m := &dnswire.Msg{Response: true}
	name := q.Name

	// 1. Delegation at or above the name (but below the apex) -> referral.
	for n := name; n != z.Origin && n != "."; n = dnswire.Parent(n) {
		if ns, ok := z.cuts[n]; ok {
			m.Authority = append(m.Authority, ns...)
			for _, rr := range ns {
				t, _ := rr.Target()
				m.Additional = append(m.Additional, z.glue[t]...)
				m.Additional = append(m.Additional, z.addrs(t)...)
			}
			return m
		}
	}

	m.Authoritative = true
	// 2. Data at the name, following in-zone CNAMEs.
	cur := name
	for hops := 0; hops < 8; hops++ {
		rrs := z.records[cur]
		var match []dnswire.RR
		var cname *dnswire.RR
		for i := range rrs {
			if rrs[i].Type == q.Type || q.Type == dnswire.TypeANY {
				match = append(match, rrs[i])
			} else if rrs[i].Type == dnswire.TypeCNAME {
				cname = &rrs[i]
			}
		}
		if len(match) > 0 {
			m.Answer = append(m.Answer, match...)
			return m
		}
		if cname != nil {
			m.Answer = append(m.Answer, *cname)
			t, _ := cname.Target()
			if !dnswire.IsSubdomain(t, z.Origin) {
				return m // target is elsewhere; the resolver chases it
			}
			cur = t
			continue
		}
		break
	}
	if len(m.Answer) > 0 {
		return m
	}
	if z.exists[cur] {
		m.Authority = []dnswire.RR{z.soa} // NODATA
		return m
	}
	m.Rcode = dnswire.RcodeNXDomain
	m.Authority = []dnswire.RR{z.soa}
	return m
}

func (z *Zone) addrs(name string) []dnswire.RR {
	var out []dnswire.RR
	for _, rr := range z.records[name] {
		if rr.Type == dnswire.TypeA || rr.Type == dnswire.TypeAAAA {
			out = append(out, rr)
		}
	}
	return out
}
