// Package policy decides, per subscriber, whether a name is blocked.
//
// Threat lists are loaded from RPZ zone files (Response Policy Zones, the
// format DNS threat feeds are published in) or plain hosts/domain lists.
// RPZ QNAME-trigger semantics are kept exactly:
//
//	evil.com      CNAME .              -> NXDOMAIN for evil.com only
//	*.evil.com    CNAME .              -> NXDOMAIN for every name below it
//	ok.evil.com   CNAME rpz-passthru.  -> allow (an exception)
//	x.com         CNAME *.             -> NODATA
//	x.com         CNAME rpz-drop.      -> no response at all
//	x.com         A     10.0.0.53      -> answer with a walled-garden address
//
// Matching is a hash lookup for the exact name, then one per parent suffix
// for wildcards: at most one lookup per label, no allocation.
package policy

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/Other-Now/nano-dns/dnswire"
)

// Action is what a matching rule does.
type Action uint8

const (
	None Action = iota
	NXDomain
	NoData
	Drop
	Passthru
	Redirect
)

func (a Action) String() string {
	return [...]string{"none", "nxdomain", "nodata", "drop", "passthru", "redirect"}[a]
}

// Rule is one policy entry.
type Rule struct {
	Action Action
	Addr   netip.Addr // for Redirect
}

// List is one loaded feed.
type List struct {
	Name  string
	exact map[string]Rule // "evil.com."
	wild  map[string]Rule // "*.evil.com" stored as "evil.com."
}

// NewList makes an empty list.
func NewList(name string) *List {
	return &List{Name: name, exact: map[string]Rule{}, wild: map[string]Rule{}}
}

// Len is the number of rules.
func (l *List) Len() int { return len(l.exact) + len(l.wild) }

// Add adds a rule. A leading "*." makes it a wildcard rule.
func (l *List) Add(name string, r Rule) {
	name = dnswire.Canonical(name)
	if strings.HasPrefix(name, "*.") {
		l.wild[name[2:]] = r
	} else {
		l.exact[name] = r
	}
}

// Match finds the rule for a canonical name: an exact rule wins, then the
// closest wildcard. RPZ wildcards match only strictly-below names.
func (l *List) Match(name string) (Rule, bool) {
	if r, ok := l.exact[name]; ok {
		return r, true
	}
	for i := 0; i < len(name)-1; i++ {
		if name[i] == '.' {
			if r, ok := l.wild[name[i+1:]]; ok {
				return r, true
			}
		}
	}
	return Rule{}, false
}

// LoadRPZ reads an RPZ zone file. Owner names are relative to the RPZ zone
// (they carry no trailing dot); SOA/NS/$-directives are skipped. It returns
// the number of lines it could not use.
func (l *List) LoadRPZ(rd io.Reader) (skipped int, err error) {
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, ';'); i >= 0 {
			line = line[:i]
		}
		if line == "" || line[0] == ' ' || line[0] == '\t' || line[0] == '$' || line[0] == '@' {
			continue // blank, continuation of the SOA/NS block, directive
		}
		f := strings.Fields(line)
		if len(f) < 3 {
			skipped++
			continue
		}
		owner := f[0]
		f = f[1:]
		// optional TTL and class
		for len(f) > 2 && (isNumber(f[0]) || strings.EqualFold(f[0], "IN")) {
			f = f[1:]
		}
		typ, data := strings.ToUpper(f[0]), f[1]
		var r Rule
		switch {
		case typ == "CNAME" && data == ".":
			r.Action = NXDomain
		case typ == "CNAME" && data == "*.":
			r.Action = NoData
		case typ == "CNAME" && strings.EqualFold(data, "rpz-passthru."):
			r.Action = Passthru
		case typ == "CNAME" && strings.EqualFold(data, "rpz-drop."):
			r.Action = Drop
		case typ == "A" || typ == "AAAA":
			a, perr := netip.ParseAddr(data)
			if perr != nil {
				skipped++
				continue
			}
			r = Rule{Action: Redirect, Addr: a}
		case typ == "SOA" || typ == "NS":
			continue
		default:
			skipped++ // e.g. CNAME to a real name (rewrite): not supported
			continue
		}
		if strings.HasSuffix(owner, ".") { // absolute owner: not RPZ-relative, skip
			skipped++
			continue
		}
		l.Add(owner, r)
	}
	return skipped, sc.Err()
}

// LoadDomains reads a plain list ("evil.com" per line) or a hosts file
// ("0.0.0.0 evil.com"). Each domain blocks itself and everything below it,
// which is what people mean by a domain blocklist.
func (l *List) LoadDomains(rd io.Reader) error {
	sc := bufio.NewScanner(rd)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		d := f[len(f)-1]
		if d == "localhost" || strings.HasSuffix(d, ".localdomain") {
			continue
		}
		l.Add(d, Rule{Action: NXDomain})
		l.Add("*."+d, Rule{Action: NXDomain})
	}
	return sc.Err()
}

func isNumber(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// String summarises a list.
func (l *List) String() string {
	return fmt.Sprintf("%s(%d exact, %d wildcard)", l.Name, len(l.exact), len(l.wild))
}
