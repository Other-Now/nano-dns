package policy

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

const sampleRPZ = `$TTL 30
@ IN SOA localhost. root.localhost. 1 86400 3600 604800 30
 NS localhost.
; comment
evil.com CNAME .
*.evil.com CNAME .
ok.evil.com CNAME rpz-passthru.
quiet.example 300 IN CNAME *.
gone.example CNAME rpz-drop.
garden.example A 10.0.0.53
rewrite.example CNAME www.other.example.
`

func TestRPZSemantics(t *testing.T) {
	l := NewList("t")
	skipped, err := l.LoadRPZ(strings.NewReader(sampleRPZ))
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 1 { // the CNAME rewrite
		t.Fatalf("skipped %d, want 1", skipped)
	}
	cases := []struct {
		name string
		want Action
	}{
		{"evil.com.", NXDomain},
		{"a.b.evil.com.", NXDomain}, // wildcard
		{"ok.evil.com.", Passthru},  // exact beats wildcard
		{"x.ok.evil.com.", NXDomain},
		{"notevil.com.", None}, // suffix match must be on a label boundary
		{"quiet.example.", NoData},
		{"gone.example.", Drop},
		{"garden.example.", Redirect},
		{"sub.garden.example.", None}, // no wildcard for garden
	}
	for _, c := range cases {
		r, _ := l.Match(c.name)
		if r.Action != c.want {
			t.Errorf("%s: got %v want %v", c.name, r.Action, c.want)
		}
	}
}

func TestHostsFileBlocksSubdomains(t *testing.T) {
	l := NewList("h")
	l.LoadDomains(strings.NewReader("# hosts\n0.0.0.0 tracker.example\n127.0.0.1 localhost\nads.example\n"))
	for _, n := range []string{"tracker.example.", "a.tracker.example.", "ads.example."} {
		if r, _ := l.Match(n); r.Action != NXDomain {
			t.Errorf("%s not blocked", n)
		}
	}
	if _, ok := l.Match("localhost."); ok {
		t.Error("localhost blocked")
	}
}

func TestSubscriberLongestPrefix(t *testing.T) {
	threats, adult := NewList("threats"), NewList("adult")
	threats.Add("evil.com", Rule{Action: NXDomain})
	adult.Add("*.adult.example", Rule{Action: Redirect, Addr: netip.MustParseAddr("10.0.0.53")})
	def := &Profile{Name: "default", Lists: []*List{threats}}
	family := &Profile{Name: "family", Lists: []*List{threats, adult}}
	e := NewEngine(def)
	e.AddSubscriber(netip.MustParsePrefix("10.1.0.0/16"), family)
	e.AddSubscriber(netip.MustParsePrefix("10.1.2.0/24"), def) // carve-out

	if p := e.ProfileFor(netip.MustParseAddr("10.1.9.9")); p != family {
		t.Fatalf("10.1.9.9 -> %s", p.Name)
	}
	if p := e.ProfileFor(netip.MustParseAddr("10.1.2.3")); p != def {
		t.Fatalf("10.1.2.3 -> %s (longest prefix must win)", p.Name)
	}
	if r, _ := family.Match("www.adult.example."); r.Action != Redirect {
		t.Fatal("family profile does not redirect adult")
	}
	if r, _ := def.Match("www.adult.example."); r.Action != None {
		t.Fatal("default profile blocks adult")
	}
}

// BenchmarkMatch: per-query cost against a 1M-rule list, for a clean name
// (worst case: every suffix probed) and a blocked one.
func BenchmarkMatch(b *testing.B) {
	l := NewList("big")
	for i := 0; i < 500_000; i++ {
		l.Add(fmt.Sprintf("bad%d.example", i), Rule{Action: NXDomain})
		l.Add(fmt.Sprintf("*.bad%d.example", i), Rule{Action: NXDomain})
	}
	b.Run("clean-4-labels", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			l.Match("static.cdn.goodsite.com.")
		}
	})
	b.Run("blocked-wildcard", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			l.Match("x.bad123.example.")
		}
	})
}
