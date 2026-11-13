package guard

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/Other-Now/nano-dns/dnswire"
)

func TestRRLPerNetblock(t *testing.T) {
	r := NewRRL(10, 10, 2)
	now := time.Unix(0, 0)
	a := netip.MustParseAddr("192.0.2.1")
	sameBlock := netip.MustParseAddr("192.0.2.200")
	other := netip.MustParseAddr("198.51.100.1")
	for i := 0; i < 10; i++ {
		if r.Check(a, now) != Allow {
			t.Fatalf("burst denied at %d", i)
		}
	}
	// same /24 shares the bucket: limited now; slip=2 -> drop, slip, drop, slip
	got := []Verdict{r.Check(sameBlock, now), r.Check(a, now), r.Check(a, now), r.Check(a, now)}
	want := []Verdict{Drop, Slip, Drop, Slip}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("limited verdicts %v want %v", got, want)
		}
	}
	if r.Check(other, now) != Allow {
		t.Fatal("another netblock was limited")
	}
	// refill: 0.5 s at 10/s = 5 tokens
	now = now.Add(500 * time.Millisecond)
	for i := 0; i < 5; i++ {
		if r.Check(a, now) != Allow {
			t.Fatalf("refill: denied at %d", i)
		}
	}
}

func TestBase(t *testing.T) {
	for in, want := range map[string]string{
		"x7f3.victim.com.":      "victim.com.",
		"a.b.example.co.uk.":    "example.co.uk.",
		"foo.github.io.":        "foo.github.io.", // github.io is a public suffix
		"com.":                  "com.",
		"www.shop.example.org.": "example.org.",
	} {
		if got := Base(in); got != want {
			t.Errorf("Base(%s) = %s want %s", in, got, want)
		}
	}
}

func TestTortureMitigation(t *testing.T) {
	tt := NewTorture(time.Second, 50, 10*time.Second)
	now := time.Unix(100, 0)
	// before the attack, a legitimate name resolves
	tt.Observe("www.victim.com.", dnswire.RcodeSuccess, true, now)
	tt.Observe("api.victim.com.", dnswire.RcodeSuccess, true, now)
	// attack: 60 random names fail inside one window
	for i := 0; i < 60; i++ {
		name := fmt.Sprintf("r%dq.victim.com.", i)
		if !tt.Allow(name, now) && i < 49 {
			t.Fatalf("mitigation started early at %d", i)
		}
		tt.Observe(name, dnswire.RcodeNXDomain, false, now)
	}
	if tt.Allow("zz9.victim.com.", now) {
		t.Fatal("random name allowed during mitigation")
	}
	if !tt.Allow("www.victim.com.", now) {
		t.Fatal("known-good name blocked")
	}
	if !tt.Allow("www.other.com.", now) {
		t.Fatal("unrelated domain blocked")
	}
	// mitigation ends after Hold with no more failures
	if !tt.Allow("zz9.victim.com.", now.Add(11*time.Second)) {
		t.Fatal("mitigation never ended")
	}
}
