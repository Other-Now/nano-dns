package policy

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
)

// Profile is an ordered set of lists. The first list that matches decides,
// as with multiple RPZ zones: put allow-lists (passthru) first.
type Profile struct {
	Name  string
	Lists []*List
}

// Match returns the deciding rule and the list it came from.
func (p *Profile) Match(name string) (Rule, *List) {
	for _, l := range p.Lists {
		if r, ok := l.Match(name); ok {
			return r, l
		}
	}
	return Rule{}, nil
}

type subscriber struct {
	prefix  netip.Prefix
	profile *Profile
}

// Engine maps subscribers (client address prefixes) to profiles.
type Engine struct {
	subs    []subscriber // sorted longest prefix first
	Default *Profile
	Lists   map[string]*List
}

// ProfileFor returns the profile of the longest prefix containing addr.
// A linear scan is fine for a handful of subscriber blocks; a carrier with
// thousands would use a radix tree here.
func (e *Engine) ProfileFor(addr netip.Addr) *Profile {
	addr = addr.Unmap()
	for _, s := range e.subs {
		if s.prefix.Contains(addr) {
			return s.profile
		}
	}
	return e.Default
}

// Config is the JSON policy file.
//
//	{
//	  "lists":    {"threats": {"file": "feeds/tif.rpz", "format": "rpz"}},
//	  "profiles": {"default": ["threats"], "family": ["allow", "threats", "adult"]},
//	  "subscribers": [{"cidr": "10.1.0.0/16", "profile": "family"}],
//	  "default": "default"
//	}
type Config struct {
	Lists map[string]struct {
		File   string `json:"file"`
		Format string `json:"format"` // "rpz" or "domains"
	} `json:"lists"`
	Profiles    map[string][]string `json:"profiles"`
	Subscribers []struct {
		CIDR    string `json:"cidr"`
		Profile string `json:"profile"`
	} `json:"subscribers"`
	Default string `json:"default"`
}

// Load reads a JSON policy file. Feed paths are relative to the file.
func Load(path string) (*Engine, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("policy %s: %w", path, err)
	}
	e := &Engine{Lists: map[string]*List{}}
	for name, lc := range cfg.Lists {
		l := NewList(name)
		f, err := os.Open(filepath.Join(filepath.Dir(path), lc.File))
		if err != nil {
			return nil, err
		}
		if lc.Format == "domains" {
			err = l.LoadDomains(f)
		} else {
			_, err = l.LoadRPZ(f)
		}
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", name, err)
		}
		e.Lists[name] = l
	}
	profiles := map[string]*Profile{}
	for name, lists := range cfg.Profiles {
		p := &Profile{Name: name}
		for _, ln := range lists {
			l, ok := e.Lists[ln]
			if !ok {
				return nil, fmt.Errorf("profile %s: unknown list %q", name, ln)
			}
			p.Lists = append(p.Lists, l)
		}
		profiles[name] = p
	}
	for _, s := range cfg.Subscribers {
		pfx, err := netip.ParsePrefix(s.CIDR)
		if err != nil {
			return nil, err
		}
		p, ok := profiles[s.Profile]
		if !ok {
			return nil, fmt.Errorf("subscriber %s: unknown profile %q", s.CIDR, s.Profile)
		}
		e.subs = append(e.subs, subscriber{pfx.Masked(), p})
	}
	sort.SliceStable(e.subs, func(i, j int) bool { return e.subs[i].prefix.Bits() > e.subs[j].prefix.Bits() })
	if cfg.Default != "" {
		if e.Default = profiles[cfg.Default]; e.Default == nil {
			return nil, fmt.Errorf("unknown default profile %q", cfg.Default)
		}
	}
	if e.Default == nil {
		e.Default = &Profile{Name: "none"}
	}
	return e, nil
}

// NewEngine builds an engine in code (tests, benchmarks).
func NewEngine(def *Profile) *Engine {
	return &Engine{Default: def, Lists: map[string]*List{}}
}

// AddSubscriber maps a prefix to a profile.
func (e *Engine) AddSubscriber(p netip.Prefix, prof *Profile) {
	e.subs = append(e.subs, subscriber{p.Masked(), prof})
	sort.SliceStable(e.subs, func(i, j int) bool { return e.subs[i].prefix.Bits() > e.subs[j].prefix.Bits() })
}
