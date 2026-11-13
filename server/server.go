// Package server is the client-facing side: UDP and TCP listeners, policy,
// abuse guards, cache fast path and the slow path into the resolver.
//
// Per query, in order:
//
//	parse/validate -> subscriber policy (RPZ) -> cache (inline, on the
//	socket's reader goroutine) -> [miss] water-torture gate -> coalesce
//	identical in-flight queries -> iterate -> policy on CNAME targets ->
//	RRL -> send
package server

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/Other-Now/nano-dns/dnswire"
	"github.com/Other-Now/nano-dns/guard"
	"github.com/Other-Now/nano-dns/policy"
	"github.com/Other-Now/nano-dns/resolver"
)

// Config configures a Server.
type Config struct {
	Listen string // e.g. "127.0.0.1:5354"
	// Sockets is the number of UDP sockets bound with SO_REUSEPORT (Linux
	// only; elsewhere 1). The kernel spreads clients across them by hash.
	Sockets int
	// Readers is the number of goroutines reading each socket.
	Readers      int
	Resolver     *resolver.Resolver
	Policy       *policy.Engine // nil: no blocking
	RRL          *guard.RRL     // nil: off
	Torture      *guard.Torture // nil: off
	Metrics      *Metrics
	QueryTimeout time.Duration
}

// Server answers recursive queries.
type Server struct {
	cfg   Config
	udp   []*net.UDPConn
	tcp   net.Listener
	fl    flight
	m     *Metrics
	close sync.Once
}

// New validates cfg and returns an unstarted server.
func New(cfg Config) *Server {
	if cfg.Sockets < 1 {
		cfg.Sockets = 1
	}
	if cfg.Readers < 1 {
		cfg.Readers = 1
	}
	if cfg.QueryTimeout == 0 {
		cfg.QueryTimeout = 3 * time.Second
	}
	if cfg.Metrics == nil {
		cfg.Metrics = NewMetrics(nil)
	}
	return &Server{cfg: cfg, m: cfg.Metrics, fl: flight{m: map[fkey]*call{}}}
}

// Start binds the sockets and serves in the background.
func (s *Server) Start() error {
	n := s.cfg.Sockets
	if !reusePortSupported {
		n = 1
	}
	for i := 0; i < n; i++ {
		c, err := listenUDP(s.cfg.Listen, n > 1)
		if err != nil {
			s.Close()
			return err
		}
		s.udp = append(s.udp, c)
		for j := 0; j < s.cfg.Readers; j++ {
			go s.readUDP(c)
		}
	}
	t, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		s.Close()
		return err
	}
	s.tcp = t
	go s.serveTCP()
	return nil
}

// Close stops listening.
func (s *Server) Close() {
	s.close.Do(func() {
		for _, c := range s.udp {
			c.Close()
		}
		if s.tcp != nil {
			s.tcp.Close()
		}
	})
}

func (s *Server) readUDP(c *net.UDPConn) {
	buf := make([]byte, 1500)
	for {
		n, from, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		start := time.Now()
		var q dnswire.Msg
		if err := q.Unpack(buf[:n]); err != nil {
			s.m.badRequest.Inc()
			continue // unparseable: dropping is safer than reflecting
		}
		resp, slow := s.fast(&q, from.Addr())
		if slow {
			go func() {
				resp := s.slow(&q, from.Addr())
				s.sendUDP(c, &q, resp, from)
				s.m.durMiss.Observe(time.Since(start).Seconds())
			}()
			continue
		}
		s.sendUDP(c, &q, resp, from)
		s.m.durFast.Observe(time.Since(start).Seconds())
	}
}

func (s *Server) sendUDP(c *net.UDPConn, q, resp *dnswire.Msg, to netip.AddrPort) {
	if resp == nil {
		return // policy drop
	}
	if s.cfg.RRL != nil {
		switch s.cfg.RRL.Check(to.Addr(), time.Now()) {
		case guard.Drop:
			s.m.rrlDrop.Inc()
			return
		case guard.Slip:
			s.m.rrlSlip.Inc()
			t := *resp
			t.Truncated, t.Answer, t.Authority, t.Additional = true, nil, nil, nil
			resp = &t
		}
	}
	limit := 512
	if sz, ok := q.EDNS(); ok {
		limit = int(min(max(sz, 512), 1232))
	}
	b, err := resp.PackLimit(limit)
	if err != nil {
		return
	}
	s.m.responses(resp.Rcode).Inc()
	c.WriteToUDPAddrPort(b, to)
}

// fast handles everything that needs no network I/O. It returns slow=true
// when the query has to go to the resolver.
func (s *Server) fast(q *dnswire.Msg, client netip.Addr) (resp *dnswire.Msg, slow bool) {
	if q.Response || len(q.Question) != 1 {
		s.m.badRequest.Inc()
		return reply(q, dnswire.RcodeFormErr, nil, nil), false
	}
	if q.Opcode != 0 {
		return reply(q, dnswire.RcodeNotImp, nil, nil), false
	}
	qq := q.Question[0]
	if qq.Class != dnswire.ClassINET || qq.Type == dnswire.TypeANY {
		// ANY is a favourite amplification vector; RFC 8482 lets us refuse it.
		return reply(q, dnswire.RcodeRefused, nil, nil), false
	}
	var prof *policy.Profile
	if s.cfg.Policy != nil {
		prof = s.cfg.Policy.ProfileFor(client)
		if r, l := prof.Match(qq.Name); r.Action != policy.None && r.Action != policy.Passthru {
			s.m.blocked(l.Name, r.Action).Inc()
			return blockReply(q, r), false
		}
	}
	res, ok := s.cfg.Resolver.Lookup(qq.Name, qq.Type)
	if !ok {
		return nil, true
	}
	s.m.cacheHit.Inc()
	return s.answer(q, prof, res), false
}

// slow resolves a cache miss.
func (s *Server) slow(q *dnswire.Msg, client netip.Addr) *dnswire.Msg {
	qq := q.Question[0]
	now := time.Now()
	if s.cfg.Torture != nil && !s.cfg.Torture.Allow(qq.Name, now) {
		s.m.mitigated.Inc()
		return reply(q, dnswire.RcodeServFail, nil, nil)
	}
	res, err, shared := s.fl.do(fkey{qq.Name, qq.Type}, func() (resolver.Result, error) {
		ctx, cancel := context.WithTimeout(context.Background(), s.cfg.QueryTimeout)
		defer cancel()
		return s.cfg.Resolver.Resolve(ctx, qq.Name, qq.Type)
	})
	if shared {
		s.m.coalesced.Inc()
	} else if s.cfg.Torture != nil {
		s.cfg.Torture.Observe(qq.Name, res.Rcode, len(res.Answer) > 0, time.Now())
	}
	if err != nil {
		s.m.servfail.Inc()
		return reply(q, dnswire.RcodeServFail, nil, nil)
	}
	s.m.resolved.Inc()
	var prof *policy.Profile
	if s.cfg.Policy != nil {
		prof = s.cfg.Policy.ProfileFor(client)
	}
	return s.answer(q, prof, res)
}

// answer turns a resolver result into a response, applying policy to every
// CNAME target in the chain: a clean name that aliases to a listed one is
// blocked too (RPZ applies triggers to the whole chain).
func (s *Server) answer(q *dnswire.Msg, prof *policy.Profile, res resolver.Result) *dnswire.Msg {
	if prof != nil {
		for _, rr := range res.Answer {
			if rr.Type != dnswire.TypeCNAME {
				continue
			}
			t, _ := rr.Target()
			if r, l := prof.Match(t); r.Action != policy.None && r.Action != policy.Passthru {
				s.m.blocked(l.Name, r.Action).Inc()
				return blockReply(q, r)
			}
		}
	}
	return reply(q, res.Rcode, res.Answer, res.Authority)
}

func reply(q *dnswire.Msg, rcode uint8, ans, auth []dnswire.RR) *dnswire.Msg {
	m := &dnswire.Msg{
		ID: q.ID, Response: true, Opcode: q.Opcode,
		RecursionDesired: q.RecursionDesired, RecursionAvailable: true,
		Rcode: rcode, Question: q.Question, Answer: ans, Authority: auth,
	}
	if _, ok := q.EDNS(); ok {
		m.SetEDNS(1232)
	}
	return m
}

var policySOA = dnswire.NewSOA("rpz.nano-dns.", 30, "localhost.", "root.localhost.", 1, 30)

func blockReply(q *dnswire.Msg, r policy.Rule) *dnswire.Msg {
	qq := q.Question[0]
	switch r.Action {
	case policy.Drop:
		return nil
	case policy.Redirect:
		if (qq.Type == dnswire.TypeA && r.Addr.Is4()) || (qq.Type == dnswire.TypeAAAA && r.Addr.Is6()) {
			return reply(q, dnswire.RcodeSuccess, []dnswire.RR{dnswire.NewA(qq.Name, 30, r.Addr)}, nil)
		}
		return reply(q, dnswire.RcodeSuccess, nil, []dnswire.RR{policySOA})
	case policy.NoData:
		return reply(q, dnswire.RcodeSuccess, nil, []dnswire.RR{policySOA})
	}
	return reply(q, dnswire.RcodeNXDomain, nil, []dnswire.RR{policySOA})
}

func (s *Server) serveTCP() {
	for {
		c, err := s.tcp.Accept()
		if err != nil {
			return
		}
		go s.handleTCP(c)
	}
}

func (s *Server) handleTCP(c net.Conn) {
	defer c.Close()
	client := netip.Addr{}
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		client = a.AddrPort().Addr()
	}
	var lb [2]byte
	for {
		c.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			return
		}
		buf := make([]byte, binary.BigEndian.Uint16(lb[:]))
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		var q dnswire.Msg
		if q.Unpack(buf) != nil {
			return
		}
		resp, slow := s.fast(&q, client)
		if slow {
			resp = s.slow(&q, client)
		}
		if resp == nil {
			continue
		}
		b, err := resp.Pack()
		if err != nil {
			return
		}
		s.m.responses(resp.Rcode).Inc()
		if _, err := c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...)); err != nil {
			return
		}
	}
}

// flight coalesces identical concurrent cache misses into one resolution
// (a small singleflight). Without it, a burst of N clients asking for the
// same just-expired name sends N identical queries upstream.
type fkey struct {
	name  string
	qtype uint16
}

type call struct {
	done chan struct{}
	res  resolver.Result
	err  error
}

type flight struct {
	mu sync.Mutex
	m  map[fkey]*call
}

func (f *flight) do(k fkey, fn func() (resolver.Result, error)) (resolver.Result, error, bool) {
	f.mu.Lock()
	if c, ok := f.m[k]; ok {
		f.mu.Unlock()
		<-c.done
		return c.res, c.err, true
	}
	c := &call{done: make(chan struct{})}
	f.m[k] = c
	f.mu.Unlock()
	c.res, c.err = fn()
	f.mu.Lock()
	delete(f.m, k)
	f.mu.Unlock()
	close(c.done)
	return c.res, c.err, false
}
