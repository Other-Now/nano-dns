package authsim

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Other-Now/nano-dns/dnswire"
)

// Server serves a set of zones on one address (UDP and TCP).
type Server struct {
	Addr  netip.AddrPort
	Zones []*Zone
	// Delay is added before every UDP reply (a simulated network RTT).
	Delay time.Duration
	// Capacity is the most UDP queries per second this server answers; the
	// rest are dropped, the way an overloaded authoritative server behaves.
	// 0 means unlimited.
	Capacity int
	// OnQuery, if set, sees every question received (before dropping).
	OnQuery func(q dnswire.Question)

	Queries atomic.Int64
	Dropped atomic.Int64

	udp *net.UDPConn
	tcp net.Listener

	mu        sync.Mutex
	winStart  time.Time
	winCount  int
	closeOnce sync.Once
}

// Start binds and serves in the background.
func (s *Server) Start() error {
	u, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(s.Addr))
	if err != nil {
		return err
	}
	t, err := net.Listen("tcp", s.Addr.String())
	if err != nil {
		u.Close()
		return err
	}
	s.udp, s.tcp = u, t
	go s.serveUDP()
	go s.serveTCP()
	return nil
}

// Close stops the server.
func (s *Server) Close() {
	s.closeOnce.Do(func() {
		s.udp.Close()
		s.tcp.Close()
	})
}

func (s *Server) admit() bool {
	if s.Capacity <= 0 {
		return true
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if now.Sub(s.winStart) >= 100*time.Millisecond {
		s.winStart, s.winCount = now, 0
	}
	s.winCount++
	return s.winCount <= s.Capacity/10 // budget per 100 ms window
}

func (s *Server) serveUDP() {
	buf := make([]byte, 4096)
	for {
		n, from, err := s.udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		s.Queries.Add(1)
		var q dnswire.Msg
		if q.Unpack(buf[:n]) != nil || len(q.Question) != 1 {
			continue
		}
		if s.OnQuery != nil {
			s.OnQuery(q.Question[0])
		}
		if !s.admit() {
			s.Dropped.Add(1)
			continue
		}
		limit := 512
		if sz, ok := q.EDNS(); ok && sz > 512 {
			limit = int(sz)
		}
		go func(q dnswire.Msg) {
			if s.Delay > 0 {
				time.Sleep(s.Delay)
			}
			out, err := s.respond(&q).PackLimit(limit)
			if err == nil {
				s.udp.WriteToUDPAddrPort(out, from)
			}
		}(q)
	}
}

func (s *Server) serveTCP() {
	for {
		c, err := s.tcp.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			var lb [2]byte
			for {
				if _, err := io.ReadFull(c, lb[:]); err != nil {
					return
				}
				msg := make([]byte, binary.BigEndian.Uint16(lb[:]))
				if _, err := io.ReadFull(c, msg); err != nil {
					return
				}
				s.Queries.Add(1)
				var q dnswire.Msg
				if q.Unpack(msg) != nil || len(q.Question) != 1 {
					return
				}
				out, err := s.respond(&q).Pack()
				if err != nil {
					return
				}
				c.Write(binary.BigEndian.AppendUint16(nil, uint16(len(out))))
				c.Write(out)
			}
		}()
	}
}

func (s *Server) respond(q *dnswire.Msg) *dnswire.Msg {
	qq := q.Question[0]
	var best *Zone
	for _, z := range s.Zones {
		if dnswire.IsSubdomain(qq.Name, z.Origin) && (best == nil || len(z.Origin) > len(best.Origin)) {
			best = z
		}
	}
	var m *dnswire.Msg
	if best == nil {
		m = &dnswire.Msg{Response: true, Rcode: dnswire.RcodeRefused}
	} else {
		m = best.Answer(qq)
	}
	m.ID = q.ID
	m.Opcode = q.Opcode
	m.RecursionDesired = q.RecursionDesired
	m.Question = q.Question
	if _, ok := q.EDNS(); ok {
		m.SetEDNS(1232)
	}
	return m
}
