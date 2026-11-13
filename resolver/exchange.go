package resolver

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"time"

	"github.com/Other-Now/nano-dns/dnswire"
)

var errMismatch = errors.New("resolver: no matching response")

// exchange sends one iterative query (RD=0) to server.
//
// Spoofing defences (the Kaminsky-era basics):
//   - a fresh socket per query, so the kernel picks a random source port;
//   - a random 16-bit ID;
//   - the reply must come from the server we asked (connected UDP socket),
//     carry our ID and echo our exact question. Anything else is ignored and
//     we keep waiting until the deadline.
func (r *Resolver) exchange(ctx context.Context, server netip.AddrPort, name string, qtype uint16) (*dnswire.Msg, error) {
	q := &dnswire.Msg{ID: uint16(rand.Uint32()), Question: []dnswire.Question{{Name: name, Type: qtype, Class: dnswire.ClassINET}}}
	q.SetEDNS(1232)
	wire, err := q.Pack()
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(r.cfg.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	r.stats.Upstream.Add(1)
	if r.cfg.OnUpstream != nil {
		r.cfg.OnUpstream(server, name, qtype)
	}
	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(server))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(deadline)
	if _, err := conn.Write(wire); err != nil {
		return nil, err
	}
	buf := make([]byte, 1232)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			r.stats.Timeouts.Add(1)
			return nil, err
		}
		var resp dnswire.Msg
		if resp.Unpack(buf[:n]) != nil || !matches(q, &resp) {
			r.stats.Mismatched.Add(1)
			continue
		}
		if resp.Truncated {
			return r.exchangeTCP(server, wire, q, deadline)
		}
		return &resp, nil
	}
}

func matches(q, resp *dnswire.Msg) bool {
	return resp.Response && resp.ID == q.ID && len(resp.Question) == 1 &&
		resp.Question[0] == q.Question[0]
}

// exchangeTCP retries a truncated query over TCP (RFC 7766).
func (r *Resolver) exchangeTCP(server netip.AddrPort, wire []byte, q *dnswire.Msg, deadline time.Time) (*dnswire.Msg, error) {
	r.stats.UpstreamTCP.Add(1)
	d := net.Dialer{Deadline: deadline}
	c, err := d.Dial("tcp", server.String())
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(deadline)
	if _, err := c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(wire))), wire...)); err != nil {
		return nil, err
	}
	var lb [2]byte
	if _, err := io.ReadFull(c, lb[:]); err != nil {
		return nil, err
	}
	b := make([]byte, binary.BigEndian.Uint16(lb[:]))
	if _, err := io.ReadFull(c, b); err != nil {
		return nil, err
	}
	var resp dnswire.Msg
	if err := resp.Unpack(b); err != nil {
		return nil, err
	}
	if !matches(q, &resp) {
		return nil, errMismatch
	}
	return &resp, nil
}

// exchangeAny makes up to cfg.Tries attempts, walking the servers in random
// order and wrapping around if there are fewer servers than attempts. A
// server that times out or answers SERVFAIL/REFUSED/FORMERR/NOTIMP is
// skipped.
//
// The retry budget is per step, not per server: with one known server
// address, a single lost UDP packet must not become a SERVFAIL. (It did, for
// 22 of the Tranco top 1,000 before this was fixed; see docs/NOTES.md.)
func (r *Resolver) exchangeAny(ctx context.Context, servers []netip.AddrPort, name string, qtype uint16) (*dnswire.Msg, error) {
	var last error = errors.New("resolver: no servers")
	if len(servers) == 0 {
		return nil, last
	}
	order := rand.Perm(len(servers))
	for i := 0; i < r.cfg.Tries; i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		resp, err := r.exchange(ctx, servers[order[i%len(order)]], name, qtype)
		if err != nil {
			last = err
			continue
		}
		switch resp.Rcode {
		case dnswire.RcodeSuccess, dnswire.RcodeNXDomain:
			return resp, nil
		}
		last = errors.New("resolver: upstream " + dnswire.RcodeString(resp.Rcode))
	}
	return nil, last
}
