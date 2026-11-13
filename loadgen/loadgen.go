// Package loadgen is a small dnsperf-style load generator.
//
// Closed loop: Concurrency workers, each with its own UDP socket, send one
// query and wait for the answer (or a timeout) before sending the next. This
// measures latency and the throughput the server sustains at that
// concurrency.
//
// Open loop: queries are sent at a fixed Rate whether or not answers come
// back, the way an attacker (or a botnet) sends. Only counts are kept.
package loadgen

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Other-Now/nano-dns/dnswire"
)

// Gen produces the next query. It is called from one goroutine per worker
// with that worker's own rng.
type Gen func(r *rand.Rand) (name string, qtype uint16)

// Config describes a run.
type Config struct {
	Server      string
	Gen         Gen
	Concurrency int           // closed loop workers
	Rate        int           // >0: open loop at this many queries/s
	Duration    time.Duration // run length
	Timeout     time.Duration // per query (closed loop)
}

// Report is the result of a run.
type Report struct {
	Sent     int64            `json:"sent"`
	Received int64            `json:"received"`
	Timeouts int64            `json:"timeouts"`
	Rcodes   map[string]int64 `json:"rcodes"`
	Seconds  float64          `json:"seconds"`
	QPS      float64          `json:"qps"` // answered per second
	P50us    float64          `json:"p50_us,omitempty"`
	P90us    float64          `json:"p90_us,omitempty"`
	P99us    float64          `json:"p99_us,omitempty"`
	P999us   float64          `json:"p999_us,omitempty"`
}

// Success is the fraction of sent queries answered NOERROR.
func (r Report) Success() float64 {
	if r.Sent == 0 {
		return 0
	}
	return float64(r.Rcodes["NOERROR"]) / float64(r.Sent)
}

func (r Report) String() string {
	return fmt.Sprintf("sent=%d recv=%d timeouts=%d qps=%.0f p50=%.0fus p99=%.0fus rcodes=%v",
		r.Sent, r.Received, r.Timeouts, r.QPS, r.P50us, r.P99us, r.Rcodes)
}

// Run executes a closed- or open-loop run.
func Run(ctx context.Context, cfg Config) (Report, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 2 * time.Second
	}
	if cfg.Rate > 0 {
		return openLoop(ctx, cfg)
	}
	return closedLoop(ctx, cfg)
}

type tally struct {
	mu     sync.Mutex
	rcodes map[string]int64
}

func (t *tally) add(m map[uint8]int64) {
	t.mu.Lock()
	for k, v := range m {
		t.rcodes[dnswire.RcodeString(k)] += v
	}
	t.mu.Unlock()
}

func closedLoop(ctx context.Context, cfg Config) (Report, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.Duration)
	defer cancel()
	var sent, recv, timeouts atomic.Int64
	t := &tally{rcodes: map[string]int64{}}
	lats := make([][]time.Duration, cfg.Concurrency)
	var wg sync.WaitGroup
	errc := make(chan error, cfg.Concurrency)
	start := time.Now()
	for w := 0; w < cfg.Concurrency; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			conn, err := net.Dial("udp", cfg.Server)
			if err != nil {
				errc <- err
				return
			}
			defer conn.Close()
			rng := rand.New(rand.NewPCG(uint64(w), uint64(time.Now().UnixNano())))
			rc := map[uint8]int64{}
			buf := make([]byte, 1500)
			var q, resp dnswire.Msg
			for ctx.Err() == nil {
				name, qt := cfg.Gen(rng)
				q = dnswire.Msg{ID: uint16(rng.Uint32()), RecursionDesired: true,
					Question: []dnswire.Question{{Name: dnswire.Canonical(name), Type: qt, Class: dnswire.ClassINET}}}
				wire, _ := q.Pack()
				t0 := time.Now()
				conn.SetDeadline(t0.Add(cfg.Timeout))
				if _, err := conn.Write(wire); err != nil {
					continue
				}
				sent.Add(1)
				for {
					n, err := conn.Read(buf)
					if err != nil {
						timeouts.Add(1)
						break
					}
					if resp.Unpack(buf[:n]) != nil || resp.ID != q.ID {
						continue // a late answer to an earlier, timed-out query
					}
					lats[w] = append(lats[w], time.Since(t0))
					recv.Add(1)
					rc[resp.Rcode]++
					break
				}
			}
			t.add(rc)
		}(w)
	}
	wg.Wait()
	select {
	case err := <-errc:
		return Report{}, err
	default:
	}
	el := time.Since(start).Seconds()
	var all []time.Duration
	for _, l := range lats {
		all = append(all, l...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
	r := Report{Sent: sent.Load(), Received: recv.Load(), Timeouts: timeouts.Load(), Rcodes: t.rcodes,
		Seconds: el, QPS: float64(recv.Load()) / el}
	if len(all) > 0 {
		pct := func(p float64) float64 {
			return float64(all[min(len(all)-1, int(p*float64(len(all))))].Nanoseconds()) / 1e3
		}
		r.P50us, r.P90us, r.P99us, r.P999us = pct(0.50), pct(0.90), pct(0.99), pct(0.999)
	}
	return r, nil
}

// openLoop sends at cfg.Rate from a few sockets and counts whatever comes
// back until shortly after the end.
func openLoop(ctx context.Context, cfg Config) (Report, error) {
	const socks = 4
	var sent, recv atomic.Int64
	t := &tally{rcodes: map[string]int64{}}
	conns := make([]*net.UDPConn, socks)
	for i := range conns {
		c, err := net.Dial("udp", cfg.Server)
		if err != nil {
			return Report{}, err
		}
		conns[i] = c.(*net.UDPConn)
		conns[i].SetReadBuffer(4 << 20)
	}
	var rwg sync.WaitGroup
	for _, c := range conns {
		rwg.Add(1)
		go func(c *net.UDPConn) {
			defer rwg.Done()
			buf := make([]byte, 1500)
			rc := map[uint8]int64{}
			var m dnswire.Msg
			for {
				n, err := c.Read(buf)
				if err != nil {
					break
				}
				if m.Unpack(buf[:n]) == nil {
					recv.Add(1)
					rc[m.Rcode]++
				}
			}
			t.add(rc)
		}(c)
	}
	start := time.Now()
	end := start.Add(cfg.Duration)
	rng := rand.New(rand.NewPCG(1, uint64(start.UnixNano())))
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	due := 0.0
	i := 0
	for now := start; now.Before(end) && ctx.Err() == nil; now = <-tick.C {
		// send whatever is due by now; catches up after a slow tick
		target := now.Sub(start).Seconds() * float64(cfg.Rate)
		for due < target {
			name, qt := cfg.Gen(rng)
			q := dnswire.Msg{ID: uint16(rng.Uint32()), RecursionDesired: true,
				Question: []dnswire.Question{{Name: dnswire.Canonical(name), Type: qt, Class: dnswire.ClassINET}}}
			wire, _ := q.Pack()
			if _, err := conns[i%socks].Write(wire); err == nil {
				sent.Add(1)
			}
			i++
			due++
		}
	}
	el := time.Since(start).Seconds()
	// let in-flight answers arrive, then stop the readers
	for _, c := range conns {
		c.SetReadDeadline(time.Now().Add(cfg.Timeout))
	}
	rwg.Wait()
	for _, c := range conns {
		c.Close()
	}
	return Report{Sent: sent.Load(), Received: recv.Load(), Rcodes: t.rcodes, Seconds: el,
		QPS: float64(recv.Load()) / el}, nil
}

// Query sends one query and returns the response (for tests and the CLI).
func Query(server, name string, qtype uint16, timeout time.Duration) (*dnswire.Msg, error) {
	return QueryFrom("", server, name, qtype, timeout)
}

// QueryFrom is Query from a chosen local address ("" = any), so a demo can
// act as different subscribers.
func QueryFrom(source, server, name string, qtype uint16, timeout time.Duration) (*dnswire.Msg, error) {
	d := net.Dialer{}
	if source != "" {
		d.LocalAddr = &net.UDPAddr{IP: net.ParseIP(source)}
	}
	conn, err := d.Dial("udp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	q := dnswire.Msg{ID: uint16(rand.Uint32()), RecursionDesired: true,
		Question: []dnswire.Question{{Name: dnswire.Canonical(name), Type: qtype, Class: dnswire.ClassINET}}}
	q.SetEDNS(1232)
	wire, _ := q.Pack()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(wire); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		var m dnswire.Msg
		if m.Unpack(buf[:n]) == nil && m.ID == q.ID {
			return &m, nil
		}
	}
}
