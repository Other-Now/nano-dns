package server

import (
	"sync"

	"github.com/Other-Now/nano-dns/dnswire"
	"github.com/Other-Now/nano-dns/policy"
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics are the Prometheus series the server exports. Hot-path counters
// are resolved to children once, so a query pays an atomic add, not a label
// lookup.
type Metrics struct {
	queries  *prometheus.CounterVec
	rcodes   *prometheus.CounterVec
	blockedV *prometheus.CounterVec
	dur      *prometheus.HistogramVec

	cacheHit, resolved, servfail, mitigated prometheus.Counter
	rrlDrop, rrlSlip, badRequest, coalesced prometheus.Counter
	durFast, durMiss                        prometheus.Observer
	rcodeChildren                           [16]prometheus.Counter
	blockedChildren                         sync.Map // "list/action" -> Counter
}

// NewMetrics registers the series on reg (nil: a private registry).
func NewMetrics(reg prometheus.Registerer) *Metrics {
	if reg == nil {
		reg = prometheus.NewRegistry()
	}
	m := &Metrics{
		queries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nanodns_queries_total", Help: "Client queries by outcome.",
		}, []string{"outcome"}),
		rcodes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nanodns_responses_total", Help: "Responses sent by rcode.",
		}, []string{"rcode"}),
		blockedV: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "nanodns_blocked_total", Help: "Queries blocked by policy.",
		}, []string{"list", "action"}),
		dur: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "nanodns_query_duration_seconds", Help: "Receive-to-send time.",
			Buckets: prometheus.ExponentialBuckets(10e-6, 2.5, 12),
		}, []string{"path"}),
	}
	reg.MustRegister(m.queries, m.rcodes, m.blockedV, m.dur)
	m.cacheHit = m.queries.WithLabelValues("cache_hit")
	m.resolved = m.queries.WithLabelValues("resolved")
	m.servfail = m.queries.WithLabelValues("servfail")
	m.mitigated = m.queries.WithLabelValues("torture_mitigated")
	m.rrlDrop = m.queries.WithLabelValues("rrl_drop")
	m.rrlSlip = m.queries.WithLabelValues("rrl_slip")
	m.badRequest = m.queries.WithLabelValues("bad_request")
	m.coalesced = m.queries.WithLabelValues("coalesced")
	m.durFast = m.dur.WithLabelValues("fast")
	m.durMiss = m.dur.WithLabelValues("miss")
	for i := range m.rcodeChildren {
		m.rcodeChildren[i] = m.rcodes.WithLabelValues(dnswire.RcodeString(uint8(i)))
	}
	return m
}

func (m *Metrics) responses(rcode uint8) prometheus.Counter { return m.rcodeChildren[rcode&0xF] }

func (m *Metrics) blocked(list string, a policy.Action) prometheus.Counter {
	k := list + "/" + a.String()
	if c, ok := m.blockedChildren.Load(k); ok {
		return c.(prometheus.Counter)
	}
	c := m.blockedV.WithLabelValues(list, a.String())
	m.blockedChildren.Store(k, c)
	return c
}
