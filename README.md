# nano-dns

A carrier-style recursive DNS resolver with threat blocking, written in Go:
its own wire-format codec, iterative resolution from the root servers, a
cache with negative caching, and the abuse defences a resolver for millions
of subscribers needs: per-subscriber RPZ threat policy, response rate
limiting, and random-subdomain ("water torture") attack mitigation.

Everything is measured. Attack traffic only ever goes to a simulated DNS
hierarchy on loopback (`authsim`), never at a real server. Correctness is
checked against public resolvers on the real Tranco top 1,000.

```
client ──UDP/TCP──▶ server ─┬─ parse + validate (FORMERR / REFUSED ANY)
                            ├─ subscriber profile (longest-prefix match on client IP)
                            ├─ RPZ policy on QNAME ──────────────▶ NXDOMAIN / NODATA / walled garden / drop
                            ├─ cache (inline on the socket reader) ▶ answer
                            └─ miss ─▶ water-torture gate ─▶ coalesce identical misses ─▶ resolver
                                                                                         │
       root ◀──────── iterate: referrals, glue, bailiwick checks, QNAME minimisation ◀───┘
       TLD  ◀──────── CNAME chasing across zones, TC=1 → TCP retry, retry budget per step
       auth ◀──────── random ID + source port, reply must match server/ID/question
                     then: RPZ on every CNAME target ─▶ RRL (per /24, slip) ─▶ send
```

## Results

Laptop numbers: WSL2, 4 vCPU, 2 GB RAM, with the load generator on the same
4 vCPUs. Every number is in `results/`. CI repeats the experiments on a
GitHub runner.

| what | result | file |
|---|---|---|
| correctness, Tranco top 1,000 (real roots vs 1.1.1.1) | **985 agree** (866 identical, 65 rotating answers, 52 CDN edges where 1.1.1.1 and 8.8.8.8 also disagree, 2 overlap); 7 same-CDN-different-edge; 1 where 1.1.1.1 fails and 8.8.8.8/Quad9 agree with us; **5 SERVFAIL** (transient timeouts) | `difftest.json` |
| retry-budget fix (see stories) | our SERVFAILs on the top 1,000: **24 → 6** | `difftest-baseline.json` |
| QNAME minimisation, real internet | no extra failures; +5.5% upstream queries (2,759 → 2,912); cold p50 357 → 398 ms | `difftest-qmin.json` |
| QNAME minimisation, simulated | root and TLD see the full name in 2/2 and 5/5 queries → **0/2, 0/5**; +3 queries of 411 | `qmin.json` |
| cache hits, 1 socket vs 4 `SO_REUSEPORT` sockets | 1 socket peaks ~72k qps, then drops to 49k with **362 timeouts at 256 clients**; 4 sockets **~101k qps, 0 timeouts** | `throughput.json` |
| …those 362 timeouts | exactly the kernel's `UdpRcvbufErrors` (+362), so the single socket's receive queue overflows | `rcvbuf-check.txt` |
| 1M-rule policy on the hot path | 100.9k → 98.2k qps (−3%) | `throughput.json` |
| cache-miss path (one upstream query each, no RTT) | 23.6k qps | `throughput.json` |
| cache hit ratio, Zipf over 100k names | 1k entries 58.6%, 10k 80.5%, 100k 92.6% | `cache.json` |
| real threat feeds (HaGeZi TIF + URLhaus, 733k RPZ rules) | load 2.1 s, 72 MB; **271 ns/lookup**; padded to 1M rules: 352 ns, 107 MB | `blocklist.json` |
| Tranco top 10,000 on the threat list | 15 (popunder ad networks, a crypto-miner pool, random-word malvertising domains) | `blocklist.json` |
| water torture, 10k q/s random subdomains vs a 2k q/s authoritative | unmitigated: victim server gets **23.6k q/s (2.4× the attack, from retries)**, legit victim.com throughput **209,847 → 439 answers**, p99 1.6 s. Mitigated: victim back to 274 q/s (baseline 247), legit **222,195 answers, p99 1.5 ms** | `torture.json` |
| RRL, 20k q/s flood at one /24 | full answers 199,911 → **1,099**; 99,431 sent as 32-byte TC=1, 99,431 dropped | `rrl.json` |
| fuzzing the parser (Unpack → Pack → Unpack must be identical) | **37.5M inputs in 10 min, 0 failures** (CI: 60 s per push) | `fuzz.txt` |
| microbenchmarks | policy match 86 ns (clean 4-label name) / 34 ns (blocked), 0 allocs; codec unpack+pack **5.7 µs, 67 allocs**: the obvious next optimisation | `microbench.txt` |
| tests | 29 tests (codec, cache, resolver vs simulator, spoofed reply, bailiwick poisoning, policy, RRL, torture, coalescing), `-race` clean | — |

## Run it

```bash
go build -o nanodns ./cmd/nanodns
./scripts/fetch-feeds.sh                       # threat feeds + Tranco (into feeds/)

./nanodns serve -policy feeds/policy.example.json      # real roots, :5354, metrics :9153
./nanodns query example.com
./nanodns query -source 127.0.0.2 clickadu.net         # a "strict" subscriber: NXDOMAIN

./nanodns authsim -port 5300 &                 # simulated root/TLD/zones on 127.0.1.1-4
./nanodns serve -sim-port 5300 -sockets 4 -torture-threshold 200 -rrl-rate 100

./nanodns exp all                              # every experiment -> results/*.json
./nanodns difftest -n 1000                     # real internet vs 1.1.1.1
```

Linux is needed for `SO_REUSEPORT` and for the 127.0.1.x loopback
addresses the simulator uses. On Windows, build and run everything inside
WSL (`scripts/wsl-go.sh`).

## Layout

| package | what |
|---|---|
| `dnswire` | RFC 1035 codec: compression (pointers must point backwards, so no loops), escapes, EDNS(0), truncation; fuzzed |
| `cache` | sharded `(name, type)` cache; TTL ageing; NXDOMAIN for all types and NODATA per type (RFC 2308); bounded, random eviction |
| `resolver` | iteration from the roots: referrals, glue, bailiwick, CNAME chasing, QNAME minimisation (RFC 9156), TCP fallback, spoofing checks |
| `policy` | RPZ loader (NXDOMAIN, NODATA, passthru, drop, walled garden; exact vs `*.` wildcard), hosts lists, subscriber → profile by longest prefix |
| `guard` | RRL per /24 with slip; water-torture detector per registrable domain (public suffix list) with a known-good allowance |
| `server` | UDP (N `SO_REUSEPORT` sockets) + TCP; inline cache fast path; coalescing of identical misses; Prometheus metrics |
| `authsim` | authoritative server + simulated root → com/net → zones, with RTT, capacity limit and drop counters |
| `loadgen` | closed-loop (latency) and open-loop (attack) load generator |
| `cmd/nanodns` | `serve`, `authsim`, `query`, `bench`, `exp`, `difftest` |

Study notes for the interview: [docs/NOTES.md](docs/NOTES.md).

## Honest scope

- **No DNSSEC validation.** Answers are not checked against signatures. A
  validating resolver would SERVFAIL on a broken chain where this one answers.
- **IPv4 only upstream.** AAAA records are resolved, but name servers are
  contacted over IPv4 only.
- **Missing resolver features:** no server selection by RTT (SRTT), no
  prefetch, no serve-stale, no DNS cookies or 0x20, and no DoT/DoH.
- **No full RPZ:** QNAME and CNAME-target triggers only. There are no IP or
  NSDNAME triggers and no CNAME rewrites.
- **Our own load generator, not dnsperf.** dnsperf isn't installed here and
  there's no sudo. Loopback numbers on a shared 4-vCPU laptop are best read
  relative to each other.
- **The attacks are simulated.** Water torture and RRL were measured against
  `authsim`, not a real authoritative server. Water-torture detection keys on
  the eTLD+1 and its threshold was hand-picked. A real deployment would also
  use aggressive NSEC (RFC 8198) for signed zones.
- **The real-internet run was lossy.** The difftest ran over a home
  connection through WSL2 NAT, and 4–6% of upstream UDP queries timed out.
  The remaining 5 SERVFAILs come from that.
- **No Kubernetes deployment.** Only a single process exposing Prometheus
  metrics was built.
