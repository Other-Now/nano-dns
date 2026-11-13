# nano-dns: study notes (1–2 days)

Read in this order: the pitch, DNS in 15 minutes, one query through the
code, the defences, the stories, then the interview questions. Every number
here is in `results/`.

## 1. The 60-second pitch

> I built a recursive DNS resolver in Go, the kind a carrier runs for its
> subscribers. I wrote the wire-format codec myself and fuzzed it. It
> resolves iteratively from the real root servers with bailiwick and
> anti-spoofing checks, and it caches positive and negative answers. On top
> of that are the security features: per-subscriber threat policy loaded
> from real RPZ feeds (733k rules, 271 ns per lookup), response rate
> limiting, and detection of random-subdomain "water torture" attacks.
> Against a simulated 10k q/s attack, the victim's authoritative server went
> from 23.6k q/s back to baseline, and legitimate traffic recovered from 439
> answers to 222k. I checked correctness against 1.1.1.1 on the Tranco top
> 1,000: 985 agree, and the difference is explained for the rest. That
> check also found a real retry bug, which I fixed (SERVFAILs 24 → 6).

## 2. DNS in 15 minutes

**Roles**
- A **stub resolver** (the phone) asks the **recursive resolver** (the
  carrier's, this project) with RD=1.
- The recursive resolver asks **authoritative** servers with RD=0: first the
  root, then the TLD (`com.`), then the zone (`example.com.`).

**Referral**
- The root doesn't know `www.example.com`. It returns NS records for `com.`
  in the AUTHORITY section, plus **glue** (A records for those name servers)
  in ADDITIONAL.
- Iteration means following referrals down to a server that answers with
  AA=1.

**Message format** (`dnswire/msg.go`)
- A 12-byte header: ID, flags (QR, opcode, AA, TC, RD, RA, AD, CD, rcode)
  and four counts.
- Then the question, answer, authority and additional sections.
- A name is a sequence of length-prefixed labels: `3www7example3com0`.

**Compression**
- Wherever a label would start, a 2-byte pointer `0b11xxxxxx xxxxxxxx` can
  stand in for "the rest of the name is at offset X".
- Attack surface:
  - **Loops:** a pointer to itself.
  - **Forward pointers.**
  - **Over-long names:** the limit is 255 octets, and 63 per label.
- My rule: a pointer must point strictly backwards, so the offset strictly
  decreases and no loop can exist (`dnswire/name.go: readName`).
- Pointers inside RDATA (NS, CNAME, SOA, MX) are message-relative, so I
  decompress them on parse. Otherwise a cached record would point into a
  message that no longer exists.

**EDNS(0)** (RFC 6891)
- An OPT pseudo-record in ADDITIONAL advertises a UDP payload size larger
  than 512.
- 1232 is the DNS Flag Day 2020 value: it avoids IP fragmentation
  (1280 IPv6 minimum MTU, minus 48 bytes of headers).

**TC=1**
- The answer didn't fit in UDP, so retry over TCP, which uses a 2-byte
  length prefix (RFC 7766).

**TTL**
- The cache keeps a record until its TTL runs out and hands out the
  remaining TTL on each hit (`cache.aged`).

**Negative caching** (RFC 2308)
- NXDOMAIN (the name doesn't exist) and NODATA (the name exists but not
  this type) are cached for **min(SOA TTL, SOA MINIMUM)**, taken from the
  SOA in AUTHORITY.
- NXDOMAIN applies to *every* type at that name; NODATA is per type.
- With no SOA there's no negative TTL, so nothing is cached.

**CNAME**
- An alias. If the target is in another zone, the resolver starts a new
  resolution for it (`resolver.chase`).

**Bailiwick**
- A server for zone Z is only believed about names under Z.
- This is what stops a server for `evil.com` from putting `www.bank.com A
  6.6.6.6` in its additional section and poisoning the cache.

## 3. One query through the code

1. `server.readUDP` reads a packet, then `dnswire.Unpack`. If it fails to
   parse, the packet is **dropped** (answering garbage helps reflection).
2. `server.fast` handles everything that needs no network:
   - **Validation:** one question, opcode 0, class IN; ANY gets REFUSED
     (RFC 8482).
   - **Subscriber profile:** `policy.Engine.ProfileFor(clientIP)`, the
     longest prefix wins.
   - **RPZ:** `Profile.Match(qname)`. The exact name is checked first, then
     one wildcard probe per parent suffix, with no allocation. A hit returns
     NXDOMAIN, NODATA, a walled-garden A record, or a drop.
   - **Cache:** `resolver.Lookup`, cache only, following cached CNAMEs. On a
     hit it answers inline on the socket's reader goroutine.
3. On a miss, `server.slow` runs in a new goroutine:
   - **Water-torture gate:** `guard.Torture.Allow`.
   - **Coalescing:** `flight.do`. Twenty clients asking the same expired name
     produce 1 upstream query (`TestCoalescing`).
   - **Resolution:** `resolver.Resolve`.
4. `resolver.iterate`:
   - `closest` finds the deepest cached zone cut that has server
     addresses, so a second name under a known zone skips the root and TLD.
   - Loop: `exchangeAny`, then `classify` decides between answer, NXDOMAIN,
     NODATA, referral and lame.
   - On a referral: cache the NS records plus **in-bailiwick** glue. If
     there's no glue (common with Route 53), resolve **two** NS names, each
     as a full resolution one level deeper.
   - With QNAME minimisation on, ask for `ChildOf(name, zone)` (A type)
     until the full name is reached.
5. `resolver.exchange`:
   - A new socket per query, so the kernel picks a random source port.
   - A random 16-bit ID.
   - The reply must come from the server we asked (connected UDP) and match
     both the ID and the exact question; otherwise it's ignored and we keep
     waiting.
   - TC=1 triggers a TCP retry.
6. Back in the server:
   - **RPZ on every CNAME target:** a clean name that aliases to a listed
     one is blocked too.
   - **RRL:** `guard.RRL.Check(clientIP)`, then send.

## 4. The defences: what, why and how

| defence | attack it stops | how here | knob |
|---|---|---|---|
| random ID + source port + question match | off-path spoofing / Kaminsky cache poisoning (forge a reply before the real one) | `exchange`; mismatches counted (`nanodns_upstream_mismatched_total`) | — |
| bailiwick filtering | poisoning via extra records | `filterAnswer`, `referralData`; `TestOutOfBailiwickAnswerDropped` | — |
| RRL with slip | the resolver used as a reflector against a spoofed victim | token bucket per /24 (`/56` for v6). Over the limit, every 2nd answer becomes a 32-byte TC=1 and the rest are dropped. A real client whose address is being spoofed retries over TCP, which can't be spoofed | `-rrl-rate -rrl-slip` |
| refuse ANY | ANY is the classic amplification query | REFUSED | — |
| water-torture mitigation | random-subdomain DDoS on a domain's authoritative servers (and on the resolver) | count failed upstream lookups (NXDOMAIN/SERVFAIL) per eTLD+1 per window. Over the threshold, cache misses under that domain get a local SERVFAIL, except names that resolved before the attack ("known-good") | `-torture-threshold -window -hold` |
| RPZ threat policy | users reaching malware/phishing/C2 domains | QNAME and CNAME-target triggers, per-subscriber profiles | `-policy` |
| QNAME minimisation | privacy: the root and TLD don't need the full name | RFC 9156; relaxed fallback on NXDOMAIN for empty non-terminals | `-qmin` |
| coalescing | thundering herd when a popular name expires | singleflight per (name, type) | — |

**Why count failures, not query rate, for water torture?** A popular domain
can legitimately get huge query rates, but it doesn't produce thousands of
NXDOMAINs a second. Counting SERVFAIL too matters because, mid-attack, the
victim's server drops queries and the resolver sees timeouts, not NXDOMAIN.

**Why does a "known-good" allowance matter?** Legitimate names expire from
the cache during a long attack. Without the allowance, mitigation would
block the victim's real users as well, which completes the attacker's job.

## 5. The stories (all measured)

**1. A single lost packet became a SERVFAIL** (`difftest-baseline.json` →
`difftest.json`)
- The first 1,000-domain difftest had 22 "ours failed". The pattern: many
  were AWS Route 53 domains, whose NS names (awsdns-xx.com/.net/.org) have
  no glue.
- The resolver resolved only the first NS name, which gave one server
  address. The retry loop iterated over servers, so one address meant one
  attempt.
- On this link 4–6% of upstream UDP queries time out, so a single drop
  meant SERVFAIL.
- The fix:
  - the retry budget is per step (3 attempts, wrapping around the servers);
  - two NS names get resolved.
- Our errors went 24 → 6. To make the comparison fair, the reference
  resolver got 3 retries too.

**2. The single-socket "timeouts" were kernel drops** (`rcvbuf-check.txt`)
- With 1 UDP socket and 256 concurrent clients, throughput *fell* (72k →
  49k qps) and 362 queries timed out.
- `/proc/net/snmp` showed `UdpRcvbufErrors` +362, exactly equal to the
  timeouts: one reader goroutine can't drain one receive queue.
- With 4 `SO_REUSEPORT` sockets the kernel hashes clients onto 4 queues:
  ~101k qps and 0 drops.
- Four readers on *one* socket helped only a little (79k), and 355
  timeouts remained at 256 clients. I didn't check the kernel counter for
  that variant.

**3. The resolver amplified the attack** (`torture.json`)
- The attacker sent 10k q/s, but the victim's authoritative server received
  23.6k q/s, because every timed-out query is retried (3 tries).
- Unmitigated, legitimate victim.com clients got 439 answers in 10 s against
  209,847 in the baseline: each expired name waited through about 2.4 s of
  timeouts.
- Unrelated domains' p99 went from 0.85 to 5.3 ms (CPU spent on 241k
  upstream queries).
- With mitigation the victim's server was back at baseline (274 vs 247 q/s)
  and legitimate traffic was fully restored.

**4. A test that proved nothing** (`server_test.go`)
- My first water-torture test checked that a known-good name still resolved
  during mitigation. It passed, but the name was still in the cache, so the
  allow-upstream path never ran.
- Now the TTL is 1 s, the test sleeps past it, and it asserts the victim
  server actually got a query.

**5. My own bailiwick test was wrong**
- The fake server "for example.com" was configured as a *root* server, and
  the root is in bailiwick for every name, so the poisoned record was
  legitimately accepted.
- The fix: delegate `example.` to the fake server through the cache.

**6. "Different answer" ≠ wrong answer** (`difftest.json`)
- x.com's authoritative servers rotate between 2 IPs per query; it isn't a
  bug.
- CDNs answer by resolver location: we got CloudFront London, 1.1.1.1 got
  Singapore (checked with PTR).
- The classifier re-queries both public resolvers and checks whether they
  disagree with each other.
- charter.net: 1.1.1.1 SERVFAILed after 4.3 s, while 8.8.8.8 and Quad9
  answered the same as we did.

**7. Popular ≠ safe** (`blocklist.json`)
- 15 of the Tranco top 10,000 are on the HaGeZi threat feed: popunder ad
  networks, a crypto-miner pool, and random-word malvertising domains.
- They're popular *because* malicious traffic hits them, so a "top sites
  allow-list" would be a bad false-positive filter.

## 6. Likely questions, short answers

- **Kaminsky attack?**
  - Ask the resolver for `random123.bank.com` (not cached, so it always goes
    upstream) and flood forged replies carrying an in-bailiwick referral for
    `bank.com` NS → the attacker's server.
  - With only a 16-bit ID, one forgery in 65,536 wins, and the attacker can
    repeat as often as they like.
  - Defences:
    - random source port (×~60k);
    - question match;
    - bailiwick;
    - 0x20 case randomisation;
    - DNSSEC, which is the real fix.
- **Why 1232?** It avoids fragmentation. Fragmented UDP is unreliable and
  makes forgery easier.
- **How would you scale this to carrier load?**
  - SO_REUSEPORT sockets per core, with the cache hit path free of
    allocation. The codec currently costs 5.7 µs and 67 allocations per
    unpack+pack (`microbench.txt`): a cached packed response, patched with
    the client's ID, would avoid most of that.
  - Anycast the service.
  - Shard the cache by name (the code already uses 64 shards).
  - Prefetch popular names before they expire.
  - Serve-stale (RFC 8767) when authoritative servers are down.
  - Above roughly 1M qps per box: AF_XDP/DPDK.
- **Storing 10M blocklist entries?**
  - The Go map here costs about 100 bytes per rule (72 MB for 733k).
  - Options:
    - a compact hash of fixed-size keys;
    - a Bloom filter in front, with an exact check behind it;
    - a reversed-label radix tree, which shares suffixes.
  - Cost per lookup = one probe per label (271 ns average).
- **RPZ semantics?**
  - `x CNAME .` = NXDOMAIN; `*.` = NODATA; `rpz-passthru.` = allow;
    `rpz-drop.` = no answer; an A record = local data.
  - `*.evil.com` matches only names *below* evil.com.
  - The first matching zone wins.
- **Water-torture false positives?**
  - A domain that legitimately produces many NXDOMAINs: some anti-abuse
    services and DNSBL-style lookups do this by design.
  - Mitigations: a per-domain allow-list, a higher threshold, or a scope
    finer than the eTLD+1.
  - For DNSSEC-signed zones, aggressive NSEC (RFC 8198) answers NXDOMAIN
    from cached NSEC ranges without asking upstream.
- **What does QNAME minimisation cost?**
  - Measured on the real top 1,000: +5.5% upstream queries and +41 ms cold
    p50.
  - It also exposes broken servers that answer NXDOMAIN for empty
    non-terminals, so I fall back to the full name once.
- **TCP vs UDP?**
  - TCP is used on TC=1, for zone transfers, and in RRL slip.
  - TCP cannot be spoofed (handshake), which is why slip works.
- **Negative TTL?** min(SOA TTL, SOA MINIMUM), capped (I use 1 h).
- **What would you add next?** DNSSEC validation, SRTT-based server
  selection, serve-stale, and DoT/DoH listeners.

## 7. Do not claim

- No DNSSEC validation, no DoT/DoH, no IPv6 upstream, no SRTT.
- **The attack numbers are simulator numbers:** a capacity-limited
  `authsim` on loopback. No real authoritative server was attacked.
- **The load generator is my own, not dnsperf.** It runs on the same
  4-vCPU WSL2 laptop as the resolver.
- **The difftest compares against public resolvers, not Unbound**, which
  isn't installed here.
- **The water-torture threshold was picked by hand** (200 failures per 2 s
  window).
- **No Kubernetes or eBPF here.** Those are in other projects.
