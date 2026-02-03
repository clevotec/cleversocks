# CleverSocks Ethos

## Why CleverSocks Exists

The SOCKS5 protocol is 28 years old. It works. It's simple. It's
everywhere. But the implementations haven't kept pace with modern
security expectations.

Every major SOCKS5 proxy is written in C:

- **Dante** — powerful but complex, slow release cycle
- **microsocks** — tiny but unmaintained, no tests
- **3proxy** — feature-rich but sprawling, questionable security
- **srelay** — abandoned

C is fast. C is small. C is also the source of 70% of serious
security vulnerabilities. Buffer overflows, use-after-free, integer
overflows — these aren't theoretical risks. They're the reality of
every C codebase that handles untrusted network input.

CleverSocks exists because **a proxy is a security boundary**, and
security boundaries should not be written in memory-unsafe languages.

---

## Why Rust

Rust gives us:

- **Memory safety without garbage collection.** No buffer overflows,
  no use-after-free, no data races. The compiler catches these at
  build time, not in production.

- **C-like performance.** Zero-cost abstractions, no runtime, direct
  hardware access when needed. CleverSocks is as fast as the C
  alternatives.

- **Fearless concurrency.** The borrow checker prevents data races at
  compile time. We can write multithreaded code with confidence.

- **Modern tooling.** Cargo for dependencies, rustfmt for formatting,
  clippy for linting, cargo-fuzz for fuzzing. The ecosystem makes
  quality easy.

The tradeoff is a steeper learning curve and longer compile times. We
accept this tradeoff because **security is not optional** for a proxy
that handles untrusted traffic.

---

## The Problem We Solve

SOCKS5 is a tunneling protocol. It forwards TCP (and optionally UDP)
connections through an intermediary. This is useful for:

- **Privacy** — hide your origin IP
- **Access control** — route traffic through specific networks
- **Bypassing restrictions** — reach services behind firewalls
- **Traffic shaping** — exit different traffic through different paths

But SOCKS5 implementations have stagnated. They're either:

1. **Overly simple** — no auth, no ACLs, no monitoring, no security
2. **Overly complex** — kitchen-sink feature sets, hard to configure
3. **Unmaintained** — security bugs linger for years

CleverSocks aims for the middle ground: **simple enough to deploy in
five minutes, clever enough to handle real-world routing needs.**

---

## Design Philosophy

### Simple but Clever

SOCKS5 is a simple protocol. The implementation should match. But
"simple" doesn't mean "dumb." CleverSocks is clever about:

- **Upstream selection** — route traffic through proxy pools, select
  by latency, rotate for anonymity
- **Access control** — block private networks, restrict ports, filter
  by domain
- **Health management** — detect failed upstreams, recover
  automatically
- **Integration** — work seamlessly with mesh networks, container
  orchestrators, init systems

The cleverness is in the routing, not the complexity.

### Secure by Default

A proxy exposed to the internet must be secure out of the box:

- **Warn loudly** when running without authentication on public
  interfaces
- **Block dangerous targets** by default (private IPs, cloud metadata,
  SMTP)
- **Fail closed** — when in doubt, reject the connection
- **Zero unsafe code** — Rust's safety guarantees are non-negotiable

Security is not a feature to be enabled. It's the foundation.

### Tested Relentlessly

Every code path has a test. Every parser is fuzzed. Every security
fix adds a regression test. 100% coverage is not a goal — it's a
requirement.

Untested code is broken code. We just don't know how yet.

### Minimal Dependencies

Every dependency is a liability:

- Supply chain risk (malicious code injection)
- Maintenance burden (keeping up with updates)
- Binary bloat (unused features compiled in)
- Audit complexity (more code to review)

CleverSocks depends on `socket2` for low-level socket operations.
That's it for the core. Additional features (TLS, async) are behind
feature flags with carefully chosen dependencies.

---

## Use Cases

### Public Internet Proxy

CleverSocks is secure enough to expose directly to the internet. With
authentication enabled and ACLs configured, it can serve as a public
proxy endpoint without fear of abuse.

```
Internet → CleverSocks (public IP) → Target
```

### Mesh Network Exit Node

In a mesh network (Tailscale, Netbird, WireGuard), not all traffic
needs to traverse the mesh. CleverSocks enables selective proxying:

```
Local App → CleverSocks → Mesh Network → Exit Node → Internet
                ↓
           Direct (local traffic)
```

Applications that need to exit via a specific node use the SOCKS5
proxy. Everything else goes direct.

### Kubernetes Traffic Routing

In a multi-cloud cluster, you may want AWS API traffic to exit via AWS
nodes, GCP traffic via GCP nodes, and so on. CleverSocks with
forwarding rules makes this possible:

```yaml
forwarding:
  - match: "*.amazonaws.com:*"
    upstream: "aws-exit-node.internal:1080"
    remote: "*.amazonaws.com:*"

  - match: "*.googleapis.com:*"
    upstream: "gcp-exit-node.internal:1080"
    remote: "*.googleapis.com:*"

proxy_pool:
  enabled: true
  source: /etc/cleversocks/default-exits.json
```

Traffic to AWS services exits via AWS. Traffic to GCP exits via GCP.
Everything else uses the default pool.

### Proxy Chaining

CleverSocks can chain through multiple proxies, creating layered
routing:

```
Client → CleverSocks (local)
              ↓
         CleverSocks (datacenter)
              ↓
         CleverSocks (exit node)
              ↓
         Target
```

Each hop can apply its own ACLs and routing rules. The mesh network
provides the underlying transit; SOCKS5 provides the application-layer
routing logic.

### Rotating Proxy Pool

For web scraping, testing, or privacy, CleverSocks can rotate through
a pool of upstream proxies:

```
Client → CleverSocks → [Proxy Pool] → Target
                          ↓
                    Rotate per-request
                    Health check
                    Remove failures
                    Reload from file
```

Integrate with proxy scrapers like proxybroker2 to maintain a fresh
pool of working proxies automatically.

---

## What CleverSocks Is Not

**Not an HTTP proxy.** Use nginx, squid, or a dedicated HTTP proxy.
SOCKS5 operates at the TCP level; HTTP proxies operate at the
application level. Different tools for different jobs.

**Not a VPN.** Use WireGuard, Tailscale, or Netbird for full network
tunneling. SOCKS5 is per-application proxying, not system-wide
routing.

**Not a load balancer.** Use haproxy or nginx for high-performance
load balancing. CleverSocks can distribute across upstreams, but it's
not optimized for millions of requests per second.

**Not a caching proxy.** Use squid or varnish for HTTP caching.
SOCKS5 is a transparent tunnel; it doesn't inspect or cache content.

---

## Innovation in SOCKS5

SOCKS5 is old, but it doesn't have to be stagnant. CleverSocks
innovates in:

### Smart Upstream Selection

Traditional SOCKS5 proxies connect directly to the target or through
a single upstream. CleverSocks introduces:

- **Proxy pools** with multiple selection strategies
- **Health-aware routing** that avoids failed upstreams
- **Forwarding rules** for content-based routing
- **Integration with proxy scrapers** for dynamic pool management

### Modern Operations

Traditional SOCKS5 proxies are black boxes. CleverSocks provides:

- **Prometheus metrics** for observability
- **Health endpoints** for orchestrator integration
- **Structured logging** for debugging
- **Graceful shutdown** for zero-downtime deployments
- **Config hot-reload** for live updates

### Defense in Depth

Traditional SOCKS5 proxies trust the client. CleverSocks applies:

- **Access control lists** to restrict targets
- **Rate limiting** to prevent abuse
- **Connection limits** to prevent resource exhaustion
- **Constant-time authentication** to prevent timing attacks

---

## The Name

**Clever** — smart routing, health-aware selection, seamless
integration. Not just a dumb pipe.

**Socks** — SOCKS5 protocol, the foundation we build on.

CleverSocks: the SOCKS5 proxy that's clever enough to do what you
actually need.

---

## Our Commitment

1. **Security first.** Every decision considers the security
   implications. When in doubt, choose the safer path.

2. **Simplicity always.** Features must justify their complexity. If
   it can be done with fewer lines of code, do it.

3. **Quality over speed.** We ship when it's ready, not when the
   calendar says so. 100% test coverage is a requirement, not a goal.

4. **Community driven.** Issues get responses. PRs get reviews. Good
   ideas get implemented.

5. **Long-term thinking.** CleverSocks will be maintained for years,
   not months. We make decisions that age well.

---

*CleverSocks: Because your proxy shouldn't be the weakest link.*
