# CleverSocks Roadmap

Items are grouped into milestones by theme. Within each milestone, items are
ordered roughly by priority. Checked boxes track completion.

References to the security review use `MEDIUM-XX` / `LOW-XX` IDs from
[SECURITY_REVIEW.md](SECURITY_REVIEW.md).

---

## Milestone 1 — Hardening & Stability

Address the findings from the v1.0.5 security review and close the most
impactful reliability gaps.

- [ ] **Max connection limit** — Add an optional `-m <max>` flag backed by an
      `AtomicUsize` counter. Reject new connections when the ceiling is reached.
      *(MEDIUM-01)*
- [ ] **Auth-once whitelist bounds** — Cap the whitelist size and add a TTL so
      entries expire. Evict oldest entries when the cap is hit. *(MEDIUM-02)*
- [ ] **Warn on open-relay start** — Print a clear warning to stderr when the
      server starts without authentication on a non-loopback address.
      *(MEDIUM-03)*
- [ ] **Handshake timeout** — Set a 30-second read timeout on the client socket
      during the SOCKS5 handshake so half-open connections cannot hold a thread
      forever. *(LOW-08)*
- [ ] **TCP keepalive** — Enable `SO_KEEPALIVE` on relay connections using the
      already-present `socket2` crate. *(LOW-08)*
- [ ] **Clear write timeout before relay** — After `connect_target()` succeeds,
      clear the 5-second write timeout before entering `copyloop()`, matching
      the upstream-connection path. *(LOW-03)*
- [ ] **Try all upstream addresses** — `connect_via_upstream()` should iterate
      all DNS-resolved addresses, matching `connect_target()` behavior.
      *(LOW-04)*
- [ ] **Compare credentials as bytes** — Operate on raw `&[u8]` instead of
      `String::from_utf8_lossy` for credential parsing and comparison.
      *(LOW-05)*
- [ ] **Log on RwLock poisoning** — Emit a warning when auth-state lock
      acquisition fails instead of silently returning `false`. *(LOW-07)*
- [ ] **Accumulate partial reads** — Replace single `read()` calls in the
      handshake with a loop that accumulates until a complete message is
      received. *(LOW-02)*
- [ ] **Pad constant-time comparison** — Remove the early return on length
      mismatch in `constant_time_eq`. *(LOW-01)*

---

## Milestone 2 — Security Features

Features that reduce abuse potential and protect traffic in transit.

- [ ] **Destination ACLs** — Configurable allow/deny rules for target
      IP CIDRs, ports, and domains. Block RFC 1918 ranges and link-local
      addresses by default when ACLs are enabled. Prevents SSRF and open-relay
      abuse.
- [ ] **TLS listener (rustls)** — Optional `--tls-cert` / `--tls-key` flags to
      wrap the SOCKS5 listener in TLS, protecting credentials and proxied data
      on untrusted networks.
- [ ] **Rate limiting** — Per-IP connection rate limit and auth-attempt
      throttling to slow brute-force attacks. Configurable burst and sustained
      rates.
- [ ] **Multi-user authentication** — Support multiple username/password pairs
      loaded from a credentials file, enabling per-user access rules in the
      future.
- [ ] **Credential file / env-var support** — Read `-u`/`-P` values from a
      file (`--credentials-file`) or environment variables so they no longer
      appear in `ps` output.

---

## Milestone 3 — Operational Maturity

Make CleverSocks easier to run, monitor, and manage in production.

- [ ] **Configuration file (TOML)** — Support a `--config <path>` option for
      all settings currently handled by CLI flags, plus settings that are
      impractical on the command line (ACL rules, multiple users, multiple
      forwarding rules).
- [ ] **Structured / leveled logging** — Replace the binary on/off logging with
      levels (`error`, `warn`, `info`, `debug`, `trace`). Optionally output
      JSON for log aggregation pipelines. Add per-connection IDs.
- [ ] **Graceful shutdown** — Handle `SIGTERM`/`SIGINT`: stop accepting new
      connections, drain active relays up to a configurable timeout, then exit
      cleanly.
- [ ] **Systemd integration** — Ship a systemd unit file. Optionally support
      `sd_notify` (`Type=notify`) for readiness signaling and socket
      activation.
- [ ] **Metrics endpoint** — Expose active connections, bytes in/out,
      auth success/failure counts, and connection error counts. A minimal
      Prometheus-compatible HTTP endpoint on a separate management port.
- [ ] **Config hot-reload** — Re-read the config file on `SIGHUP` without
      dropping active connections. Useful for ACL and credential changes.
- [ ] **Health check** — A lightweight TCP or HTTP endpoint for load-balancer
      probes.

---

## Milestone 4 — Protocol Completeness

Implement remaining SOCKS5 commands and add compatibility layers.

- [ ] **UDP ASSOCIATE (RFC 1928 §7)** — Relay UDP datagrams for DNS, gaming,
      VoIP, and QUIC traversal. Requires a UDP relay socket and a mapping table
      from client to remote addresses.
- [ ] **BIND command (RFC 1928 §6)** — Support server-to-client connections
      for protocols like FTP active mode.
- [ ] **HTTP CONNECT proxy mode** — Listen for HTTP CONNECT requests alongside
      SOCKS5 on the same or a separate port, broadening client compatibility.
- [ ] **SOCKS4/4a backward compatibility** — Accept SOCKS4 CONNECT requests
      from legacy clients.
- [ ] **GSSAPI authentication (RFC 1961)** — Kerberos-based auth for
      enterprise / Active Directory environments.

---

## Milestone 5 — Performance

Move from thread-per-connection to an async architecture and add network
optimizations.

- [ ] **Async I/O (tokio)** — Replace the synchronous thread-per-connection
      model with `tokio` tasks. Eliminates per-thread stack overhead and
      enables tens-of-thousands of concurrent connections. This is the single
      largest architectural change.
- [ ] **TCP_NODELAY** — Disable Nagle's algorithm for latency-sensitive
      interactive protocols (SSH, RDP) proxied through SOCKS5.
- [ ] **Configurable relay buffer size** — Allow tuning the 16 KB relay buffer
      via config. Larger buffers improve bulk throughput; smaller ones reduce
      latency.
- [ ] **DNS caching** — Cache resolved addresses with a configurable TTL to
      avoid repeated lookups for the same host. Consider `hickory-resolver` for
      a full-featured async resolver.
- [ ] **Happy Eyeballs (RFC 8305)** — Race IPv6 and IPv4 connections with a
      staggered start to improve connection times on dual-stack networks.
- [ ] **Connection pooling for upstream proxies** — Reuse TCP connections to
      upstream proxies across forwarding rules to reduce connection overhead.
- [ ] **Zero-copy relay (`splice()`)** — On Linux, use `splice()` to transfer
      data between sockets without copying through userspace.
- [ ] **`SO_REUSEPORT`** — Allow multiple listeners on the same port for
      improved accept throughput on multi-core systems. The `socket2` crate
      already supports this.

---

## Milestone 6 — Advanced Networking

Features for specialized deployment scenarios.

- [ ] **PROXY protocol v1/v2** — Preserve original client IP when deployed
      behind a load balancer (HAProxy, AWS NLB).
- [ ] **DNS-over-TLS / DNS-over-HTTPS** — Encrypt upstream DNS resolution to
      prevent query interception.
- [ ] **Transparent proxy mode** — Linux `iptables REDIRECT` / `TPROXY`
      support so traffic can be routed through the proxy without
      per-application configuration.
- [ ] **Non-root Docker user** — Add a `USER` directive to the Dockerfile for
      defense-in-depth, even on the scratch base image.
