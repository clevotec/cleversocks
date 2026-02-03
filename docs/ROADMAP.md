# CleverSocks Roadmap

This roadmap tracks the evolution from v1.0.5 (flat module monolith) to a
pluggable, production-grade SOCKS5 proxy. Phases are ordered so that each
one produces a releasable binary with no regressions for existing users.

Architectural details and trait definitions are in
[ARCHITECTURE.md](ARCHITECTURE.md). Security audit findings referenced as
`MEDIUM-XX` / `LOW-XX` are documented in
[SECURITY_REVIEW.md](SECURITY_REVIEW.md).

---

## Phase 1 — Module Extraction (no behavior changes)

Split `proxy.rs` into the target directory layout without adding any new
features. Every existing test and CLI invocation must produce identical
results.

- [ ] Create `src/server/mod.rs` — extract accept loop
      (`run_server`, `run_blocking`, `run_with_idle_timeout`)
- [ ] Create `src/server/relay.rs` — extract `copyloop()`
- [ ] Create `src/protocol/socks5.rs` — rename existing `socks.rs`
- [ ] Create `src/protocol/handshake.rs` — extract `handshake()`,
      `choose_auth_method()`, `check_credentials()`
- [ ] Create `src/auth/mod.rs` + `src/auth/userpass.rs` +
      `src/auth/whitelist.rs` — extract `AuthState`,
      `constant_time_eq`, credential checking
- [ ] Create `src/connect/direct.rs` — extract `connect_target()`,
      `connect_with_bind()`
- [ ] Create `src/connect/upstream.rs` — extract
      `connect_via_upstream()`
- [ ] Create `src/resolver/system.rs` — extract `resolve_ip()`,
      `resolve_to_socketaddr()`
- [ ] Move `logging.rs` → `src/logging/stderr.rs`
- [ ] Move `forward.rs` → `src/forward.rs` (unchanged)
- [ ] Verify: `cargo test`, `cargo clippy`, integration tests all pass

---

## Phase 2 — Trait Boundaries

Introduce the four core traits (`Resolver`, `Authenticator`, `Connector`,
`AccessControl`). Wrap the Phase 1 concrete implementations behind them.
Wire trait objects together in `main.rs` via a `ServerContext` struct.

- [ ] Define `Resolver` trait in `src/resolver/mod.rs`
- [ ] Implement `Resolver` for `SystemResolver`
- [ ] Define `Authenticator` trait in `src/auth/mod.rs`
- [ ] Implement `Authenticator` for `NoAuth`, `UserPassAuth`,
      `WhitelistAuth`
- [ ] Define `Connector` trait in `src/connect/mod.rs`
- [ ] Implement `Connector` for `DirectConnector`, `UpstreamConnector`
- [ ] Define `AccessControl` trait in `src/acl/mod.rs`
- [ ] Implement `AccessControl` for `AllowAll` (default, pass-through)
- [ ] Create `ServerContext` struct holding `Arc<dyn Trait>` for each
- [ ] Update `handshake()` to accept `&ServerContext` instead of raw
      `&Config` + `Option<&AuthState>`
- [ ] Add unit tests with mock trait implementations
- [ ] Verify: all existing tests and CLI behavior unchanged

---

## Phase 3 — Hardening

Address all security review findings. These are standalone fixes that
don't depend on the trait refactor but benefit from the cleaner module
boundaries.

- [ ] **Warn on insecure startup** — Print a warning to stderr when
      starting without auth on a non-loopback address.
      Do **not** block startup. *(MEDIUM-03)*
- [ ] **Max connection limit** — `AtomicUsize` counter in the accept
      loop. Configurable via `-m <max>` / `max_connections` in YAML.
      Default: 0 (unlimited). *(MEDIUM-01)*
- [ ] **Auth-once whitelist bounds** — Add TTL and max size to the
      whitelist. Evict oldest entry when full. Configurable via YAML.
      *(MEDIUM-02)*
- [ ] **Handshake timeout** — 30-second read timeout on client socket
      during handshake, cleared before relay. *(LOW-08)*
- [ ] **TCP keepalive** — Enable `SO_KEEPALIVE` via `socket2` on both
      client and remote sockets during relay. *(LOW-08)*
- [ ] **Clear write timeout before relay** — Match the upstream path:
      clear read/write timeouts on the remote stream after connect
      succeeds. *(LOW-03)*
- [ ] **Try all upstream addresses** — `connect_via_upstream()` iterates
      all resolved addresses. *(LOW-04)*
- [ ] **Byte-level credential comparison** — `parse_credentials()`
      returns `(&[u8], &[u8])` instead of `(String, String)`. *(LOW-05)*
- [ ] **Log on RwLock poisoning** — Emit a warning instead of silent
      fallback. *(LOW-07)*
- [ ] **Accumulate partial reads** — Handshake reads loop until a
      complete SOCKS5 message is received. *(LOW-02)*
- [ ] **Pad constant-time comparison** — Eliminate the early return on
      length mismatch. *(LOW-01)*

---

## Phase 4 — YAML Config

Add YAML config file support. CLI flags remain fully functional.
The two modes are mutually exclusive: `-c config.yaml` rejects any other
flag.

- [ ] Add `serde` + `serde_yaml` as dependencies
- [ ] Create `src/config/mod.rs` with the unified `Config` struct
- [ ] Create `src/config/cli.rs` — migrate existing CLI parser
- [ ] Create `src/config/yaml.rs` — YAML loader with env-var expansion
      (`${VAR_NAME}` syntax)
- [ ] Add `-c <path>` flag; error if mixed with other flags
- [ ] Validation: same rules apply regardless of source (user/pass
      pairing, -1/-w require auth, etc.)
- [ ] New YAML-only fields: `log_level`, `max_connections`,
      `auth_once_ttl`, `auth_once_max`, `acl` section, multi-user
      `auth.users` array
- [ ] Create `dist/config/config.yaml` — default config with sane
      production defaults (listen `127.0.0.1`, auth required, block
      RFC 1918 and metadata endpoints)
- [ ] Update man page with YAML schema documentation
- [ ] Tests: YAML parsing, env-var expansion, CLI/YAML mutual exclusion

---

## Phase 5 — Logging Levels

Replace binary on/off logging with leveled output.

- [ ] Define `LogLevel` enum: `error`, `warn`, `info`, `debug`, `trace`
- [ ] Update `dolog()` to accept a level and filter against config
- [ ] Update `log_msg!` macro to `log_info!`, `log_warn!`,
      `log_debug!`, `log_error!`, `log_trace!`
- [ ] `-q` sets level to `error` (backward compat)
- [ ] YAML: `log_level: info` (default)
- [ ] Add per-connection ID to log messages
- [ ] Optional JSON output format via `log_format: json` in YAML

---

## Phase 6 — Platform Integration & Packaging

Ship init system configs so packages deploy as managed services
out of the box.

### Systemd (Linux)

- [ ] Create `dist/systemd/cleversocks.service` — `Type=simple`,
      `DynamicUser=true`, hardened with `NoNewPrivileges`,
      `ProtectSystem=strict`, `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`
- [ ] Ship default config as `/etc/cleversocks/config.yaml`
- [ ] Update `nfpm.yaml` to include:
  - `/etc/cleversocks/config.yaml` (mode 0640, `noreplace`)
  - `/usr/lib/systemd/system/cleversocks.service`
- [ ] Post-install scriptlet: `systemctl daemon-reload`
- [ ] Test: install .deb/.rpm, `systemctl start cleversocks`, verify
      proxy works

### Upstart (Legacy Ubuntu/RHEL)

- [ ] Create `dist/upstart/cleversocks.conf` — respawn, setuid, exec
      with `-c /etc/cleversocks/config.yaml`
- [ ] Include in packages for platforms that ship upstart

### SysVinit

- [ ] Create `dist/sysvinit/cleversocks` — LSB-compliant init script,
      sources `/etc/default/cleversocks`, manages PID file, supports
      `start`, `stop`, `restart`, `status`, `force-reload`
- [ ] Include in .deb packages as fallback for non-systemd systems

### macOS (Homebrew)

- [ ] Create `dist/launchd/com.clevotec.cleversocks.plist` — `KeepAlive`,
      `RunAtLoad`, log to `/usr/local/var/log/cleversocks.log`
- [ ] Ship default config at `/usr/local/etc/cleversocks/config.yaml`
- [ ] Create Homebrew formula (or tap) that installs binary, config,
      plist; `brew services start cleversocks` works out of the box
- [ ] Test on macOS with `brew install --build-from-source`

### Windows Service

- [ ] Add `windows-service` crate dependency behind `#[cfg(windows)]`
- [ ] Implement `src/platform/windows.rs`:
  - `cleversocks.exe service install [--config path]` — registers with
    SCM, stores config path in registry
  - `cleversocks.exe service uninstall` — removes service
  - `cleversocks.exe service start` / `service stop` — SCM control
  - Auto-detect SCM vs. interactive launch
- [ ] Create default config at `C:\ProgramData\CleverSocks\config.yaml`
- [ ] Document installation in README
- [ ] Test: `sc query cleversocks`, verify proxy works

### Signal Handling & Graceful Shutdown

- [ ] Create `src/platform/signals.rs`
- [ ] `SIGTERM` / `SIGINT` → set shutdown flag, stop accepting, drain
      active connections up to a configurable timeout
- [ ] `SIGHUP` → reload config file (re-read YAML, update ACLs,
      credentials, log level; keep listener open)
- [ ] On Windows, handle `SERVICE_CONTROL_STOP` and
      `SERVICE_CONTROL_SHUTDOWN`

---

## Phase 7 — Security Features

New security capabilities that plug into the trait system.

- [ ] **Destination ACLs** — `RuleBasedAcl` implementing `AccessControl`
      trait. CIDR, port, and domain-glob rules. Configurable in YAML.
      Default shipped config blocks RFC 1918, link-local,
      `169.254.169.254`, and SMTP ports.
- [ ] **Rate limiting** — `src/server/rate_limit.rs`. Per-IP connection
      rate and auth-attempt throttling. Token-bucket algorithm.
      Configurable burst and sustained rates.
- [ ] **Multi-user auth** — `MultiUserAuth` implementing `Authenticator`.
      User table loaded from YAML `auth.users` array. Per-user
      connection limits (future).
- [ ] **Credential file / env-var** — YAML `${VAR}` expansion (Phase 4)
      covers this. Document the pattern. CLI adds `--password-file`
      flag that reads first line of a file.
- [ ] **TLS listener** — `rustls` behind a `tls` Cargo feature flag.
      YAML: `tls.cert` and `tls.key`. Wraps the `TcpListener` accept
      in a TLS handshake. No changes to handshake or relay modules.

---

## Phase 8 — Proxy Pool & proxybroker2 Integration

Rotating upstream proxy pool for load distribution, anonymity rotation,
and integration with proxy scrapers like
[proxybroker2](https://github.com/bluet/proxybroker2).

### Core Implementation

- [ ] **`ProxyPool` trait** — Define in `src/pool/mod.rs`:
  - `select() -> Option<UpstreamProxy>` — get next proxy
  - `mark_failed()` / `mark_success()` — health tracking
  - `reload()` — refresh from source
  - `len()` — available proxy count

- [ ] **`UpstreamProxy` struct** — Proxy metadata:
  - host, port, protocol (SOCKS5/SOCKS4/HTTP)
  - optional auth credentials
  - optional metadata (country, response time, error rate)

- [ ] **`StaticPool`** — Fixed list of proxies from YAML config

- [ ] **`FilePool`** — Load proxies from file with auto-reload

### Format Parsers (proxybroker2 compatibility)

- [ ] **JSON parser** — Parse proxybroker2 `--format json` output:
  ```json
  [{"host": "1.2.3.4", "port": 1080,
    "types": [{"type": "SOCKS5", "level": "High"}],
    "avg_resp_time": 1.2}]
  ```

- [ ] **Text parser** — Parse `host:port` format (one per line)

- [ ] **Extended text parser** — Parse `protocol://[user:pass@]host:port`

- [ ] **Auto-detection** — Detect format from file content (JSON array
      vs. text lines)

### Selection Strategies

- [ ] **Round-robin** — Cycle through proxies sequentially
- [ ] **Random** — Uniform random selection
- [ ] **Least-connections** — Track active connections per proxy
- [ ] **Fastest** — Prefer proxies with lowest `avg_resp_time`
- [ ] **Weighted random** — Weight by inverse response time / error rate

### Protocol Filtering

- [ ] Filter loaded proxies by protocol type (e.g., only SOCKS5)
- [ ] Filter by country code (if metadata available)
- [ ] Filter by anonymity level (if metadata available)

### Health Checking

- [ ] **Passive health** — Track success/failure from actual requests
- [ ] **Active health** — Periodic background connectivity checks
- [ ] **Failure threshold** — Remove proxy after N consecutive failures
- [ ] **Recovery** — Re-add proxy after reload if it reappears

### Integration

- [ ] **`PooledConnector`** — `Connector` implementation that wraps
      `DirectConnector` and routes through pool-selected upstream

- [ ] **Forwarding rule precedence** — Explicit forwarding rules take
      priority over pool routing

- [ ] **YAML config section** — `proxy_pool:` with all options:
  ```yaml
  proxy_pool:
    enabled: true
    source: /var/lib/cleversocks/proxies.json
    format: auto
    protocol_filter: [socks5]
    strategy: round_robin
    reload_interval: 300
    health_check:
      enabled: true
      interval: 60
      timeout: 5
      max_failures: 3
  ```

- [ ] **Hot reload** — Reload proxy list on SIGHUP or timer without
      dropping active connections

### Documentation

- [ ] Add proxybroker2 integration example to docs
- [ ] Document cron setup for periodic proxy scraping
- [ ] Document all supported input formats

---

## Phase 9 — Protocol Completeness

Implement remaining SOCKS5 commands and compatibility layers.

- [ ] **UDP ASSOCIATE (RFC 1928 §7)** — New `src/protocol/udp.rs`.
      Allocates a UDP relay socket per client. Mapping table from client
      address to remote address. Configurable enable/disable.
- [ ] **BIND command (RFC 1928 §6)** — Accept server-to-client
      connections for FTP active mode and similar protocols.
- [ ] **HTTP CONNECT proxy mode** — Detect HTTP CONNECT requests on the
      listener (first bytes are ASCII, not `\x05`). Parse HTTP CONNECT
      header, establish tunnel, relay. Same port or separate port via
      config.
- [ ] **SOCKS4/4a** — `src/protocol/socks4.rs`. Detect version byte
      `\x04` on accept and handle SOCKS4 CONNECT with optional 4a
      domain resolution.
- [ ] **GSSAPI auth (RFC 1961)** — Behind a `gssapi` Cargo feature
      flag. Enterprise/AD environments.

---

## Phase 10 — Performance

Major architectural shift from threads to async, plus network
optimizations.

- [ ] **Async I/O (tokio)** — Behind an `async` Cargo feature flag. The
      synchronous thread-per-connection model remains the default for
      simplicity. Async mode uses `tokio::spawn` tasks. All traits get
      async variants. This is the largest single change.
- [ ] **TCP_NODELAY** — Disable Nagle on relay connections. Configurable
      via YAML `tcp_nodelay: true` (default: true).
- [ ] **Configurable relay buffer** — YAML `relay_buffer_size: 32768`.
      Default remains 16 KB.
- [ ] **DNS caching** — `CachingResolver` wrapping `SystemResolver`.
      TTL-based. YAML `dns_cache_ttl: 300`. Plugs into the `Resolver`
      trait with zero changes to other modules.
- [ ] **Happy Eyeballs (RFC 8305)** — `HappyEyeballsConnector`
      implementing `Connector`. Races IPv6/IPv4 with 250ms stagger.
- [ ] **Connection pooling** — Reuse upstream proxy connections across
      forwarding rules. Pool keyed by (upstream_host, upstream_port).
- [ ] **Zero-copy relay (`splice`)** — Linux-only. Use `splice()` in
      `server/relay.rs` when both fds are sockets. Fall back to
      userspace copy on other platforms.
- [ ] **`SO_REUSEPORT`** — Multiple accept threads on multi-core
      systems. `socket2` already supports this.

---

## Phase 11 — Observability & Advanced Networking

- [ ] **Metrics endpoint** — Minimal HTTP server on a management port.
      Prometheus text format. Counters: active connections, total
      connections, bytes in/out, auth success/fail, ACL denials,
      proxy pool stats (per-upstream success/fail/latency).
- [ ] **Health check endpoint** — `/healthz` on the metrics port.
      Returns 200 if the listener is alive.
- [ ] **PROXY protocol v1/v2** — Preserve client IP behind load
      balancers. Uses `proxy-protocol` crate.
- [ ] **DNS-over-TLS / DNS-over-HTTPS** — `HickoryResolver`
      implementing `Resolver` trait. Behind a `doh` feature flag.
- [ ] **Transparent proxy mode** — Linux `TPROXY` / `REDIRECT` support.
      Detect original destination via `SO_ORIGINAL_DST`.
- [ ] **Non-root Docker user** — Add numeric UID to scratch Dockerfile.

---

## Default Shipped Configs

Each package format ships a config file tuned for its platform.

### Linux packages (`/etc/cleversocks/config.yaml`)

```yaml
listen: 127.0.0.1
port: 1080
log_level: info

auth:
  users:
    - username: proxy
      password: ${CLEVERSOCKS_PASSWORD}
  auth_once: false
  whitelist: []

max_connections: 10000

acl:
  default: allow
  rules:
    - { action: deny, cidr: "10.0.0.0/8" }
    - { action: deny, cidr: "172.16.0.0/12" }
    - { action: deny, cidr: "192.168.0.0/16" }
    - { action: deny, cidr: "169.254.169.254/32" }
    - { action: deny, cidr: "127.0.0.0/8" }
    - { action: deny, cidr: "::1/128" }
    - { action: deny, ports: [25, 465, 587] }
```

### macOS Homebrew (`/usr/local/etc/cleversocks/config.yaml`)

Same as Linux but `listen: 127.0.0.1` and the ACL section commented out
with a note explaining each rule.

### Windows (`C:\ProgramData\CleverSocks\config.yaml`)

Same structure, Windows-style paths in comments.
