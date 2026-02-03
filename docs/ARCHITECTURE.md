# Architecture Improvement Plan

**Vision:** The nginx of SOCKS proxies — small, fast, secure, reliable.

---

## Design Philosophy

1. **Simplicity over features.** Every feature must justify its existence.
   If nginx/squid/haproxy does it better, don't add it.

2. **Security by default.** Unsafe configurations warn loudly. Safe
   configurations work out of the box.

3. **100% test coverage.** Untested code is broken code. Every code path
   has a test. Every bug fix adds a regression test.

4. **Zero unsafe.** Rust's safety guarantees are non-negotiable. No
   `unsafe` blocks, no exceptions.

5. **Minimal dependencies.** Each dependency is a liability. Justify
   every crate. Prefer std when reasonable.

6. **Measure everything.** Performance claims require benchmarks.
   Security claims require audits. Coverage claims require metrics.

---

## Quality Standards

| Metric | Target | Enforcement |
|--------|--------|-------------|
| Test coverage | 100% line | CI blocks merge below threshold |
| Fuzz testing | No crashes (1M iterations) | CI runs fuzzers on each PR |
| Clippy | Zero warnings | `cargo clippy -- -D warnings` |
| Security audit | No high/critical | `cargo-audit` in CI |
| Binary size | < 500 KB (musl) | CI reports size delta |
| Unsafe code | Zero blocks | `#![forbid(unsafe_code)]` |
| Documentation | 100% public API | `cargo doc --deny warnings` |

---

## Current State

CleverSocks v1.0.5 has five flat modules in `src/`:

```
main.rs        44 lines   Entry point
config.rs     418 lines   CLI parsing + DNS helpers
proxy.rs      898 lines   Server loop, handshake, auth, connect, relay
socks.rs      490 lines   SOCKS5 wire protocol
forward.rs    357 lines   Forwarding rule parsing + upstream builders
logging.rs    176 lines   Timestamped stderr output
```

### Problems

1. **`proxy.rs` is a monolith.** It owns the accept loop, per-client
   handshake, authentication decisions, target connection, upstream proxy
   negotiation, and bidirectional relay. Adding any feature (ACLs, rate
   limiting, UDP, metrics) means editing this single 900-line file.

2. **No trait boundaries.** Every subsystem (auth, DNS, connect, logging) is
   called as concrete functions. There is no way to swap implementations
   without rewriting callers.

3. **DNS is scattered.** `config.rs` exports `resolve_ip` and
   `resolve_to_socketaddr`. `proxy.rs` calls them inline. There is no
   caching, no async path, and no way to substitute a different resolver.

4. **Config is CLI-only.** Complex deployments (multiple users, ACL rules,
   many forwarding rules) are impractical as command-line arguments.

5. **No platform integration.** No systemd notify, no Windows service
   wrapper, no signal handling, no graceful shutdown.

---

## Design Principles

1. **Traits define plugin boundaries.** Each subsystem exposes a trait.
   New implementations are added by implementing the trait in a new file.
   Callers depend on the trait, never on the concrete type.

2. **One module = one responsibility.** The accept loop does not know how
   authentication works. The handshake does not know how DNS works.

3. **Config is the source of truth.** A single `Config` struct is built
   from *either* CLI arguments *or* a YAML file (never both mixed).
   All modules read from `Config`; none parse arguments themselves.

4. **Keep the binary small.** Features behind Cargo feature flags where
   they pull in large dependencies (TLS, async). The default build stays
   minimal.

5. **Warn, don't block.** Insecure defaults (open relay, no auth) print a
   clear warning but do not prevent startup. Sane defaults are provided via
   the shipped YAML config files in packages.

---

## Target Module Layout

```
src/
├── main.rs                    Entry point, service wrapper dispatch
│
├── config/
│   ├── mod.rs                 Config struct, validation, merge logic
│   ├── cli.rs                 CLI argument parser (existing logic)
│   └── yaml.rs                YAML file loader
│
├── server/
│   ├── mod.rs                 Accept loop, connection limits, shutdown
│   └── relay.rs               Bidirectional TCP copy (copyloop)
│
├── protocol/
│   ├── mod.rs                 Re-exports
│   ├── socks5.rs              SOCKS5 wire types + parsers (existing socks.rs)
│   ├── handshake.rs           SOCKS5 handshake state machine
│   └── socks4.rs              (future) SOCKS4/4a compat
│
├── auth/
│   ├── mod.rs                 Authenticator trait + registry
│   ├── noauth.rs              No-auth pass-through
│   ├── userpass.rs            Username/password (RFC 1929)
│   └── whitelist.rs           IP whitelist + auth-once state
│
├── resolver/
│   ├── mod.rs                 Resolver trait
│   └── system.rs              System DNS (std ToSocketAddrs)
│
├── connect/
│   ├── mod.rs                 Connector trait
│   ├── direct.rs              Direct TCP connect with bind support
│   ├── upstream.rs            SOCKS5 proxy chaining
│   └── pooled.rs              Connector using ProxyPool
│
├── pool/
│   ├── mod.rs                 ProxyPool trait, UpstreamProxy struct
│   ├── static_pool.rs         Fixed list from config
│   ├── file_pool.rs           Load from file (JSON/text formats)
│   └── parser.rs              Proxybroker2 format parsers
│
├── forward.rs                 Forwarding rule parsing (mostly unchanged)
│
├── acl/
│   ├── mod.rs                 AccessControl trait
│   └── rules.rs               CIDR / port / domain rules
│
├── logging/
│   ├── mod.rs                 Log trait, level enum, macros
│   └── stderr.rs              Timestamped stderr (existing, plus levels)
│
└── platform/
    ├── mod.rs                 Platform detection, re-exports
    ├── systemd.rs             sd_notify, watchdog
    ├── launchd.rs             macOS launchd helpers
    ├── windows.rs             Windows SCM service wrapper
    └── signals.rs             SIGTERM/SIGHUP handling
```

---

## Core Traits

Each trait is the seam where new implementations plug in. The server
module receives trait objects (or generics) at startup and never imports
concrete types from sibling modules.

### Resolver

```rust
// src/resolver/mod.rs

pub trait Resolver: Send + Sync {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>>;
}
```

**Shipped implementations:**
- `SystemResolver` — wraps `ToSocketAddrs` (current behavior).
- (future) `CachingResolver` — TTL-based cache in front of any inner
  `Resolver`.
- (future) `HickoryResolver` — async DNS with DoT/DoH, behind a feature
  flag.

**How to add a new resolver:**
1. Create `src/resolver/my_resolver.rs`.
2. Implement `Resolver` for your struct.
3. Add a config variant (e.g., `resolver: my_resolver`) to the YAML
   schema.
4. Register it in `src/resolver/mod.rs` factory function.

### Authenticator

```rust
// src/auth/mod.rs

pub enum AuthDecision {
    Allow,
    Deny,
    NeedCredentials,
}

pub trait Authenticator: Send + Sync {
    /// Decide what to do before seeing credentials.
    fn pre_auth(&self, client_ip: &IpAddr, methods: &[AuthMethod]) -> AuthDecision;

    /// Verify supplied credentials.  Called only when pre_auth
    /// returned NeedCredentials and the client sent a username/password.
    fn check(&self, client_ip: &IpAddr, user: &[u8], pass: &[u8]) -> bool;

    /// Called after successful auth (for auth-once bookkeeping).
    fn on_success(&self, client_ip: &IpAddr) {}
}
```

**Shipped implementations:**
- `NoAuth` — always allows.
- `UserPassAuth` — single user/pass with constant-time comparison.
- `WhitelistAuth` — static IP list + auth-once dynamic list with TTL.
- (future) `MultiUserAuth` — loads user table from config.
- (future) `PamAuth` — delegates to system PAM, behind a feature flag.

**How to add a new auth backend:**
1. Create `src/auth/my_auth.rs`.
2. Implement `Authenticator`.
3. Wire it into the auth chain in `src/auth/mod.rs`.

### Connector

```rust
// src/connect/mod.rs

pub trait Connector: Send + Sync {
    fn connect(
        &self,
        host: &str,
        port: u16,
        bind_addr: Option<IpAddr>,
    ) -> io::Result<TcpStream>;
}
```

**Shipped implementations:**
- `DirectConnector` — resolves + connects, tries all addresses (current
  `connect_target`).
- `UpstreamConnector` — SOCKS5 proxy chaining (current
  `connect_via_upstream`).
- (future) `HappyEyeballsConnector` — RFC 8305 parallel connect.

### AccessControl

```rust
// src/acl/mod.rs

pub enum AclDecision {
    Allow,
    Deny(ErrorCode),
}

pub trait AccessControl: Send + Sync {
    fn check_target(&self, host: &str, port: u16) -> AclDecision;
}
```

**Shipped implementations:**
- `AllowAll` — default, no restrictions.
- `RuleBasedAcl` — CIDR + port + domain allow/deny lists loaded from
  config.

### ProxyPool

```rust
// src/pool/mod.rs

pub struct UpstreamProxy {
    pub host: String,
    pub port: u16,
    pub protocol: ProxyProtocol,      // Socks5, Socks4, HttpConnect
    pub auth: Option<ProxyAuth>,
    pub country: Option<String>,
    pub avg_resp_time: Option<f64>,
    pub error_rate: Option<f64>,
}

pub enum SelectionStrategy {
    RoundRobin,
    Random,
    LeastConnections,
    Fastest,
    WeightedRandom,
}

pub trait ProxyPool: Send + Sync {
    /// Select the next upstream proxy based on the configured strategy.
    fn select(&self) -> Option<UpstreamProxy>;

    /// Mark a proxy as failed (for health tracking).
    fn mark_failed(&self, proxy: &UpstreamProxy);

    /// Mark a proxy as successful (for health tracking).
    fn mark_success(&self, proxy: &UpstreamProxy, response_time: Duration);

    /// Reload the proxy list from the configured source.
    fn reload(&self) -> io::Result<usize>;

    /// Number of currently available proxies.
    fn len(&self) -> usize;
}
```

**Shipped implementations:**
- `StaticPool` — fixed list of proxies from config.
- `FilePool` — loads proxies from a file, supports multiple formats,
  optional periodic reload.

**Supported input formats (for proxybroker2 compatibility):**

1. **JSON format** — proxybroker2 `--format json` output:
   ```json
   [
     {
       "host": "10.0.0.1",
       "port": 8080,
       "types": [{"type": "SOCKS5", "level": "High"}],
       "country": {"code": "US"},
       "avg_resp_time": 1.12,
       "error_rate": 0.05
     }
   ]
   ```

2. **Text format** — proxybroker2 `--format text` or simple proxy lists:
   ```
   10.0.0.1:8080
   10.0.0.2:1080
   socks5://user:pass@10.0.0.3:1080
   ```

3. **Extended text format** — protocol prefix and optional auth:
   ```
   socks5://10.0.0.1:1080
   socks4://10.0.0.2:1080
   http://10.0.0.3:8080
   socks5://user:pass@10.0.0.4:1080
   ```

**How to add a new proxy source:**
1. Create `src/pool/my_source.rs`.
2. Implement `ProxyPool` for your struct.
3. Add config variant to YAML schema.
4. Wire it in `main.rs`.

---

## Config System

### Design

Config comes from **one** source per invocation:

```
cleversocks -c /etc/cleversocks/config.yaml   # YAML mode
cleversocks -i 0.0.0.0 -p 1080 -u user -P pw  # CLI mode (no -c)
```

When `-c` is present, all other flags are rejected with an error message
pointing the user to the config file. This avoids ambiguity about which
source wins.

### YAML Schema

```yaml
# /etc/cleversocks/config.yaml

listen: 0.0.0.0
port: 1080
quiet: false
log_level: info            # error | warn | info | debug | trace

auth:
  users:
    - username: proxy_user
      password: ${CLEVERSOCKS_PASSWORD}  # env-var expansion
  auth_once: true
  auth_once_ttl: 3600      # seconds, 0 = forever
  auth_once_max: 10000     # max whitelist entries
  whitelist:
    - 127.0.0.1
    - ::1

bind_address: null         # outgoing IP, null = OS default

idle_timeout: null         # seconds, null = wait forever

max_connections: 0         # 0 = unlimited

acl:
  default: allow           # allow | deny
  rules:
    - action: deny
      cidr: 169.254.169.254/32   # block cloud metadata
    - action: deny
      cidr: 10.0.0.0/8
    - action: deny
      ports: [25, 465, 587]      # block SMTP

forwarding:
  - match: "example.com:443"
    upstream: "proxy.internal:1080"
    remote: "target.com:443"
    upstream_auth:
      username: chain_user
      password: chain_pass

# Proxy pool for upstream rotation (proxybroker2 integration)
proxy_pool:
  enabled: false
  source: /var/lib/cleversocks/proxies.json  # or proxies.txt
  format: auto                # auto | json | text
  protocol_filter: [socks5]   # only use SOCKS5 proxies from the list
  strategy: round_robin       # round_robin | random | least_connections | fastest
  reload_interval: 300        # seconds, 0 = no auto-reload
  health_check:
    enabled: true
    interval: 60              # seconds between health checks
    timeout: 5                # seconds
    max_failures: 3           # remove proxy after N consecutive failures

# tls:                     # (future)
#   cert: /etc/cleversocks/cert.pem
#   key: /etc/cleversocks/key.pem
```

### Config Struct

The internal `Config` struct is identical regardless of source. Both
`cli.rs` and `yaml.rs` produce the same `Config`:

```rust
pub struct Config {
    // Network
    pub listen_ip: String,
    pub port: u16,
    pub bind_addr: Option<IpAddr>,

    // Auth
    pub users: Vec<UserCredential>,     // empty = no auth
    pub auth_once: bool,
    pub auth_once_ttl: u64,
    pub auth_once_max: usize,
    pub whitelist_ips: Vec<IpAddr>,

    // Limits
    pub idle_timeout: Option<u64>,
    pub max_connections: usize,         // 0 = unlimited

    // ACL
    pub acl_default: AclDefault,
    pub acl_rules: Vec<AclRule>,

    // Forwarding
    pub forward_rules: Vec<ForwardRule>,

    // Logging
    pub quiet: bool,
    pub log_level: LogLevel,
}
```

The CLI parser maps existing flags to this struct (single-user `-u`/`-P`
becomes a one-element `users` vec). New fields get sensible defaults so
existing CLI invocations keep working.

### Env-Var Expansion

YAML values containing `${VAR_NAME}` are expanded from the environment
at load time. This keeps credentials out of the config file on disk.
Unset variables cause a startup error with a clear message.

---

## Server Lifecycle

```
main()
  ├── parse config (CLI or YAML)
  ├── validate config
  ├── warn if insecure (no auth + non-loopback)
  ├── init logging
  ├── init resolver
  ├── init authenticator chain
  ├── init access control
  ├── init connector
  ├── register signal handlers (SIGTERM → shutdown, SIGHUP → reload)
  ├── platform_init()       // sd_notify, Windows SCM, etc.
  ├── bind listener
  ├── log "Listening on ..."
  ├── sd_notify(READY=1)    // if systemd
  └── accept_loop()
        ├── check shutdown flag
        ├── check max_connections
        ├── accept()
        └── spawn handle_client(client, &ServerContext)
              ├── set handshake timeout (30s)
              ├── handshake (method selection → auth → connect request)
              │     ├── authenticator.pre_auth()
              │     ├── authenticator.check() if needed
              │     ├── acl.check_target()
              │     └── connector.connect()
              ├── clear timeouts
              ├── relay::copyloop()
              └── decrement active count
```

`ServerContext` is a cheaply-cloneable handle holding `Arc` references to
the resolver, authenticator, ACL, connector, config, and metrics
counters.

---

## Handshake Extraction

The current `handshake()` function in `proxy.rs` (lines 194-323) is
extracted into `src/protocol/handshake.rs`. It receives trait objects
instead of raw config:

```rust
pub fn handshake(
    client: &mut TcpStream,
    auth: &dyn Authenticator,
    acl: &dyn AccessControl,
    connector: &dyn Connector,
    rules: &[ForwardRule],
    client_addr: &SocketAddr,
) -> io::Result<TcpStream> { ... }
```

This makes the handshake testable in isolation by injecting mock
implementations of each trait.

---

## Relay Extraction

`copyloop()` moves to `src/server/relay.rs`. No trait needed — it
operates purely on `TcpStream` pairs. Future enhancements (splice,
metrics counting) are added here without touching the handshake.

---

## Platform Integration

### How to Add a New Platform

1. Create `src/platform/my_platform.rs`.
2. Implement the platform hooks:
   ```rust
   pub fn platform_init(config: &Config) -> io::Result<()>;
   pub fn notify_ready();
   pub fn notify_stopping();
   ```
3. Gate it with `#[cfg(target_os = "...")]` or a Cargo feature flag.
4. Call it from `main.rs` at the appropriate lifecycle point.

### Systemd

File: `dist/systemd/cleversocks.service`

```ini
[Unit]
Description=CleverSocks SOCKS5 Proxy
Documentation=man:cleversocks(1)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/cleversocks -c /etc/cleversocks/config.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/
ReadWritePaths=/run/cleversocks
DynamicUser=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

### Upstart (Ubuntu 14.04 and earlier)

File: `dist/upstart/cleversocks.conf`

```
description "CleverSocks SOCKS5 Proxy"

start on runlevel [2345]
stop on runlevel [!2345]

respawn
respawn limit 10 5

setuid cleversocks
setgid cleversocks

exec /usr/bin/cleversocks -c /etc/cleversocks/config.yaml
```

### SysVinit

File: `dist/sysvinit/cleversocks`

Standard LSB init script that sources `/etc/default/cleversocks` for
`DAEMON_ARGS`, manages a PID file under `/var/run/cleversocks.pid`, and
implements `start`, `stop`, `restart`, `status`.

### macOS launchd (Homebrew)

File: `dist/launchd/com.clevotec.cleversocks.plist`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.clevotec.cleversocks</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/cleversocks</string>
    <string>-c</string>
    <string>/usr/local/etc/cleversocks/config.yaml</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardErrorPath</key>
  <string>/usr/local/var/log/cleversocks.log</string>
</dict>
</plist>
```

Homebrew formula installs the plist via `brew services`.

### Windows Service

The binary detects whether it is running as a Windows service (launched
by SCM) or interactively (launched from a terminal):

```
cleversocks.exe -c config.yaml              # interactive
cleversocks.exe service install             # register as Windows service
cleversocks.exe service uninstall           # remove service
cleversocks.exe service start               # start via SCM
cleversocks.exe service stop                # stop via SCM
```

Implementation in `src/platform/windows.rs` uses the `windows-service`
crate (behind `#[cfg(windows)]`). The service reads its config path from
the registry key set during `service install`.

---

## Adding a New Feature — Step by Step

This is the process for adding any new capability to CleverSocks.

### Example: Adding a DNS Cache

1. **Define the interface** (if new, or reuse existing trait).
   The `Resolver` trait already exists. A caching resolver wraps an inner
   `Resolver`.

2. **Create the implementation file.**
   ```
   src/resolver/caching.rs
   ```

3. **Implement the trait.**
   ```rust
   pub struct CachingResolver<R: Resolver> {
       inner: R,
       cache: RwLock<HashMap<(String, u16), (Vec<SocketAddr>, Instant)>>,
       ttl: Duration,
   }

   impl<R: Resolver> Resolver for CachingResolver<R> {
       fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
           // check cache, delegate to inner if miss/expired
       }
   }
   ```

4. **Add config support.**
   In `config/mod.rs`, add a field:
   ```rust
   pub dns_cache_ttl: Option<u64>,  // None = no cache
   ```
   In `config/yaml.rs`, map the YAML key `dns_cache_ttl: 300`.
   In `config/cli.rs`, add flag `--dns-cache-ttl <seconds>`.

5. **Wire it up in `main.rs`.**
   ```rust
   let resolver: Box<dyn Resolver> = if let Some(ttl) = config.dns_cache_ttl {
       Box::new(CachingResolver::new(SystemResolver, Duration::from_secs(ttl)))
   } else {
       Box::new(SystemResolver)
   };
   ```

6. **Write tests** in `src/resolver/caching.rs` using a mock `Resolver`.

7. **Update docs.** Add the config key to the YAML schema section in this
   document and to the man page.

That's it. No changes to the handshake, server loop, relay, auth, or ACL
modules.

### Example: Adding a New Auth Backend

1. Create `src/auth/ldap.rs`.
2. Implement `Authenticator` for `LdapAuth`.
3. Add `auth.backend: ldap` to the YAML schema + config struct.
4. Wire it in `main.rs` based on config.
5. Add `ldap` Cargo feature flag if it pulls in new dependencies.
6. Tests with a mock LDAP server or integration test.

### Example: Adding Rate Limiting

1. Create `src/server/rate_limit.rs`.
2. Implement as middleware in the accept loop:
   ```rust
   pub struct RateLimiter { ... }
   impl RateLimiter {
       pub fn check(&self, ip: &IpAddr) -> bool;
   }
   ```
3. Call `rate_limiter.check()` in `accept_loop` before spawning the
   client thread. If denied, close the connection immediately.
4. Config: `rate_limit.connections_per_ip: 10`,
   `rate_limit.burst: 20`.
5. No changes to handshake, auth, connect, or relay.

### Example: Using proxybroker2 Scraped Proxies

This example shows how to use CleverSocks with
[proxybroker2](https://github.com/bluet/proxybroker2) to route traffic
through a rotating pool of public SOCKS5 proxies.

**Step 1: Scrape proxies with proxybroker2**

```bash
# Install proxybroker2
pip install proxybroker2

# Scrape SOCKS5 proxies and save as JSON
python -m proxybroker grab --types SOCKS5 --lvl High --limit 100 \
    --format json --outfile /var/lib/cleversocks/proxies.json
```

**Step 2: Configure CleverSocks to use the proxy pool**

```yaml
# /etc/cleversocks/config.yaml

listen: 127.0.0.1
port: 1080

proxy_pool:
  enabled: true
  source: /var/lib/cleversocks/proxies.json
  format: json
  protocol_filter: [socks5]
  strategy: fastest
  reload_interval: 300
  health_check:
    enabled: true
    interval: 60
    timeout: 5
    max_failures: 3
```

**Step 3: Set up periodic proxy refresh (cron)**

```cron
# Refresh proxy list every 5 minutes
*/5 * * * * python -m proxybroker grab --types SOCKS5 --lvl High \
    --limit 100 --format json \
    --outfile /var/lib/cleversocks/proxies.json 2>/dev/null
```

CleverSocks will automatically reload the proxy list when
`reload_interval` elapses, picking up new proxies without restart.

**How it works:**

1. When `proxy_pool.enabled` is true, the `PooledConnector` wraps the
   normal `DirectConnector`.
2. For each outbound connection, `PooledConnector` calls
   `pool.select()` to get an upstream proxy.
3. The connection is established through the selected upstream using
   SOCKS5 proxy chaining.
4. Success/failure is reported back to the pool for health tracking.
5. Failed proxies are removed after `max_failures` consecutive errors.
6. The pool is periodically refreshed from the source file.

**Integration with forwarding rules:**

Proxy pool and forwarding rules can coexist. Forwarding rules take
precedence — if a rule matches, its explicit upstream is used. For
non-matching connections, the pool selects an upstream.

```yaml
forwarding:
  # Specific route for internal service
  - match: "internal.example.com:*"
    upstream: "corporate-proxy.internal:1080"
    remote: "internal.example.com:*"

# Everything else goes through the rotating pool
proxy_pool:
  enabled: true
  source: /var/lib/cleversocks/proxies.json
```

---

## Testing Strategy

### Test Pyramid

```
                    ┌─────────────────┐
                    │   E2E Tests     │  Few, slow, high confidence
                    │  (real clients) │
                    ├─────────────────┤
                    │ Integration     │  Test module boundaries
                    │ Tests           │  Mock external systems
                    ├─────────────────┤
                    │                 │
                    │   Unit Tests    │  Fast, isolated, comprehensive
                    │                 │  One test file per source file
                    │                 │
                    └─────────────────┘
```

### Test Organization

```
tests/
├── unit/                    # Unit tests (mirror src/ structure)
│   ├── protocol/
│   │   ├── socks5_test.rs
│   │   └── handshake_test.rs
│   ├── auth/
│   │   ├── userpass_test.rs
│   │   └── whitelist_test.rs
│   └── ...
├── integration/             # Integration tests
│   ├── test_auth.rs         # Authentication scenarios
│   ├── test_protocol.rs     # Protocol compliance
│   ├── test_relay.rs        # Data transfer
│   ├── test_errors.rs       # Error handling
│   └── test_pool.rs         # Proxy pool
├── fuzz/                    # Fuzz targets
│   ├── fuzz_socks5_parser.rs
│   ├── fuzz_credentials.rs
│   └── fuzz_forward_rules.rs
├── conformance/             # RFC compliance tests
│   ├── rfc1928_test.rs      # SOCKS5 protocol
│   └── rfc1929_test.rs      # Username/password auth
└── benches/                 # Performance benchmarks
    ├── throughput.rs
    ├── latency.rs
    └── concurrency.rs
```

### Testing Each Trait

Every trait has a corresponding mock for testing:

```rust
// src/resolver/mod.rs
pub trait Resolver: Send + Sync {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>>;
}

// tests/unit/resolver/mock.rs
pub struct MockResolver {
    pub responses: HashMap<(String, u16), io::Result<Vec<SocketAddr>>>,
}

impl Resolver for MockResolver {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        self.responses.get(&(host.to_string(), port))
            .cloned()
            .unwrap_or_else(|| Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no mock response configured"
            )))
    }
}
```

This allows testing components in isolation without network I/O.

### Property-Based Testing

Use `proptest` for invariant testing:

```rust
proptest! {
    #[test]
    fn parse_then_serialize_roundtrips(req in connect_request_strategy()) {
        let bytes = req.to_bytes();
        let parsed = parse_connect_request(&bytes).unwrap();
        prop_assert_eq!(req, parsed);
    }

    #[test]
    fn pool_select_never_returns_failed_proxy(
        proxies in vec(proxy_strategy(), 1..100),
        failures in vec(usize::arbitrary(), 0..50)
    ) {
        let pool = FilePool::new(proxies);
        for idx in failures {
            if let Some(p) = pool.get(idx % pool.len()) {
                pool.mark_failed(&p);
                pool.mark_failed(&p);
                pool.mark_failed(&p); // 3 failures = removed
            }
        }
        // Select should never return a failed proxy
        for _ in 0..1000 {
            if let Some(p) = pool.select() {
                prop_assert!(pool.is_healthy(&p));
            }
        }
    }
}
```

### Fuzz Testing

Every parser has a fuzz target:

```rust
// fuzz/fuzz_targets/socks5_parser.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use cleversocks::protocol::socks5::parse_connect_request;

fuzz_target!(|data: &[u8]| {
    // Should never panic, regardless of input
    let _ = parse_connect_request(data);
});
```

CI runs fuzzers for 10 minutes on each PR. Local development can run
longer campaigns overnight.

### Benchmark Suite

```rust
// benches/throughput.rs
fn bench_relay_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("relay");

    for size in [1024, 16384, 65536, 1048576].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            size,
            |b, &size| {
                b.iter(|| relay_data(size))
            },
        );
    }
}
```

Benchmarks run on every release. Results are published in the README
with comparison against Dante, microsocks, and 3proxy.

---

## Migration Path from v1.0.5

The refactor is done in phases so that each phase produces a working,
releasable binary with no behavior changes for existing users.

### Phase 1: Extract modules (no new features)

Move code into the new directory structure. `proxy.rs` is split into
`server/mod.rs`, `server/relay.rs`, `protocol/handshake.rs`,
`auth/mod.rs`, `auth/userpass.rs`, `auth/whitelist.rs`,
`connect/direct.rs`, `connect/upstream.rs`. All tests must pass. The
binary behaves identically to v1.0.5.

### Phase 2: Introduce traits

Define `Resolver`, `Authenticator`, `Connector`, `AccessControl`. Wrap
existing concrete implementations behind these traits. `main.rs` wires
them together. All tests still pass.

### Phase 3: YAML config

Add `config/yaml.rs` and the `-c` flag. Existing CLI flags continue to
work. New config fields (log_level, max_connections, acl, auth_once_ttl)
are only available via YAML initially.

### Phase 4: Platform integration

Add init system files, Windows service wrapper, signal handling, and
graceful shutdown. Package them via nfpm.

### Phase 5: New features

With trait boundaries in place, new features (ACLs, rate limiting, DNS
cache, TLS, UDP, etc.) are added as independent modules without touching
the core.
