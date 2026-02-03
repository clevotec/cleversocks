# CleverSocks Roadmap

**Vision:** The nginx of SOCKS proxies — small, fast, secure, reliable.

CleverSocks aims to be the definitive SOCKS5 proxy implementation:
minimal footprint, maximum performance, 100% test coverage, and
production-grade reliability. Simple to configure, easy to deploy,
impossible to break.

---

## Quality Standards

Every phase must meet these criteria before completion:

| Metric | Target | Tooling |
|--------|--------|---------|
| Test coverage | 100% line coverage | `cargo-tarpaulin`, `llvm-cov` |
| Fuzz testing | No crashes after 1M iterations | `cargo-fuzz`, `afl.rs` |
| Clippy | Zero warnings | `cargo clippy -- -D warnings` |
| Security audit | No high/critical findings | `cargo-audit`, `cargo-deny` |
| Binary size | < 500 KB (musl, stripped) | `cargo bloat`, `twiggy` |
| Memory safety | Zero `unsafe` blocks | Manual review |
| Documentation | 100% public API documented | `cargo doc --deny warnings` |

**CI gates:** PRs blocked until all metrics pass. No exceptions.

---

## Phase 1 — Foundation: Module Extraction

Split the monolith without changing behavior. Every existing test must
pass. This phase establishes the module structure for all future work.

### Code Changes

- [ ] Create `src/server/mod.rs` — extract accept loop
- [ ] Create `src/server/relay.rs` — extract `copyloop()`
- [ ] Create `src/protocol/socks5.rs` — rename existing `socks.rs`
- [ ] Create `src/protocol/handshake.rs` — extract handshake state machine
- [ ] Create `src/auth/mod.rs` + `userpass.rs` + `whitelist.rs`
- [ ] Create `src/connect/direct.rs` + `upstream.rs`
- [ ] Create `src/resolver/system.rs`
- [ ] Move `logging.rs` → `src/logging/stderr.rs`
- [ ] Move `forward.rs` → `src/forward.rs`

### Quality Gates

- [ ] All existing unit tests pass
- [ ] All existing integration tests pass
- [ ] `cargo clippy` zero warnings
- [ ] Binary size unchanged (±5%)
- [ ] Benchmark: no performance regression (±2%)

---

## Phase 2 — Test Infrastructure

Build the testing foundation before adding features. Tests are not
optional — they're the specification.

### Unit Test Framework

- [ ] Create `tests/unit/` directory structure mirroring `src/`
- [ ] Add `proptest` for property-based testing
- [ ] Add `criterion` for micro-benchmarks
- [ ] Add `test-case` for parameterized tests
- [ ] Target: 100% line coverage on existing code

### Integration Test Framework

- [ ] Refactor `tests/integration_test.rs` into focused test modules
- [ ] Add `test_auth.rs` — all authentication scenarios
- [ ] Add `test_protocol.rs` — SOCKS5 protocol edge cases
- [ ] Add `test_relay.rs` — data transfer correctness
- [ ] Add `test_errors.rs` — error handling paths
- [ ] Add `test_performance.rs` — throughput and latency benchmarks

### Fuzz Testing

- [ ] Set up `cargo-fuzz` infrastructure
- [ ] Fuzz target: SOCKS5 method selection parser
- [ ] Fuzz target: SOCKS5 credential parser
- [ ] Fuzz target: SOCKS5 connect request parser
- [ ] Fuzz target: forwarding rule parser
- [ ] CI job: run fuzzers for 10 minutes on each PR

### Coverage Tracking

- [ ] Set up `cargo-tarpaulin` in CI
- [ ] Add coverage badge to README
- [ ] Block PRs that reduce coverage
- [ ] Document uncovered lines (must have justification)

---

## Phase 3 — Trait Architecture

Introduce plugin boundaries. This enables testing with mocks and future
extensibility without bloat.

### Core Traits

- [ ] `Resolver` trait + `SystemResolver` implementation
- [ ] `Authenticator` trait + `NoAuth`, `UserPassAuth`, `WhitelistAuth`
- [ ] `Connector` trait + `DirectConnector`, `UpstreamConnector`
- [ ] `AccessControl` trait + `AllowAll` implementation
- [ ] `ServerContext` struct wiring all traits together

### Testing

- [ ] Mock implementations for each trait
- [ ] Unit tests using mocks (no network I/O)
- [ ] Property tests for trait contracts
- [ ] 100% coverage on all trait implementations

### Documentation

- [ ] Rustdoc for all public traits and types
- [ ] Examples in doc comments
- [ ] Architecture decision records (ADRs) for trait design

---

## Phase 4 — Security Hardening

Address all audit findings and go beyond. Security is not a feature —
it's the foundation.

### Audit Findings

- [ ] **MEDIUM-01:** Max connection limit (`-m` / `max_connections`)
- [ ] **MEDIUM-02:** Auth-once whitelist TTL and max size
- [ ] **MEDIUM-03:** Warn on insecure startup (no auth + non-loopback)
- [ ] **LOW-01:** Pad constant-time comparison (no length leak)
- [ ] **LOW-02:** Accumulate partial reads in handshake
- [ ] **LOW-03:** Clear write timeout before relay
- [ ] **LOW-04:** Try all upstream addresses
- [ ] **LOW-05:** Byte-level credential comparison
- [ ] **LOW-07:** Log on RwLock poisoning
- [ ] **LOW-08:** Handshake timeout + TCP keepalive

### Beyond the Audit

- [ ] Add `seccomp` filter on Linux (restrict syscalls)
- [ ] Add `pledge`/`unveil` on OpenBSD
- [ ] Memory zeroing for credential buffers (`zeroize` crate)
- [ ] Constant-time operations audit (use `subtle` crate)
- [ ] Stack canaries verification in release builds
- [ ] ASLR verification in CI

### Testing

- [ ] Unit tests for every security fix
- [ ] Fuzz tests for parser hardening
- [ ] Timing attack tests for constant-time code
- [ ] Memory safety tests with `miri`

---

## Phase 5 — Configuration System

YAML config for complex deployments, CLI for simple ones. One or the
other, never mixed.

### Implementation

- [ ] Add `serde` + `serde_yaml` dependencies
- [ ] Create `src/config/mod.rs` — unified `Config` struct
- [ ] Create `src/config/cli.rs` — existing CLI parser refactored
- [ ] Create `src/config/yaml.rs` — YAML loader
- [ ] Environment variable expansion (`${VAR}` syntax)
- [ ] `-c <path>` flag, mutual exclusion with other flags
- [ ] Config validation with clear error messages

### New Config Options (YAML only initially)

- [ ] `log_level`: error/warn/info/debug/trace
- [ ] `max_connections`: connection limit
- [ ] `auth_once_ttl`: whitelist entry TTL
- [ ] `auth_once_max`: whitelist max size
- [ ] `acl`: access control rules section
- [ ] `auth.users`: multi-user array

### Testing

- [ ] Unit tests for YAML parsing
- [ ] Unit tests for CLI parsing
- [ ] Unit tests for env-var expansion
- [ ] Integration tests for config validation
- [ ] Fuzz tests for YAML parser
- [ ] 100% coverage on config module

### Documentation

- [ ] Complete YAML schema reference
- [ ] Migration guide from CLI to YAML
- [ ] Example configs for common scenarios

---

## Phase 6 — Logging & Diagnostics

Structured, leveled logging for production debugging.

### Implementation

- [ ] `LogLevel` enum: error, warn, info, debug, trace
- [ ] Level-aware `log_*!` macros
- [ ] Per-connection unique ID in all log messages
- [ ] JSON output format option
- [ ] `-q` backward compatibility (sets level to error)
- [ ] Timestamp in RFC 3339 format

### Testing

- [ ] Unit tests for log formatting
- [ ] Unit tests for level filtering
- [ ] Integration tests for log output capture
- [ ] No logging in hot paths (benchmark verification)

---

## Phase 7 — Platform Integration

First-class support for all major platforms. Install once, run forever.

### Linux (systemd)

- [ ] `dist/systemd/cleversocks.service` — hardened unit file
- [ ] Default config at `/etc/cleversocks/config.yaml`
- [ ] DynamicUser, NoNewPrivileges, ProtectSystem=strict
- [ ] Socket activation support (optional)
- [ ] `sd_notify` for readiness signaling

### Linux (legacy)

- [ ] `dist/upstart/cleversocks.conf`
- [ ] `dist/sysvinit/cleversocks` — LSB init script
- [ ] `/etc/default/cleversocks` for environment

### macOS

- [ ] `dist/launchd/com.clevotec.cleversocks.plist`
- [ ] Homebrew formula in separate tap
- [ ] `brew services` integration

### Windows

- [ ] `windows-service` crate integration
- [ ] `cleversocks service install/uninstall/start/stop`
- [ ] Event log integration
- [ ] MSI installer (optional)

### Signal Handling

- [ ] `SIGTERM`/`SIGINT` → graceful shutdown
- [ ] `SIGHUP` → config reload
- [ ] `SIGUSR1` → reopen log files
- [ ] Windows: SERVICE_CONTROL_* equivalents

### Packaging

- [ ] Update `nfpm.yaml` with all platform files
- [ ] DEB: config noreplace, systemd integration
- [ ] RPM: config noreplace, systemd integration
- [ ] APK: OpenRC script
- [ ] Arch: PKGBUILD in AUR

### Testing

- [ ] Integration tests for signal handling
- [ ] Integration tests for graceful shutdown
- [ ] Manual testing checklist for each platform

---

## Phase 8 — Access Control

Defense in depth. Block abuse at the proxy level.

### Implementation

- [ ] `RuleBasedAcl` implementing `AccessControl`
- [ ] CIDR matching (IPv4 and IPv6)
- [ ] Port matching (single, range, list)
- [ ] Domain matching (exact, wildcard, regex)
- [ ] Default allow/deny policy
- [ ] Rule ordering (first match wins)

### Default Rules (shipped config)

- [ ] Block RFC 1918 (10/8, 172.16/12, 192.168/16)
- [ ] Block loopback (127/8, ::1)
- [ ] Block link-local (169.254/16, fe80::/10)
- [ ] Block cloud metadata (169.254.169.254)
- [ ] Block SMTP (25, 465, 587)

### Testing

- [ ] Unit tests for CIDR matching
- [ ] Unit tests for domain matching
- [ ] Property tests for rule evaluation
- [ ] Integration tests for ACL enforcement
- [ ] Fuzz tests for rule parsing
- [ ] Performance benchmark (rule evaluation overhead)

---

## Phase 9 — Proxy Pool (proxybroker2 Integration)

Rotating upstream proxies for anonymity and load distribution.

### Core Implementation

- [ ] `ProxyPool` trait in `src/pool/mod.rs`
- [ ] `UpstreamProxy` struct with metadata
- [ ] `StaticPool` — fixed list from config
- [ ] `FilePool` — load from file with auto-reload
- [ ] `PooledConnector` — `Connector` wrapping pool

### Format Parsers

- [ ] JSON parser (proxybroker2 `--format json`)
- [ ] Text parser (`host:port` per line)
- [ ] Extended parser (`protocol://[user:pass@]host:port`)
- [ ] Auto-detection from file content

### Selection Strategies

- [ ] Round-robin
- [ ] Random
- [ ] Least-connections
- [ ] Fastest (by avg_resp_time)
- [ ] Weighted random

### Health Checking

- [ ] Passive health (track request success/failure)
- [ ] Active health (periodic connectivity checks)
- [ ] Failure threshold with automatic removal
- [ ] Recovery on reload

### Testing

- [ ] Unit tests for each parser
- [ ] Unit tests for each selection strategy
- [ ] Property tests for pool invariants
- [ ] Integration tests with mock upstream
- [ ] Fuzz tests for parsers
- [ ] 100% coverage on pool module

---

## Phase 10 — Protocol Completeness

Full SOCKS5 RFC compliance plus compatibility layers.

### SOCKS5

- [ ] UDP ASSOCIATE (RFC 1928 §7)
- [ ] BIND command (RFC 1928 §6)
- [ ] GSSAPI auth (RFC 1961) — behind feature flag

### Compatibility

- [ ] HTTP CONNECT proxy mode
- [ ] SOCKS4/4a backward compatibility
- [ ] Protocol auto-detection

### Testing

- [ ] Conformance tests against RFC 1928
- [ ] Conformance tests against RFC 1929
- [ ] Integration tests with real clients (curl, Firefox, etc.)
- [ ] Fuzz tests for new protocol parsers

---

## Phase 11 — Performance Optimization

Make it fast. Measure everything. Optimize with data.

### Benchmarking Suite

- [ ] `benches/throughput.rs` — bytes/sec for various payloads
- [ ] `benches/latency.rs` — connection establishment time
- [ ] `benches/concurrency.rs` — connections/sec at scale
- [ ] `benches/memory.rs` — memory per connection
- [ ] Compare against: Dante, microsocks, 3proxy, srelay
- [ ] Publish benchmark results in README

### Optimizations

- [ ] TCP_NODELAY for interactive workloads
- [ ] Configurable relay buffer size
- [ ] DNS caching (`CachingResolver`)
- [ ] Happy Eyeballs (RFC 8305) for dual-stack
- [ ] Zero-copy relay with `splice()` on Linux
- [ ] `SO_REUSEPORT` for multi-core scaling

### Async Runtime (feature flag)

- [ ] `tokio` runtime behind `async` feature
- [ ] Async variants of all traits
- [ ] Task-per-connection instead of thread-per-connection
- [ ] Benchmark: async vs. sync at high concurrency

### Binary Size

- [ ] Audit dependencies with `cargo bloat`
- [ ] Remove unused features from dependencies
- [ ] LTO and codegen optimization
- [ ] Target: < 500 KB musl binary

### Testing

- [ ] Regression tests for performance
- [ ] CI job: benchmark comparison against baseline
- [ ] Memory leak detection with valgrind/heaptrack

---

## Phase 12 — Observability

Production visibility without the bloat.

### Metrics

- [ ] Minimal HTTP server on management port
- [ ] Prometheus text format
- [ ] Counters: connections (active, total, failed)
- [ ] Counters: bytes (in, out)
- [ ] Counters: auth (success, failure)
- [ ] Counters: ACL (allowed, denied)
- [ ] Counters: pool (per-upstream stats)
- [ ] Histograms: latency (connection, request)

### Health Endpoints

- [ ] `/healthz` — liveness check
- [ ] `/readyz` — readiness check
- [ ] `/metrics` — Prometheus metrics

### Testing

- [ ] Unit tests for metric collection
- [ ] Integration tests for HTTP endpoints
- [ ] Load test: metrics overhead < 1%

---

## Phase 13 — TLS & Advanced Security

Encrypted transport for sensitive deployments.

### TLS Listener

- [ ] `rustls` behind `tls` feature flag
- [ ] YAML: `tls.cert`, `tls.key`
- [ ] SNI support
- [ ] Client certificate authentication (optional)
- [ ] TLS 1.3 only by default

### Advanced

- [ ] PROXY protocol v1/v2 support
- [ ] DNS-over-TLS/HTTPS (`hickory-resolver`)
- [ ] Transparent proxy mode (Linux TPROXY)

### Testing

- [ ] Integration tests with TLS clients
- [ ] Certificate validation tests
- [ ] Cipher suite verification

---

## Phase 14 — Documentation & Developer Experience

The best proxy is the one people can actually use.

### User Documentation

- [ ] README rewrite: quick start, features, comparison
- [ ] `docs/configuration.md` — complete config reference
- [ ] `docs/deployment.md` — platform-specific guides
- [ ] `docs/security.md` — hardening recommendations
- [ ] `docs/troubleshooting.md` — common issues
- [ ] Man page update (`cleversocks.1`)

### Developer Documentation

- [ ] `CONTRIBUTING.md` — how to contribute
- [ ] `docs/architecture.md` — system design (already exists)
- [ ] `docs/testing.md` — how to run and write tests
- [ ] `docs/releasing.md` — release process
- [ ] ADRs for all major decisions

### Examples

- [ ] `examples/basic.yaml` — minimal config
- [ ] `examples/production.yaml` — hardened production config
- [ ] `examples/proxybroker2.yaml` — rotating proxy pool
- [ ] `examples/kubernetes.yaml` — K8s deployment
- [ ] `examples/docker-compose.yaml` — Docker setup

### Testing

- [ ] Doc tests for all code examples
- [ ] Link checker for documentation
- [ ] Spell checker in CI

---

## Phase 15 — Production Readiness

The final polish. Ready for battle.

### Stability

- [ ] Run in production for 30 days without restart
- [ ] Handle 10,000 concurrent connections
- [ ] Zero memory leaks over extended runs
- [ ] Graceful handling of all error conditions

### Release Process

- [ ] Semantic versioning policy
- [ ] Changelog automation
- [ ] Signed releases (GPG)
- [ ] SBOM generation
- [ ] Security advisory process

### Ecosystem

- [ ] Docker Hub official image
- [ ] GitHub Container Registry
- [ ] Homebrew core (not just tap)
- [ ] Debian/Ubuntu official repos (long-term goal)
- [ ] Chocolatey package (Windows)

### Certification

- [ ] CII Best Practices badge
- [ ] Security audit by third party
- [ ] Performance benchmark publication

---

## Competitive Comparison

CleverSocks vs. the competition:

| Feature | CleverSocks | Dante | microsocks | 3proxy | srelay |
|---------|-------------|-------|------------|--------|--------|
| Language | Rust | C | C | C | C |
| Memory safety | ✅ | ❌ | ❌ | ❌ | ❌ |
| Binary size | < 500 KB | ~2 MB | ~50 KB | ~500 KB | ~200 KB |
| Test coverage | 100% | Unknown | None | Unknown | Unknown |
| Fuzz tested | ✅ | ❌ | ❌ | ❌ | ❌ |
| Async I/O | Optional | ❌ | ❌ | ❌ | ❌ |
| YAML config | ✅ | ✅ | ❌ | ✅ | ❌ |
| Proxy pool | ✅ | ❌ | ❌ | ❌ | ❌ |
| TLS | ✅ | ✅ | ❌ | ❌ | ❌ |
| UDP ASSOCIATE | ✅ | ✅ | ❌ | ✅ | ❌ |
| Metrics | ✅ | ❌ | ❌ | ❌ | ❌ |
| Active maint. | ✅ | Slow | ❌ | Slow | ❌ |

---

## Release Milestones

| Version | Phases | Theme |
|---------|--------|-------|
| v2.0.0 | 1-4 | Foundation + Security |
| v2.1.0 | 5-6 | Config + Logging |
| v2.2.0 | 7-8 | Platform + ACLs |
| v2.3.0 | 9 | Proxy Pool |
| v2.4.0 | 10 | Protocol Complete |
| v3.0.0 | 11-12 | Performance + Observability |
| v3.1.0 | 13 | TLS |
| v3.2.0 | 14-15 | Production Ready |

Each release is production-ready. No "beta" phases — if it's released,
it works.

---

## Non-Goals

Staying focused means saying no:

- ❌ HTTP proxy (use nginx/squid)
- ❌ Caching proxy (use squid/varnish)
- ❌ Load balancer (use haproxy/nginx)
- ❌ VPN replacement (use WireGuard)
- ❌ Web UI (use Prometheus/Grafana)
- ❌ Plugins/scripting (keep it simple)
- ❌ Database backend (flat files only)

CleverSocks does one thing well: SOCKS5 proxying.
