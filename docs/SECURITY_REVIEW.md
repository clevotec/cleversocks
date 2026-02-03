# Security Review: CleverSocks v1.0.5

**Date:** 2026-02-02
**Scope:** Full source audit of all Rust source files, Dockerfile, CI/CD pipeline, and dependencies.
**Commit reviewed:** 35f9bec

---

## Executive Summary

CleverSocks is a well-written, memory-safe SOCKS5 proxy implementation in Rust with zero `unsafe` code and a minimal dependency footprint (only `socket2`). The codebase demonstrates strong awareness of common security concerns: constant-time credential comparison, strict protocol validation, and comprehensive input bounds checking.

This review identified **3 medium-severity** and **8 low-severity** findings, plus several informational notes. No critical or high-severity vulnerabilities were found. The medium findings relate to denial-of-service resilience and default configuration posture rather than memory safety or code execution risks.

---

## Findings

### MEDIUM-01: Unbounded Thread Creation Enables Denial of Service

**File:** `src/proxy.rs:86-88`
**Category:** Resource Management

Each incoming connection spawns a new OS thread with no upper bound:

```rust
thread::spawn(move || {
    handle_client(client_stream, &config, auth_state.as_deref());
});
```

An attacker can open thousands of concurrent connections, exhausting memory and file descriptors. While the server handles `accept()` failures gracefully (line 91-93 with a 64-microsecond backoff), it does not proactively limit the number of active connections.

**Impact:** Denial of service via resource exhaustion.
**Recommendation:** Add an optional maximum connection limit (e.g., `-m <max>` flag) using an `AtomicUsize` counter, rejecting or queuing new connections when the limit is reached.

---

### MEDIUM-02: Unbounded Auth-Once Whitelist Growth

**File:** `src/proxy.rs:22-47`
**Category:** Resource Management

The auth-once feature (`-1` flag) stores whitelisted IPs in a `HashSet<IpAddr>` that grows without bound:

```rust
fn add_ip(&self, ip: IpAddr) {
    if let Ok(mut ips) = self.authed_ips.write() {
        ips.insert(ip);
    }
}
```

In long-running deployments exposed to many distinct source IPs, this set grows indefinitely with no eviction or maximum size. Additionally:
- **No expiry:** Once whitelisted, an IP stays whitelisted for the server's lifetime.
- **No revocation:** There is no mechanism to remove an IP.
- **IP reuse risk:** In environments with DHCP or NAT, a previously-authenticated IP may later be assigned to a different (unauthorized) user.

**Impact:** Memory exhaustion in long-running deployments; stale whitelist entries could grant access to unauthorized users after IP reassignment.
**Recommendation:** Add an optional TTL for whitelist entries, a maximum whitelist size with LRU eviction, or both.

---

### MEDIUM-03: Open Relay by Default

**File:** `src/config.rs:22-23`
**Category:** Configuration / Access Control

The server defaults to binding on `0.0.0.0:1080` with no authentication:

```rust
listen_ip: "0.0.0.0".to_string(),
port: 1080,
auth_user: None,
auth_pass: None,
```

Running `cleversocks` with no arguments creates an open SOCKS5 proxy on all interfaces. Open proxies are commonly abused for spam relaying, anonymizing malicious traffic, and accessing internal network services.

**Impact:** If deployed without explicit configuration, the proxy is immediately usable by any network-reachable client for any purpose.
**Recommendation:** Consider defaulting the listen address to `127.0.0.1`, or printing a clear warning to stderr when starting without authentication on a non-loopback address.

---

### LOW-01: Constant-Time Comparison Leaks Credential Length

**File:** `src/proxy.rs:371-380`
**Category:** Authentication

The `constant_time_eq` function returns early when lengths differ:

```rust
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // ...
}
```

An attacker measuring response latency could determine the length of the expected username and password. While the RFC 1929 wire format already transmits username/password lengths in cleartext (so a passive observer already knows the *client's* credential lengths), the early return reveals the *server's* expected credential length.

**Impact:** Leaks credential length through timing side-channel. Practical exploitability is low since credentials are typically short and the timing difference is small.
**Recommendation:** Pad the comparison to the maximum of both lengths, XORing with a dummy value for the shorter input.

---

### LOW-02: Partial Reads During SOCKS5 Handshake

**File:** `src/proxy.rs:203, 235, 266`
**Category:** Protocol Robustness

The handshake uses single `read()` calls to receive protocol messages:

```rust
let n = client.read(&mut buf)?;
```

TCP is a stream protocol; a single `read()` may return a partial message, especially under network congestion or with certain client TCP stacks. If a SOCKS5 method selection message arrives in two TCP segments, the server would only process the first segment and likely reject the connection.

The protocol parsers (`parse_method_selection`, `parse_credentials`, `parse_connect_request`) all validate lengths and return `None` or `Err` on short input, so this cannot cause memory corruption. However, legitimate connections could be spuriously rejected.

**Impact:** Potential false rejections under adverse network conditions. No memory safety impact.
**Recommendation:** Accumulate reads until a complete message is received, or use `read_exact()` for fixed-length portions of the protocol.

---

### LOW-03: Write Timeout Not Cleared for Direct Connections

**File:** `src/proxy.rs:406-418` vs `src/proxy.rs:557-558`
**Category:** Reliability

`connect_target()` sets a 5-second read/write timeout on the remote socket:

```rust
stream.set_read_timeout(Some(UPSTREAM_TIMEOUT))?;
stream.set_write_timeout(Some(UPSTREAM_TIMEOUT))?;
```

For upstream proxy connections, these are explicitly cleared before entering the relay (line 557-558). For direct connections, they are not. While the `copyloop()` overrides the read timeout to 15 minutes (line 576-577), the 5-second write timeout persists. This means writes to a slow remote target during relay will timeout after 5 seconds.

**Impact:** Premature connection drops when relaying data to slow targets. Not a security vulnerability per se, but a reliability bug that could be mistaken for a network attack.
**Recommendation:** Clear read/write timeouts on the remote stream after successful connection and before entering the relay loop, consistent with how upstream connections are handled.

---

### LOW-04: Upstream Proxy Connection Only Tries First Resolved Address

**File:** `src/proxy.rs:448`
**Category:** Reliability

`connect_via_upstream()` only attempts connection to the first DNS-resolved address:

```rust
let mut upstream = TcpStream::connect_timeout(&addrs[0], UPSTREAM_TIMEOUT)?;
```

By contrast, `connect_target()` iterates through all resolved addresses (line 413-423). If the upstream proxy's first DNS record is unreachable but others are valid, the forwarding rule fails unnecessarily.

**Impact:** Reduced reliability for upstream proxy connections with multiple DNS records.
**Recommendation:** Iterate through all resolved addresses, matching the `connect_target()` behavior.

---

### LOW-05: Lossy UTF-8 Conversion for Credentials

**File:** `src/socks.rs:156-157`
**Category:** Authentication

Credentials are parsed using `String::from_utf8_lossy`:

```rust
let user = String::from_utf8_lossy(&buf[2..2 + ulen]).to_string();
let pass = String::from_utf8_lossy(&buf[2 + ulen + 1..2 + ulen + 1 + plen]).to_string();
```

If a client sends non-UTF-8 bytes as credentials, they are silently replaced with U+FFFD (replacement character). This means the comparison in `check_credentials` happens on the *lossy* string, not the raw bytes. A credential containing invalid UTF-8 could never match the server's expected credential (which is always valid UTF-8 from CLI args), so there is no bypass risk. However, the credential comparison should ideally operate on raw bytes rather than decoded strings.

**Impact:** No security bypass. Potential interoperability issue with clients using non-UTF-8 credentials.
**Recommendation:** Compare credentials as raw `&[u8]` rather than converting to `String`.

---

### LOW-06: Credentials Visible in Process Arguments

**File:** `src/config.rs:63-77`
**Category:** Information Disclosure

The `-u`, `-P` flags and `-f` rules with embedded credentials are passed as command-line arguments, visible via `ps aux`, `/proc/<pid>/cmdline`, and similar tools.

**Impact:** Local users on the same system can read proxy credentials.
**Recommendation:** Document this limitation. Optionally support reading credentials from a file or environment variable.

---

### LOW-07: RwLock Poisoning Silently Degrades Auth

**File:** `src/proxy.rs:34-40`
**Category:** Concurrency

The `AuthState` methods silently swallow poisoned lock errors:

```rust
fn is_authed(&self, ip: &IpAddr) -> bool {
    if let Ok(ips) = self.authed_ips.read() {
        ips.contains(ip)
    } else {
        false
    }
}
```

If a thread panics while holding the write lock (e.g., during `add_ip`), all subsequent `is_authed` checks return `false`, forcing re-authentication for every connection. This is a safe degradation (fails closed), but it happens silently with no logging.

**Impact:** Auth-once whitelist silently stops working after a thread panic. Connections still require authentication, so no security bypass occurs.
**Recommendation:** Log a warning when lock acquisition fails.

---

### LOW-08: No TCP Keepalive on Connections

**File:** `src/proxy.rs`
**Category:** Resource Management

The proxy does not enable `SO_KEEPALIVE` on client or remote connections. If a client crashes without sending a TCP FIN/RST, the connection persists until the 15-minute inactivity timeout expires. In the pre-relay handshake phase, there is no timeout at all—a client that connects and never sends data will block a thread indefinitely.

**Impact:** Thread leak from half-open connections, especially in the handshake phase.
**Recommendation:** Set a shorter read timeout during the handshake phase (e.g., 30 seconds), and enable TCP keepalive for relay connections.

---

## Informational Notes

### INFO-01: No Target Address Restrictions (SSRF Surface)

The proxy will connect to any address the client requests, including private IP ranges (10.x, 172.16.x, 192.168.x, 127.x), link-local addresses, and cloud metadata endpoints (e.g., 169.254.169.254). This is expected behavior for a general-purpose proxy, but operators should be aware of the SSRF potential when deploying in cloud environments.

### INFO-02: Docker Container Runs as Root

The Dockerfile uses `FROM scratch` with no `USER` directive. While scratch containers have minimal attack surface, running as a non-root user is a defense-in-depth best practice.

### INFO-03: CI/CD Uses Trusted Repository Without GPG Verification

`build.yml:141` adds the goreleaser apt repository with `[trusted=yes]`, bypassing GPG signature verification for the `nfpm` package installation.

### INFO-04: No TLS Support

All SOCKS5 communication is in cleartext, including authentication credentials. This is standard for the SOCKS5 protocol (RFC 1928 does not define TLS), but operators should use SSH tunneling or other encryption when deploying over untrusted networks.

### INFO-05: DNS Resolution at Config Parse Time

The `-b` and `-w` options resolve hostnames to IP addresses at startup. If DNS records change after the server starts, the stale IPs are used for the server's lifetime.

---

## Positive Security Properties

The following design decisions demonstrate good security practice:

1. **Zero `unsafe` code** — Eliminates entire classes of memory safety bugs.
2. **Minimal dependencies** — Only `socket2` (+ transitive `libc`/`windows-sys`), reducing supply chain risk.
3. **Constant-time credential comparison** — Prevents timing attacks on authentication (with the minor length-leak caveat noted above).
4. **Strict protocol validation** — All SOCKS5 messages are validated for version, length, and field correctness before processing.
5. **Connect replies return 0.0.0.0:0** — Does not leak the server's bound address to clients.
6. **Comprehensive test coverage** — 40+ unit tests and 20+ integration tests covering auth, protocol edge cases, and error handling.
7. **Docker scratch image** — Minimal container attack surface with no shell or tools.
8. **Cargo.lock committed** — Ensures reproducible builds with pinned dependency versions.
9. **SHA256 checksums in releases** — Enables verification of downloaded artifacts.
10. **Graceful error handling** — Accept failures trigger backoff rather than crashes; resource exhaustion is handled without panicking.

---

## Dependency Audit

| Crate | Version | Risk | Notes |
|-------|---------|------|-------|
| socket2 | 0.5.10 | Low | Well-maintained, widely-used socket abstraction |
| libc | 0.2.180 | Low | Standard FFI bindings, Rust ecosystem staple |
| windows-sys | 0.52.0 | Low | Microsoft-maintained Windows API bindings |
| windows-targets | 0.52.6 | Low | Microsoft-maintained, build-time only |

Total transitive dependencies: 4 crates (excluding platform-specific Windows link libraries). This is an exceptionally small dependency tree for a Rust project, minimizing supply chain attack surface.

---

## Summary Table

| ID | Severity | Category | Title |
|----|----------|----------|-------|
| MEDIUM-01 | Medium | Resource Mgmt | Unbounded thread creation enables DoS |
| MEDIUM-02 | Medium | Resource Mgmt | Unbounded auth-once whitelist growth |
| MEDIUM-03 | Medium | Configuration | Open relay by default |
| LOW-01 | Low | Authentication | Constant-time comparison leaks credential length |
| LOW-02 | Low | Protocol | Partial reads during SOCKS5 handshake |
| LOW-03 | Low | Reliability | Write timeout not cleared for direct connections |
| LOW-04 | Low | Reliability | Upstream proxy connection only tries first address |
| LOW-05 | Low | Authentication | Lossy UTF-8 conversion for credentials |
| LOW-06 | Low | Info Disclosure | Credentials visible in process arguments |
| LOW-07 | Low | Concurrency | RwLock poisoning silently degrades auth |
| LOW-08 | Low | Resource Mgmt | No TCP keepalive / no handshake timeout |
| INFO-01 | Info | Network | No target address restrictions (SSRF) |
| INFO-02 | Info | Docker | Container runs as root |
| INFO-03 | Info | CI/CD | Trusted repo without GPG verification |
| INFO-04 | Info | Network | No TLS support |
| INFO-05 | Info | Configuration | DNS resolution at config parse time |
