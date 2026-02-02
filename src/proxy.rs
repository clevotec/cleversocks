use crate::config::{resolve_to_socketaddr, Config};
use crate::forward::ForwardRule;
use crate::log_msg;
use crate::logging;
use crate::socks::{self, AuthMethod, ErrorCode};
use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

/// Timeout for inactive connections (15 minutes).
const INACTIVITY_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Timeout for upstream SOCKS5 proxy connections (5 seconds).
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);

/// Buffer size for data relay.
const RELAY_BUF_SIZE: usize = 16 * 1024;

/// Shared state for auth-once IP whitelist.
struct AuthState {
    authed_ips: RwLock<HashSet<IpAddr>>,
}

impl AuthState {
    fn new(initial_ips: Vec<IpAddr>) -> Self {
        AuthState {
            authed_ips: RwLock::new(initial_ips.into_iter().collect()),
        }
    }

    fn is_authed(&self, ip: &IpAddr) -> bool {
        if let Ok(ips) = self.authed_ips.read() {
            ips.contains(ip)
        } else {
            false
        }
    }

    fn add_ip(&self, ip: IpAddr) {
        if let Ok(mut ips) = self.authed_ips.write() {
            ips.insert(ip);
        }
    }
}

/// Run the main SOCKS5 proxy server.
pub fn run_server(config: Arc<Config>) -> io::Result<()> {
    logging::set_quiet(config.quiet);

    let listen_addr = format!("{}:{}", config.listen_ip, config.port);
    // SO_REUSEADDR is set automatically by TcpListener::bind on Unix
    let listener = TcpListener::bind(&listen_addr)?;

    log_msg!("Listening on {}:{}\n", config.listen_ip, config.port);

    // Build shared auth state
    let auth_state = if config.has_auth_ips() {
        Some(Arc::new(AuthState::new(config.whitelist_ips.clone())))
    } else {
        None
    };

    // Handle idle timeout with non-blocking accept
    if let Some(timeout) = config.idle_timeout {
        listener.set_nonblocking(true)?;
        run_with_idle_timeout(listener, config, auth_state, timeout)
    } else {
        listener.set_nonblocking(false)?;
        run_blocking(listener, config, auth_state)
    }
}

fn run_blocking(
    listener: TcpListener,
    config: Arc<Config>,
    auth_state: Option<Arc<AuthState>>,
) -> io::Result<()> {
    for stream in listener.incoming() {
        match stream {
            Ok(client_stream) => {
                let config = Arc::clone(&config);
                let auth_state = auth_state.as_ref().map(Arc::clone);
                thread::spawn(move || {
                    handle_client(client_stream, &config, auth_state.as_deref());
                });
            }
            Err(e) => {
                log_msg!("failed to accept connection: {e}\n");
                thread::sleep(Duration::from_micros(64));
            }
        }
    }
    Ok(())
}

fn run_with_idle_timeout(
    listener: TcpListener,
    config: Arc<Config>,
    auth_state: Option<Arc<AuthState>>,
    timeout_secs: u64,
) -> io::Result<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let active_count = Arc::new(AtomicUsize::new(0));
    let timeout = Duration::from_secs(timeout_secs);

    loop {
        match listener.accept() {
            Ok((client_stream, _addr)) => {
                // Set back to blocking for the client
                client_stream.set_nonblocking(false)?;
                let config = Arc::clone(&config);
                let auth_state = auth_state.as_ref().map(Arc::clone);
                let active = Arc::clone(&active_count);
                active.fetch_add(1, Ordering::Relaxed);
                thread::spawn(move || {
                    handle_client(client_stream, &config, auth_state.as_deref());
                    active.fetch_sub(1, Ordering::Relaxed);
                });
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // Poll-style: sleep and check again
                thread::sleep(Duration::from_millis(100));
                // Check idle timeout
                if active_count.load(Ordering::Relaxed) == 0 {
                    // No active connections, check if we should exit
                    // We re-check with a longer sleep in a loop
                    let mut idle_ms = 100u64;
                    let timeout_ms = timeout.as_millis() as u64;
                    loop {
                        if idle_ms >= timeout_ms {
                            eprintln!("idle timeout exit");
                            return Ok(());
                        }
                        thread::sleep(Duration::from_millis(100));
                        idle_ms += 100;
                        // Check if a new connection came in
                        if active_count.load(Ordering::Relaxed) > 0 {
                            break;
                        }
                        match listener.accept() {
                            Ok((client_stream, _)) => {
                                client_stream.set_nonblocking(false)?;
                                let config = Arc::clone(&config);
                                let auth_state = auth_state.as_ref().map(Arc::clone);
                                let active = Arc::clone(&active_count);
                                active.fetch_add(1, Ordering::Relaxed);
                                thread::spawn(move || {
                                    handle_client(
                                        client_stream,
                                        &config,
                                        auth_state.as_deref(),
                                    );
                                    active.fetch_sub(1, Ordering::Relaxed);
                                });
                                break;
                            }
                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                continue;
                            }
                            Err(e) => return Err(e),
                        }
                    }
                }
            }
            Err(e) => {
                log_msg!("failed to accept connection: {e}\n");
                thread::sleep(Duration::from_micros(64));
            }
        }
    }
}

/// Handle a single SOCKS5 client connection.
fn handle_client(
    mut client: TcpStream,
    config: &Config,
    auth_state: Option<&AuthState>,
) {
    let client_addr = match client.peer_addr() {
        Ok(addr) => addr,
        Err(_) => return,
    };

    if let Ok(remote) = handshake(&mut client, config, auth_state, &client_addr) {
        copyloop(&mut client, remote);
    }
}

/// SOCKS5 handshake state machine.
fn handshake(
    client: &mut TcpStream,
    config: &Config,
    auth_state: Option<&AuthState>,
    client_addr: &SocketAddr,
) -> io::Result<TcpStream> {
    let mut buf = [0u8; 1024];

    // State 1: Method selection
    let n = client.read(&mut buf)?;
    if n == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "empty read"));
    }

    let methods = match socks::parse_method_selection(&buf[..n]) {
        Some(m) => m,
        None => {
            // Send rejection even if we can't parse (e.g. wrong SOCKS version)
            let response = socks::build_method_response(AuthMethod::Invalid);
            let _ = client.write_all(&response);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid method selection",
            ));
        }
    };

    let selected_method = choose_auth_method(&methods, config, auth_state, &client_addr.ip());

    let response = socks::build_method_response(selected_method);
    client.write_all(&response)?;

    if selected_method == AuthMethod::Invalid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "no acceptable auth method",
        ));
    }

    // State 2: Authentication (if needed)
    if selected_method == AuthMethod::Username {
        let n = client.read(&mut buf)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "empty auth read",
            ));
        }

        let valid = check_credentials(&buf[..n], config);
        let status = if valid {
            ErrorCode::Success as u8
        } else {
            ErrorCode::NotAllowed as u8
        };
        let auth_resp = socks::build_auth_response(1, status);
        client.write_all(&auth_resp)?;

        if !valid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "auth failed",
            ));
        }

        // Add to auth-once whitelist
        if let Some(state) = auth_state {
            state.add_ip(client_addr.ip());
        }
    }

    // State 3: Connect request
    let n = client.read(&mut buf)?;
    if n == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "empty connect read",
        ));
    }

    let target = match socks::parse_connect_request(&buf[..n]) {
        Ok(t) => t,
        Err(ec) => {
            let reply = socks::build_connect_reply(ec);
            let _ = client.write_all(&reply);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("connect request error: {ec:?}"),
            ));
        }
    };

    // Check forwarding rules
    if let Some(rule) = find_matching_rule(&config.forward_rules, &target.host, target.port) {
        log_msg!(
            "client[{}] {}: {}:{} -> via {}:{}\n",
            client_addr,
            client_addr.ip(),
            target.host,
            target.port,
            rule.upstream_host,
            rule.upstream_port
        );
        return connect_via_upstream(client, rule, &target.raw_request, client_addr);
    }

    // Direct connection
    let remote = match connect_target(&target.host, target.port, config) {
        Ok(stream) => stream,
        Err(e) => {
            let ec = ErrorCode::from_io_error(&e);
            let reply = socks::build_connect_reply(ec);
            let _ = client.write_all(&reply);
            return Err(e);
        }
    };

    log_msg!(
        "client[{}] {}: connected to {}:{}\n",
        client_addr,
        client_addr.ip(),
        target.host,
        target.port
    );

    let reply = socks::build_connect_reply(ErrorCode::Success);
    client.write_all(&reply)?;

    Ok(remote)
}

/// Choose which auth method to use based on config and client offerings.
fn choose_auth_method(
    methods: &[AuthMethod],
    config: &Config,
    auth_state: Option<&AuthState>,
    client_ip: &IpAddr,
) -> AuthMethod {
    for &method in methods {
        match method {
            AuthMethod::NoAuth => {
                if !config.requires_auth() {
                    return AuthMethod::NoAuth;
                }
                // Check if client IP is in whitelist
                if let Some(state) = auth_state {
                    if state.is_authed(client_ip) {
                        return AuthMethod::NoAuth;
                    }
                }
            }
            AuthMethod::Username => {
                if config.requires_auth() {
                    return AuthMethod::Username;
                }
            }
            _ => {}
        }
    }
    AuthMethod::Invalid
}

/// Check username/password credentials using constant-time comparison.
fn check_credentials(buf: &[u8], config: &Config) -> bool {
    if let Some((user, pass)) = socks::parse_credentials(buf) {
        if let (Some(ref expected_user), Some(ref expected_pass)) =
            (&config.auth_user, &config.auth_pass)
        {
            let user_match = constant_time_eq(user.as_bytes(), expected_user.as_bytes());
            let pass_match = constant_time_eq(pass.as_bytes(), expected_pass.as_bytes());
            return user_match & pass_match;
        }
    }
    false
}

/// Constant-time byte comparison to prevent timing side-channel attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for (&x, &y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

/// Find the first matching forwarding rule.
fn find_matching_rule<'a>(
    rules: &'a [ForwardRule],
    host: &str,
    port: u16,
) -> Option<&'a ForwardRule> {
    rules.iter().find(|r| r.matches(host, port))
}

/// Connect to a target host, respecting bind address configuration.
/// When multiple addresses are resolved (e.g. IPv6 + IPv4 for "localhost"),
/// each is tried in order until one succeeds.
fn connect_target(host: &str, port: u16, config: &Config) -> io::Result<TcpStream> {
    let addrs = resolve_to_socketaddr(host, port)?;

    if let Some(bind_ip) = config.bind_addr {
        // Pick the first address whose family matches the bind address.
        let addr = addrs
            .iter()
            .find(|a| matches!((a, bind_ip), (SocketAddr::V4(_), IpAddr::V4(_)) | (SocketAddr::V6(_), IpAddr::V6(_))))
            .or(addrs.first())
            .copied()
            .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no addr"))?;

        let stream = connect_with_bind(addr, bind_ip)?;
        stream.set_read_timeout(Some(UPSTREAM_TIMEOUT))?;
        stream.set_write_timeout(Some(UPSTREAM_TIMEOUT))?;
        Ok(stream)
    } else {
        // Try each resolved address in order.
        let mut last_err = io::Error::new(io::ErrorKind::AddrNotAvailable, "no addresses");
        for &addr in &addrs {
            match TcpStream::connect_timeout(&addr, UPSTREAM_TIMEOUT) {
                Ok(stream) => {
                    stream.set_read_timeout(Some(UPSTREAM_TIMEOUT))?;
                    stream.set_write_timeout(Some(UPSTREAM_TIMEOUT))?;
                    return Ok(stream);
                }
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }
}

/// Connect to a target address, binding to a specific local IP first.
fn connect_with_bind(target: SocketAddr, bind_ip: IpAddr) -> io::Result<TcpStream> {
    let domain = if target.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    socket.bind(&socket2::SockAddr::from(SocketAddr::new(bind_ip, 0)))?;
    socket.connect_timeout(&socket2::SockAddr::from(target), UPSTREAM_TIMEOUT)?;
    Ok(TcpStream::from(socket))
}

/// Connect through an upstream SOCKS5 proxy.
fn connect_via_upstream(
    client: &mut TcpStream,
    rule: &ForwardRule,
    _client_request: &[u8],
    _client_addr: &SocketAddr,
) -> io::Result<TcpStream> {
    let addrs = resolve_to_socketaddr(&rule.upstream_host, rule.upstream_port)?;
    let mut upstream = TcpStream::connect_timeout(&addrs[0], UPSTREAM_TIMEOUT)?;
    upstream.set_read_timeout(Some(UPSTREAM_TIMEOUT))?;
    upstream.set_write_timeout(Some(UPSTREAM_TIMEOUT))?;

    // Step 1: Send handshake to upstream
    let handshake = rule.build_upstream_handshake();
    upstream.write_all(&handshake)?;

    // Step 2: Read upstream method response
    let mut resp = [0u8; 2];
    upstream.read_exact(&mut resp)?;
    if resp[0] != 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid upstream SOCKS version",
        ));
    }

    // Step 3: Handle upstream authentication
    if resp[1] == 2 {
        // Username/password auth required
        let auth = rule
            .upstream_auth
            .as_ref()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "upstream requires auth but none configured",
                )
            })?;
        let auth_buf = auth.to_auth_buf();
        upstream.write_all(&auth_buf)?;

        let mut auth_resp = [0u8; 2];
        upstream.read_exact(&mut auth_resp)?;
        if auth_resp[0] != 1 || auth_resp[1] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "upstream auth failed",
            ));
        }
    } else if resp[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "upstream rejected auth methods",
        ));
    }

    // Step 4: Send connect request for remote target
    let remote_req = rule.build_remote_request();
    upstream.write_all(&remote_req)?;

    // Step 5: Read upstream connect response
    let mut header = [0u8; 4];
    upstream.read_exact(&mut header)?;

    if header[1] != 0 {
        let reply = socks::build_connect_reply(
            match header[1] {
                1 => ErrorCode::GeneralFailure,
                2 => ErrorCode::NotAllowed,
                3 => ErrorCode::NetworkUnreachable,
                4 => ErrorCode::HostUnreachable,
                5 => ErrorCode::ConnectionRefused,
                6 => ErrorCode::TtlExpired,
                7 => ErrorCode::CommandNotSupported,
                8 => ErrorCode::AddressTypeNotSupported,
                _ => ErrorCode::GeneralFailure,
            },
        );
        let _ = client.write_all(&reply);
        return Err(io::Error::other(
            format!("upstream connection failed: {}", header[1]),
        ));
    }

    // Read the rest of the upstream response (bound address)
    let (remaining, domain_len) = match header[3] {
        1 => (4 + 2, None),  // IPv4 + port
        4 => (16 + 2, None), // IPv6 + port
        3 => {
            // Domain: read length byte first
            let mut lenbyte = [0u8; 1];
            upstream.read_exact(&mut lenbyte)?;
            ((lenbyte[0] as usize) + 2, Some(lenbyte[0]))
        }
        _ => {
            let reply = socks::build_connect_reply(ErrorCode::AddressTypeNotSupported);
            let _ = client.write_all(&reply);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "upstream returned unsupported address type",
            ));
        }
    };

    let mut rest = vec![0u8; remaining];
    upstream.read_exact(&mut rest)?;

    // Forward the upstream's response back to our client
    let mut full_resp = Vec::with_capacity(4 + if domain_len.is_some() { 1 } else { 0 } + remaining);
    full_resp.extend_from_slice(&header);
    if let Some(dlen) = domain_len {
        full_resp.push(dlen);
    }
    full_resp.extend_from_slice(&rest);
    client.write_all(&full_resp)?;

    // Clear timeouts for relay
    upstream.set_read_timeout(None)?;
    upstream.set_write_timeout(None)?;

    Ok(upstream)
}

/// Bidirectional data relay between two TCP streams.
/// Uses two threads with read timeouts for inactivity detection.
fn copyloop(client: &mut TcpStream, remote: TcpStream) {
    // Only 2 clones needed: read handles for each direction
    let mut client_read = match client.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut remote_read = match remote.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };

    let _ = client_read.set_read_timeout(Some(INACTIVITY_TIMEOUT));
    let _ = remote_read.set_read_timeout(Some(INACTIVITY_TIMEOUT));

    // Move original remote into thread as write handle
    let mut remote_write = remote;

    // Spawn thread for client -> remote direction
    let handle = thread::spawn(move || {
        let mut buf = [0u8; RELAY_BUF_SIZE];
        loop {
            match client_read.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if remote_write.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = remote_write.shutdown(Shutdown::Write);
    });

    // remote -> client direction in current thread (client is our write handle)
    let mut buf = [0u8; RELAY_BUF_SIZE];
    loop {
        match remote_read.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if client.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let _ = client.shutdown(Shutdown::Write);
    let _ = remote_read.shutdown(Shutdown::Both);
    let _ = client.shutdown(Shutdown::Both);
    let _ = handle.join();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_choose_auth_method_no_auth_no_config() {
        let config = Config {
            listen_ip: "0.0.0.0".to_string(),
            port: 1080,
            quiet: false,
            auth_user: None,
            auth_pass: None,
            auth_once: false,
            whitelist_ips: vec![],
            bind_addr: None,
            idle_timeout: None,
            forward_rules: vec![],
        };
        let methods = vec![AuthMethod::NoAuth];
        let method = choose_auth_method(&methods, &config, None, &"127.0.0.1".parse().unwrap());
        assert_eq!(method, AuthMethod::NoAuth);
    }

    #[test]
    fn test_choose_auth_method_requires_username() {
        let config = Config {
            listen_ip: "0.0.0.0".to_string(),
            port: 1080,
            quiet: false,
            auth_user: Some("user".to_string()),
            auth_pass: Some("pass".to_string()),
            auth_once: false,
            whitelist_ips: vec![],
            bind_addr: None,
            idle_timeout: None,
            forward_rules: vec![],
        };
        let methods = vec![AuthMethod::NoAuth, AuthMethod::Username];
        let method = choose_auth_method(&methods, &config, None, &"127.0.0.1".parse().unwrap());
        assert_eq!(method, AuthMethod::Username);
    }

    #[test]
    fn test_choose_auth_method_no_acceptable() {
        let config = Config {
            listen_ip: "0.0.0.0".to_string(),
            port: 1080,
            quiet: false,
            auth_user: Some("user".to_string()),
            auth_pass: Some("pass".to_string()),
            auth_once: false,
            whitelist_ips: vec![],
            bind_addr: None,
            idle_timeout: None,
            forward_rules: vec![],
        };
        let methods = vec![AuthMethod::NoAuth]; // Only offers NO_AUTH but we require USERNAME
        let method = choose_auth_method(&methods, &config, None, &"127.0.0.1".parse().unwrap());
        assert_eq!(method, AuthMethod::Invalid);
    }

    #[test]
    fn test_choose_auth_method_whitelisted_ip() {
        let config = Config {
            listen_ip: "0.0.0.0".to_string(),
            port: 1080,
            quiet: false,
            auth_user: Some("user".to_string()),
            auth_pass: Some("pass".to_string()),
            auth_once: true,
            whitelist_ips: vec![],
            bind_addr: None,
            idle_timeout: None,
            forward_rules: vec![],
        };
        let auth_state = AuthState::new(vec!["127.0.0.1".parse().unwrap()]);
        let methods = vec![AuthMethod::NoAuth];
        let method = choose_auth_method(
            &methods,
            &config,
            Some(&auth_state),
            &"127.0.0.1".parse().unwrap(),
        );
        assert_eq!(method, AuthMethod::NoAuth);
    }

    #[test]
    fn test_choose_auth_method_non_whitelisted_ip() {
        let config = Config {
            listen_ip: "0.0.0.0".to_string(),
            port: 1080,
            quiet: false,
            auth_user: Some("user".to_string()),
            auth_pass: Some("pass".to_string()),
            auth_once: true,
            whitelist_ips: vec![],
            bind_addr: None,
            idle_timeout: None,
            forward_rules: vec![],
        };
        let auth_state = AuthState::new(vec!["127.0.0.1".parse().unwrap()]);
        let methods = vec![AuthMethod::NoAuth];
        let method = choose_auth_method(
            &methods,
            &config,
            Some(&auth_state),
            &"192.168.1.1".parse().unwrap(),
        );
        // 192.168.1.1 is not whitelisted, and only offers NO_AUTH
        assert_eq!(method, AuthMethod::Invalid);
    }

    #[test]
    fn test_check_credentials_valid() {
        let config = Config {
            listen_ip: "0.0.0.0".to_string(),
            port: 1080,
            quiet: false,
            auth_user: Some("admin".to_string()),
            auth_pass: Some("secret".to_string()),
            auth_once: false,
            whitelist_ips: vec![],
            bind_addr: None,
            idle_timeout: None,
            forward_rules: vec![],
        };
        // RFC 1929: version=1, ulen=5, "admin", plen=6, "secret"
        let buf = [1, 5, b'a', b'd', b'm', b'i', b'n', 6, b's', b'e', b'c', b'r', b'e', b't'];
        assert!(check_credentials(&buf, &config));
    }

    #[test]
    fn test_check_credentials_invalid_user() {
        let config = Config {
            listen_ip: "0.0.0.0".to_string(),
            port: 1080,
            quiet: false,
            auth_user: Some("admin".to_string()),
            auth_pass: Some("secret".to_string()),
            auth_once: false,
            whitelist_ips: vec![],
            bind_addr: None,
            idle_timeout: None,
            forward_rules: vec![],
        };
        let buf = [1, 4, b'r', b'o', b'o', b't', 6, b's', b'e', b'c', b'r', b'e', b't'];
        assert!(!check_credentials(&buf, &config));
    }

    #[test]
    fn test_check_credentials_invalid_pass() {
        let config = Config {
            listen_ip: "0.0.0.0".to_string(),
            port: 1080,
            quiet: false,
            auth_user: Some("admin".to_string()),
            auth_pass: Some("secret".to_string()),
            auth_once: false,
            whitelist_ips: vec![],
            bind_addr: None,
            idle_timeout: None,
            forward_rules: vec![],
        };
        let buf = [1, 5, b'a', b'd', b'm', b'i', b'n', 5, b'w', b'r', b'o', b'n', b'g'];
        assert!(!check_credentials(&buf, &config));
    }

    #[test]
    fn test_check_credentials_no_config_auth() {
        let config = Config {
            listen_ip: "0.0.0.0".to_string(),
            port: 1080,
            quiet: false,
            auth_user: None,
            auth_pass: None,
            auth_once: false,
            whitelist_ips: vec![],
            bind_addr: None,
            idle_timeout: None,
            forward_rules: vec![],
        };
        let buf = [1, 4, b'u', b's', b'e', b'r', 4, b'p', b'a', b's', b's'];
        assert!(!check_credentials(&buf, &config));
    }

    #[test]
    fn test_auth_state_add_and_check() {
        let state = AuthState::new(vec![]);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(!state.is_authed(&ip));
        state.add_ip(ip);
        assert!(state.is_authed(&ip));
    }

    #[test]
    fn test_auth_state_initial_ips() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let state = AuthState::new(vec![ip]);
        assert!(state.is_authed(&ip));
    }

    #[test]
    fn test_auth_state_no_duplicate() {
        let state = AuthState::new(vec![]);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        state.add_ip(ip);
        state.add_ip(ip);
        assert_eq!(state.authed_ips.read().unwrap().len(), 1);
    }

    #[test]
    fn test_auth_state_multiple_ips() {
        let state = AuthState::new(vec![]);
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let ip3: IpAddr = "::1".parse().unwrap();
        state.add_ip(ip1);
        state.add_ip(ip2);
        state.add_ip(ip3);
        assert!(state.is_authed(&ip1));
        assert!(state.is_authed(&ip2));
        assert!(state.is_authed(&ip3));
        assert!(!state.is_authed(&"10.0.0.3".parse().unwrap()));
    }

    #[test]
    fn test_constant_time_eq_equal() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"\x00\xff", b"\x00\xff"));
    }

    #[test]
    fn test_constant_time_eq_not_equal() {
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hellp"));
        assert!(!constant_time_eq(b"\x00", b"\x01"));
    }

    #[test]
    fn test_constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"short", b"longer"));
        assert!(!constant_time_eq(b"hello", b"hell"));
        assert!(!constant_time_eq(b"", b"x"));
    }

    #[test]
    fn test_find_matching_rule_found() {
        let rule = ForwardRule::parse("example.com:443,proxy.com:1080,target.com:443").unwrap();
        let rules = vec![rule];
        let found = find_matching_rule(&rules, "example.com", 443);
        assert!(found.is_some());
        assert_eq!(found.unwrap().upstream_host, "proxy.com");
    }

    #[test]
    fn test_find_matching_rule_not_found() {
        let rule = ForwardRule::parse("example.com:443,proxy.com:1080,target.com:443").unwrap();
        let rules = vec![rule];
        let found = find_matching_rule(&rules, "other.com", 443);
        assert!(found.is_none());
    }

    #[test]
    fn test_find_matching_rule_first_match() {
        let rule1 = ForwardRule::parse("*:0,proxy1.com:1080,target1.com:443").unwrap();
        let rule2 = ForwardRule::parse("*:0,proxy2.com:1080,target2.com:443").unwrap();
        let rules = vec![rule1, rule2];
        let found = find_matching_rule(&rules, "anything", 80);
        assert!(found.is_some());
        assert_eq!(found.unwrap().upstream_host, "proxy1.com");
    }

    #[test]
    fn test_find_matching_rule_empty() {
        let rules: Vec<ForwardRule> = vec![];
        let found = find_matching_rule(&rules, "example.com", 443);
        assert!(found.is_none());
    }
}
