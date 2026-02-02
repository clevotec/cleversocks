/// Integration tests for the CleverSocks SOCKS5 proxy server.
///
/// These tests start the actual server binary and exercise the SOCKS5
/// protocol over real TCP connections.
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command};
use std::thread;
use std::time::Duration;

/// Get an OS-assigned free port by binding to port 0.
fn get_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// Helper to start cleversocks on a given port with extra args.
/// Waits for the server to be ready to accept connections.
fn start_server(port: u16, extra_args: &[&str]) -> Child {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cleversocks"));
    cmd.arg("-i").arg("127.0.0.1").arg("-p").arg(port.to_string());
    for arg in extra_args {
        cmd.arg(arg);
    }
    let child = cmd.spawn().expect("failed to start cleversocks");

    // Wait for the server to be ready (up to 2 seconds)
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    for _ in 0..40 {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok() {
            return child;
        }
        thread::sleep(Duration::from_millis(50));
    }
    child
}

/// Helper: connect to the SOCKS5 proxy.
fn connect_proxy(port: u16) -> TcpStream {
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    stream
}

/// Helper: perform SOCKS5 handshake with NO_AUTH.
fn socks5_handshake_no_auth(stream: &mut TcpStream) {
    // Send method selection: version 5, 1 method, NO_AUTH
    stream.write_all(&[5, 1, 0]).unwrap();
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).unwrap();
    assert_eq!(resp[0], 5, "SOCKS version mismatch in handshake");
    assert_eq!(resp[1], 0, "expected NO_AUTH accepted");
}

/// Helper: perform SOCKS5 handshake with USERNAME auth.
fn socks5_handshake_auth(stream: &mut TcpStream, user: &str, pass: &str) -> bool {
    // Send method selection: version 5, 2 methods, NO_AUTH and USERNAME
    stream.write_all(&[5, 2, 0, 2]).unwrap();
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).unwrap();
    assert_eq!(resp[0], 5);

    if resp[1] == 0xFF {
        return false; // No acceptable methods
    }

    if resp[1] == 2 {
        // Send username/password auth (RFC 1929)
        let mut auth_req = vec![1u8]; // version
        auth_req.push(user.len() as u8);
        auth_req.extend_from_slice(user.as_bytes());
        auth_req.push(pass.len() as u8);
        auth_req.extend_from_slice(pass.as_bytes());
        stream.write_all(&auth_req).unwrap();

        let mut auth_resp = [0u8; 2];
        stream.read_exact(&mut auth_resp).unwrap();
        assert_eq!(auth_resp[0], 1);
        return auth_resp[1] == 0;
    }

    resp[1] == 0 // NO_AUTH accepted
}

/// Helper: send SOCKS5 CONNECT request for IPv4 address.
fn socks5_connect_ipv4(stream: &mut TcpStream, ip: [u8; 4], port: u16) -> u8 {
    let mut req = vec![5, 1, 0, 1]; // version, CONNECT, reserved, IPv4
    req.extend_from_slice(&ip);
    req.push((port >> 8) as u8);
    req.push((port & 0xFF) as u8);
    stream.write_all(&req).unwrap();

    let mut resp = [0u8; 10];
    stream.read_exact(&mut resp).unwrap();
    assert_eq!(resp[0], 5);
    resp[1] // return status code
}

/// Helper: send SOCKS5 CONNECT request for domain name.
fn socks5_connect_domain(stream: &mut TcpStream, domain: &str, port: u16) -> u8 {
    let mut req = vec![5, 1, 0, 3]; // version, CONNECT, reserved, Domain
    req.push(domain.len() as u8);
    req.extend_from_slice(domain.as_bytes());
    req.push((port >> 8) as u8);
    req.push((port & 0xFF) as u8);
    stream.write_all(&req).unwrap();

    let mut resp = [0u8; 10];
    stream.read_exact(&mut resp).unwrap();
    assert_eq!(resp[0], 5);
    resp[1]
}

/// Start a simple TCP echo server that echoes back whatever it receives.
fn start_echo_server() -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut buf = [0u8; 4096];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if stream.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    });

    (port, handle)
}

/// Start a simple TCP server that sends a fixed message and closes.
fn start_message_server(msg: &'static [u8]) -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.write_all(msg);
            let _ = stream.shutdown(Shutdown::Both);
        }
    });

    (port, handle)
}

// =====================================================================
// Test Cases
// =====================================================================

#[test]
fn test_basic_connect_no_auth() {
    let proxy_port = get_free_port();
    let (echo_port, echo_handle) = start_echo_server();
    let mut server = start_server(proxy_port, &["-q"]);

    let mut client = connect_proxy(proxy_port);
    socks5_handshake_no_auth(&mut client);
    let status = socks5_connect_ipv4(&mut client, [127, 0, 0, 1], echo_port);
    assert_eq!(status, 0, "connect should succeed");

    // Send data through the proxy and verify echo
    let test_data = b"Hello through SOCKS5!";
    client.write_all(test_data).unwrap();
    let mut resp = vec![0u8; test_data.len()];
    client.read_exact(&mut resp).unwrap();
    assert_eq!(&resp, test_data);

    drop(client);
    let _ = echo_handle.join();
    server.kill().ok();
}

#[test]
fn test_connect_domain_localhost() {
    let proxy_port = get_free_port();
    let (echo_port, echo_handle) = start_echo_server();
    let mut server = start_server(proxy_port, &["-q"]);

    let mut client = connect_proxy(proxy_port);
    socks5_handshake_no_auth(&mut client);
    let status = socks5_connect_domain(&mut client, "localhost", echo_port);
    assert_eq!(status, 0, "connect via domain should succeed");

    let test_data = b"domain test";
    client.write_all(test_data).unwrap();
    let mut resp = vec![0u8; test_data.len()];
    client.read_exact(&mut resp).unwrap();
    assert_eq!(&resp, test_data);

    drop(client);
    let _ = echo_handle.join();
    server.kill().ok();
}

#[test]
fn test_auth_required_valid_credentials() {
    let proxy_port = get_free_port();
    let (echo_port, echo_handle) = start_echo_server();
    let mut server = start_server(proxy_port, &["-q", "-u", "testuser", "-P", "testpass"]);

    let mut client = connect_proxy(proxy_port);
    let authed = socks5_handshake_auth(&mut client, "testuser", "testpass");
    assert!(authed, "auth should succeed with valid credentials");

    let status = socks5_connect_ipv4(&mut client, [127, 0, 0, 1], echo_port);
    assert_eq!(status, 0, "connect after auth should succeed");

    let test_data = b"authenticated data";
    client.write_all(test_data).unwrap();
    let mut resp = vec![0u8; test_data.len()];
    client.read_exact(&mut resp).unwrap();
    assert_eq!(&resp, test_data);

    drop(client);
    let _ = echo_handle.join();
    server.kill().ok();
}

#[test]
fn test_auth_required_invalid_credentials() {
    let proxy_port = get_free_port();
    let mut server = start_server(proxy_port, &["-q", "-u", "testuser", "-P", "testpass"]);

    let mut client = connect_proxy(proxy_port);
    let authed = socks5_handshake_auth(&mut client, "wrong", "wrong");
    assert!(!authed, "auth should fail with invalid credentials");

    drop(client);
    server.kill().ok();
}

#[test]
fn test_auth_required_wrong_password() {
    let proxy_port = get_free_port();
    let mut server = start_server(proxy_port, &["-q", "-u", "testuser", "-P", "testpass"]);

    let mut client = connect_proxy(proxy_port);
    let authed = socks5_handshake_auth(&mut client, "testuser", "wrongpass");
    assert!(!authed, "auth should fail with wrong password");

    drop(client);
    server.kill().ok();
}

#[test]
fn test_no_auth_method_when_auth_required() {
    let proxy_port = get_free_port();
    let mut server = start_server(proxy_port, &["-q", "-u", "testuser", "-P", "testpass"]);

    let mut client = connect_proxy(proxy_port);
    // Only offer NO_AUTH
    client.write_all(&[5, 1, 0]).unwrap();
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).unwrap();
    assert_eq!(resp[0], 5);
    assert_eq!(resp[1], 0xFF, "server should reject when only NO_AUTH offered but auth required");

    drop(client);
    server.kill().ok();
}

#[test]
fn test_connect_refused_target() {
    let proxy_port = get_free_port();
    let mut server = start_server(proxy_port, &["-q"]);

    // Use the standard SOCKS port (1080) as the target.  Parallel tests use
    // get_free_port() / bind(0) which returns ephemeral ports, so 1080 will
    // never be claimed by another test, avoiding the race condition.
    let bad_port: u16 = 1080;

    let mut client = connect_proxy(proxy_port);
    socks5_handshake_no_auth(&mut client);
    let status = socks5_connect_ipv4(&mut client, [127, 0, 0, 1], bad_port);
    // Should get connection refused (5) or general failure (1)
    assert!(
        status == 5 || status == 1,
        "expected connection refused or general failure, got {status}"
    );

    drop(client);
    server.kill().ok();
}

#[test]
fn test_unsupported_command_bind() {
    let proxy_port = get_free_port();
    let mut server = start_server(proxy_port, &["-q"]);

    let mut client = connect_proxy(proxy_port);
    socks5_handshake_no_auth(&mut client);

    // Send BIND command (2) instead of CONNECT (1)
    let req = [5, 2, 0, 1, 127, 0, 0, 1, 0, 80];
    client.write_all(&req).unwrap();
    let mut resp = [0u8; 10];
    client.read_exact(&mut resp).unwrap();
    assert_eq!(resp[0], 5);
    assert_eq!(resp[1], 7, "expected command not supported error");

    drop(client);
    server.kill().ok();
}

#[test]
fn test_unsupported_command_udp_associate() {
    let proxy_port = get_free_port();
    let mut server = start_server(proxy_port, &["-q"]);

    let mut client = connect_proxy(proxy_port);
    socks5_handshake_no_auth(&mut client);

    // Send UDP ASSOCIATE command (3)
    let req = [5, 3, 0, 1, 127, 0, 0, 1, 0, 80];
    client.write_all(&req).unwrap();
    let mut resp = [0u8; 10];
    client.read_exact(&mut resp).unwrap();
    assert_eq!(resp[0], 5);
    assert_eq!(resp[1], 7, "expected command not supported error");

    drop(client);
    server.kill().ok();
}

#[test]
fn test_unsupported_address_type() {
    let proxy_port = get_free_port();
    let mut server = start_server(proxy_port, &["-q"]);

    let mut client = connect_proxy(proxy_port);
    socks5_handshake_no_auth(&mut client);

    // Send request with invalid address type (5)
    let req = [5, 1, 0, 5, 127, 0, 0, 1, 0, 80];
    client.write_all(&req).unwrap();
    let mut resp = [0u8; 10];
    client.read_exact(&mut resp).unwrap();
    assert_eq!(resp[0], 5);
    assert_eq!(resp[1], 8, "expected address type not supported error");

    drop(client);
    server.kill().ok();
}

#[test]
fn test_wrong_socks_version() {
    let proxy_port = get_free_port();
    let mut server = start_server(proxy_port, &["-q"]);

    let mut client = connect_proxy(proxy_port);
    // Send SOCKS4 handshake (version 4)
    client.write_all(&[4, 1, 0]).unwrap();
    let mut resp = [0u8; 2];
    // Server should respond with [5, 0xFF] and close connection
    match client.read_exact(&mut resp) {
        Ok(()) => {
            assert_eq!(resp[0], 5);
            assert_eq!(resp[1], 0xFF, "should reject non-SOCKS5 version");
        }
        Err(e) => {
            // Connection reset is also acceptable - server rejected the connection
            assert!(
                e.kind() == std::io::ErrorKind::UnexpectedEof
                    || e.kind() == std::io::ErrorKind::ConnectionReset,
                "unexpected error: {e}"
            );
        }
    }

    drop(client);
    server.kill().ok();
}

#[test]
fn test_large_data_transfer() {
    let proxy_port = get_free_port();
    let (echo_port, echo_handle) = start_echo_server();
    let mut server = start_server(proxy_port, &["-q"]);

    let mut client = connect_proxy(proxy_port);
    socks5_handshake_no_auth(&mut client);
    let status = socks5_connect_ipv4(&mut client, [127, 0, 0, 1], echo_port);
    assert_eq!(status, 0);

    // Send 64KB of data
    let data: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();
    client.write_all(&data).unwrap();

    let mut received = vec![0u8; data.len()];
    client.read_exact(&mut received).unwrap();
    assert_eq!(received, data, "large data should round-trip correctly");

    drop(client);
    let _ = echo_handle.join();
    server.kill().ok();
}

#[test]
fn test_multiple_concurrent_connections() {
    let proxy_port = get_free_port();
    let mut server = start_server(proxy_port, &["-q"]);

    let mut handles = vec![];
    for i in 0..5 {
        let pp = proxy_port;
        let handle = thread::spawn(move || {
            let (echo_port, echo_handle) = start_echo_server();
            let mut client = connect_proxy(pp);
            socks5_handshake_no_auth(&mut client);
            let status = socks5_connect_ipv4(&mut client, [127, 0, 0, 1], echo_port);
            assert_eq!(status, 0, "connection {i} should succeed");

            let msg = format!("message from client {i}");
            client.write_all(msg.as_bytes()).unwrap();
            let mut resp = vec![0u8; msg.len()];
            client.read_exact(&mut resp).unwrap();
            assert_eq!(String::from_utf8_lossy(&resp), msg);

            drop(client);
            let _ = echo_handle.join();
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().unwrap();
    }
    server.kill().ok();
}

#[test]
fn test_server_receives_data_from_target() {
    let proxy_port = get_free_port();
    let msg = b"Hello from server!";
    let (msg_port, msg_handle) = start_message_server(msg);
    let mut server = start_server(proxy_port, &["-q"]);

    let mut client = connect_proxy(proxy_port);
    socks5_handshake_no_auth(&mut client);
    let status = socks5_connect_ipv4(&mut client, [127, 0, 0, 1], msg_port);
    assert_eq!(status, 0);

    let mut resp = vec![0u8; msg.len()];
    client.read_exact(&mut resp).unwrap();
    assert_eq!(&resp, msg);

    drop(client);
    let _ = msg_handle.join();
    server.kill().ok();
}

#[test]
fn test_ipv6_connect() {
    let proxy_port = get_free_port();

    // Try to bind IPv6 echo server
    let listener = match TcpListener::bind("[::1]:0") {
        Ok(l) => l,
        Err(_) => return, // Skip test if IPv6 not available
    };
    let echo_port = listener.local_addr().unwrap().port();
    let echo_handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = [0u8; 4096];
            if let Ok(n) = stream.read(&mut buf) {
                let _ = stream.write_all(&buf[..n]);
            }
        }
    });

    // Start proxy on IPv6
    let mut server_cmd = Command::new(env!("CARGO_BIN_EXE_cleversocks"));
    server_cmd
        .arg("-i")
        .arg("::1")
        .arg("-p")
        .arg(proxy_port.to_string())
        .arg("-q");
    let mut server = server_cmd.spawn().expect("failed to start cleversocks");

    // Wait for IPv6 server to be ready
    let addr: SocketAddr = format!("[::1]:{proxy_port}").parse().unwrap();
    let mut ready = false;
    for _ in 0..40 {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok() {
            ready = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    if !ready {
        server.kill().ok();
        return; // IPv6 not working
    }

    let mut client = match TcpStream::connect_timeout(&addr, Duration::from_secs(2)) {
        Ok(s) => s,
        Err(_) => {
            server.kill().ok();
            return;
        }
    };
    client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    socks5_handshake_no_auth(&mut client);

    // SOCKS5 CONNECT to IPv6 address ::1
    let mut req = vec![5, 1, 0, 4];
    req.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // ::1
    req.push((echo_port >> 8) as u8);
    req.push((echo_port & 0xFF) as u8);
    client.write_all(&req).unwrap();

    let mut resp = [0u8; 10];
    client.read_exact(&mut resp).unwrap();
    assert_eq!(resp[0], 5);
    assert_eq!(resp[1], 0, "IPv6 connect should succeed");

    let test_data = b"IPv6 test";
    client.write_all(test_data).unwrap();
    let mut echo_resp = vec![0u8; test_data.len()];
    client.read_exact(&mut echo_resp).unwrap();
    assert_eq!(&echo_resp, test_data);

    drop(client);
    let _ = echo_handle.join();
    server.kill().ok();
}

#[test]
fn test_auth_once_whitelist() {
    let proxy_port = get_free_port();
    let (echo_port, echo_handle) = start_echo_server();
    let mut server = start_server(
        proxy_port,
        &["-q", "-u", "testuser", "-P", "testpass", "-1"],
    );

    // First connection: authenticate with username/password
    {
        let mut client = connect_proxy(proxy_port);
        let authed = socks5_handshake_auth(&mut client, "testuser", "testpass");
        assert!(authed, "first auth should succeed");

        let status = socks5_connect_ipv4(&mut client, [127, 0, 0, 1], echo_port);
        assert_eq!(status, 0);

        client.write_all(b"first").unwrap();
        let mut resp = [0u8; 5];
        client.read_exact(&mut resp).unwrap();
        assert_eq!(&resp, b"first");
        drop(client);
    }

    let _ = echo_handle.join();

    // Second connection: should be able to use NO_AUTH since IP is now whitelisted
    let (echo_port2, echo_handle2) = start_echo_server();
    {
        let mut client = connect_proxy(proxy_port);
        // Only offer NO_AUTH - should be accepted now that we're whitelisted
        client.write_all(&[5, 1, 0]).unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).unwrap();
        assert_eq!(resp[0], 5);
        assert_eq!(resp[1], 0, "should accept NO_AUTH after auth-once whitelist");

        let status = socks5_connect_ipv4(&mut client, [127, 0, 0, 1], echo_port2);
        assert_eq!(status, 0);
        drop(client);
    }

    let _ = echo_handle2.join();
    server.kill().ok();
}

#[test]
fn test_whitelist_ip_bypass() {
    let proxy_port = get_free_port();
    let (echo_port, echo_handle) = start_echo_server();
    let mut server = start_server(
        proxy_port,
        &["-q", "-u", "testuser", "-P", "testpass", "-w", "127.0.0.1"],
    );

    // Should be able to use NO_AUTH since 127.0.0.1 is in whitelist
    let mut client = connect_proxy(proxy_port);
    client.write_all(&[5, 1, 0]).unwrap();
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).unwrap();
    assert_eq!(resp[0], 5);
    assert_eq!(resp[1], 0, "whitelisted IP should be able to use NO_AUTH");

    let status = socks5_connect_ipv4(&mut client, [127, 0, 0, 1], echo_port);
    assert_eq!(status, 0);

    drop(client);
    let _ = echo_handle.join();
    server.kill().ok();
}

#[test]
fn test_version_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_cleversocks"))
        .arg("-V")
        .output()
        .expect("failed to run cleversocks -V");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("CleverSocks"),
        "version output should contain 'CleverSocks'"
    );
    assert!(output.status.success());
}

#[test]
fn test_help_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_cleversocks"))
        .arg("-h")
        .output()
        .expect("failed to run cleversocks -h");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("SOCKS5") || stderr.contains("socks5"),
        "help should mention SOCKS5"
    );
    assert!(output.status.success());
}

#[test]
fn test_invalid_args_user_without_pass() {
    let output = Command::new(env!("CARGO_BIN_EXE_cleversocks"))
        .arg("-u")
        .arg("user")
        .output()
        .expect("failed to run");
    assert!(!output.status.success());
}

#[test]
fn test_invalid_args_pass_without_user() {
    let output = Command::new(env!("CARGO_BIN_EXE_cleversocks"))
        .arg("-P")
        .arg("pass")
        .output()
        .expect("failed to run");
    assert!(!output.status.success());
}

#[test]
fn test_invalid_args_auth_once_without_auth() {
    let output = Command::new(env!("CARGO_BIN_EXE_cleversocks"))
        .arg("-1")
        .output()
        .expect("failed to run");
    assert!(!output.status.success());
}

#[test]
fn test_connection_close_propagation() {
    let proxy_port = get_free_port();
    let mut server = start_server(proxy_port, &["-q"]);

    // Start a server that accepts and immediately closes
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let target_port = listener.local_addr().unwrap().port();
    let target_handle = thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            drop(stream); // Immediately close
        }
    });

    let mut client = connect_proxy(proxy_port);
    socks5_handshake_no_auth(&mut client);
    let status = socks5_connect_ipv4(&mut client, [127, 0, 0, 1], target_port);
    assert_eq!(status, 0);

    // Read should return 0 (EOF) since target closed
    let mut buf = [0u8; 1];
    let n = client.read(&mut buf).unwrap_or(0);
    assert_eq!(n, 0, "should get EOF when target closes");

    drop(client);
    let _ = target_handle.join();
    server.kill().ok();
}

#[test]
fn test_bidirectional_data_flow() {
    let proxy_port = get_free_port();
    let mut server = start_server(proxy_port, &["-q"]);

    // Start a server that reads, transforms, and writes back
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let target_port = listener.local_addr().unwrap().port();
    let target_handle = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = [0u8; 1024];
            if let Ok(n) = stream.read(&mut buf) {
                // Transform: uppercase the data
                let response: Vec<u8> = buf[..n]
                    .iter()
                    .map(|&b| {
                        if b.is_ascii_lowercase() {
                            b - 32
                        } else {
                            b
                        }
                    })
                    .collect();
                let _ = stream.write_all(&response);
            }
        }
    });

    let mut client = connect_proxy(proxy_port);
    socks5_handshake_no_auth(&mut client);
    let status = socks5_connect_ipv4(&mut client, [127, 0, 0, 1], target_port);
    assert_eq!(status, 0);

    client.write_all(b"hello world").unwrap();
    let mut resp = [0u8; 11];
    client.read_exact(&mut resp).unwrap();
    assert_eq!(&resp, b"HELLO WORLD");

    drop(client);
    let _ = target_handle.join();
    server.kill().ok();
}

#[test]
fn test_multiple_sequential_requests_same_proxy() {
    let proxy_port = get_free_port();
    let mut server = start_server(proxy_port, &["-q"]);

    for i in 0..3 {
        let (echo_port, echo_handle) = start_echo_server();
        let mut client = connect_proxy(proxy_port);
        socks5_handshake_no_auth(&mut client);
        let status = socks5_connect_ipv4(&mut client, [127, 0, 0, 1], echo_port);
        assert_eq!(status, 0, "request {i} should succeed");

        let msg = format!("request {i}");
        client.write_all(msg.as_bytes()).unwrap();
        let mut resp = vec![0u8; msg.len()];
        client.read_exact(&mut resp).unwrap();
        assert_eq!(String::from_utf8_lossy(&resp), msg);

        drop(client);
        let _ = echo_handle.join();
    }

    server.kill().ok();
}

#[test]
fn test_empty_method_list() {
    let proxy_port = get_free_port();
    let mut server = start_server(proxy_port, &["-q"]);

    let mut client = connect_proxy(proxy_port);
    // Send version 5, 0 methods
    client.write_all(&[5, 0]).unwrap();
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).unwrap();
    assert_eq!(resp[0], 5);
    assert_eq!(resp[1], 0xFF, "should reject empty method list");

    drop(client);
    server.kill().ok();
}

#[test]
fn test_idle_timeout_exit() {
    let proxy_port = get_free_port();
    let mut server = Command::new(env!("CARGO_BIN_EXE_cleversocks"))
        .arg("-i")
        .arg("127.0.0.1")
        .arg("-p")
        .arg(proxy_port.to_string())
        .arg("-q")
        .arg("-t")
        .arg("1") // 1 second timeout
        .spawn()
        .expect("failed to start cleversocks");

    // Wait for server to start
    let addr: SocketAddr = format!("127.0.0.1:{proxy_port}").parse().unwrap();
    for _ in 0..40 {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }

    // Wait for idle timeout to expire (1s + buffer)
    thread::sleep(Duration::from_millis(1500));

    // Server should have exited
    match server.try_wait() {
        Ok(Some(status)) => assert!(status.success(), "server should exit cleanly on idle timeout"),
        Ok(None) => {
            // Still running - give it a bit more time
            thread::sleep(Duration::from_millis(500));
            match server.try_wait() {
                Ok(Some(status)) => assert!(status.success()),
                _ => {
                    server.kill().ok();
                    panic!("server did not exit after idle timeout");
                }
            }
        }
        Err(e) => panic!("error waiting for server: {e}"),
    }
}

#[test]
fn test_partial_handshake_disconnect() {
    let proxy_port = get_free_port();
    let mut server = start_server(proxy_port, &["-q"]);

    // Connect and send partial data, then disconnect
    let mut client = connect_proxy(proxy_port);
    // Send just the version byte
    client.write_all(&[5]).unwrap();
    drop(client);

    // Server should still be running and accepting connections
    thread::sleep(Duration::from_millis(100));
    let (echo_port, echo_handle) = start_echo_server();
    let mut client2 = connect_proxy(proxy_port);
    socks5_handshake_no_auth(&mut client2);
    let status = socks5_connect_ipv4(&mut client2, [127, 0, 0, 1], echo_port);
    assert_eq!(status, 0, "server should still work after partial handshake");

    drop(client2);
    let _ = echo_handle.join();
    server.kill().ok();
}

#[test]
fn test_connect_ipv4_dynamic_port() {
    let proxy_port = get_free_port();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let target_port = listener.local_addr().unwrap().port();
    let _target_handle = thread::spawn(move || {
        let _ = listener.accept();
    });
    let mut server = start_server(proxy_port, &["-q"]);

    let mut client = connect_proxy(proxy_port);
    socks5_handshake_no_auth(&mut client);
    let status = socks5_connect_ipv4(&mut client, [127, 0, 0, 1], target_port);
    assert_eq!(status, 0, "should connect to dynamically allocated port");

    drop(client);
    server.kill().ok();
}
