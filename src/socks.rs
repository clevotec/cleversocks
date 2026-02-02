//! SOCKS5 protocol constants and types per RFC 1928 / RFC 1929.

pub const SOCKS_VERSION: u8 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthMethod {
    NoAuth = 0,
    // Gssapi = 1,
    Username = 2,
    Invalid = 0xFF,
}

impl From<u8> for AuthMethod {
    fn from(v: u8) -> Self {
        match v {
            0 => AuthMethod::NoAuth,
            2 => AuthMethod::Username,
            _ => AuthMethod::Invalid,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SocksCommand {
    Connect = 1,
    Bind = 2,
    UdpAssociate = 3,
}

impl TryFrom<u8> for SocksCommand {
    type Error = u8;
    fn try_from(v: u8) -> Result<Self, u8> {
        match v {
            1 => Ok(SocksCommand::Connect),
            2 => Ok(SocksCommand::Bind),
            3 => Ok(SocksCommand::UdpAssociate),
            other => Err(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AddressType {
    IPv4 = 1,
    Domain = 3,
    IPv6 = 4,
}

impl TryFrom<u8> for AddressType {
    type Error = u8;
    fn try_from(v: u8) -> Result<Self, u8> {
        match v {
            1 => Ok(AddressType::IPv4),
            3 => Ok(AddressType::Domain),
            4 => Ok(AddressType::IPv6),
            other => Err(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ErrorCode {
    Success = 0,
    GeneralFailure = 1,
    NotAllowed = 2,
    NetworkUnreachable = 3,
    HostUnreachable = 4,
    ConnectionRefused = 5,
    TtlExpired = 6,
    CommandNotSupported = 7,
    AddressTypeNotSupported = 8,
}

impl ErrorCode {
    pub fn from_io_error(e: &std::io::Error) -> ErrorCode {
        match e.kind() {
            std::io::ErrorKind::TimedOut => ErrorCode::TtlExpired,
            std::io::ErrorKind::ConnectionRefused => ErrorCode::ConnectionRefused,
            _ => {
                // Check raw OS error for more detail
                if let Some(code) = e.raw_os_error() {
                    match code {
                        101 | 113 => ErrorCode::NetworkUnreachable, // ENETUNREACH
                        112 | 110 => ErrorCode::HostUnreachable,    // EHOSTUNREACH
                        111 => ErrorCode::ConnectionRefused,        // ECONNREFUSED
                        _ => ErrorCode::GeneralFailure,
                    }
                } else {
                    ErrorCode::GeneralFailure
                }
            }
        }
    }
}

/// Parsed SOCKS5 connect request target.
#[derive(Debug, Clone)]
pub struct ConnectTarget {
    pub host: String,
    pub port: u16,
    /// The raw request bytes (for forwarding to upstream).
    pub raw_request: Vec<u8>,
}

/// Parse the SOCKS5 method selection message.
/// Returns the list of methods the client supports.
pub fn parse_method_selection(buf: &[u8]) -> Option<Vec<AuthMethod>> {
    if buf.len() < 2 {
        return None;
    }
    if buf[0] != SOCKS_VERSION {
        return None;
    }
    let nmethods = buf[1] as usize;
    if buf.len() < 2 + nmethods {
        return None;
    }
    let methods: Vec<AuthMethod> = buf[2..2 + nmethods]
        .iter()
        .map(|&m| AuthMethod::from(m))
        .collect();
    Some(methods)
}

/// Build a SOCKS5 method selection response.
pub fn build_method_response(method: AuthMethod) -> [u8; 2] {
    [SOCKS_VERSION, method as u8]
}

/// Build an auth response (used for both method selection and credential check).
pub fn build_auth_response(version: u8, status: u8) -> [u8; 2] {
    [version, status]
}

/// Parse RFC 1929 username/password authentication request.
/// Returns (username, password) on success.
pub fn parse_credentials(buf: &[u8]) -> Option<(String, String)> {
    if buf.len() < 5 {
        return None;
    }
    if buf[0] != 1 {
        return None;
    }
    let ulen = buf[1] as usize;
    if buf.len() < 2 + ulen + 1 {
        return None;
    }
    let plen = buf[2 + ulen] as usize;
    if buf.len() < 2 + ulen + 1 + plen {
        return None;
    }
    let user = String::from_utf8_lossy(&buf[2..2 + ulen]).to_string();
    let pass = String::from_utf8_lossy(&buf[2 + ulen + 1..2 + ulen + 1 + plen]).to_string();
    Some((user, pass))
}

/// Parse a SOCKS5 connect request.
/// Returns the ConnectTarget on success, or an ErrorCode on failure.
pub fn parse_connect_request(buf: &[u8]) -> Result<ConnectTarget, ErrorCode> {
    if buf.len() < 5 {
        return Err(ErrorCode::GeneralFailure);
    }
    if buf[0] != SOCKS_VERSION {
        return Err(ErrorCode::GeneralFailure);
    }

    // Command
    let cmd = SocksCommand::try_from(buf[1]).map_err(|_| ErrorCode::CommandNotSupported)?;
    if cmd != SocksCommand::Connect {
        return Err(ErrorCode::CommandNotSupported);
    }

    // Reserved
    if buf[2] != 0 {
        return Err(ErrorCode::GeneralFailure);
    }

    let atyp = AddressType::try_from(buf[3]).map_err(|_| ErrorCode::AddressTypeNotSupported)?;
    let (host, port_offset) = match atyp {
        AddressType::IPv4 => {
            if buf.len() < 10 {
                return Err(ErrorCode::GeneralFailure);
            }
            let ip = std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            (ip.to_string(), 8usize)
        }
        AddressType::Domain => {
            if buf.len() < 5 {
                return Err(ErrorCode::GeneralFailure);
            }
            let dlen = buf[4] as usize;
            if buf.len() < 4 + 1 + dlen + 2 {
                return Err(ErrorCode::GeneralFailure);
            }
            let domain = String::from_utf8_lossy(&buf[5..5 + dlen]).to_string();
            (domain, 5 + dlen)
        }
        AddressType::IPv6 => {
            if buf.len() < 22 {
                return Err(ErrorCode::GeneralFailure);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[4..20]);
            let ip = std::net::Ipv6Addr::from(octets);
            (ip.to_string(), 20usize)
        }
    };

    if buf.len() < port_offset + 2 {
        return Err(ErrorCode::GeneralFailure);
    }
    let port = ((buf[port_offset] as u16) << 8) | (buf[port_offset + 1] as u16);

    Ok(ConnectTarget {
        host,
        port,
        raw_request: buf.to_vec(),
    })
}

/// Build a SOCKS5 reply for a connect request.
pub fn build_connect_reply(error_code: ErrorCode) -> [u8; 10] {
    // Always return IPv4 address type 0.0.0.0:0 in replies
    [
        SOCKS_VERSION,
        error_code as u8,
        0,
        1, // IPv4
        0, 0, 0, 0, // 0.0.0.0
        0, 0, // port 0
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_method_from_u8() {
        assert_eq!(AuthMethod::from(0), AuthMethod::NoAuth);
        assert_eq!(AuthMethod::from(2), AuthMethod::Username);
        assert_eq!(AuthMethod::from(0xFF), AuthMethod::Invalid);
        assert_eq!(AuthMethod::from(1), AuthMethod::Invalid); // GSSAPI not supported
        assert_eq!(AuthMethod::from(99), AuthMethod::Invalid);
    }

    #[test]
    fn test_socks_command_try_from() {
        assert_eq!(SocksCommand::try_from(1), Ok(SocksCommand::Connect));
        assert_eq!(SocksCommand::try_from(2), Ok(SocksCommand::Bind));
        assert_eq!(SocksCommand::try_from(3), Ok(SocksCommand::UdpAssociate));
        assert!(SocksCommand::try_from(0).is_err());
        assert!(SocksCommand::try_from(4).is_err());
    }

    #[test]
    fn test_address_type_try_from() {
        assert_eq!(AddressType::try_from(1), Ok(AddressType::IPv4));
        assert_eq!(AddressType::try_from(3), Ok(AddressType::Domain));
        assert_eq!(AddressType::try_from(4), Ok(AddressType::IPv6));
        assert!(AddressType::try_from(0).is_err());
        assert!(AddressType::try_from(2).is_err());
    }

    #[test]
    fn test_parse_method_selection_no_auth() {
        // Client offers only NO_AUTH
        let buf = [5, 1, 0];
        let methods = parse_method_selection(&buf).unwrap();
        assert_eq!(methods.len(), 1);
        assert_eq!(methods[0], AuthMethod::NoAuth);
    }

    #[test]
    fn test_parse_method_selection_multiple() {
        // Client offers NO_AUTH and USERNAME
        let buf = [5, 2, 0, 2];
        let methods = parse_method_selection(&buf).unwrap();
        assert_eq!(methods.len(), 2);
        assert_eq!(methods[0], AuthMethod::NoAuth);
        assert_eq!(methods[1], AuthMethod::Username);
    }

    #[test]
    fn test_parse_method_selection_wrong_version() {
        let buf = [4, 1, 0];
        assert!(parse_method_selection(&buf).is_none());
    }

    #[test]
    fn test_parse_method_selection_too_short() {
        let buf = [5];
        assert!(parse_method_selection(&buf).is_none());
    }

    #[test]
    fn test_parse_method_selection_truncated() {
        // Says 3 methods but only 1 byte
        let buf = [5, 3, 0];
        assert!(parse_method_selection(&buf).is_none());
    }

    #[test]
    fn test_build_method_response() {
        assert_eq!(build_method_response(AuthMethod::NoAuth), [5, 0]);
        assert_eq!(build_method_response(AuthMethod::Username), [5, 2]);
        assert_eq!(build_method_response(AuthMethod::Invalid), [5, 0xFF]);
    }

    #[test]
    fn test_build_auth_response() {
        assert_eq!(build_auth_response(5, 0), [5, 0]);
        assert_eq!(build_auth_response(1, 0), [1, 0]);
        assert_eq!(build_auth_response(1, 1), [1, 1]);
    }

    #[test]
    fn test_parse_credentials_valid() {
        // Version 1, ulen=4, "user", plen=4, "pass"
        let buf = [1, 4, b'u', b's', b'e', b'r', 4, b'p', b'a', b's', b's'];
        let (user, pass) = parse_credentials(&buf).unwrap();
        assert_eq!(user, "user");
        assert_eq!(pass, "pass");
    }

    #[test]
    fn test_parse_credentials_empty_user() {
        // Version 1, ulen=0, plen=3, "abc"
        let buf = [1, 0, 3, b'a', b'b', b'c'];
        let (user, pass) = parse_credentials(&buf).unwrap();
        assert_eq!(user, "");
        assert_eq!(pass, "abc");
    }

    #[test]
    fn test_parse_credentials_wrong_version() {
        let buf = [2, 4, b'u', b's', b'e', b'r', 4, b'p', b'a', b's', b's'];
        assert!(parse_credentials(&buf).is_none());
    }

    #[test]
    fn test_parse_credentials_too_short() {
        let buf = [1, 4, b'u'];
        assert!(parse_credentials(&buf).is_none());
    }

    #[test]
    fn test_parse_connect_request_ipv4() {
        // SOCKS5, CONNECT, RSV, IPv4, 127.0.0.1:80
        let buf = [5, 1, 0, 1, 127, 0, 0, 1, 0, 80];
        let target = parse_connect_request(&buf).unwrap();
        assert_eq!(target.host, "127.0.0.1");
        assert_eq!(target.port, 80);
    }

    #[test]
    fn test_parse_connect_request_ipv6() {
        // SOCKS5, CONNECT, RSV, IPv6, ::1, port 443
        let mut buf = vec![5, 1, 0, 4];
        buf.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // ::1
        buf.extend_from_slice(&[1, 0xBB]); // port 443
        let target = parse_connect_request(&buf).unwrap();
        assert_eq!(target.host, "::1");
        assert_eq!(target.port, 443);
    }

    #[test]
    fn test_parse_connect_request_domain() {
        // SOCKS5, CONNECT, RSV, Domain, len=11, "example.com", port 80
        let mut buf = vec![5, 1, 0, 3, 11];
        buf.extend_from_slice(b"example.com");
        buf.extend_from_slice(&[0, 80]);
        let target = parse_connect_request(&buf).unwrap();
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 80);
    }

    #[test]
    fn test_parse_connect_request_bind_unsupported() {
        let buf = [5, 2, 0, 1, 127, 0, 0, 1, 0, 80];
        let err = parse_connect_request(&buf).unwrap_err();
        assert_eq!(err, ErrorCode::CommandNotSupported);
    }

    #[test]
    fn test_parse_connect_request_udp_unsupported() {
        let buf = [5, 3, 0, 1, 127, 0, 0, 1, 0, 80];
        let err = parse_connect_request(&buf).unwrap_err();
        assert_eq!(err, ErrorCode::CommandNotSupported);
    }

    #[test]
    fn test_parse_connect_request_bad_version() {
        let buf = [4, 1, 0, 1, 127, 0, 0, 1, 0, 80];
        let err = parse_connect_request(&buf).unwrap_err();
        assert_eq!(err, ErrorCode::GeneralFailure);
    }

    #[test]
    fn test_parse_connect_request_bad_atyp() {
        let buf = [5, 1, 0, 5, 127, 0, 0, 1, 0, 80];
        let err = parse_connect_request(&buf).unwrap_err();
        assert_eq!(err, ErrorCode::AddressTypeNotSupported);
    }

    #[test]
    fn test_parse_connect_request_too_short_ipv4() {
        let buf = [5, 1, 0, 1, 127, 0];
        let err = parse_connect_request(&buf).unwrap_err();
        assert_eq!(err, ErrorCode::GeneralFailure);
    }

    #[test]
    fn test_parse_connect_request_too_short_domain() {
        let buf = [5, 1, 0, 3, 11, b'e', b'x'];
        let err = parse_connect_request(&buf).unwrap_err();
        assert_eq!(err, ErrorCode::GeneralFailure);
    }

    #[test]
    fn test_parse_connect_request_too_short_ipv6() {
        let buf = [5, 1, 0, 4, 0, 0, 0, 0, 0, 0];
        let err = parse_connect_request(&buf).unwrap_err();
        assert_eq!(err, ErrorCode::GeneralFailure);
    }

    #[test]
    fn test_parse_connect_request_nonzero_reserved() {
        let buf = [5, 1, 1, 1, 127, 0, 0, 1, 0, 80];
        let err = parse_connect_request(&buf).unwrap_err();
        assert_eq!(err, ErrorCode::GeneralFailure);
    }

    #[test]
    fn test_build_connect_reply_success() {
        let reply = build_connect_reply(ErrorCode::Success);
        assert_eq!(reply, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_build_connect_reply_error() {
        let reply = build_connect_reply(ErrorCode::ConnectionRefused);
        assert_eq!(reply, [5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_error_code_from_io_error_refused() {
        let e = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        assert_eq!(ErrorCode::from_io_error(&e), ErrorCode::ConnectionRefused);
    }

    #[test]
    fn test_error_code_from_io_error_timeout() {
        let e = std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out");
        assert_eq!(ErrorCode::from_io_error(&e), ErrorCode::TtlExpired);
    }

    #[test]
    fn test_error_code_from_io_error_other() {
        let e = std::io::Error::new(std::io::ErrorKind::Other, "unknown");
        assert_eq!(ErrorCode::from_io_error(&e), ErrorCode::GeneralFailure);
    }

    #[test]
    fn test_parse_connect_request_high_port() {
        // Port 65535
        let buf = [5, 1, 0, 1, 10, 0, 0, 1, 0xFF, 0xFF];
        let target = parse_connect_request(&buf).unwrap();
        assert_eq!(target.port, 65535);
    }

    #[test]
    fn test_parse_connect_request_port_zero() {
        let buf = [5, 1, 0, 1, 10, 0, 0, 1, 0, 0];
        let target = parse_connect_request(&buf).unwrap();
        assert_eq!(target.port, 0);
    }

    #[test]
    fn test_connect_target_raw_request_preserved() {
        let buf = vec![5, 1, 0, 1, 192, 168, 1, 1, 0, 80];
        let target = parse_connect_request(&buf).unwrap();
        assert_eq!(target.raw_request, buf);
    }
}
