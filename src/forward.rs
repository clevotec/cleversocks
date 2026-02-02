/// Forwarding rules for SOCKS5 proxy chaining.
///
/// A forwarding rule matches on destination name and port,
/// and redirects the connection through an upstream SOCKS5 proxy.

#[derive(Debug, Clone)]
pub struct ForwardRule {
    pub match_name: String,
    pub match_port: u16,
    pub upstream_host: String,
    pub upstream_port: u16,
    pub upstream_auth: Option<UpstreamAuth>,
    pub remote_name: String,
    pub remote_port: u16,
}

#[derive(Debug, Clone)]
pub struct UpstreamAuth {
    pub username: String,
    pub password: String,
}

impl UpstreamAuth {
    /// Build RFC 1929 auth request buffer.
    pub fn to_auth_buf(&self) -> Vec<u8> {
        let ulen = self.username.len();
        let plen = self.password.len();
        let mut buf = Vec::with_capacity(1 + 1 + ulen + 1 + plen);
        buf.push(1); // version
        buf.push(ulen as u8);
        buf.extend_from_slice(self.username.as_bytes());
        buf.push(plen as u8);
        buf.extend_from_slice(self.password.as_bytes());
        buf
    }
}

impl ForwardRule {
    /// Parse a forwarding rule from a string of the form:
    /// `match_name:match_port,[user:password@]upstream_name:upstream_port,remote_name:remote_port`
    pub fn parse(s: &str) -> Result<ForwardRule, String> {
        let parts: Vec<&str> = s.splitn(3, ',').collect();
        if parts.len() != 3 {
            return Err(format!("invalid forwarding rule format: {s}"));
        }

        let (match_name, match_port) = parse_host_port(parts[0])?;
        let (remote_name, remote_port) = parse_host_port(parts[2])?;

        // Parse upstream which may contain auth: [user:pass@]host:port
        let upstream_str = parts[1];
        let (upstream_auth, upstream_host, upstream_port) =
            if let Some(at_pos) = upstream_str.find('@') {
                let auth_part = &upstream_str[..at_pos];
                let host_part = &upstream_str[at_pos + 1..];
                let (host, port) = parse_host_port(host_part)?;
                if port == 0 {
                    return Err("upstream port must be > 0".to_string());
                }
                let colon_pos = auth_part
                    .find(':')
                    .ok_or("invalid auth format, expected user:pass")?;
                let username = auth_part[..colon_pos].to_string();
                let password = auth_part[colon_pos + 1..].to_string();
                if username.len() > 255 || password.len() > 255 {
                    return Err("username/password too long (max 255)".to_string());
                }
                (
                    Some(UpstreamAuth { username, password }),
                    host.to_string(),
                    port,
                )
            } else {
                let (host, port) = parse_host_port(upstream_str)?;
                if port == 0 {
                    return Err("upstream port must be > 0".to_string());
                }
                (None, host.to_string(), port)
            };

        // Validate remote_name fits in a SOCKS5 domain address (max 255 bytes)
        if remote_name.len() > 255 {
            return Err("remote name too long (max 255 bytes)".to_string());
        }

        // Normalize wildcard match names
        let match_name = if match_name == "0.0.0.0" || match_name == "*" {
            String::new()
        } else {
            match_name.to_string()
        };

        Ok(ForwardRule {
            match_name,
            match_port,
            upstream_host,
            upstream_port,
            upstream_auth,
            remote_name: remote_name.to_string(),
            remote_port,
        })
    }

    /// Check if this rule matches the given target name and port.
    pub fn matches(&self, name: &str, port: u16) -> bool {
        let name_match = self.match_name.is_empty() || self.match_name == name;
        let port_match = self.match_port == 0 || self.match_port == port;
        name_match && port_match
    }

    /// Build the SOCKS5 connect request for the remote target.
    pub fn build_remote_request(&self) -> Vec<u8> {
        let rlen = self.remote_name.len();
        let mut buf = Vec::with_capacity(3 + 1 + 1 + rlen + 2);
        buf.push(5); // SOCKS version
        buf.push(1); // CONNECT
        buf.push(0); // reserved
        buf.push(3); // domain name
        buf.push(rlen as u8);
        buf.extend_from_slice(self.remote_name.as_bytes());
        buf.push((self.remote_port >> 8) as u8);
        buf.push((self.remote_port & 0xFF) as u8);
        buf
    }

    /// Build the SOCKS5 handshake for the upstream proxy.
    pub fn build_upstream_handshake(&self) -> Vec<u8> {
        if self.upstream_auth.is_some() {
            vec![5, 2, 0, 2] // Offer NO_AUTH and USERNAME
        } else {
            vec![5, 1, 0] // Offer NO_AUTH only
        }
    }
}

/// Parse "host:port" where port is optional (default 0).
fn parse_host_port(s: &str) -> Result<(&str, u16), String> {
    if let Some(colon_pos) = s.rfind(':') {
        let host = &s[..colon_pos];
        let port_str = &s[colon_pos + 1..];
        if port_str.is_empty() {
            return Err(format!("empty port in: {s}"));
        }
        let port: u16 = port_str
            .parse()
            .map_err(|_| format!("invalid port in: {s}"))?;
        Ok((host, port))
    } else {
        Err(format!("missing port in: {s}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_host_port_valid() {
        let (host, port) = parse_host_port("example.com:443").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_host_port_zero() {
        let (host, port) = parse_host_port("*:0").unwrap();
        assert_eq!(host, "*");
        assert_eq!(port, 0);
    }

    #[test]
    fn test_parse_host_port_missing_port() {
        assert!(parse_host_port("example.com").is_err());
    }

    #[test]
    fn test_parse_host_port_empty_port() {
        assert!(parse_host_port("example.com:").is_err());
    }

    #[test]
    fn test_parse_host_port_invalid_port() {
        assert!(parse_host_port("example.com:abc").is_err());
    }

    #[test]
    fn test_parse_forward_rule_simple() {
        let rule =
            ForwardRule::parse("example.com:443,proxy.com:1080,target.com:443").unwrap();
        assert_eq!(rule.match_name, "example.com");
        assert_eq!(rule.match_port, 443);
        assert_eq!(rule.upstream_host, "proxy.com");
        assert_eq!(rule.upstream_port, 1080);
        assert!(rule.upstream_auth.is_none());
        assert_eq!(rule.remote_name, "target.com");
        assert_eq!(rule.remote_port, 443);
    }

    #[test]
    fn test_parse_forward_rule_with_auth() {
        let rule = ForwardRule::parse(
            "example.com:443,user:pass@proxy.com:1080,target.com:443",
        )
        .unwrap();
        assert_eq!(rule.match_name, "example.com");
        assert_eq!(rule.match_port, 443);
        assert_eq!(rule.upstream_host, "proxy.com");
        assert_eq!(rule.upstream_port, 1080);
        let auth = rule.upstream_auth.as_ref().unwrap();
        assert_eq!(auth.username, "user");
        assert_eq!(auth.password, "pass");
        assert_eq!(rule.remote_name, "target.com");
        assert_eq!(rule.remote_port, 443);
    }

    #[test]
    fn test_parse_forward_rule_wildcard() {
        let rule =
            ForwardRule::parse("*:0,proxy.com:1080,target.com:80").unwrap();
        assert_eq!(rule.match_name, "");
        assert_eq!(rule.match_port, 0);
    }

    #[test]
    fn test_parse_forward_rule_zero_ip() {
        let rule =
            ForwardRule::parse("0.0.0.0:0,proxy.com:1080,target.com:80").unwrap();
        assert_eq!(rule.match_name, "");
    }

    #[test]
    fn test_parse_forward_rule_invalid_format() {
        assert!(ForwardRule::parse("only_one_part").is_err());
        assert!(ForwardRule::parse("one,two").is_err());
    }

    #[test]
    fn test_parse_forward_rule_upstream_port_zero() {
        assert!(ForwardRule::parse("a:80,proxy.com:0,target.com:80").is_err());
    }

    #[test]
    fn test_forward_rule_matches_exact() {
        let rule =
            ForwardRule::parse("example.com:443,proxy.com:1080,target.com:443").unwrap();
        assert!(rule.matches("example.com", 443));
        assert!(!rule.matches("other.com", 443));
        assert!(!rule.matches("example.com", 80));
    }

    #[test]
    fn test_forward_rule_matches_wildcard_name() {
        let rule =
            ForwardRule::parse("*:443,proxy.com:1080,target.com:443").unwrap();
        assert!(rule.matches("anything.com", 443));
        assert!(rule.matches("other.com", 443));
        assert!(!rule.matches("other.com", 80));
    }

    #[test]
    fn test_forward_rule_matches_wildcard_port() {
        let rule =
            ForwardRule::parse("example.com:0,proxy.com:1080,target.com:443").unwrap();
        assert!(rule.matches("example.com", 443));
        assert!(rule.matches("example.com", 80));
        assert!(!rule.matches("other.com", 80));
    }

    #[test]
    fn test_forward_rule_matches_all_wildcard() {
        let rule =
            ForwardRule::parse("*:0,proxy.com:1080,target.com:443").unwrap();
        assert!(rule.matches("anything", 12345));
    }

    #[test]
    fn test_build_remote_request() {
        let rule =
            ForwardRule::parse("*:0,proxy.com:1080,target.com:443").unwrap();
        let req = rule.build_remote_request();
        assert_eq!(req[0], 5); // SOCKS version
        assert_eq!(req[1], 1); // CONNECT
        assert_eq!(req[2], 0); // reserved
        assert_eq!(req[3], 3); // domain
        assert_eq!(req[4], 10); // len("target.com")
        assert_eq!(&req[5..15], b"target.com");
        assert_eq!(req[15], 1); // 443 >> 8
        assert_eq!(req[16], 0xBB); // 443 & 0xFF
    }

    #[test]
    fn test_build_upstream_handshake_no_auth() {
        let rule =
            ForwardRule::parse("*:0,proxy.com:1080,target.com:443").unwrap();
        let hs = rule.build_upstream_handshake();
        assert_eq!(hs, vec![5, 1, 0]);
    }

    #[test]
    fn test_build_upstream_handshake_with_auth() {
        let rule = ForwardRule::parse(
            "example.com:443,user:pass@proxy.com:1080,target.com:443",
        )
        .unwrap();
        let hs = rule.build_upstream_handshake();
        assert_eq!(hs, vec![5, 2, 0, 2]);
    }

    #[test]
    fn test_upstream_auth_to_buf() {
        let auth = UpstreamAuth {
            username: "ab".to_string(),
            password: "cd".to_string(),
        };
        let buf = auth.to_auth_buf();
        assert_eq!(buf, vec![1, 2, b'a', b'b', 2, b'c', b'd']);
    }

    #[test]
    fn test_upstream_auth_to_buf_empty() {
        let auth = UpstreamAuth {
            username: "".to_string(),
            password: "".to_string(),
        };
        let buf = auth.to_auth_buf();
        assert_eq!(buf, vec![1, 0, 0]);
    }

    #[test]
    fn test_forward_rule_long_credentials_rejected() {
        let long_user = "a".repeat(256);
        let rule_str = format!("{long_user}:pass@proxy.com:1080");
        let full = format!("host:80,{rule_str},target.com:80");
        assert!(ForwardRule::parse(&full).is_err());
    }

    #[test]
    fn test_forward_rule_auth_missing_colon() {
        assert!(ForwardRule::parse("h:80,useronly@proxy.com:1080,t:80").is_err());
    }

    #[test]
    fn test_forward_rule_remote_name_too_long() {
        let long_name = "a".repeat(256);
        let rule_str = format!("h:80,proxy.com:1080,{long_name}:80");
        let err = ForwardRule::parse(&rule_str).unwrap_err();
        assert!(err.contains("too long"));
    }

    #[test]
    fn test_forward_rule_remote_name_max_length() {
        let name = "a".repeat(255);
        let rule_str = format!("h:80,proxy.com:1080,{name}:80");
        assert!(ForwardRule::parse(&rule_str).is_ok());
    }
}
