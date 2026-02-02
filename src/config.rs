use crate::forward::ForwardRule;
use crate::VERSION;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

#[derive(Debug)]
pub struct Config {
    pub listen_ip: String,
    pub port: u16,
    pub quiet: bool,
    pub auth_user: Option<String>,
    pub auth_pass: Option<String>,
    pub auth_once: bool,
    pub whitelist_ips: Vec<IpAddr>,
    pub bind_addr: Option<IpAddr>,
    pub idle_timeout: Option<u64>,
    pub forward_rules: Vec<ForwardRule>,
}

impl Config {
    pub fn from_args(args: Vec<String>) -> Result<Config, String> {
        let mut config = Config {
            listen_ip: "0.0.0.0".to_string(),
            port: 1080,
            quiet: false,
            auth_user: None,
            auth_pass: None,
            auth_once: false,
            whitelist_ips: Vec::new(),
            bind_addr: None,
            idle_timeout: None,
            forward_rules: Vec::new(),
        };

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "-1" => {
                    config.auth_once = true;
                    i += 1;
                }
                "-q" => {
                    config.quiet = true;
                    i += 1;
                }
                "-i" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("option -i requires an operand".to_string());
                    }
                    config.listen_ip = args[i].clone();
                    i += 1;
                }
                "-p" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("option -p requires an operand".to_string());
                    }
                    config.port = args[i]
                        .parse()
                        .map_err(|_| format!("invalid port: {}", args[i]))?;
                    i += 1;
                }
                "-u" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("option -u requires an operand".to_string());
                    }
                    config.auth_user = Some(args[i].clone());
                    i += 1;
                }
                "-P" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("option -P requires an operand".to_string());
                    }
                    config.auth_pass = Some(args[i].clone());
                    i += 1;
                }
                "-b" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("option -b requires an operand".to_string());
                    }
                    let addr: IpAddr = resolve_ip(&args[i])?;
                    config.bind_addr = Some(addr);
                    i += 1;
                }
                "-w" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("option -w requires an operand".to_string());
                    }
                    for ip_str in args[i].split(',') {
                        let ip = resolve_ip(ip_str)?;
                        config.whitelist_ips.push(ip);
                    }
                    i += 1;
                }
                "-t" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("option -t requires an operand".to_string());
                    }
                    let t: u64 = args[i]
                        .parse()
                        .map_err(|_| format!("invalid timeout: {}", args[i]))?;
                    config.idle_timeout = Some(t);
                    i += 1;
                }
                "-f" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("option -f requires an operand".to_string());
                    }
                    let rule = ForwardRule::parse(&args[i])?;
                    config.forward_rules.push(rule);
                    i += 1;
                }
                "-V" => {
                    println!("CleverSocks {VERSION}");
                    std::process::exit(0);
                }
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => {
                    return Err(format!("unknown option: {other}"));
                }
            }
        }

        // Validate: user and pass must be used together
        if config.auth_user.is_some() != config.auth_pass.is_some() {
            return Err("user and pass must be used together".to_string());
        }

        // Validate: -1/-w require user/pass
        if (config.auth_once || !config.whitelist_ips.is_empty())
            && config.auth_pass.is_none()
        {
            return Err("-1/-w options must be used together with user/pass".to_string());
        }

        Ok(config)
    }

    pub fn requires_auth(&self) -> bool {
        self.auth_user.is_some()
    }

    pub fn has_auth_ips(&self) -> bool {
        self.auth_once || !self.whitelist_ips.is_empty()
    }
}

fn resolve_ip(s: &str) -> Result<IpAddr, String> {
    // Try parsing as IP address first
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(ip);
    }
    // Try DNS resolution
    let addr_str = format!("{s}:0");
    match addr_str.to_socket_addrs() {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.next() {
                Ok(addr.ip())
            } else {
                Err(format!("failed to resolve {s}"))
            }
        }
        Err(e) => Err(format!("failed to resolve {s}: {e}")),
    }
}

pub fn resolve_to_socketaddr(host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    let addr_str = format!("{host}:{port}");
    let addrs: Vec<SocketAddr> = addr_str.to_socket_addrs()?.collect();
    if addrs.is_empty() {
        Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            format!("could not resolve {host}"),
        ))
    } else {
        Ok(addrs)
    }
}

fn print_usage() {
    eprintln!(
        "CleverSocks SOCKS5 Server
-------------------------
usage: cleversocks -1 -q -i listenip -p port -u user -P pass -b bindaddr -w ips -t timeout -f fwdrule
all arguments are optional.
by default listenip is 0.0.0.0 and port 1080.

option -q disables logging.
option -t specifies an idle exit timeout in seconds. default is to wait forever.
option -b specifies which ip outgoing connections are bound to.
option -w allows to specify a comma-separated whitelist of ip addresses,
 that may use the proxy without user/pass authentication.
 e.g. -w 127.0.0.1,192.168.1.1,::1 or just -w 10.0.0.1
 to allow access ONLY to those ips, choose an impossible to guess user/pw combo.
option -1 activates auth_once mode: once a specific ip address
 authed successfully with user/pass, it is added to a whitelist
 and may use the proxy without auth.
 this is handy for programs like firefox that don't support
 user/pass auth. for it to work you'd basically make one connection
 with another program that supports it, and then you can use firefox too.
option -f specifies a forwarding rule of the form
  match_name:match_port,[user:password@]upstream_name:upstream_port,remote_name:remote_port
 this will cause requests that /match/ to be renamed to /remote/
 and sent to the /upstream/ SOCKS5 proxy server.
 this option may be specified multiple times.
option -V prints version information and exits."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let args = vec!["cleversocks".to_string()];
        let config = Config::from_args(args).unwrap();
        assert_eq!(config.listen_ip, "0.0.0.0");
        assert_eq!(config.port, 1080);
        assert!(!config.quiet);
        assert!(config.auth_user.is_none());
        assert!(config.auth_pass.is_none());
        assert!(!config.auth_once);
        assert!(config.whitelist_ips.is_empty());
        assert!(config.bind_addr.is_none());
        assert!(config.idle_timeout.is_none());
        assert!(config.forward_rules.is_empty());
    }

    #[test]
    fn test_custom_listen_ip_and_port() {
        let args = vec![
            "cleversocks".to_string(),
            "-i".to_string(),
            "127.0.0.1".to_string(),
            "-p".to_string(),
            "9050".to_string(),
        ];
        let config = Config::from_args(args).unwrap();
        assert_eq!(config.listen_ip, "127.0.0.1");
        assert_eq!(config.port, 9050);
    }

    #[test]
    fn test_auth_user_pass() {
        let args = vec![
            "cleversocks".to_string(),
            "-u".to_string(),
            "admin".to_string(),
            "-P".to_string(),
            "secret".to_string(),
        ];
        let config = Config::from_args(args).unwrap();
        assert_eq!(config.auth_user.as_deref(), Some("admin"));
        assert_eq!(config.auth_pass.as_deref(), Some("secret"));
        assert!(config.requires_auth());
    }

    #[test]
    fn test_auth_user_without_pass_fails() {
        let args = vec![
            "cleversocks".to_string(),
            "-u".to_string(),
            "admin".to_string(),
        ];
        assert!(Config::from_args(args).is_err());
    }

    #[test]
    fn test_auth_pass_without_user_fails() {
        let args = vec![
            "cleversocks".to_string(),
            "-P".to_string(),
            "secret".to_string(),
        ];
        assert!(Config::from_args(args).is_err());
    }

    #[test]
    fn test_auth_once_without_auth_fails() {
        let args = vec!["cleversocks".to_string(), "-1".to_string()];
        assert!(Config::from_args(args).is_err());
    }

    #[test]
    fn test_whitelist_without_auth_fails() {
        let args = vec![
            "cleversocks".to_string(),
            "-w".to_string(),
            "127.0.0.1".to_string(),
        ];
        assert!(Config::from_args(args).is_err());
    }

    #[test]
    fn test_auth_once_with_auth() {
        let args = vec![
            "cleversocks".to_string(),
            "-u".to_string(),
            "user".to_string(),
            "-P".to_string(),
            "pass".to_string(),
            "-1".to_string(),
        ];
        let config = Config::from_args(args).unwrap();
        assert!(config.auth_once);
        assert!(config.has_auth_ips());
    }

    #[test]
    fn test_whitelist_ips() {
        let args = vec![
            "cleversocks".to_string(),
            "-u".to_string(),
            "user".to_string(),
            "-P".to_string(),
            "pass".to_string(),
            "-w".to_string(),
            "127.0.0.1,::1".to_string(),
        ];
        let config = Config::from_args(args).unwrap();
        assert_eq!(config.whitelist_ips.len(), 2);
        assert_eq!(
            config.whitelist_ips[0],
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(config.whitelist_ips[1], "::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_quiet_mode() {
        let args = vec!["cleversocks".to_string(), "-q".to_string()];
        let config = Config::from_args(args).unwrap();
        assert!(config.quiet);
    }

    #[test]
    fn test_bind_addr() {
        let args = vec![
            "cleversocks".to_string(),
            "-b".to_string(),
            "192.168.1.1".to_string(),
        ];
        let config = Config::from_args(args).unwrap();
        assert_eq!(
            config.bind_addr,
            Some("192.168.1.1".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn test_idle_timeout() {
        let args = vec![
            "cleversocks".to_string(),
            "-t".to_string(),
            "300".to_string(),
        ];
        let config = Config::from_args(args).unwrap();
        assert_eq!(config.idle_timeout, Some(300));
    }

    #[test]
    fn test_invalid_port() {
        let args = vec![
            "cleversocks".to_string(),
            "-p".to_string(),
            "notanumber".to_string(),
        ];
        assert!(Config::from_args(args).is_err());
    }

    #[test]
    fn test_missing_option_arg() {
        let args = vec!["cleversocks".to_string(), "-i".to_string()];
        assert!(Config::from_args(args).is_err());
    }

    #[test]
    fn test_unknown_option() {
        let args = vec!["cleversocks".to_string(), "-Z".to_string()];
        assert!(Config::from_args(args).is_err());
    }

    #[test]
    fn test_forward_rule() {
        let args = vec![
            "cleversocks".to_string(),
            "-f".to_string(),
            "example.com:443,proxy.com:1080,target.com:443".to_string(),
        ];
        let config = Config::from_args(args).unwrap();
        assert_eq!(config.forward_rules.len(), 1);
        assert_eq!(config.forward_rules[0].match_name, "example.com");
        assert_eq!(config.forward_rules[0].match_port, 443);
    }

    #[test]
    fn test_resolve_ip_v4() {
        let ip = resolve_ip("127.0.0.1").unwrap();
        assert_eq!(ip, "127.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_resolve_ip_v6() {
        let ip = resolve_ip("::1").unwrap();
        assert_eq!(ip, "::1".parse::<IpAddr>().unwrap());
    }
}
