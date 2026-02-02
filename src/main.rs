/*
   CleverSocks - multithreaded, small, efficient SOCKS5 server.

   Rust rewrite of the original C implementation by rofl0r.

   Features:
   - IPv4, IPv6, DNS resolution out of the box
   - Username/password authentication (RFC 1929)
   - Auth-once IP whitelisting
   - Forwarding rules with upstream SOCKS5 proxy chaining
   - Constant-time credential comparison
   - Zero unsafe code
*/

mod config;
mod forward;
mod logging;
mod proxy;
mod socks;

use config::Config;
use proxy::run_server;
use std::process;
use std::sync::Arc;

pub const VERSION: &str = "1.0.5";

fn main() {
    let config = match Config::from_args(std::env::args().collect()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            process::exit(1);
        }
    };

    let config = Arc::new(config);

    if let Err(e) = run_server(config) {
        eprintln!("error: {e}");
        process::exit(1);
    }
}
