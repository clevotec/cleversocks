CleverSocks - multithreaded, small, efficient SOCKS5 server.
===========================================================

a SOCKS5 service that you can run on your remote boxes to tunnel connections
through them, if for some reason SSH doesn't cut it for you.

It's very lightweight, and very light on resources too:

for every client, a thread with a low stack size is spawned.
the main process basically doesn't consume any resources at all.

the only limits are the amount of file descriptors and the RAM.

It's also designed to be robust: it handles resource exhaustion
gracefully by simply denying new connections, instead of crashing
as most other programs do these days.

another plus is ease-of-use: no config file necessary, everything can be
done from the command line and doesn't even need any parameters for quick
setup.

History
-------

This is a Rust rewrite of the original C implementation
[microsocks](https://github.com/rofl0r/microsocks) by rofl0r, itself
the successor of "rocksocks5". Goals of the rewrite:

- memory safety without any `unsafe` code
- modern tooling with Cargo, cross-compilation, and CI/CD
- no artificial limits
- minimal source code size with maximal readability and extensibility

IPv4, DNS, and IPv6 are supported out of the box. When statically
linked against musl the binary is well under 1 MB.

command line options
--------------------

    cleversocks -1 -q -i listenip -p port -u user -P pass -b bindaddr -w ips -t timeout -f fwdrule

all arguments are optional.
by default listenip is 0.0.0.0 and port 1080.

- option -q disables logging.
- option -b specifies which ip outgoing connections are bound to
- option -w allows to specify a comma-separated whitelist of ip addresses,
that may use the proxy without user/pass authentication.
e.g. -w 127.0.0.1,192.168.1.1.1,::1 or just -w 10.0.0.1
to allow access ONLY to those ips, choose an impossible to guess user/pw combo.
- option -1 activates auth_once mode: once a specific ip address
authed successfully with user/pass, it is added to a whitelist
and may use the proxy without auth.
this is handy for programs like firefox that don't support
user/pass auth. for it to work you'd basically make one connection
with another program that supports it, and then you can use firefox too.
for example, authenticate once using curl:

    curl --socks5 user:password@listenip:port anyurl


- option -t specifies an idle exit timeout in seconds. when no connections
are active for this duration the server exits. default is to wait forever.
- option -f specifies a forwarding rule of the form
`match_name:match_port,[user:password@]upstream_name:upstream_port,remote_name:remote_port`.
requests matching the rule are renamed to the remote address and sent through
the upstream SOCKS5 proxy. this option may be specified multiple times.
- option -V prints version information and exits.

Supported SOCKS5 Features
-------------------------
- authentication: none, password, one-time
- IPv4, IPv6, DNS
- TCP (no UDP at this time)
- forwarding rules with upstream SOCKS5 proxy chaining

Docker container
----------------
You can run cleversocks in a docker container:

    docker run --init -d -p 7777:1080 ghcr.io/clevotec/cleversocks

Replace 7777 with the port cleversocks will be accessible on.

Building from source
--------------------

    cargo build --release

The binary will be at `target/release/cleversocks`.

For static musl builds (Linux):

    cargo build --release --target x86_64-unknown-linux-musl
