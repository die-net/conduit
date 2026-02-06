# conduit

`conduit` is a protocol-converting proxy service written in Go.

It can accept inbound proxy traffic via:

- HTTP proxy (including `CONNECT` for HTTPS tunneling)
- SOCKS5 proxy (no-auth)
- Linux transparent proxy listener (TPROXY-style; Linux-only)

It can forward outbound connections:

- Directly to the destination
- Via an upstream HTTP or HTTPS proxy (with optional basic auth)
- Via an upstream SOCKS5 proxy (with optional user+pass)
- Via an upstream SSH server using SSH dynamic port forwarding (like "ssh -D")

The HTTP proxy (when not using the `CONNECT` method) uses the Go standard library's proxy support, inheriting its high performance, connection pooling, and standards conformance.

The SOCKS5 proxy, the Linux transparent proxy, and HTTP proxy when using the `CONNECT` method pass TCP data as-is, without trying to interpret the protocol.  After setting up the connection, data is transferred on Linux via the zero-copy splice() mechanism to maximize throughput.

## Build

Requirements:

- Go 1.25+ (the module targets Go 1.25)

Build a local binary:

```bash
go build -o conduit .
```

Run tests:

```bash
go test ./...
```

## Run

Run from the repo root:

```bash
conduit --http-listen 127.0.0.1:8080
```

### Common examples

HTTP proxy (direct):

```bash
conduit \
  --http-listen 127.0.0.1:8080 \
  --upstream direct://
```

SOCKS5 proxy (direct):

```bash
conduit \
  --socks5-listen 127.0.0.1:1080 \
  --upstream direct://
```

HTTP proxy that forwards outbound connections via an upstream HTTP proxy:

```bash
conduit \
  --http-listen 127.0.0.1:8080 \
  --upstream http://10.0.0.2:3128
```

HTTP proxy that forwards outbound connections via an upstream SOCKS5 proxy:

```bash
conduit \
  --http-listen 127.0.0.1:8080 \
  --upstream socks5://10.0.0.3:1080
```

HTTP proxy that forwards outbound connections via an upstream SSH server (password auth):

```bash
conduit \
  --http-listen 127.0.0.1:8080 \
  --upstream ssh://user:pass@10.0.0.4:22
```

HTTP proxy that forwards outbound connections via an upstream SSH server (key auth via agent):

```bash
conduit \
  --http-listen 127.0.0.1:8080 \
  --upstream ssh://user@10.0.0.4:22
```

HTTP proxy that forwards outbound connections via an upstream SSH server (key file):

```bash
conduit \
  --http-listen 127.0.0.1:8080 \
  --upstream ssh://user@10.0.0.4:22 \
  --ssh-key ~/.ssh/id_ed25519
```

## Flags

Listener flags (any can be omitted to disable that listener):

- `--http-listen=IP:port`
- `--socks5-listen=IP:port`
- `--tproxy-listen=IP:port` (Linux only)

Debug flags:

- `--debug-listen=IP:port` (enables `/debug/pprof`)
- `--verbose` (default: false): log per-connection errors.

Forwarding flags:

- `--upstream=direct:// | http://[user:pass@]host:port | https://[user:pass@]host:port | socks5://[user:pass@]host:port | ssh://user[:pass]@host:port`
- `--ssh-key=agent|path|""` (default: `agent` if `SSH_AUTH_SOCK` is set, else empty): SSH key source for ssh:// upstream. Use `agent` for SSH agent, a file path for a private key (OpenSSH format), or empty to disable key auth. If both key and password are provided, both methods are offered to the server.
- `--ssh-known-hosts=path|""` (default: `~/.ssh/known_hosts`): Path to known_hosts file for SSH host key verification. Unknown hosts are automatically added on first connection (trust on first use). Empty disables host verification.

Timeout behavior:

- `--dial-timeout` bounds DNS lookups and TCP connect.
- `--negotiation-timeout` bounds protocol handshakes (HTTP CONNECT and SOCKS5 negotiation/CONNECT).
- `--http-idle-timeout` limits how long HTTP connections remain idle before being closed.
- After negotiation completes, there's no explicit timeout on connections.  It is assumed that either the client or server will close as needed, or that TCP keepalive will detect and remove stale connections.

TCP keepalive is optionally applied to all accepted TCP connections and all outbound TCP dials, so the kernel will detect when connections are stale:

- `--tcp-keepalive=on|off|keepidle:keepintvl:keepcnt`
  - `on`: enable keepalive with kernel defaults
  - `off`: disable keepalive
  - `keepidle:keepintvl:keepcnt`: enable keepalive and (where supported) set:
    - `keepidle` (seconds)
    - `keepintvl` (seconds)
    - `keepcnt` (count)

## Current behavior / implementation notes

- **HTTP (non-CONNECT)** uses `net/http/httputil.ReverseProxy`.
  - A custom `RoundTripper` dials via the configured forwarding mode.
- **HTTP CONNECT** uses HTTP hijacking and then bidirectional `io.Copy` piping.
- **SOCKS5 server** supports:
  - No-auth negotiation
  - `CONNECT` command
  - IPv4/IPv6/domain targets
- **Upstream SOCKS5 forwarding** uses `github.com/txthinking/socks5`.
  - Outbound proxy connections are dialed with the internal dialer interface (`DialContext`).
  - SOCKS5 negotiation and CONNECT are performed via shared helpers in `internal/socks5` (built on the library's low-level protocol API).
- **Upstream SSH forwarding** uses `golang.org/x/crypto/ssh`.
  - A single SSH transport connection is established lazily and reused.
  - Each proxied outbound connection opens a new `direct-tcpip` channel over the shared SSH transport.
  - Authentication supports password, public key, SSH agent, or combinations. Keys from the SSH agent are used by default when `SSH_AUTH_SOCK` is set.
  - Host key checking uses `~/.ssh/known_hosts` by default (trust on first use). Can be disabled with `--ssh-known-hosts=off`.
  - Servers commonly have a low limit of max forwarded connections (MaxSessions defaults to 10), which this doesn't handle well.
- After connections are negotiated, we try to preserve the Linux zero-copy fast path.

## Linux transparent proxy (TPROXY)

The Linux transparent proxy listener is intended for TPROXY-style deployments.

Important notes:

- You still need appropriate **routing and firewall rules** (iptables/nftables) to redirect traffic.
- The implementation uses `golang.org/x/sys/unix` and `unix.SO_ORIGINAL_DST` to retrieve the original destination via `getsockopt` for both IPv4 and IPv6.
- On non-Linux platforms, `--tproxy-listen` returns an error (build remains portable).

## TODO / Caveats

- **TPROXY robustness**:
  - Improve validation/diagnostics around kernel/sysctl prerequisites.
- **HTTP proxy correctness/performance**:
  - Consider connection reuse tuning and explicit transport settings (idle conns, max conns per host, etc.).
  - Add explicit filtering/handling for hop-by-hop headers as needed for edge cases.
- **Security/authentication**:
  - Add optional auth for HTTP proxy and SOCKS5.
  - Add allow/deny lists.
- **Observability**:
  - Structured logging.
  - Prometheus metrics.
- **Graceful shutdown**:
  - Drain active tunnel connections more gracefully (currently relies on listener/server close).
- **Context handling for upstream SOCKS5**:
  - Verify cancellation behavior across all failure modes (DNS, connect, handshake) and add targeted tests.
