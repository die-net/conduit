# conduit

`conduit` is a high-concurrency proxy service written in Go.

It can accept inbound proxy traffic via:

- HTTP proxy (including `CONNECT` for HTTPS tunneling)
- SOCKS5 proxy (no-auth)
- Linux transparent proxy listener (TPROXY-style; Linux-only)

It can forward outbound connections:

- Directly to the destination
- Via an upstream HTTP proxy
- Via an upstream SOCKS5 proxy

## Build

Requirements:

- Go 1.22+ (the module targets Go 1.22)

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
  --upstream-mode direct
```

SOCKS5 proxy (direct):

```bash
conduit \
  --socks5-listen 127.0.0.1:1080 \
  --upstream-mode direct
```

HTTP proxy that forwards outbound connections via an upstream HTTP proxy:

```bash
conduit \
  --http-listen 127.0.0.1:8080 \
  --upstream-mode http \
  --upstream-addr 10.0.0.2:3128
```

HTTP proxy that forwards outbound connections via an upstream SOCKS5 proxy:

```bash
conduit \
  --http-listen 127.0.0.1:8080 \
  --upstream-mode socks5 \
  --upstream-addr 10.0.0.3:1080
```

## Flags

Listener flags (any can be omitted to disable that listener):

- `--http-listen=IP:port`
- `--socks5-listen=IP:port`
- `--tproxy-listen=IP:port` (Linux only)

Forwarding flags:

- `--upstream-mode=direct|http|socks5`
- `--upstream-addr=IP:port` (required for `http` and `socks5` upstream modes)

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
  - SOCKS5 negotiation and CONNECT are performed using the library's low-level protocol API.
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
