package socks5

// Package socks5 provides a small, shared SOCKS5 handshake implementation used
// by conduit.
//
// It wraps the low-level protocol types in github.com/txthinking/socks5 to keep
// conduit-specific behavior in one place and avoid duplicating negotiation and
// CONNECT parsing/writing logic across internal/proxy and internal/dialer.
//
// This package is not intended to be a full SOCKS5 server/client implementation;
// it is a thin layer around the library primitives with conduit-friendly
// defaults and error handling.
