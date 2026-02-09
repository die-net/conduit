// Package tproxy implements transparent proxy listeners for Linux, FreeBSD,
// and OpenBSD.
//
// On Linux, it listens with IP_TRANSPARENT and retrieves the original
// destination of redirected TCP connections via SO_ORIGINAL_DST (getsockopt).
// This is designed for use with iptables/nftables TPROXY rules.
//
// On FreeBSD, it listens with IP_BINDANY (protocol-level) and retrieves the
// original destination from the socket's local address (which IPFW fwd and
// PF rdr-to preserve).
//
// On OpenBSD, it listens with SO_BINDANY (socket-level) and retrieves the
// original destination from the socket's local address (which PF rdr-to
// preserves).
//
// On other platforms, the listener and original-destination lookup are stubbed
// out and return errors.
package tproxy
