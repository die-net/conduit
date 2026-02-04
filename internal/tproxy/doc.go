package tproxy

// Package tproxy implements a Linux transparent proxy (TPROXY-style) listener.
//
// On Linux, it can listen with IP_TRANSPARENT and retrieve the original
// destination of redirected TCP connections (SO_ORIGINAL_DST), then forward the
// connection to that destination using the configured outbound dialer.
//
// On non-Linux platforms, the listener and original-destination lookup are
// stubbed out.
