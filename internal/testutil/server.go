package testutil

import (
	"context"
	"net"
	"sync"
	"testing"
)

// StartSingleAcceptServer starts a TCP listener on 127.0.0.1:0 and accepts
// exactly one connection.
//
// The accepted connection is passed to handler and then closed.
//
// The returned wait func closes the listener and waits for the handler
// goroutine to exit.
func StartSingleAcceptServer(ctx context.Context, t *testing.T, handler func(net.Conn)) (net.Listener, func()) {
	t.Helper()

	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		handler(c)
	})

	wait := func() {
		_ = ln.Close()
		wg.Wait()
	}

	return ln, wait
}
