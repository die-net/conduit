package testutil

import (
	"context"
	"net"
	"sync"
	"testing"
)

func StartSingleAcceptServer(t *testing.T, ctx context.Context, handler func(net.Conn)) (net.Listener, func()) {
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
