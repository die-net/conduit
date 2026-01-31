package proxy

import (
	"context"
	"io"
	"net"

	"golang.org/x/sync/errgroup"
)

func CopyBidirectional(ctx context.Context, left, right net.Conn) error {
	// There can't be deadlines set on arguments to io.Copy to be able
	// to use Go's zero-copy hot path that uses splice.  Instead,
	// we Close() both sockets if the context is cancelled.
	cctx, cancel := context.WithCancel(ctx)
	g, gctx := errgroup.WithContext(cctx)

	g.Go(func() error {
		_, err := io.Copy(left, right)
		cancel()
		return err
	})

	g.Go(func() error {
		_, err := io.Copy(right, left)
		cancel()
		return err
	})

	// When the context is canceled, ensure we close both sides to unblock Copy.
	<-gctx.Done()
	_ = left.Close()
	_ = right.Close()

	return g.Wait()
}
