package proxy

import (
	"context"
	"io"
	"net"
	"time"

	"golang.org/x/sync/errgroup"
)

func CopyBidirectional(ctx context.Context, left, right net.Conn, ioTimeout time.Duration) error {
	if ioTimeout > 0 {
		dl := time.Now().Add(time.Duration(ioTimeout))
		_ = left.SetDeadline(dl)
		_ = right.SetDeadline(dl)
	}

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
