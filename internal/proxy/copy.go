package proxy

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

func CopyBidirectional(ctx context.Context, left, right net.Conn, ioTimeout time.Duration) error {
	if ioTimeout > 0 {
		dl := time.Now().Add(time.Duration(ioTimeout))
		_ = left.SetDeadline(dl)
		_ = right.SetDeadline(dl)
	}

	g, gctx := errgroup.WithContext(ctx)

	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = left.Close()
			_ = right.Close()
		})
	}
	defer closeBoth()

	g.Go(func() error {
		_, err := io.Copy(left, right)
		return err
	})

	g.Go(func() error {
		_, err := io.Copy(right, left)
		return err
	})

	// If the context is canceled, ensure we close both sides to unblock Copy.
	g.Go(func() error {
		<-gctx.Done()
		closeBoth()
		return nil
	})

	return g.Wait()
}
