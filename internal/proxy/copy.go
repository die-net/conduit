package proxy

import (
	"context"
	"fmt"
	"io"
	"net"

	"golang.org/x/sync/errgroup"
)

// CopyBidirectional proxies bytes between left and right until one side
// returns an error or ctx is canceled.
//
// It intentionally avoids setting deadlines so io.Copy can use Go's zero-copy
// fast path when available.
//
// When ctx is canceled, both connections are closed to unblock any pending
// copies.
func CopyBidirectional(ctx context.Context, left, right net.Conn) error {
	// There can't be deadlines set on arguments to io.Copy to be able
	// to use Go's zero-copy hot path that uses splice.  Instead,
	// we Close() both sockets if the context is canceled.
	cctx, cancel := context.WithCancel(ctx)
	g, gctx := errgroup.WithContext(cctx)

	g.Go(func() error {
		_, err := io.Copy(left, right)
		cancel()
		if err != nil {
			return fmt.Errorf("copy right->left: %w", err)
		}
		return nil
	})

	g.Go(func() error {
		_, err := io.Copy(right, left)
		cancel()
		if err != nil {
			return fmt.Errorf("copy left->right: %w", err)
		}
		return nil
	})

	// When the context is canceled, ensure we close both sides to unblock Copy.
	<-gctx.Done()
	_ = left.Close()
	_ = right.Close()

	if err := g.Wait(); err != nil {
		return fmt.Errorf("bidirectional copy: %w", err)
	}
	return nil
}
