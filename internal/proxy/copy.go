package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"

	"golang.org/x/sync/errgroup"
)

// CopyBidirectional proxies bytes between left and right until one side
// returns an error or ctx is canceled.  Connections are gracefully shut
// down via TCP half-close (CloseWrite) where possible or normal Close
// otherwise.
//
// It intentionally avoids setting deadlines so io.Copy can use Go's zero-copy
// fast path when available.
//
// When ctx is canceled, both connections are closed to unblock any pending
// copies.
func CopyBidirectional(ctx context.Context, left, right net.Conn) error {
	g, gctx := errgroup.WithContext(ctx)
	context.AfterFunc(gctx, func() {
		_ = left.Close()
		_ = right.Close()
	})

	g.Go(func() error {
		return copyClose(left, right)
	})

	g.Go(func() error {
		return copyClose(right, left)
	})

	if err := g.Wait(); err != nil {
		return fmt.Errorf("copy: %w", err)
	}
	return nil
}

// copyClose does an io.Copy to dst from src, then CloseWrite (graceful TCP
// half-close) or Close dst.
func copyClose(dst, src net.Conn) error {
	_, err := io.Copy(dst, src)

	// We double-close in some cases, so ignore this error.
	if err != nil && errors.Is(err, net.ErrClosed) {
		err = nil
	}

	// Gracefully shut dst down with CloseWrite() if available.
	if dcw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = dcw.CloseWrite()
		return err
	}

	// Otherwise, Close() will have to do, even though it
	// immediately breaks receive.
	_ = dst.Close()
	return err
}
