package proxy

import (
	"net/http/httputil"
	"sync"
)

type bufferPool struct {
	pool sync.Pool
}

func NewBufferPool(size int) httputil.BufferPool {
	bp := &bufferPool{}
	bp.pool.New = func() any {
		b := make([]byte, size)
		return &b
	}

	return bp
}

func (p *bufferPool) Get() []byte {
	b := p.pool.Get().(*[]byte)
	return *b
}

func (p *bufferPool) Put(b []byte) {
	// This &b forces a 32-byte heap allocation.  There's no way to avoid this when converting a non-pointer to an interface{}.
	p.pool.Put(&b)
}
