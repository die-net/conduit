package proxy

var (
	// Reduce GC overhead by setting a minimum GC heap size;
	// GOGC+GOMEMLIMIT can't express this.  This only allocates virtual
	// memory, not RSS.  Ignore it.
	ballast = make([]byte, 0, 25_000_000)
	_       = ballast
)
