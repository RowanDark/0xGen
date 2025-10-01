package cases

import "sync"

// SummaryCache stores summariser outputs for deterministic replay.
type SummaryCache interface {
	Get(key string) (SummaryOutput, bool)
	Set(key string, value SummaryOutput)
}

// MemoryCache is a threadsafe in-memory cache implementation suitable for tests.
type MemoryCache struct {
	mu sync.RWMutex
	m  map[string]SummaryOutput
}

// NewMemoryCache constructs an empty memory cache.
func NewMemoryCache() *MemoryCache {
	return &MemoryCache{m: make(map[string]SummaryOutput)}
}

// Get retrieves a cached summary.
func (c *MemoryCache) Get(key string) (SummaryOutput, bool) {
	if c == nil {
		return SummaryOutput{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.m[key]
	return v, ok
}

// Set stores a summary output.
func (c *MemoryCache) Set(key string, value SummaryOutput) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.m[key] = value
	c.mu.Unlock()
}
