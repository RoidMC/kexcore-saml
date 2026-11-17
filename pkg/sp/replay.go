package sp

import (
	"sync"
	"time"
)

// MemoryReplayCache is a process-local ReplayCache.
//
// It is only correct for a single instance. A deployment with more than one
// server must supply a shared implementation (Redis, SQL) through
// Config.ReplayCache; otherwise a captured assertion can be replayed against
// another instance.
type MemoryReplayCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
	now     func() time.Time
}

// NewMemoryReplayCache returns an empty in-memory cache.
func NewMemoryReplayCache() *MemoryReplayCache {
	return &MemoryReplayCache{
		entries: make(map[string]time.Time),
		now:     time.Now,
	}
}

// Consume implements ReplayCache.
func (c *MemoryReplayCache) Consume(assertionID string, expiresAt time.Time) error {
	if assertionID == "" {
		return ErrReplay
	}

	now := c.now()
	if expiresAt.IsZero() || !expiresAt.After(now) {
		expiresAt = now.Add(time.Hour)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if recordedUntil, ok := c.entries[assertionID]; ok && now.Before(recordedUntil) {
		return ErrReplay
	}

	// Opportunistic cleanup keeps the map bounded without a background
	// goroutine.
	if len(c.entries) > 1024 {
		for id, until := range c.entries {
			if !now.Before(until) {
				delete(c.entries, id)
			}
		}
	}

	c.entries[assertionID] = expiresAt
	return nil
}
