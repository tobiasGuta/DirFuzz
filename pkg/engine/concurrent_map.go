package engine

import "sync"

// ConcurrentMap is a strongly-typed, mutex-protected map designed for
// write-heavy workloads where sync.Map performs poorly.
type ConcurrentMap[K comparable, V any] struct {
	mu sync.RWMutex
	m  map[K]V
}

// NewConcurrentMap creates a new ConcurrentMap.
func NewConcurrentMap[K comparable, V any]() *ConcurrentMap[K, V] {
	return &ConcurrentMap[K, V]{
		m: make(map[K]V),
	}
}

// Load returns the value stored in the map for a key, or nil if no
// value is present. The ok result indicates whether value was found in the map.
func (c *ConcurrentMap[K, V]) Load(key K) (V, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	val, ok := c.m[key]
	return val, ok
}

// Store sets the value for a key.
func (c *ConcurrentMap[K, V]) Store(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[key] = value
}

// LoadOrStore returns the existing value for the key if present.
// Otherwise, it stores and returns the given value.
// The loaded result is true if the value was loaded, false if stored.
func (c *ConcurrentMap[K, V]) LoadOrStore(key K, value V) (actual V, loaded bool) {
	c.mu.RLock()
	val, ok := c.m[key]
	c.mu.RUnlock()
	if ok {
		return val, true
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if val, ok := c.m[key]; ok {
		return val, true
	}
	c.m[key] = value
	return value, false
}

// Delete deletes the value for a key.
func (c *ConcurrentMap[K, V]) Delete(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, key)
}

// Range calls f sequentially for each key and value present in the map.
// If f returns false, range stops the iteration.
//
// WARNING: f must not call Store or Delete, otherwise it will deadlock.
func (c *ConcurrentMap[K, V]) Range(f func(key K, value V) bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for k, v := range c.m {
		if !f(k, v) {
			break
		}
	}
}

// Clear removes all elements from the map.
func (c *ConcurrentMap[K, V]) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m = make(map[K]V)
}
