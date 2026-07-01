package engine

import (
	"sync"
)

type EventBusConfig struct {
	BufferSize int
	DropPolicy string // e.g., "drop-oldest", "block"
}

type EngineSubscriber interface {
	OnEvent(event GraphEvent)
}

type EventBus struct {
	mu          sync.RWMutex
	config      EventBusConfig
	subscribers map[EngineSubscriber]chan GraphEvent
}

func NewEventBus(config EventBusConfig) *EventBus {
	return &EventBus{
		config:      config,
		subscribers: make(map[EngineSubscriber]chan GraphEvent),
	}
}

func (eb *EventBus) Subscribe(sub EngineSubscriber) {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	ch := make(chan GraphEvent, eb.config.BufferSize)
	eb.subscribers[sub] = ch

	// Start a lightweight worker to drain the channel and call OnEvent
	go func() {
		for ev := range ch {
			sub.OnEvent(ev)
		}
	}()
}

func (eb *EventBus) Unsubscribe(sub EngineSubscriber) {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	if ch, ok := eb.subscribers[sub]; ok {
		close(ch)
		delete(eb.subscribers, sub)
	}
}

func (eb *EventBus) Publish(event GraphEvent) {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	for _, ch := range eb.subscribers {
		select {
		case ch <- event:
			// successfully queued
		default:
			// Backpressure handling
			if eb.config.DropPolicy == "drop-oldest" {
				select {
				case <-ch: // drop oldest
				default:
				}
				// try push again
				select {
				case ch <- event:
				default:
				}
			}
			// if "block", we would wait, but TUI usually uses drop-oldest
		}
	}
}
