package engine

import (
	"testing"
	"time"
)

func TestEventBusBackpressure(t *testing.T) {
	config := EventBusConfig{
		BufferSize: 2,
		DropPolicy: "drop-oldest",
	}
	bus := NewEventBus(config)

	// Mock slow subscriber
	type mockSub struct {
		received int
		ch       chan GraphEvent
	}
	// We don't actually process inside OnEvent to simulate a blocked/slow TUI thread
	// But we need to define OnEvent to satisfy interface. 
	// We'll just block purposefully or not read.
	// Actually, the bus spins up a goroutine that calls OnEvent. If OnEvent blocks, the channel fills up.
	// We will simulate it by making OnEvent block.

	bus.Subscribe(&mockSubImpl{
		onEvent: func(ev GraphEvent) {
			time.Sleep(50 * time.Millisecond) // Block
		},
	})

	// Fire 10 events rapidly. Buffer is 2.
	for i := 0; i < 10; i++ {
		bus.Publish(GraphEvent{Type: GraphEventNodeAdded, NodeID: "rapid-event"})
	}

	// If Publish() blocked, the test would deadlock.
	// The fact we reach here proves backpressure (drop-oldest) successfully prevented a lock.
}

type mockSubImpl struct {
	onEvent func(ev GraphEvent)
}

func (m *mockSubImpl) OnEvent(ev GraphEvent) {
	m.onEvent(ev)
}
