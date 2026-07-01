package campaign

import (
	"context"
	"time"
)

// Event defines the standard interface for all immutable ledger events.
// Any structure written to the EventLedger must implement this interface.
type Event interface {
	EventID() string
	EventType() string
	Timestamp() time.Time
}

// EventStore represents the foundational persistence contract for DirFuzz.
// Implementations (e.g., memory, sqlite, postgres, badger) must guarantee
// append-only chronologically ordered operations.
type EventStore interface {
	// Append writes a new immutable event to the end of the ledger.
	Append(ctx context.Context, event Event) error

	// Read retrieves a chronological slice of events bounded by time.
	Read(ctx context.Context, from, to time.Time) ([]Event, error)

	// Snapshot creates a compacted point-in-time state array for fast projection rebuilds.
	Snapshot(ctx context.Context) ([]byte, error)

	// Replay returns the complete chronological ledger for projection rebuilding.
	Replay(ctx context.Context) ([]Event, error)
}
