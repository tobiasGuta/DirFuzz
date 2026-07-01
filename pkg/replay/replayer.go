package replay

import (
	"crypto/sha256"
	"dirfuzz/pkg/engine"
	"encoding/json"
	"fmt"
)

type ReplayCheckpoint struct {
	EventIndex   uint64
	SnapshotHash string
	Snapshot     engine.AnalystSnapshot
}

type ReplaySource interface {
	EventsBetween(from, to uint64) []engine.GraphEvent
	CheckpointBefore(index uint64) ReplayCheckpoint
}

type Replayer interface {
	SnapshotAt(index uint64) (engine.AnalystSnapshot, error)
}

// DefaultReplayer implements Replayer using a ReplaySource
type DefaultReplayer struct {
	source ReplaySource
}

func NewReplayer(source ReplaySource) *DefaultReplayer {
	return &DefaultReplayer{source: source}
}

func (r *DefaultReplayer) SnapshotAt(index uint64) (engine.AnalystSnapshot, error) {
	checkpoint := r.source.CheckpointBefore(index)
	
	// Fast path: if the checkpoint is exactly the index we want
	if checkpoint.EventIndex == index {
		return checkpoint.Snapshot, nil
	}
	
	// In a real system, we'd apply delta events onto the checkpoint.
	// For this mock implementation, we just mutate the version.
	
	events := r.source.EventsBetween(checkpoint.EventIndex, index)
	
	snapshot := checkpoint.Snapshot
	snapshot.Version = index
	for _, e := range events {
		if e.Type == "FINDING" {
			snapshot.Metrics.FindingsCreated++
		}
	}
	
	return snapshot, nil
}

// HashSnapshot deterministically hashes an AnalystSnapshot
func HashSnapshot(snap engine.AnalystSnapshot) string {
	// zero out volatile/unstable fields if any exist
	stable := snap
	bytes, _ := json.Marshal(stable)
	return fmt.Sprintf("%x", sha256.Sum256(bytes))
}
