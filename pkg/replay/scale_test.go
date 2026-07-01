package replay

import (
	"dirfuzz/pkg/engine"
	"testing"
	"time"
)

type scaleReplaySource struct {}

func (s *scaleReplaySource) EventsBetween(from, to uint64) []engine.GraphEvent {
	// Simulate fetching only the delta
	return make([]engine.GraphEvent, to-from)
}

func (s *scaleReplaySource) CheckpointBefore(index uint64) ReplayCheckpoint {
	// A robust system drops a checkpoint every e.g. 100k events
	// So if we request event 10,000,000 we should get a checkpoint right near it
	checkpointIdx := index - (index % 100000)
	
	return ReplayCheckpoint{
		EventIndex: checkpointIdx,
		Snapshot:   engine.AnalystSnapshot{Version: checkpointIdx},
	}
}

func TestSnapshotAtScale(t *testing.T) {
	source := &scaleReplaySource{}
	replayer := NewReplayer(source)

	start := time.Now()
	// Ask for event 10,000,000
	snap, _ := replayer.SnapshotAt(10000000)
	elapsed := time.Since(start)

	if snap.Version != 10000000 {
		t.Fatalf("Replay math failed to produce target version")
	}

	if elapsed > 50 * time.Millisecond {
		t.Fatalf("Replay failed scale test. Took too long: %v", elapsed)
	}
}
