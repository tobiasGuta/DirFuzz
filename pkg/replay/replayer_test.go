package replay

import (
	"dirfuzz/pkg/engine"
	"testing"
)

type mockReplaySource struct {
	events []engine.GraphEvent
}

func (m *mockReplaySource) EventsBetween(from, to uint64) []engine.GraphEvent {
	if from >= uint64(len(m.events)) {
		return []engine.GraphEvent{}
	}
	end := to
	if end > uint64(len(m.events)) {
		end = uint64(len(m.events))
	}
	return m.events[from:end]
}

func (m *mockReplaySource) CheckpointBefore(index uint64) ReplayCheckpoint {
	return ReplayCheckpoint{
		EventIndex: 0,
		Snapshot:   engine.AnalystSnapshot{Version: 0},
	}
}

func TestReplayDeterminism(t *testing.T) {
	events := []engine.GraphEvent{
		{Type: "DISCOVERY"},
		{Type: "FINDING"},
	}

	source := &mockReplaySource{events: events}
	replayer := NewReplayer(source)

	snapshotA, _ := replayer.SnapshotAt(2)
	snapshotB, _ := replayer.SnapshotAt(2)

	hashA := HashSnapshot(snapshotA)
	hashB := HashSnapshot(snapshotB)

	if hashA != hashB {
		t.Fatalf("Replayer produced non-deterministic output: %s != %s", hashA, hashB)
	}
}
