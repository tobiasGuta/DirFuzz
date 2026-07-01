package engine

import (
	"sync"
	"testing"
	"time"
)

func TestAnalystStateIndependence(t *testing.T) {
	// 1. Verify Adding AnalystNote does not mutate active engine state
	f := Finding{
		ID:       "f1",
		NodeID:   "n1",
		Severity: "high",
		Score: FindingScore{
			FinalScore: 80,
		},
	}

	// Engine creates Finding
	originalNotesLen := len(f.Notes)

	// Analyst UI adds Note
	f.Notes = append(f.Notes, AnalystNote{
		ID:        "note1",
		Author:    "Analyst",
		CreatedAt: time.Now(),
		Text:      "Confirmed manually",
	})

	if len(f.Notes) != originalNotesLen+1 {
		t.Fatalf("Expected Note to be added successfully")
	}

	// 2. Verify Adding FindingSnapshot captures state temporally
	f.Snapshots = append(f.Snapshots, FindingSnapshot{
		CreatedAt: time.Now(),
		Score:     f.Score,
		Evidence:  f.Chain,
	})

	// Engine mutates Finding score due to 404
	f.Score.FinalScore = 10

	// Snapshot must retain historical context
	if f.Snapshots[0].Score.FinalScore != 80 {
		t.Fatalf("FindingSnapshot mutated along with current active state, breaking historical context")
	}

	if f.Score.FinalScore != 10 {
		t.Fatalf("Finding failed to mutate its active score")
	}
}

func TestSnapshotAtomicity(t *testing.T) {
	// Simulate the core engine state
	var mu sync.RWMutex
	var metrics EngineMetricsSnap
	var version uint64

	var wg sync.WaitGroup
	wg.Add(2)

	// Simulate Worker A doing a multi-part update atomically
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			mu.Lock()
			// Atomicity assumption: Everything under one lock is an atomic engine change
			metrics.FindingsCreated++
			metrics.QueueDepth++
			version++
			mu.Unlock()
		}
	}()

	var snapshots []AnalystSnapshot
	var snapMu sync.Mutex

	// Simulate SnapshotBuilder reading simultaneously
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			mu.RLock()
			// Shallow copy the metrics
			snap := AnalystSnapshot{
				Version: version,
				Metrics: metrics,
			}
			mu.RUnlock()
			
			snapMu.Lock()
			snapshots = append(snapshots, snap)
			snapMu.Unlock()
		}
	}()

	wg.Wait()

	// Verify atomicity constraint: FindingsCreated must exactly equal QueueDepth
	// because they are modified within the same engine write boundary.
	for _, snap := range snapshots {
		if snap.Metrics.FindingsCreated != snap.Metrics.QueueDepth {
			t.Fatalf("Torn read detected in snapshot %d! FindingsCreated=%d, QueueDepth=%d", 
				snap.Version, snap.Metrics.FindingsCreated, snap.Metrics.QueueDepth)
		}
	}
}
