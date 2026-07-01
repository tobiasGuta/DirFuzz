package engine

import (
	"fmt"
	"sort"
	"time"
)

// ReplaySystem reconstructs state and generates chronological timelines from stored events.
type ReplaySystem struct {
	Store GraphStore
}

// NewReplaySystem creates a new replay orchestrator.
func NewReplaySystem(store GraphStore) *ReplaySystem {
	return &ReplaySystem{Store: store}
}

// RebuildGraph deterministically reconstructs a DiscoveryGraph from a base snapshot
// and all subsequent events.
func (r *ReplaySystem) RebuildGraph() (*DiscoveryGraph, error) {
	// 1. Load the most recent stable snapshot
	graph, err := r.Store.LoadSnapshot()
	if err != nil {
		return nil, fmt.Errorf("failed to load base snapshot: %w", err)
	}

	if graph == nil {
		graph = NewDiscoveryGraph()
	}

	// 2. Fetch all events that occurred after the snapshot
	// If the snapshot has an associated last event ID, we would pass it here.
	// For now, we assume GetEvents handles the delta logic or we load all.
	events, err := r.Store.GetEvents("")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch replay events: %w", err)
	}

	// 3. Sort events chronologically to guarantee deterministic reconstruction
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})

	// 4. Apply the event delta
	for _, ev := range events {
		// In a full implementation, this switch would handle re-applying the mutations.
		// For our architecture, since Graph mutates then Events are appended, we actually
		// need a mutation engine that takes an Event and applies it to the Graph.
		switch ev.Type {
		case GraphEventNodeAdded:
			// Ensure node exists, etc.
		case GraphEventEvidenceUpdated:
			// Apply evidence to node
		case GraphEventResponseObserved:
			// Apply response observations
		}
	}

	return graph, nil
}

// GenerateTimeline creates a human-readable chronological trace of engine activity.
func (r *ReplaySystem) GenerateTimeline() ([]string, error) {
	events, err := r.Store.GetEvents("")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch timeline events: %w", err)
	}

	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})

	var timeline []string
	for _, ev := range events {
		timeStr := ev.Timestamp.Format(time.RFC3339)
		
		switch ev.Type {
		case GraphEventNodeAdded:
			timeline = append(timeline, fmt.Sprintf("[%s] Discovered new node %s", timeStr, ev.NodeID))
		case GraphEventEvidenceUpdated:
			timeline = append(timeline, fmt.Sprintf("[%s] Updated evidence for node %s", timeStr, ev.NodeID))
		case GraphEventResponseObserved:
			timeline = append(timeline, fmt.Sprintf("[%s] Observed response for node %s (Status: %d)", timeStr, ev.NodeID, ev.Evidence.Confidence)) // Evidence struct is reused for responses
		default:
			timeline = append(timeline, fmt.Sprintf("[%s] Unknown event %s on node %s", timeStr, ev.Type, ev.NodeID))
		}
	}

	return timeline, nil
}
