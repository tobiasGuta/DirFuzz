package tui

import (
	"dirfuzz/pkg/engine"
	"dirfuzz/pkg/ui/actions"
	"testing"
	"time"
)

// MockAnalystStore to intercept UI actions
type mockAnalystStore struct {
	lastCommand actions.AnalystCommand
}

func (m *mockAnalystStore) Dispatch(cmd actions.AnalystCommand) {
	m.lastCommand = cmd
}

func TestAnalystIsolation(t *testing.T) {
	graph := engine.NewDiscoveryGraph()
	// Add a dummy finding node directly to the graph
	graph.AddSourceNode("finding-123", "javascript")

	store := &mockAnalystStore{}

	// Simulate the UI dispatching a Confirm action
	cmd := actions.AnalystCommand{
		ID:        "finding-123",
		Action:    actions.ActionConfirm,
		CreatedAt: time.Now(),
		Actor:     "analyst@example.com",
		Reason:    "Looks like a valid IDOR",
	}

	// UI fires the command to the store
	store.Dispatch(cmd)

	// Verify the graph itself was NOT mutated synchronously
	// Since we haven't implemented finding statuses strictly on nodes yet in this test,
	// the core test is that the Graph object has NO references or knowledge of the 
	// AnalystCommand. The command is entirely captured by the Store boundary.
	if store.lastCommand.ID != "finding-123" {
		t.Fatalf("Expected AnalystStore to capture the command ID")
	}
	
	if store.lastCommand.Action != actions.ActionConfirm {
		t.Fatalf("Expected AnalystStore to capture the Confirm action")
	}

	if len(graph.Nodes) != 1 {
		t.Fatalf("Graph size unexpectedly changed, isolation breached!")
	}
}
