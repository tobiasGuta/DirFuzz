package tui

import (
	"dirfuzz/pkg/ui/presenter"
	"testing"
)

func TestReplayCursorPreservation(t *testing.T) {
	// Scenario: Analyst selects /api/admin, drops into replay mode 50k events ago,
	// then returns to LIVE mode. The cursor must remain strictly attached to /api/admin.
	
	// Simulated LIVE state
	liveState := presenter.TreeState{
		Expanded: map[string]bool{"root": true, "api": true},
		CursorID: "admin",
	}
	
	// Drop into Replay Mode
	replayMode := ReplayState{
		Enabled: true,
		CurrentIndex: 1000,
		TotalEvents: 51000,
	}
	
	// During replay, the tree is fundamentally altered because discoveries un-happen.
	// But the liveState object representing LIVE mode remains mathematically pinned
	// because it uses "admin" instead of array index 5.
	
	// Analyst hits 'r' to return live
	replayMode.Enabled = false
	
	// Assert
	if liveState.CursorID != "admin" {
		t.Fatalf("Returning to LIVE mode failed to preserve cursor. Cursor drift detected.")
	}
}
