package presenter

import (
	"dirfuzz/pkg/ui/models"
	"testing"
)

func TestTreeExpansionIsolation(t *testing.T) {
	idx := &models.SurfaceIndex{
		Nodes: map[string]*models.SurfaceNode{
			"root": {ID: "root", Name: "target.com", ChildIDs: []string{"api", "assets"}},
			"api":  {ID: "api", Name: "/api", ChildIDs: []string{"users", "admin"}},
			"assets": {ID: "assets", Name: "/assets", ChildIDs: []string{"js"}},
			"users": {ID: "users", Name: "/users"},
			"admin": {ID: "admin", Name: "/admin"},
			"js": {ID: "js", Name: "app.js"},
		},
	}

	state := TreeState{
		Expanded: map[string]bool{"root": true, "api": true},
	}

	presenter := &DefaultTreePresenter{}
	lines := presenter.RenderBranch(idx, state, "root")

	// Expecting:
	// target.com
	//   /api
	//     /users
	//     /admin
	//   /assets (but NOT expanded, so no app.js)
	
	materializedJS := false
	for _, line := range lines {
		if line == "    app.js" {
			materializedJS = true
		}
	}

	if materializedJS {
		t.Fatalf("Tree expanded an unrelated branch, breaking isolation")
	}
	
	if len(lines) != 5 {
		t.Fatalf("Expected exactly 5 lines rendered, got %d", len(lines))
	}
}

func TestSurfaceCursorStability(t *testing.T) {
	// Snapshot A
	state := TreeState{
		Expanded: map[string]bool{"root": true, "api": true},
		CursorID: "admin", // The cursor is bound directly to the NodeID
	}

	// Snapshot B injects 500 new discoveries "before" /admin
	idx := &models.SurfaceIndex{
		Nodes: map[string]*models.SurfaceNode{
			"root": {ID: "root", Name: "target.com", ChildIDs: []string{"api"}},
			"api":  {ID: "api", Name: "/api", ChildIDs: []string{}},
			"admin": {ID: "admin", Name: "/admin"},
		},
	}
	
	// Add 500 sibling endpoints before admin
	for i := 0; i < 500; i++ {
		id := string(rune('a'+i%26)) + string(rune(i)) // Fake ID
		idx.Nodes[id] = &models.SurfaceNode{ID: id, Name: "new-discovery"}
		idx.Nodes["api"].ChildIDs = append(idx.Nodes["api"].ChildIDs, id)
	}
	idx.Nodes["api"].ChildIDs = append(idx.Nodes["api"].ChildIDs, "admin")

	presenter := &DefaultTreePresenter{}
	lines := presenter.RenderBranch(idx, state, "root")

	// Assert cursor stability
	cursorFound := false
	for _, line := range lines {
		if line == "    >  /admin" {
			cursorFound = true
		}
	}

	if !cursorFound {
		t.Fatalf("Cursor decoupled from NodeID and lost stability!")
	}
}
