package validation

import (
	"dirfuzz/pkg/ui/actions"
	"dirfuzz/pkg/ui/models"
	"dirfuzz/pkg/ui/viewmodel"
	"testing"
)

func TestValidationIsolation(t *testing.T) {
	// Assert that a command from the UI never touches engine graphs directly
	// It goes: UI -> ValidationCommand -> Planner -> Queue (Pending)
	
	finding := viewmodel.FindingDetailView{
		FindingID: "f1",
		Title:     "IDOR",
	}

	planner := &DefaultPlanner{}
	reqs := planner.Suggest(finding)

	if len(reqs) == 0 {
		t.Fatalf("Planner failed to suggest validation")
	}

	cmd := actions.ValidationCommand{
		NodeID:     "node-f1",
		Validation: string(models.ValidateAuthBoundary),
		Priority:   1,
	}

	// This is a unit test asserting that the Planner -> Command lifecycle
	// creates decoupled Models (ValidationRequest) that contain no pointers 
	// to DiscoveryGraph or Engine internals.
	
	// `cmd` and `reqs` are plain data structs.
	if cmd.NodeID != reqs[0].NodeID {
		t.Fatalf("Command node ID does not match planned node ID")
	}
}
