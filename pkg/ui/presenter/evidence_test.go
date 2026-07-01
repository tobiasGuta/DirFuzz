package presenter

import (
	"dirfuzz/pkg/ui/models"
	"dirfuzz/pkg/ui/viewmodel"
	"testing"
)

func TestEvidenceStory(t *testing.T) {
	// Setup the finding presenter
	presenter := &DefaultFindingPresenter{}
	ctx := PresenterContext{}
	
	// Create a mock presentation model with the finding we want to test
	model := models.PresentationModel{}
	
	// Execute the presenter logic
	view := presenter.Detail(model, "finding-123", ctx)

	// Verify the translation mapping
	if view.Evidence.OriginChain[0] != "app.js" {
		t.Fatalf("Expected origin chain to start with app.js, got %s", view.Evidence.OriginChain[0])
	}
	
	if len(view.Evidence.Timeline) != 2 {
		t.Fatalf("Expected timeline to have 2 entries, got %d", len(view.Evidence.Timeline))
	}
	
	if view.Evidence.Timeline[0].Type != viewmodel.EvidenceSource {
		t.Fatalf("Expected timeline item 0 to be of type EvidenceSource, got %v", view.Evidence.Timeline[0].Type)
	}

	if view.Evidence.Timeline[1].Type != viewmodel.EvidenceValidation {
		t.Fatalf("Expected timeline item 1 to be of type EvidenceValidation, got %v", view.Evidence.Timeline[1].Type)
	}
}
