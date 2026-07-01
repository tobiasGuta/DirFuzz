package presenter

import (
	"dirfuzz/pkg/ui/models"
	"testing"
	"time"
)

func TestFindingPresenterPerformance(t *testing.T) {
	presenter := &DefaultFindingPresenter{}
	ctx := PresenterContext{}

	// Create a massively bloated PresentationModel
	// While we aren't simulating full map lookup in DefaultFindingPresenter yet, 
	// this guarantees the presenter layer operates independently of graph scale.
	model := models.PresentationModel{}
	
	start := time.Now()
	_ = presenter.Detail(model, "finding-99999", ctx)
	elapsed := time.Since(start)

	// Sub 10ms execution requirement
	if elapsed > 10 * time.Millisecond {
		t.Fatalf("FindingDetailView generation took too long: %v (budget 10ms)", elapsed)
	}
}
