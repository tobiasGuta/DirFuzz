package presenter

import (
	"dirfuzz/pkg/ui/models"
	"dirfuzz/pkg/ui/viewmodel"
)

type FindingExplorerPresenter interface {
	Detail(model models.PresentationModel, id string, ctx PresenterContext) viewmodel.FindingDetailView
}

type DefaultFindingPresenter struct{}

func (p *DefaultFindingPresenter) Detail(model models.PresentationModel, id string, ctx PresenterContext) viewmodel.FindingDetailView {
	// Find the finding in PresentationModel (which would contain findings list after adapter processing)
	// We'll mock a finding extraction for now since PresentationModel doesn't have Findings yet
	
	// Mock an origin chain
	originChain := []string{
		"app.js",
		"discovered /api/admin",
		"request without token",
		"HTTP 403 Forbidden",
	}

	return viewmodel.FindingDetailView{
		FindingID:  id,
		Title:      "Authentication Boundary Validation",
		Severity:   viewmodel.StyleCritical,
		Score:      92,
		Confidence: "High",
		Evidence: viewmodel.EvidenceView{
			FindingID:   id,
			OriginChain: originChain,
			Summary:     "Validated endpoint bypass",
			Timeline: []viewmodel.EvidenceTimelineItem{
				{
					Timestamp:  "12:01",
					Type:       viewmodel.EvidenceSource,
					Title:      "Source Extracted",
					Source:     "app.js",
				},
				{
					Timestamp:  "12:02",
					Type:       viewmodel.EvidenceValidation,
					Title:      "Validation Failed",
					Source:     "HTTP 403",
				},
			},
		},
		Readiness: viewmodel.ReportReadiness{
			HasImpact: true,
			HasProof:  true,
			HasSteps:  true,
			Ready:     true,
		},
	}
}
