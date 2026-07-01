package report

import (
	"dirfuzz/pkg/ui/viewmodel"
	"errors"
	"fmt"
	"time"
)

type Builder interface {
	Build(finding viewmodel.FindingDetailView) (ReportArtifact, error)
}

type DefaultBuilder struct{}

func (b *DefaultBuilder) Build(finding viewmodel.FindingDetailView) (ReportArtifact, error) {
	if !finding.Readiness.Ready {
		return ReportArtifact{}, errors.New("finding not exportable: missing readiness prerequisites")
	}

	var evidenceItems []EvidenceItem
	for i, ev := range finding.Evidence.Timeline {
		evidenceItems = append(evidenceItems, EvidenceItem{
			ID:       fmt.Sprintf("%s-ev-%d", finding.FindingID, i),
			Summary:  ev.Title,
			Hash:     fmt.Sprintf("mock-hash-%d", i), // Ideally derived from immutable evidence source
			SourceID: ev.Source,
		})
	}

	art := ReportArtifact{
		ID:        fmt.Sprintf("report-%s", finding.FindingID),
		FindingID: finding.FindingID,
		Title:     finding.Title,
		Severity:  fmt.Sprintf("%v", finding.Severity),
		Summary:   finding.Evidence.Summary,
		Impact:    "Requires explicit impact definition in real usage",
		Reproduction: []Step{
			{Order: 1, Description: "Navigate to target", Action: "GET /"},
		},
		Evidence:  evidenceItems,
		Target:    "target.com", // Mocked for now
		CreatedAt: time.Now(),
		Status:    ArtifactDraft,
		Version:   1,
	}

	art.Hash = art.ComputeHash()
	return art, nil
}
