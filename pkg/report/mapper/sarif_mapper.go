package mapper

import "dirfuzz/pkg/report"

// SARIFDocument represents a mock structure for the test
type SARIFDocument struct {
	Version string
	Runs    []SARIFRun
}

type SARIFRun struct {
	Tool    SARIFTool
	Results []SARIFResult
}

type SARIFTool struct {
	Driver SARIFDriver
}

type SARIFDriver struct {
	Name string
}

type SARIFResult struct {
	RuleID    string
	Level     string
	Message   SARIFMessage
	Locations []SARIFLocation
}

type SARIFMessage struct {
	Text string
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation
}

type SARIFArtifactLocation struct {
	URI string
}

func MapToSARIF(artifact report.ReportArtifact) SARIFDocument {
	// A simple mapping from our domain logic to the SARIF standard format
	res := SARIFResult{
		RuleID:  artifact.FindingID,
		Level:   artifact.Severity,
		Message: SARIFMessage{Text: artifact.Summary},
	}

	for _, ev := range artifact.Evidence {
		res.Locations = append(res.Locations, SARIFLocation{
			PhysicalLocation: SARIFPhysicalLocation{
				ArtifactLocation: SARIFArtifactLocation{URI: ev.SourceID},
			},
		})
	}

	return SARIFDocument{
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{Name: "DirFuzz"},
				},
				Results: []SARIFResult{res},
			},
		},
	}
}
