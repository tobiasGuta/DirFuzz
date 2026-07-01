package adapter

import (
	"dirfuzz/pkg/engine"
	"dirfuzz/pkg/ui/models"
)

// SnapshotAdapter explicitly prevents UI Presenters from importing Engine objects.
type SnapshotAdapter struct{}

func NewSnapshotAdapter() *SnapshotAdapter {
	return &SnapshotAdapter{}
}

func (a *SnapshotAdapter) Convert(snap engine.AnalystSnapshot) models.PresentationModel {
	pm := models.PresentationModel{
		Version: snap.Version,
		Metrics: models.MetricsData{
			RequestsSent:    snap.Metrics.RequestsSent,
			NodesDiscovered: snap.Metrics.NodesDiscovered,
			NodesConfirmed:  snap.Metrics.NodesConfirmed,
			FindingsCreated: snap.Metrics.FindingsCreated,
			QueueDepth:      snap.Metrics.QueueDepth,
			WorkerCount:     snap.Metrics.WorkerCount,
			GraphSize:       snap.Metrics.GraphSize,
		},
	}

	for _, t := range snap.Targets {
		pm.Targets = append(pm.Targets, models.TargetData{Host: t.Host})
	}

	for _, f := range snap.Findings {
		pm.Findings = append(pm.Findings, models.FindingData{
			ID:       f.ID,
			Title:    f.Title,
			Severity: f.Severity,
			Score:    f.Score.FinalScore,
		})
	}

	// Simplistic mapping for now to keep it bounded. QueueData and Timeline data will 
	// require future mapping if AnalystSnapshot is augmented with exact Queue and Timeline dumps.
	pm.Queue = models.QueueData{
		Validation: int(snap.Metrics.QueueDepth), // Mocking split for now
		ParamFuzz:  0,
		Discovery:  0,
	}

	return pm
}
